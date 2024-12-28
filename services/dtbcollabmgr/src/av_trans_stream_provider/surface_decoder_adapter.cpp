/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "surface_decoder_adapter.h"
#include "avcodec_common.h"
#include "avcodec_info.h"
#include "codec_server.h"
#include "dtbcollabmgr_log.h"
#include "media_description.h"
#include "meta/format.h"
#include <ctime>

namespace OHOS {
namespace DistributedCollab {
    namespace {
        static const std::string TAG = "SurfaceDecoderAdapter";
        constexpr int64_t VARIABLE_INCREMENT_INTERVAL = 1;
        using Status = Media::Status;
        using AVBufferQueueProducer = Media::AVBufferQueueProducer;
        using AVBufferQueueConsumer = Media::AVBufferQueueConsumer;
        using AVBufferQueue = Media::AVBufferQueue;
        using AVBuffer = Media::AVBuffer;
        using Meta = Media::Meta;
        using MDKey = MediaAVCodec::MediaDescriptionKey;
        using Tag = Media::Tag;
        using Task = Media::Task;
#define FALSE_RETURN_MSG(exec, fmt, args...) \
    do {                                     \
        bool returnValue = (exec);           \
        if (!returnValue) {                  \
            HILOGE(fmt, ##args);             \
            return;                          \
        }                                    \
    } while (0)
    }

    class SurfaceDecoderAdapterCallback : public MediaAVCodec::MediaCodecCallback {
    public:
        explicit SurfaceDecoderAdapterCallback(std::shared_ptr<SurfaceDecoderAdapter> adapter)
            : surfaceDecoderAdapter_(std::move(adapter))
        {
        }

        void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode) override
        {
            if (auto ptr = surfaceDecoderAdapter_.lock()) {
                ptr->decoderAdapterCallback_->OnError(errorType, errorCode);
            } else {
                HILOGI("invalid surfaceEncoderAdapter");
            }
        }

        void OnOutputFormatChanged(const MediaAVCodec::Format& format) override
        {
        }

        void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override
        {
            if (auto ptr = surfaceDecoderAdapter_.lock()) {
                ptr->OnInputBufferAvailable(index, buffer);
            }
        }

        void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override
        {
            if (auto ptr = surfaceDecoderAdapter_.lock()) {
                HILOGD("OnOutputBuffer flag %{public}d", buffer->flag_);
                ptr->OnOutputBufferAvailable(index, buffer);
                if (buffer->flag_ == 1) {
                    int64_t lastBufferPts = ptr->lastBufferPts_.load();
                    int64_t frameNum = ptr->frameNum_.load();
                    HILOGI("lastBuffer PTS:%{public}lld, frameNum:%{public}lld", lastBufferPts, frameNum);
                }
            }
        }

    private:
        std::weak_ptr<SurfaceDecoderAdapter> surfaceDecoderAdapter_;
    };

    class AVBufferAvailableListener : public Media::IConsumerListener {
    public:
        explicit AVBufferAvailableListener(std::shared_ptr<SurfaceDecoderAdapter> adapter)
            : surfaceDecoderAdapter_(std::move(adapter))
        {
        }

        void OnBufferAvailable() override
        {
            if (auto ptr = surfaceDecoderAdapter_.lock()) {
                ptr->AcquireAvailableInputBuffer();
            }
        }

    private:
        std::weak_ptr<SurfaceDecoderAdapter> surfaceDecoderAdapter_;
    };

    SurfaceDecoderAdapter::SurfaceDecoderAdapter()
    {
        HILOGI("encoder adapter create");
    }

    SurfaceDecoderAdapter::~SurfaceDecoderAdapter()
    {
        HILOGI("encoder adapter destroy");
        if (codecServer_) {
            codecServer_->Release();
        }
        codecServer_ = nullptr;
    }

    Status SurfaceDecoderAdapter::Init(const std::string& mime)
    {
        HILOGI("SurfaceDecoderAdapter::Init enter");
        HILOGI("Init mime: %{public}s", mime.c_str());
        codecServer_ = MediaAVCodec::VideoDecoderFactory::CreateByMime(mime);
        if (!codecServer_) {
            HILOGI("Create codecServer failed");
            return Status::ERROR_UNKNOWN;
        }
        if (!releaseBufferTask_) {
            releaseBufferTask_ = std::make_shared<Task>("SurfaceDecoder");
            releaseBufferTask_->RegisterJob([this] {
                ReleaseBuffer();
                return 0;
            });
        }
        return Status::OK;
    }

    Status SurfaceDecoderAdapter::Configure(const MediaAVCodec::Format& format)
    {
        HILOGI("SurfaceDecoderAdapter::Configure enter");
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        int32_t ret = codecServer_->Configure(format);
        return ret == ERR_OK ? Status::OK : Status::ERROR_UNKNOWN;
    }

    sptr<Media::AVBufferQueueProducer> SurfaceDecoderAdapter::GetInputBufferQueue()
    {
        HILOGI("SurfaceDecoderAdapter::GetInputBufferQueue enter");
        if (inputBufferQueue_ != nullptr && inputBufferQueue_->GetQueueSize() > 0) {
            HILOGI("InputBufferQueue already create");
            return inputBufferQueueProducer_;
        }
        inputBufferQueue_ = AVBufferQueue::Create(0,
            Media::MemoryType::UNKNOWN_MEMORY, "inputBufferQueue", true);
        inputBufferQueueProducer_ = inputBufferQueue_->GetProducer();
        inputBufferQueueConsumer_ = inputBufferQueue_->GetConsumer();
        sptr<Media::IConsumerListener> listener = new AVBufferAvailableListener(shared_from_this());
        inputBufferQueueConsumer_->SetBufferAvailableListener(listener);
        return inputBufferQueueProducer_;
    }

    Status SurfaceDecoderAdapter::SetOutputSurface(const sptr<Surface>& surface)
    {
        HILOGI("SurfaceDecoderAdapter::SetOutputSurface enter");
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        int32_t ret = codecServer_->SetOutputSurface(surface);
        if (ret == ERR_OK) {
            HILOGI("SetOutputSurface success");
            return Status::OK;
        } else {
            HILOGI("SetOutputSurface fail");
            return Status::ERROR_UNKNOWN;
        }
    }

    Status SurfaceDecoderAdapter::SetDecoderAdapterCallback(
        const std::shared_ptr<DecoderAdapterCallback>& decoderAdapterCallback)
    {
        HILOGI("SetDecoderAdapterCallback");
        std::shared_ptr<MediaAVCodec::MediaCodecCallback> surfaceDecoderAdapterCallback =
            std::make_shared<SurfaceDecoderAdapterCallback>(shared_from_this());
        decoderAdapterCallback_ = decoderAdapterCallback;
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        int32_t ret = codecServer_->SetCallback(surfaceDecoderAdapterCallback);
        if (ret == ERR_OK) {
            return Status::OK;
        } else {
            return Status::ERROR_UNKNOWN;
        }
    }

    Status SurfaceDecoderAdapter::Start()
    {
        HILOGI("SurfaceDecoderAdapter::Start");
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        int32_t ret = ERR_OK;
        isThreadExit_ = false;
        if (releaseBufferTask_) {
            releaseBufferTask_->Start();
        }
        ret = codecServer_->Prepare();
        if (ret == ERR_OK) {
            HILOGI("Prepare success");
        } else {
            HILOGI("Prepare fail");
            return Status::ERROR_UNKNOWN;
        }
        ret = codecServer_->Start();
        if (ret == ERR_OK) {
            HILOGI("Start success");
            return Status::OK;
        } else {
            HILOGI("Start fail");
            return Status::ERROR_UNKNOWN;
        }
    }

    Status SurfaceDecoderAdapter::Stop()
    {
        HILOGI("SurfaceDecoderAdapter::Stop enter");
        if (releaseBufferTask_) {
            isThreadExit_ = true;
            releaseBufferCondition_.notify_all();
            releaseBufferTask_->Stop();
            HILOGI("releaseBufferTask_ Stop");
        }
        if (!codecServer_) {
            return Status::OK;
        }
        int32_t ret = codecServer_->Stop();
        HILOGI("codecServer_ Stop");
        if (ret == ERR_OK) {
            return Status::OK;
        } else {
            return Status::ERROR_UNKNOWN;
        }
    }

    Status SurfaceDecoderAdapter::Pause()
    {
        HILOGI("Pause");
        return Status::OK;
    }

    Status SurfaceDecoderAdapter::Resume()
    {
        HILOGI("Resume");
        return Status::OK;
    }

    Status SurfaceDecoderAdapter::Flush()
    {
        HILOGI("Flush");
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        int32_t ret = codecServer_->Flush();
        if (ret == ERR_OK) {
            return Status::OK;
        } else {
            return Status::ERROR_UNKNOWN;
        }
    }

    Status SurfaceDecoderAdapter::Release()
    {
        HILOGI("Release");
        if (!codecServer_) {
            return Status::OK;
        }
        int32_t ret = codecServer_->Release();
        if (ret == ERR_OK) {
            return Status::OK;
        } else {
            return Status::ERROR_UNKNOWN;
        }
    }

    Status SurfaceDecoderAdapter::SetParameter(const MediaAVCodec::Format& format)
    {
        HILOGI("SetParameter");
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        int32_t ret = codecServer_->SetParameter(format);
        if (ret == ERR_OK) {
            return Status::OK;
        } else {
            return Status::ERROR_UNKNOWN;
        }
    }

    void SurfaceDecoderAdapter::OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
    {
        HILOGI("SurfaceDecoderAdapter::OnInputBufferAvailable enter");
        FALSE_RETURN_MSG(buffer != nullptr && buffer->meta_ != nullptr, "meta_ is nullptr.");
        HILOGD("OnInputAvailable enter. index:%{public}u, bufferid:%{public}lu, pts:%{public}lld, flag:%{public}u",
            index, buffer->GetUniqueId(), buffer->pts_, buffer->flag_);
        buffer->meta_->SetData(Tag::REGULAR_TRACK_ID, index);
        if (inputBufferQueueConsumer_ == nullptr) {
            HILOGE("inputBufferQueueConsumer_ is null");
            return;
        }
        if (inputBufferQueueConsumer_->IsBufferInQueue(buffer)) {
            if (inputBufferQueueConsumer_->ReleaseBuffer(buffer) != Status::OK) {
                HILOGE("InQueue RelBuf failed. index:%{public}u, bufferid:%{public}lu,pts:%{public}lld, flag:%{public}u",
                    index, buffer->GetUniqueId(), buffer->pts_, buffer->flag_);
            }
            return;
        }
        uint32_t size = inputBufferQueueConsumer_->GetQueueSize() + 1;
        HILOGI("AttachBuffer enter. index:%{public}u,  size:%{public}u , bufferid:%{public}lu",
            index, size, buffer->GetUniqueId());
        inputBufferQueueConsumer_->SetQueueSize(size);
        inputBufferQueueConsumer_->AttachBuffer(buffer, false);
    }

    void SurfaceDecoderAdapter::OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
    {
        HILOGD("SurfaceDecoderAdapter::OnOutputBufferAvailable enter");
        {
            std::lock_guard<std::mutex> lock(releaseBufferMutex_);
            if (buffer->flag_ == 1) {
                dropIndexs_.push_back(index);
            } else if (buffer->pts_ > lastBufferPts_.load()) {
                lastBufferPts_ = buffer->pts_;
                frameNum_.fetch_add(VARIABLE_INCREMENT_INTERVAL, std::memory_order_relaxed);
                indexs_.push_back(index);
            } else {
                HILOGD("OnOutputBufferAvailable drop index: %{public}u" PRIu32, index);
                dropIndexs_.push_back(index);
            }
        }
        releaseBufferCondition_.notify_all();
        HILOGD("OnOutputBufferAvailable end");
    }

    void SurfaceDecoderAdapter::AcquireAvailableInputBuffer()
    {
        HILOGD("SurfaceDecoderAdapter::AcquireAvailableInputBuffer enter");
        std::shared_ptr<AVBuffer> buffer;
        Status ret = inputBufferQueueConsumer_->AcquireBuffer(buffer);
        if (ret != Status::OK) {
            HILOGE("AcquireBuffer fail");
            return;
        }
        FALSE_RETURN_MSG(buffer->meta_ != nullptr, "buffer meta is nullptr.");
        uint32_t index;
        FALSE_RETURN_MSG(buffer->meta_->GetData(Tag::REGULAR_TRACK_ID, index), "get index failed.");
        FALSE_RETURN_MSG(codecServer_ != nullptr, "codecServer_ is nullptr.");
        if (codecServer_->QueueInputBuffer(index) != ERR_OK) {
            HILOGE("QueueInputBuffer failed, index:%{public}u, bufferid:%{public}lu, pts:%{public}lld, flag:%{public}u",
                index, buffer->GetUniqueId(), buffer->pts_, buffer->flag_);
        } else {
            HILOGD("QueueInputBuffer success, index:%{public}u, bufferid:%{public}lu, pts:%{public}lld, flag:%{public}u",
                index, buffer->GetUniqueId(), buffer->pts_, buffer->flag_);
        }
    }

    void SurfaceDecoderAdapter::ReleaseBuffer()
    {
        HILOGI("SurfaceDecoderAdapter::ReleaseBuffer enter");
        while (!isThreadExit_) {
            std::vector<uint32_t> indexs;
            std::vector<uint32_t> dropIndexs;
            {
                std::unique_lock<std::mutex> lock(releaseBufferMutex_);
                releaseBufferCondition_.wait(lock, [this] {
                    return isThreadExit_ || !indexs_.empty();
                });
                indexs = indexs_;
                indexs_.clear();
                dropIndexs = dropIndexs_;
                dropIndexs_.clear();
            }
            for (auto& index : indexs) {
                codecServer_->ReleaseOutputBuffer(index, true);
            }
            for (auto& dropIndex : dropIndexs) {
                codecServer_->ReleaseOutputBuffer(dropIndex, false);
            }
        }
        HILOGI("ReleaseBuffer end");
    }
} // namespace MEDIA
} // namespace OHOS
