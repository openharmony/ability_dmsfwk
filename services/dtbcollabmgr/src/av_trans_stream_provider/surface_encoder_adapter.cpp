/*
 * Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#include "surface_encoder_adapter.h"
#include "avcodec_common.h"
#include "avcodec_info.h"
#include "codec_server.h"
#include "dtbcollabmgr_log.h"
#include "media_description.h"
#include "meta/format.h"
#include "native_avcapability.h"
#include "native_avcodec_base.h"
#include <ctime>

namespace OHOS {
namespace DistributedCollab {
    namespace {
        static const std::string TAG = "SurfaceEncoderAdapter";
        using Status = Media::Status;
        using AVBufferQueueProducer = Media::AVBufferQueueProducer;
        using AVBufferQueueConsumer = Media::AVBufferQueueConsumer;
        using AVBufferQueue = Media::AVBufferQueue;
        using AVBuffer = Media::AVBuffer;
        using Meta = Media::Meta;
        using MDKey = MediaAVCodec::MediaDescriptionKey;
        using Format = MediaAVCodec::Format;
        using Tag = Media::Tag;
        using Task = Media::Task;
        using TaskType = Media::TaskType;
        constexpr uint32_t TIME_OUT_MS = 1000;
        constexpr uint32_t NS_PER_US = 1000;
        constexpr int64_t SEC_TO_NS = 1000000000;
#define FALSE_RETURN_MSG(exec, fmt, args...) \
    do {                                     \
        bool returnValue = (exec);           \
        if (!returnValue) {                  \
            HILOGE(fmt, ##args);             \
            return;                          \
        }                                    \
    } while (0)
    }

    class SurfaceEncoderAdapterCallback : public MediaAVCodec::MediaCodecCallback {
    public:
        explicit SurfaceEncoderAdapterCallback(std::shared_ptr<SurfaceEncoderAdapter> adapter)
            : surfaceEncoderAdapter_(std::move(adapter))
        {
        }

        void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode) override
        {
            if (auto ptr = surfaceEncoderAdapter_.lock()) {
                ptr->encoderAdapterCallback_->OnError(errorType, errorCode);
            }
        }

        void OnOutputFormatChanged(const MediaAVCodec::Format& format) override
        {
        }

        void OnInputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override
        {
        }

        void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer) override
        {
            if (auto ptr = surfaceEncoderAdapter_.lock()) {
                ptr->OnOutputBufferAvailable(index, buffer);
            }
        }

    private:
        std::weak_ptr<SurfaceEncoderAdapter> surfaceEncoderAdapter_;
    };

    class DroppedFramesCallback : public MediaAVCodec::MediaCodecParameterWithAttrCallback {
    public:
        explicit DroppedFramesCallback(std::shared_ptr<SurfaceEncoderAdapter> adapter)
            : surfaceEncoderAdapter_(std::move(adapter))
        {
        }

        void OnInputParameterWithAttrAvailable(uint32_t index, std::shared_ptr<Format> attribute,
            std::shared_ptr<Format> parameter) override
        {
            if (auto ptr = surfaceEncoderAdapter_.lock()) {
                ptr->OnInputParameterWithAttrAvailable(index, attribute, parameter);
            }
        }

    private:
        std::weak_ptr<SurfaceEncoderAdapter> surfaceEncoderAdapter_;
    };

    SurfaceEncoderAdapter::SurfaceEncoderAdapter()
    {
        HILOGI("encoder adapter create");
    }

    SurfaceEncoderAdapter::~SurfaceEncoderAdapter()
    {
        HILOGI("encoder adapter destroy");
        if (codecServer_) {
            codecServer_->Release();
        }
        codecServer_ = nullptr;
    }

    Status SurfaceEncoderAdapter::Init(const std::string& mime, bool isEncoder)
    {
        HILOGI("Init mime: %{public}s", mime.c_str());
        codecMimeType_ = mime;
        Format format;
        std::shared_ptr<Meta> callerInfo = std::make_shared<Meta>();
        callerInfo->SetData(Tag::AV_CODEC_FORWARD_CALLER_PID, appPid_);
        callerInfo->SetData(Tag::AV_CODEC_FORWARD_CALLER_UID, appUid_);
        callerInfo->SetData(Tag::AV_CODEC_FORWARD_CALLER_PROCESS_NAME, bundleName_);
        format.SetMeta(callerInfo);
        int32_t ret = MediaAVCodec::VideoEncoderFactory::CreateByMime(mime, format, codecServer_);
        HILOGI("AVCodecVideoEncoderImpl::Init CreateByMime errorCode %{public}d", ret);
        if (!codecServer_) {
            HILOGI("Create codecServer failed");
            return Status::ERROR_UNKNOWN;
        }
        if (!releaseBufferTask_) {
            releaseBufferTask_ = std::make_shared<Task>("SurfaceEncoder", "", TaskType::SINGLETON);
            releaseBufferTask_->RegisterJob([this] {
                ReleaseBuffer();
                return 0;
            });
        }
        return Status::OK;
    }

    void SurfaceEncoderAdapter::ConfigureGeneralFormat(MediaAVCodec::Format& format, const std::shared_ptr<Meta>& meta)
    {
        HILOGI("ConfigureGeneralFormat");
        if (meta->Find(Tag::VIDEO_WIDTH) != meta->end()) {
            int32_t videoWidth;
            meta->Get<Tag::VIDEO_WIDTH>(videoWidth);
            format.PutIntValue(MDKey::MD_KEY_WIDTH, videoWidth);
        }
        if (meta->Find(Tag::VIDEO_HEIGHT) != meta->end()) {
            int32_t videoHeight;
            meta->Get<Tag::VIDEO_HEIGHT>(videoHeight);
            format.PutIntValue(MDKey::MD_KEY_HEIGHT, videoHeight);
        }
        if (meta->Find(Tag::VIDEO_CAPTURE_RATE) != meta->end()) {
            double videoCaptureRate;
            meta->Get<Tag::VIDEO_CAPTURE_RATE>(videoCaptureRate);
            format.PutDoubleValue(MDKey::MD_KEY_CAPTURE_RATE, videoCaptureRate);
        }
        if (meta->Find(Tag::MEDIA_BITRATE) != meta->end()) {
            int64_t mediaBitrate;
            meta->Get<Tag::MEDIA_BITRATE>(mediaBitrate);
            format.PutLongValue(MDKey::MD_KEY_BITRATE, mediaBitrate);
        }
        if (meta->Find(Tag::VIDEO_FRAME_RATE) != meta->end()) {
            double videoFrameRate;
            meta->Get<Tag::VIDEO_FRAME_RATE>(videoFrameRate);
            format.PutDoubleValue(MDKey::MD_KEY_FRAME_RATE, videoFrameRate);
        }
        if (meta->Find(Tag::MIME_TYPE) != meta->end()) {
            std::string mimeType;
            meta->Get<Tag::MIME_TYPE>(mimeType);
            format.PutStringValue(MDKey::MD_KEY_CODEC_MIME, mimeType);
        }
        if (meta->Find(Tag::VIDEO_H265_PROFILE) != meta->end()) {
            Media::Plugins::HEVCProfile h265Profile;
            meta->Get<Tag::VIDEO_H265_PROFILE>(h265Profile);
            format.PutIntValue(MDKey::MD_KEY_PROFILE, h265Profile);
        }
    }

    Status SurfaceEncoderAdapter::Configure(const std::shared_ptr<Meta>& meta)
    {
        HILOGI("Configure");
        MediaAVCodec::Format format = MediaAVCodec::Format();
        ConfigureGeneralFormat(format, meta);
        ConfigureAboutRGBA(format, meta);
        ConfigureAboutEnableTemporalScale(format, meta);
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        int32_t ret = static_cast<int32_t>(Status::OK);
        if (!isTransCoderMode) {
            std::shared_ptr<MediaAVCodec::MediaCodecParameterWithAttrCallback> droppedFramesCallback =
                std::make_shared<DroppedFramesCallback>(shared_from_this());
            ret = codecServer_->SetCallback(droppedFramesCallback);
            if (ret != ERR_OK) {
                HILOGI("Set dropped Frames Callback failed");
                return Status::ERROR_UNKNOWN;
            }
        }
        if (isTransCoderMode) {
            format.PutIntValue(Tag::VIDEO_FRAME_RATE_ADAPTIVE_MODE, true);
        }
        ret = codecServer_->Configure(format);
        return ret == ERR_OK ? Status::OK : Status::ERROR_UNKNOWN;
    }

    Status SurfaceEncoderAdapter::SetOutputBufferQueue(const sptr<AVBufferQueueProducer>& bufferQueueProducer)
    {
        HILOGI("SetOutputBufferQueue");
        outputBufferQueueProducer_ = bufferQueueProducer;
        return Status::OK;
    }

    Status SurfaceEncoderAdapter::SetEncoderAdapterCallback(
        const std::shared_ptr<EncoderAdapterCallback>& encoderAdapterCallback)
    {
        HILOGI("SetEncoderAdapterCallback");
        std::shared_ptr<MediaAVCodec::MediaCodecCallback> surfaceEncoderAdapterCallback =
            std::make_shared<SurfaceEncoderAdapterCallback>(shared_from_this());
        encoderAdapterCallback_ = encoderAdapterCallback;
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        int32_t ret = codecServer_->SetCallback(surfaceEncoderAdapterCallback);
        return ret == ERR_OK ? Status::OK : Status::ERROR_UNKNOWN;
    }

    Status SurfaceEncoderAdapter::SetInputSurface(sptr<Surface> surface)
    {
        HILOGI("GetInputSurface");
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        MediaAVCodec::CodecServer* codecServerPtr = (MediaAVCodec::CodecServer*)(codecServer_.get());
        int32_t ret = codecServerPtr->SetInputSurface(surface);
        return ret == ERR_OK ? Status::OK : Status::ERROR_UNKNOWN;
    }

    Status SurfaceEncoderAdapter::SetTransCoderMode()
    {
        HILOGI("SetTransCoderMode");
        isTransCoderMode = true;
        return Status::OK;
    }

    sptr<Surface> SurfaceEncoderAdapter::GetInputSurface()
    {
        HILOGI("GetInputSurface enter");
        return codecServer_->CreateInputSurface();
    }

    Status SurfaceEncoderAdapter::Start()
    {
        HILOGI("Start");
        if (!codecServer_) {
            return Status::ERROR_NULL_POINTER;
        }
        int32_t ret = ERR_OK;
        isThreadExit_ = false;
        if (releaseBufferTask_) {
            releaseBufferTask_->Start();
        }
        ret = codecServer_->Start();
        isStart_ = true;
        isStartKeyFramePts_ = true;
        return ret == ERR_OK ? Status::OK : Status::ERROR_UNKNOWN;
    }

    Status SurfaceEncoderAdapter::Stop()
    {
        HILOGI("Stop");
        GetCurrentTime(stopTime_);
        isStopKeyFramePts_ = true;
        HILOGI("Stop time: %{public}ld", stopTime_);

        if (isStart_ && !isTransCoderMode) {
            std::unique_lock<std::mutex> lock(stopMutex_);
            stopCondition_.wait_for(lock, std::chrono::milliseconds(TIME_OUT_MS));
            AddStopPts();
        }
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
        isStart_ = false;
        return ret == ERR_OK ? Status::OK : Status::ERROR_UNKNOWN;
    }

    Status SurfaceEncoderAdapter::Pause()
    {
        HILOGI("Pause");
        if (isTransCoderMode) {
            return Status::OK;
        }
        std::lock_guard<std::mutex> lock(checkFramesMutex_);
        int64_t pauseTime = 0;
        GetCurrentTime(pauseTime);
        HILOGI("Pause time: %{public}ld", pauseTime);
        if (pauseResumeQueue_.empty() || (pauseResumeQueue_.back().second == StateCode::RESUME &&
            pauseResumeQueue_.back().first <= pauseTime)) {
            pauseResumeQueue_.push_back({ pauseTime, StateCode::PAUSE });
            pauseResumeQueue_.push_back({ std::numeric_limits<int64_t>::max(), StateCode::RESUME });
            pauseResumePts_.push_back({ pauseTime, StateCode::PAUSE });
            pauseResumePts_.push_back({ std::numeric_limits<int64_t>::max(), StateCode::RESUME });
        }
        return Status::OK;
    }

    Status SurfaceEncoderAdapter::Resume()
    {
        HILOGI("Resume");
        if (isTransCoderMode) {
            isResume_ = true;
            return Status::OK;
        }
        std::lock_guard<std::mutex> lock(checkFramesMutex_);
        int64_t resumeTime = 0;
        GetCurrentTime(resumeTime);
        HILOGI("resume time: %{public}ld", resumeTime);
        if (pauseResumeQueue_.empty()) {
            HILOGI("Status Error, no pause before resume");
            return Status::ERROR_UNKNOWN;
        }
        if (pauseResumeQueue_.back().second == StateCode::RESUME) {
            pauseResumeQueue_.back().first = std::min(resumeTime, pauseResumeQueue_.back().first);
            pauseResumePts_.back().first = std::min(resumeTime, pauseResumePts_.back().first);
        }
        return Status::OK;
    }

    Status SurfaceEncoderAdapter::Flush()
    {
        HILOGI("Flush");
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        int32_t ret = codecServer_->Flush();
        return ret == ERR_OK ? Status::OK : Status::ERROR_UNKNOWN;
    }

    Status SurfaceEncoderAdapter::Reset()
    {
        HILOGI("Reset");
        if (!codecServer_) {
            return Status::OK;
        }
        int32_t ret = codecServer_->Reset();
        startBufferTime_ = -1;
        stopTime_ = -1;
        totalPauseTime_ = 0;
        isStart_ = false;
        isStartKeyFramePts_ = false;
        mappingTimeQueue_.clear();
        pauseResumeQueue_.clear();
        pauseResumePts_.clear();
        return ret == ERR_OK ? Status::OK : Status::ERROR_UNKNOWN;
    }

    Status SurfaceEncoderAdapter::Release()
    {
        HILOGI("Release");
        if (!codecServer_) {
            return Status::OK;
        }
        int32_t ret = codecServer_->Release();
        return ret == ERR_OK ? Status::OK : Status::ERROR_UNKNOWN;
    }

    Status SurfaceEncoderAdapter::NotifyEos(int64_t pts)
    {
        HILOGI("NotifyEos");
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        int32_t ret = 0;
        HILOGI("lastBuffer PTS: %{public}ld, current PTS: %{public}ld", pts, currentPts_.load());
        eosPts_ = pts;
        if (!isTransCoderMode || currentPts_.load() >= eosPts_.load()) {
            HILOGI("Notify encoder eos");
            ret = codecServer_->NotifyEos();
        }
        return ret == ERR_OK ? Status::OK : Status::ERROR_UNKNOWN;
    }

    Status SurfaceEncoderAdapter::SetParameter(const std::shared_ptr<Meta>& parameter)
    {
        HILOGI("SetParameter");
        if (!codecServer_) {
            return Status::ERROR_UNKNOWN;
        }
        MediaAVCodec::Format format = MediaAVCodec::Format();
        int32_t ret = codecServer_->SetParameter(format);
        return ret == ERR_OK ? Status::OK : Status::ERROR_UNKNOWN;
    }

    void SurfaceEncoderAdapter::OnOutputBufferAvailable(uint32_t index, std::shared_ptr<AVBuffer> buffer)
    {
        HILOGD("OnOutputBufferAvailable buffer->pts: %{public}ld", buffer->pts_);
        currentPts_ = currentPts_.load() < buffer->pts_ ? buffer->pts_ : currentPts_.load();
        if (stopTime_ != -1 && buffer->pts_ > stopTime_) {
            HILOGI("buffer->pts > stopTime, ready to stop");
            std::unique_lock<std::mutex> lock(stopMutex_);
            stopCondition_.notify_all();
        }

        int64_t mappingTime = -1;
        if (!(buffer->flag_ & MediaAVCodec::AVCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA)) {
            std::lock_guard<std::mutex> mappingLock(mappingPtsMutex_);
            if (mappingTimeQueue_.empty() || mappingTimeQueue_.front().first != buffer->pts_) {
                HILOGD("buffer->pts fail");
            } else {
                mappingTime = mappingTimeQueue_.front().second;
                mappingTimeQueue_.pop_front();
            }
            if (startBufferTime_ == -1) {
                startBufferTime_ = buffer->pts_;
            }
            // cache recent 2 pts
            preKeyFramePts_ = currentKeyFramePts_;
            currentKeyFramePts_ = buffer->pts_;
            AddStartPts(buffer->pts_);
            AddPauseResumePts(buffer->pts_);
        } else {
            HILOGD("OnOutputBufferAvailable buffer->flag_ %{public}u", buffer->flag_);
            mappingTime = startBufferTime_ + buffer->pts_;
        }
        int32_t size = buffer->memory_->GetSize();
        std::shared_ptr<AVBuffer> emptyOutputBuffer;
        Media::AVBufferConfig avBufferConfig;
        avBufferConfig.size = size;
        avBufferConfig.memoryType = Media::MemoryType::SHARED_MEMORY;
        avBufferConfig.memoryFlag = Media::MemoryFlag::MEMORY_READ_WRITE;
        Status status = outputBufferQueueProducer_->RequestBuffer(emptyOutputBuffer, avBufferConfig, TIME_OUT_MS);
        FALSE_RETURN_MSG(status == Status::OK, "RequestBuffer fail.");
        std::shared_ptr<Media::AVMemory>& bufferMem = emptyOutputBuffer->memory_;
        FALSE_RETURN_MSG(emptyOutputBuffer->memory_ != nullptr, "emptyOutputBuffer->memory_ is nullptr");
        bufferMem->Write(buffer->memory_->GetAddr(), size, 0);
        *(emptyOutputBuffer->meta_) = *(buffer->meta_);
        emptyOutputBuffer->pts_ = (mappingTime - startBufferTime_) / NS_PER_US;
        emptyOutputBuffer->flag_ = buffer->flag_;
        outputBufferQueueProducer_->PushBuffer(emptyOutputBuffer, true);
        {
            std::lock_guard<std::mutex> lock(releaseBufferMutex_);
            indexs_.push_back(index);
        }
        releaseBufferCondition_.notify_all();
    }

    void SurfaceEncoderAdapter::ReleaseBuffer()
    {
        HILOGI("ReleaseBuffer");
        while (true) {
            if (isThreadExit_) {
                HILOGI("Exit ReleaseBuffer thread.");
                break;
            }
            std::vector<uint32_t> indexs;
            {
                std::unique_lock<std::mutex> lock(releaseBufferMutex_);
                releaseBufferCondition_.wait(lock, [this] {
                    return isThreadExit_ || !indexs_.empty();
                });
                indexs = indexs_;
                indexs_.clear();
            }
            for (auto& index : indexs) {
                codecServer_->ReleaseOutputBuffer(index);
            }
        }
        HILOGI("ReleaseBuffer end");
    }

    void SurfaceEncoderAdapter::ConfigureAboutRGBA(MediaAVCodec::Format& format, const std::shared_ptr<Meta>& meta)
    {
        HILOGI("SurfaceEncoderAdapter::ConfigureAboutRGBA enter");
        Media::Plugins::VideoPixelFormat pixelFormat = Media::Plugins::VideoPixelFormat::NV12;
        if (meta->Find(Tag::VIDEO_PIXEL_FORMAT) != meta->end()) {
            meta->Get<Tag::VIDEO_PIXEL_FORMAT>(pixelFormat);
        }
        format.PutIntValue(MDKey::MD_KEY_PIXEL_FORMAT, static_cast<int32_t>(pixelFormat));

        if (meta->Find(Tag::VIDEO_ENCODE_BITRATE_MODE) != meta->end()) {
            Media::Plugins::VideoEncodeBitrateMode videoEncodeBitrateMode;
            meta->Get<Tag::VIDEO_ENCODE_BITRATE_MODE>(videoEncodeBitrateMode);
            format.PutIntValue(MDKey::MD_KEY_VIDEO_ENCODE_BITRATE_MODE, videoEncodeBitrateMode);
        }
    }

    void SurfaceEncoderAdapter::ConfigureAboutEnableTemporalScale(MediaAVCodec::Format& format,
        const std::shared_ptr<Meta>& meta)
    {
        HILOGI("SurfaceEncoderAdapter::ConfigureAboutEnableTemporalScale enter");
        if (meta->Find(Tag::VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY) != meta->end()) {
            bool enableTemporalScale;
            meta->Get<Tag::VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY>(enableTemporalScale);
            if (!enableTemporalScale) {
                HILOGI("video encoder enableTemporalScale is false!");
                return;
            }
            OH_AVCapability* capability = OH_AVCodec_GetCapability(OH_AVCODEC_MIMETYPE_VIDEO_HEVC, true);
            bool isSupported = OH_AVCapability_IsFeatureSupported(capability, VIDEO_ENCODER_TEMPORAL_SCALABILITY);
            if (isSupported) {
                HILOGI("VIDEO_ENCODER_TEMPORAL_SCALABILITY is supported!");
                format.PutIntValue(MDKey::OH_MD_KEY_VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY,
                    1);
            } else {
                HILOGI("VIDEO_ENCODER_TEMPORAL_SCALABILITY is not supported!");
            }
        }
    }

    void SurfaceEncoderAdapter::SetCallingInfo(int32_t appUid, int32_t appPid,
        const std::string& bundleName, uint64_t instanceId)
    {
        appUid_ = appUid;
        appPid_ = appPid;
        bundleName_ = bundleName;
        instanceId_ = instanceId;
    }

    void SurfaceEncoderAdapter::OnInputParameterWithAttrAvailable(uint32_t index, std::shared_ptr<Format>& attribute,
        std::shared_ptr<Format>& parameter)
    {
        HILOGI("SurfaceEncoderAdapter::OnInputParameterWithAttrAvailable");
        if (isTransCoderMode) {
            HILOGD("isTransCoderMode");
            parameter->PutIntValue(Tag::VIDEO_ENCODER_PER_FRAME_DISCARD, false);
            codecServer_->QueueInputParameter(index);
            return;
        }
        std::lock_guard<std::mutex> lock(checkFramesMutex_);
        int64_t currentPts = 0;
        attribute->GetLongValue(Tag::MEDIA_TIME_STAMP, currentPts);
        HILOGD("OnInputParameterWithAttrAvailable currentPts: %{public}ld", currentPts);
        int64_t checkFramesPauseTime = 0;
        bool isDroppedFrames = CheckFrames(currentPts, checkFramesPauseTime);
        {
            std::lock_guard<std::mutex> mappingLock(mappingPtsMutex_);
            if (isDroppedFrames) {
                totalPauseTime_ = totalPauseTime_ + currentPts - lastBufferTime_;
            } else {
                int64_t frameDifference = 1000000; // Frame Difference less 1000000 ns
                if (checkFramesPauseTime + frameDifference < currentPts - lastBufferTime_) {
                    totalPauseTime_ = totalPauseTime_ + checkFramesPauseTime;
                }
                mappingTimeQueue_.push_back({ currentPts, currentPts - totalPauseTime_ });
            }
            lastBufferTime_ = currentPts;
        }
        parameter->PutIntValue(Tag::VIDEO_ENCODER_PER_FRAME_DISCARD, isDroppedFrames);
        codecServer_->QueueInputParameter(index);
    }

    bool SurfaceEncoderAdapter::CheckFrames(int64_t currentPts, int64_t& checkFramesPauseTime)
    {
        if (pauseResumeQueue_.empty()) {
            return false;
        }
        auto stateCode = pauseResumeQueue_[0].second;
        HILOGD("CheckFrames stateCode: %{public}d, time: %{public}ld",
            static_cast<int32_t>(stateCode), pauseResumeQueue_[0].first);
        // means not dropped frames when less than pause time
        if (stateCode == StateCode::PAUSE && currentPts < pauseResumeQueue_[0].first) {
            return false;
        }
        // means dropped frames when less than resume time
        if (stateCode == StateCode::RESUME && currentPts < pauseResumeQueue_[0].first) {
            return true;
        }
        if (stateCode == StateCode::PAUSE) {
            checkFramesPauseTime -= (pauseResumeQueue_[0].first - lastBufferTime_);
        } else {
            checkFramesPauseTime += (pauseResumeQueue_[0].first - lastBufferTime_);
        }
        pauseResumeQueue_.pop_front();
        return CheckFrames(currentPts, checkFramesPauseTime);
    }

    void SurfaceEncoderAdapter::GetCurrentTime(int64_t& currentTime)
    {
        struct timespec timestamp = { 0, 0 };
        clock_gettime(CLOCK_MONOTONIC, &timestamp);
        currentTime = static_cast<int64_t>(timestamp.tv_sec) * SEC_TO_NS + static_cast<int64_t>(timestamp.tv_nsec);
    }

    void SurfaceEncoderAdapter::AddStartPts(int64_t currentPts)
    {
        // start time
        if (isStartKeyFramePts_) {
            keyFramePts_ += std::to_string(currentPts / NS_PER_US) + ",";
            isStartKeyFramePts_ = false;
            HILOGI("AddStartPts success %{public}s end", keyFramePts_.c_str());
        }
    }

    void SurfaceEncoderAdapter::AddStopPts()
    {
        // stop time
        HILOGI("AddStopPts enter");
        if (isStopKeyFramePts_) {
            if (currentKeyFramePts_ > stopTime_) {
                keyFramePts_ += std::to_string(preKeyFramePts_ / NS_PER_US);
                HILOGI("AddStopPts preKeyFramePts_ %{public}s end", keyFramePts_.c_str());
            } else {
                keyFramePts_ += std::to_string(currentKeyFramePts_ / NS_PER_US);
                HILOGI("AddStopPts currentKeyFramePts_ %{public}s end", keyFramePts_.c_str());
            }
            isStopKeyFramePts_ = false;
            keyFramePts_.clear();
        }
    }

    bool SurfaceEncoderAdapter::AddPauseResumePts(int64_t currentPts)
    {
        HILOGI("AddPauseResumePts enter");
        if (pauseResumePts_.empty()) {
            return false;
        }
        auto stateCode = pauseResumePts_[0].second;
        HILOGD("CheckFrames stateCode: %{public}d, time: %{public}ld",
            static_cast<int32_t>(stateCode), pauseResumePts_[0].first);
        // means not dropped frames when less than pause time
        if (stateCode == StateCode::PAUSE && currentPts < pauseResumePts_[0].first) {
            return false;
        }
        // means dropped frames when less than resume time
        if (stateCode == StateCode::RESUME && currentPts < pauseResumePts_[0].first) {
            return true;
        }
        if (stateCode == StateCode::PAUSE) {
            HILOGD("AddPausePts %{public}s start", keyFramePts_.c_str());
            keyFramePts_ += std::to_string(preKeyFramePts_ / NS_PER_US) + ",";
            HILOGD("AddPausePts %{public}s end", keyFramePts_.c_str());
        }
        if (stateCode == StateCode::RESUME) {
            HILOGD("AddResumePts %{public}s start", keyFramePts_.c_str());
            keyFramePts_ += std::to_string(currentKeyFramePts_ / NS_PER_US) + ",";
            HILOGD("AddResumePts %{public}s end", keyFramePts_.c_str());
        }
        pauseResumePts_.pop_front();
        return AddPauseResumePts(currentPts);
    }
} // namespace MEDIA
} // namespace OHOS
