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

#include "surface_encoder_filter.h"

#include <iostream>
#include <string>

#include "common/media_core.h"
#include "dtbcollabmgr_log.h"
#include "filter/filter_factory.h"
#include "muxer_filter.h"

namespace OHOS {
namespace DistributedCollab {
    namespace {
        static const std::string TAG = "SurfaceEncoderFilter";
        using Status = Media::Status;
        using EventReceiver = Media::Pipeline::EventReceiver;
        using FilterCallback = Media::Pipeline::FilterCallback;
        using Filter = Media::Pipeline::Filter;
        using StreamType = Media::Pipeline::StreamType;
        using AVBufferQueueProducer = Media::AVBufferQueueProducer;
        using AVBufferQueueConsumer = Media::AVBufferQueueConsumer;
        using AVBufferQueue = Media::AVBufferQueue;
        using AVBuffer = Media::AVBuffer;
        using FilterLinkCallback = Media::Pipeline::FilterLinkCallback;
        using Meta = Media::Meta;
        using FilterCallBackCommand = Media::Pipeline::FilterCallBackCommand;
        using FilterType = Media::Pipeline::FilterType;
        using Tag = Media::Tag;
        using EventType = Media::EventType;
    }

    static Media::Pipeline::AutoRegisterFilter<SurfaceEncoderFilter> g_registerSurfaceEncoderFilter(
        "builtin.dtbcollab.videoencoder",
        FilterType::FILTERTYPE_VENC,
        [](const std::string& name, const FilterType type) {
            return std::make_shared<SurfaceEncoderFilter>(name, FilterType::FILTERTYPE_VENC);
        });

    class SurfaceEncoderFilterLinkCallback : public FilterLinkCallback {
    public:
        explicit SurfaceEncoderFilterLinkCallback(std::shared_ptr<SurfaceEncoderFilter> filter)
            : surfaceEncoderFilter_(std::move(filter))
        {
        }

        void OnLinkedResult(const sptr<AVBufferQueueProducer>& queue, std::shared_ptr<Meta>& meta) override
        {
            if (auto ptr = surfaceEncoderFilter_.lock()) {
                ptr->OnLinkedResult(queue, meta);
            }
        }

        void OnUnlinkedResult(std::shared_ptr<Meta>& meta) override
        {
            if (auto ptr = surfaceEncoderFilter_.lock()) {
                ptr->OnUnlinkedResult(meta);
            }
        }

        void OnUpdatedResult(std::shared_ptr<Meta>& meta) override
        {
            if (auto ptr = surfaceEncoderFilter_.lock()) {
                ptr->OnUpdatedResult(meta);
            }
        }

    private:
        std::weak_ptr<SurfaceEncoderFilter> surfaceEncoderFilter_;
    };

    class SurfaceEncoderAdapterCallback : public EncoderAdapterCallback {
    public:
        explicit SurfaceEncoderAdapterCallback(std::shared_ptr<SurfaceEncoderFilter> filter)
            : surfaceEncoderFilter_(std::move(filter))
        {
        }

        void OnError(MediaAVCodec::AVCodecErrorType type, int32_t errorCode)
        {
            if (auto ptr = surfaceEncoderFilter_.lock()) {
                ptr->OnError(type, errorCode);
            }
        }

        void OnOutputFormatChanged(const std::shared_ptr<Meta>& format)
        {
        }

    private:
        std::weak_ptr<SurfaceEncoderFilter> surfaceEncoderFilter_;
    };

    SurfaceEncoderFilter::SurfaceEncoderFilter(std::string name, FilterType type)
        : Filter(name, type)
    {
        HILOGI("encoder filter create");
    }

    SurfaceEncoderFilter::~SurfaceEncoderFilter()
    {
        HILOGI("encoder filter destroy");
    }

    void SurfaceEncoderFilter::OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode)
    {
        HILOGE("AVCodec error happened. ErrorType: %{public}d, errorCode: %{public}d",
            static_cast<int32_t>(errorType), errorCode);
        if (eventReceiver_ != nullptr) {
            eventReceiver_->OnEvent({ "surface_encoder_filter", EventType::EVENT_ERROR, Media::MSERR_VID_ENC_FAILED });
        }
    }

    Status SurfaceEncoderFilter::SetCodecFormat(const std::shared_ptr<Meta>& format)
    {
        HILOGI("SetCodecFormat");
        std::string codecMimeType;
        if (!format->Get<Tag::MIME_TYPE>(codecMimeType)) {
            HILOGE("not valid mimeType");
            return Status::ERROR_INVALID_PARAMETER;
        }
        if (strcmp(codecMimeType.c_str(), codecMimeType_.c_str()) != 0) {
            isUpdateCodecNeeded_ = true;
        }
        if (!format->Get<Tag::MIME_TYPE>(codecMimeType_)) {
            HILOGE("not valid mimeType");
            return Status::ERROR_INVALID_PARAMETER;
        }
        return Status::OK;
    }

    void SurfaceEncoderFilter::Init(const std::shared_ptr<EventReceiver>& receiver,
        const std::shared_ptr<FilterCallback>& callback)
    {
        HILOGI("SurfaceEncoderFilter::Init enters");
        eventReceiver_ = receiver;
        filterCallback_ = callback;
        if (!codecAdapter_ || isUpdateCodecNeeded_) {
            if (codecAdapter_) {
                codecAdapter_->Release();
            }
            codecAdapter_ = std::make_shared<SurfaceEncoderAdapter>();
            codecAdapter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
            Status ret = codecAdapter_->Init(codecMimeType_, true);
            if (ret == Status::OK) {
                std::shared_ptr<EncoderAdapterCallback> encoderAdapterCallback =
                    std::make_shared<SurfaceEncoderAdapterCallback>(shared_from_this());
                codecAdapter_->SetEncoderAdapterCallback(encoderAdapterCallback);
            } else {
                HILOGI("Init mediaCodec fail");
                eventReceiver_->OnEvent({ "surface_encoder_filter", EventType::EVENT_ERROR, Status::ERROR_UNKNOWN });
            }
            isUpdateCodecNeeded_ = false;
        }
    }

    Status SurfaceEncoderFilter::Configure(const std::shared_ptr<Meta>& parameter)
    {
        HILOGI("SurfaceEncoderFilter::Configure");
        if (codecAdapter_ == nullptr) {
            return Status::ERROR_UNKNOWN;
        }
        configureParameter_ = parameter;
        return codecAdapter_->Configure(parameter);
    }

    Status SurfaceEncoderFilter::SetInputSurface(sptr<Surface> surface)
    {
        HILOGI("SetInputSurface");
        codecAdapter_->SetInputSurface(surface);
        return Status::OK;
    }

    Status SurfaceEncoderFilter::SetTransCoderMode()
    {
        HILOGI("SetTransCoderMode");
        codecAdapter_->SetTransCoderMode();
        return Status::OK;
    }

    sptr<Surface> SurfaceEncoderFilter::GetInputSurface()
    {
        HILOGI("GetInputSurface");
        if (surface_) {
            return surface_;
        }
        if (codecAdapter_ != nullptr) {
            surface_ = codecAdapter_->GetInputSurface();
        }
        return surface_;
    }

    Status SurfaceEncoderFilter::DoPrepare()
    {
        HILOGI("Prepare");
        filterCallback_->OnCallback(shared_from_this(), FilterCallBackCommand::NEXT_FILTER_NEEDED,
            StreamType::STREAMTYPE_ENCODED_VIDEO);
        return Status::OK;
    }

    Status SurfaceEncoderFilter::DoStart()
    {
        HILOGI("Start");
        if (codecAdapter_ == nullptr) {
            return Status::ERROR_UNKNOWN;
        }
        return codecAdapter_->Start();
    }

    Status SurfaceEncoderFilter::DoPause()
    {
        HILOGI("Pause");
        if (codecAdapter_ == nullptr) {
            return Status::ERROR_UNKNOWN;
        }
        return codecAdapter_->Pause();
    }

    Status SurfaceEncoderFilter::DoResume()
    {
        HILOGI("Resume");
        if (codecAdapter_ == nullptr) {
            return Status::ERROR_UNKNOWN;
        }
        return codecAdapter_->Resume();
    }

    Status SurfaceEncoderFilter::DoStop()
    {
        HILOGI("Stop");
        if (codecAdapter_ == nullptr) {
            return Status::OK;
        }
        codecAdapter_->Stop();
        return Status::OK;
    }

    Status SurfaceEncoderFilter::Reset()
    {
        HILOGI("Reset");
        if (codecAdapter_ == nullptr) {
            return Status::OK;
        }
        codecAdapter_->Reset();
        return Status::OK;
    }

    Status SurfaceEncoderFilter::DoFlush()
    {
        HILOGI("Flush");
        return codecAdapter_->Flush();
    }

    Status SurfaceEncoderFilter::DoRelease()
    {
        HILOGI("Release");
        if (codecAdapter_ == nullptr) {
            return Status::OK;
        }
        return codecAdapter_->Reset();
    }

    Status SurfaceEncoderFilter::NotifyEos(int64_t pts)
    {
        HILOGI("NotifyEos");
        return codecAdapter_->NotifyEos(pts);
    }

    void SurfaceEncoderFilter::SetParameter(const std::shared_ptr<Meta>& parameter)
    {
        HILOGI("SetParameter");
        if (codecAdapter_ == nullptr) {
            return;
        }
        bool isEos = false;
        int64_t eosPts = UINT32_MAX;
        if (parameter->Find(Tag::MEDIA_END_OF_STREAM) != parameter->end() &&
            parameter->Get<Tag::MEDIA_END_OF_STREAM>(isEos) && parameter->Get<Tag::USER_FRAME_PTS>(eosPts)) {
            if (isEos) {
                HILOGI("lastBuffer PTS: %{public}ld", eosPts);
                NotifyEos(eosPts);
                return;
            }
        }
        codecAdapter_->SetParameter(parameter);
    }

    void SurfaceEncoderFilter::GetParameter(std::shared_ptr<Meta>& parameter)
    {
        HILOGI("GetParameter");
    }

    Status SurfaceEncoderFilter::LinkNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
    {
        HILOGI("LinkNext");
        nextFilter_ = nextFilter;
        nextFiltersMap_[outType].push_back(nextFilter_);
        std::shared_ptr<FilterLinkCallback> filterLinkCallback =
            std::make_shared<SurfaceEncoderFilterLinkCallback>(shared_from_this());
        nextFilter->OnLinked(outType, configureParameter_, filterLinkCallback);
        return Status::OK;
    }

    Status SurfaceEncoderFilter::UpdateNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
    {
        HILOGI("UpdateNext");
        return Status::OK;
    }

    Status SurfaceEncoderFilter::UnLinkNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
    {
        HILOGI("UnLinkNext");
        return Status::OK;
    }

    Status SurfaceEncoderFilter::OnLinked(StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback)
    {
        HILOGI("OnLinked");
        onLinkedResultCallback_ = callback;
        return Status::OK;
    }

    Status SurfaceEncoderFilter::OnUpdated(StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback)
    {
        HILOGI("OnUpdated");
        return Status::OK;
    }

    Status SurfaceEncoderFilter::OnUnLinked(StreamType inType, const std::shared_ptr<FilterLinkCallback>& callback)
    {
        HILOGI("OnUnLinked");
        return Status::OK;
    }

    void SurfaceEncoderFilter::OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue,
        std::shared_ptr<Meta>& meta)
    {
        HILOGI("OnLinkedResult");
        codecAdapter_->SetOutputBufferQueue(outputBufferQueue);
        if (onLinkedResultCallback_) {
            onLinkedResultCallback_->OnLinkedResult(nullptr, meta);
        }
    }

    void SurfaceEncoderFilter::OnUpdatedResult(std::shared_ptr<Meta>& meta)
    {
        HILOGI("OnUpdatedResult");
    }

    void SurfaceEncoderFilter::OnUnlinkedResult(std::shared_ptr<Meta>& meta)
    {
        HILOGI("OnUnlinkedResult");
    }

    void SurfaceEncoderFilter::SetCallingInfo(int32_t appUid, int32_t appPid,
        const std::string& bundleName, uint64_t instanceId)
    {
        appUid_ = appUid;
        appPid_ = appPid;
        bundleName_ = bundleName;
        instanceId_ = instanceId;
        if (codecAdapter_) {
            codecAdapter_->SetCallingInfo(appUid, appPid, bundleName, instanceId);
        }
    }
} // namespace MEDIA
} // namespace OHOS