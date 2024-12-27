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

#include "surface_decoder_filter.h"
#include "av_common.h"
#include "common/media_core.h"
#include "dtbcollabmgr_log.h"
#include "filter/filter_factory.h"
#include "media_description.h"
#include "meta/format.h"
#include "surface/native_buffer.h"
#include "surface_decoder_adapter.h"
#include "surface_encoder_filter.h"

namespace OHOS {
namespace DistributedCollab {
    namespace {
        static const std::string TAG = "SurfaceDecoderFilter";
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
        using MDKey = MediaAVCodec::MediaDescriptionKey;
        using EventType = Media::EventType;
    }

    static Media::Pipeline::AutoRegisterFilter<SurfaceDecoderFilter> g_registerSurfaceDecoderFilter(
        "builtin.dtbcollab.surfacedecoder",
        FilterType::FILTERTYPE_VIDEODEC, [](const std::string& name, const FilterType type) {
            return std::make_shared<SurfaceDecoderFilter>(name, FilterType::FILTERTYPE_VIDEODEC);
        });

    class SurfaceDecoderFilterLinkCallback : public FilterLinkCallback {
    public:
        explicit SurfaceDecoderFilterLinkCallback(std::shared_ptr<SurfaceDecoderFilter> filter)
            : surfaceDecoderFilter_(std::move(filter))
        {
        }

        ~SurfaceDecoderFilterLinkCallback() = default;

        void OnLinkedResult(const sptr<AVBufferQueueProducer>& queue, std::shared_ptr<Meta>& meta) override
        {
            if (auto ptr = surfaceDecoderFilter_.lock()) {
                ptr->OnLinkedResult(queue, meta);
            }
        }

        void OnUnlinkedResult(std::shared_ptr<Meta>& meta) override
        {
            if (auto ptr = surfaceDecoderFilter_.lock()) {
                ptr->OnUnlinkedResult(meta);
            }
        }

        void OnUpdatedResult(std::shared_ptr<Meta>& meta) override
        {
            if (auto ptr = surfaceDecoderFilter_.lock()) {
                ptr->OnUpdatedResult(meta);
            }
        }

    private:
        std::weak_ptr<SurfaceDecoderFilter> surfaceDecoderFilter_;
    };

    class SurfaceDecoderAdapterCallback : public DecoderAdapterCallback {
    public:
        explicit SurfaceDecoderAdapterCallback(std::shared_ptr<SurfaceDecoderFilter> filter)
            : surfaceDecoderFilter_(std::move(filter))
        {
        }

        void OnError(MediaAVCodec::AVCodecErrorType type, int32_t errorCode) override
        {
        }

        void OnOutputFormatChanged(const std::shared_ptr<Meta>& format) override
        {
        }

        void OnBufferEos(int64_t pts, int64_t frameNum) override
        {
        }

    private:
        std::weak_ptr<SurfaceDecoderFilter> surfaceDecoderFilter_;
    };

    SurfaceDecoderFilter::SurfaceDecoderFilter(const std::string& name, FilterType type)
        : Filter(name, type)
    {
        HILOGI("surface decoder filter create");
    }

    SurfaceDecoderFilter::~SurfaceDecoderFilter()
    {
        HILOGI("surface decoder filter destroy");
    }

    void SurfaceDecoderFilter::Init(const std::shared_ptr<EventReceiver>& receiver,
        const std::shared_ptr<FilterCallback>& callback)
    {
        HILOGI("SurfaceDecoderFilter::Init enter");
        eventReceiver_ = receiver;
        filterCallback_ = callback;
    }

    Status SurfaceDecoderFilter::Configure(const std::shared_ptr<Meta>& parameter)
    {
        HILOGI("SurfaceDecoderFilter::Configure enter");
        if (codecAdpater_ == nullptr) {
            HILOGE("mediaCodec is null");
            return Status::ERROR_NULL_POINTER;
        }
        configureParameter_ = parameter;
        configFormat_.SetMeta(configureParameter_);
        bool isHdr = false;
        configureParameter_->GetData(Tag::VIDEO_IS_HDR_VIVID, isHdr);
        if (isHdr) {
            HILOGD("isHdr true,set video_decoder_output_colorspace, pixel_format");
            configFormat_.PutIntValue(MDKey::MD_KEY_VIDEO_DECODER_OUTPUT_COLOR_SPACE,
                static_cast<int8_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_LIMIT));
            configFormat_.PutIntValue(MDKey::MD_KEY_PIXEL_FORMAT,
                static_cast<int8_t>(MediaAVCodec::VideoPixelFormat::NV12));
        }
        configFormat_.PutIntValue(Tag::VIDEO_FRAME_RATE_ADAPTIVE_MODE, true);
        Status ret = codecAdpater_->Configure(configFormat_);
        if (ret != Status::OK) {
            HILOGE("mediaCodec Configure fail");
            if (eventReceiver_ != nullptr) {
                eventReceiver_->OnEvent({ "surface_decoder_filter", EventType::EVENT_ERROR, Media::MSERR_UNKNOWN });
            }
        }
        return ret;
    }

    Status SurfaceDecoderFilter::SetOutputSurface(const sptr<Surface>& surface)
    {
        HILOGI("SurfaceDecoderFilter::SetOutputSurface enter");
        if (codecAdpater_ == nullptr) {
            HILOGE("mediaCodec is null");
            return Status::ERROR_UNKNOWN;
        }
        outputSurface_ = surface;
        Status ret = codecAdpater_->SetOutputSurface(outputSurface_);
        if (ret != Status::OK) {
            HILOGE("codecAdpater SetOutputSurface fail");
            if (eventReceiver_ != nullptr) {
                eventReceiver_->OnEvent({ "surface_decoder_filter", EventType::EVENT_ERROR, Media::MSERR_UNKNOWN });
            }
        }
        return ret;
    }

    Status SurfaceDecoderFilter::DoPrepare()
    {
        HILOGI("SurfaceDecoderFilter::DoPrepare enter");
        if (filterCallback_ == nullptr) {
            HILOGE("filterCallback is null");
            return Status::ERROR_UNKNOWN;
        }
        filterCallback_->OnCallback(shared_from_this(), FilterCallBackCommand::NEXT_FILTER_NEEDED,
            StreamType::STREAMTYPE_RAW_VIDEO);
        return Status::OK;
    }

    Status SurfaceDecoderFilter::DoStart()
    {
        HILOGI("SurfaceDecoderFilter::DoStart enter");
        if (codecAdpater_ == nullptr) {
            HILOGE("mediaCodec is null");
            return Status::ERROR_UNKNOWN;
        }
        Status ret = codecAdpater_->Start();
        if (ret != Status::OK) {
            HILOGE("mediaCodec Start fail");
            if (eventReceiver_ != nullptr) {
                eventReceiver_->OnEvent({ "surface_decoder_filter", EventType::EVENT_ERROR, Media::MSERR_UNKNOWN });
            }
        }
        return ret;
    }

    Status SurfaceDecoderFilter::DoPause()
    {
        HILOGI("SurfaceDecoderFilter::DoPause enter");
        if (codecAdpater_ == nullptr) {
            HILOGE("mediaCodec is null");
            return Status::ERROR_UNKNOWN;
        }
        Status ret = codecAdpater_->Pause();
        if (ret != Status::OK) {
            HILOGE("mediaCodec Pause fail");
            if (eventReceiver_ != nullptr) {
                eventReceiver_->OnEvent({ "surface_decoder_filter", EventType::EVENT_ERROR, Media::MSERR_UNKNOWN });
            }
        }
        return ret;
    }

    Status SurfaceDecoderFilter::DoResume()
    {
        HILOGI("SurfaceDecoderFilter::DoResume enter");
        if (codecAdpater_ == nullptr) {
            HILOGE("mediaCodec is null");
            return Status::ERROR_UNKNOWN;
        }
        Status ret = codecAdpater_->Resume();
        if (ret != Status::OK) {
            HILOGE("mediaCodec Resume fail");
            if (eventReceiver_ != nullptr) {
                eventReceiver_->OnEvent({ "surface_decoder_filter", EventType::EVENT_ERROR, Media::MSERR_UNKNOWN });
            }
        }
        return ret;
    }

    Status SurfaceDecoderFilter::DoStop()
    {
        HILOGI("SurfaceDecoderFilter::DoStop enter");
        if (codecAdpater_ == nullptr) {
            return Status::OK;
        }
        Status ret = codecAdpater_->Stop();
        if (ret != Status::OK) {
            HILOGE("mediaCodec Stop fail");
            if (eventReceiver_ != nullptr) {
                eventReceiver_->OnEvent({ "surface_decoder_filter", EventType::EVENT_ERROR, Media::MSERR_UNKNOWN });
            }
            return ret;
        }
        HILOGI("Stop done");
        return Status::OK;
    }

    Status SurfaceDecoderFilter::DoFlush()
    {
        HILOGI("SurfaceDecoderFilter::DoFlush");
        return Status::OK;
    }

    Status SurfaceDecoderFilter::DoRelease()
    {
        HILOGI("SurfaceDecoderFilter::DoRelease");
        return Status::OK;
    }

    void SurfaceDecoderFilter::SetParameter(const std::shared_ptr<Meta>& parameter)
    {
        HILOGI("SurfaceDecoderFilter::SetParameter enter");
        if (codecAdpater_ == nullptr) {
            return;
        }
        MediaAVCodec::Format format;
        format.SetMeta(parameter);
        auto ret = codecAdpater_->SetParameter(format);
        if (ret != Status::OK) {
            HILOGE("mediaCodec SetParameter fail");
            if (eventReceiver_ != nullptr) {
                eventReceiver_->OnEvent({ "surface_decoder_filter", EventType::EVENT_ERROR, Media::MSERR_UNKNOWN });
            }
        }
    }

    void SurfaceDecoderFilter::GetParameter(std::shared_ptr<Meta>& parameter)
    {
        HILOGI("SurfaceDecoderFilter::GetParameter");
    }

    Status SurfaceDecoderFilter::LinkNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
    {
        HILOGI("SurfaceDecoderFilter::LinkNext enter");
        nextFilter_ = nextFilter;
        nextFiltersMap_[outType].push_back(nextFilter_);
        std::shared_ptr<FilterLinkCallback> filterLinkCallback =
            std::make_shared<SurfaceDecoderFilterLinkCallback>(shared_from_this());
        nextFilter->OnLinked(outType, configureParameter_, filterLinkCallback);
        return Status::OK;
    }

    Status SurfaceDecoderFilter::UpdateNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
    {
        HILOGI("SurfaceDecoderFilter::UpdateNext enter");
        return Status::OK;
    }

    Status SurfaceDecoderFilter::UnLinkNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
    {
        HILOGI("SurfaceDecoderFilter::UnLinkNext");
        return Status::OK;
    }

    Status SurfaceDecoderFilter::OnLinked(StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback)
    {
        HILOGI("SurfaceDecoderFilter::OnLinked enter");
        if (!meta->GetData(Tag::MIME_TYPE, codecMimeType_)) {
            HILOGE("get mime failed");
            return Status::ERROR_INVALID_PARAMETER;
        }
        HILOGI("OnLinked enter the codecMimeType_ is %{public}s", codecMimeType_.c_str());
        codecAdpater_ = std::make_shared<SurfaceDecoderAdapter>();
        Status ret = codecAdpater_->Init(codecMimeType_);
        if (ret == Status::OK) {
            std::shared_ptr<DecoderAdapterCallback> decoderSurfaceCallback =
                std::make_shared<SurfaceDecoderAdapterCallback>(shared_from_this());
            codecAdpater_->SetDecoderAdapterCallback(decoderSurfaceCallback);
        } else {
            HILOGE("Init mediaCodec fail");
            if (eventReceiver_ != nullptr) {
                eventReceiver_->OnEvent({ "surface_encoder_filter", EventType::EVENT_ERROR, Media::MSERR_UNKNOWN });
            }
        }
        meta_ = meta;
        ret = Configure(meta);
        if (ret != Status::OK) {
            HILOGE("mediaCodec Configure fail");
        }
        onLinkedResultCallback_ = callback;
        callback->OnLinkedResult(codecAdpater_->GetInputBufferQueue(), meta_);
        return Status::OK;
    }

    Status SurfaceDecoderFilter::OnUpdated(StreamType inType, const std::shared_ptr<Meta>& meta,
        const std::shared_ptr<FilterLinkCallback>& callback)
    {
        HILOGI("SurfaceDecoderFilter::OnUpdated enter");
        return Status::OK;
    }

    Status SurfaceDecoderFilter::OnUnLinked(StreamType inType, const std::shared_ptr<FilterLinkCallback>& callback)
    {
        HILOGI("OnUnLinked");
        return Status::OK;
    }

    void SurfaceDecoderFilter::OnLinkedResult(const sptr<AVBufferQueueProducer>& outputBufferQueue,
        std::shared_ptr<Meta>& meta)
    {
        HILOGI("OnLinkedResult");
        if (onLinkedResultCallback_) {
            onLinkedResultCallback_->OnLinkedResult(codecAdpater_->GetInputBufferQueue(), meta_);
        }
    }

    void SurfaceDecoderFilter::OnUpdatedResult(std::shared_ptr<Meta>& meta)
    {
        HILOGI("OnUpdatedResult");
    }

    void SurfaceDecoderFilter::OnUnlinkedResult(std::shared_ptr<Meta>& meta)
    {
        HILOGI("OnUnlinkedResult");
    }
} // namespace MEDIA
} // namespace OHOS
