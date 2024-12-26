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
#include "av_receiver_engine.h"
#include "av_receiver_filter_listener.h"
#include "avcodec_info.h"
#include "avcodec_list.h"
#include "dtbcollabmgr_log.h"
#include "filter/filter_factory.h"
#include "media_description.h"
#include "osal/task/pipeline_threadpool.h"
#include "surface_utils.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
    static const std::string TAG = "AVTransStreamReceiverEngine";
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
    using MDKey = MediaAVCodec::MediaDescriptionKey;
    static const std::vector<std::string> DECODER_NAME = {
        std::string(MediaAVCodec::CodecMimeType::VIDEO_AVC),
        std::string(MediaAVCodec::CodecMimeType::VIDEO_MPEG4),
        std::string(MediaAVCodec::CodecMimeType::VIDEO_HEVC),
    };
}

class AVReceiverEngineEventReceiver : public EventReceiver {
public:
    explicit AVReceiverEngineEventReceiver(std::shared_ptr<AVReceiverEngine> engine)
        : engine_(engine) {};
    void OnEvent(const Media::Event& event)
    {
        if (auto ptr = engine_.lock()) {
            ptr->OnEvent(event);
        }
    }

private:
    std::weak_ptr<AVReceiverEngine> engine_;
};

class AVReceiverEngineFilterCallback : public FilterCallback {
public:
    explicit AVReceiverEngineFilterCallback(std::shared_ptr<AVReceiverEngine> engine)
        : engine_(engine) {};

    Media::Status OnCallback(const std::shared_ptr<Filter>& filter, FilterCallBackCommand cmd,
        StreamType outType)
    {
        if (auto ptr = engine_.lock()) {
            return ptr->OnCallback(filter, cmd, outType);
        }
        return Status::ERROR_INVALID_STATE;
    }

private:
    std::weak_ptr<AVReceiverEngine> engine_;
};

class RecvEngineListener : public IEngineListener {
public:
    explicit RecvEngineListener(std::shared_ptr<AVReceiverEngine> engine)
        : engine_(engine) {};

    void OnRecvPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap) override
    {
    }
    void OnRecvSurfaceParam(const SurfaceParam& param) override
    {
        if (auto ptr = engine_.lock()) {
            ptr->OnRecvSurfaceParam(param);
        }
    }

private:
    std::weak_ptr<AVReceiverEngine> engine_;
};

AVReceiverEngine::AVReceiverEngine()
{
    pipeline_ = std::make_shared<Media::Pipeline::Pipeline>();
};

AVReceiverEngine::~AVReceiverEngine()
{
    HILOGI("recv engine destroy");
    Stop(false);
    Media::PipeLineThreadPool::GetInstance().DestroyThread(engineId_);
}

void AVReceiverEngine::Init()
{
    HILOGI("AVReceiverEngine::Init enter");
    engineEventReceiver_ = std::make_shared<AVReceiverEngineEventReceiver>(shared_from_this());
    engineFilterCallback_ = std::make_shared<AVReceiverEngineFilterCallback>(shared_from_this());
    engineId_ = std::string("AVReceiverEngine_") + std::to_string(Media::Pipeline::Pipeline::GetNextPipelineId());
    pipeline_->Init(engineEventReceiver_, engineFilterCallback_, engineId_);
}

int32_t AVReceiverEngine::InitRecvHeaderFilter()
{
    HILOGI("AVReceiverEngine::InitRecvHeaderFilter enter");
    Status ret = Status::ERROR_NULL_POINTER;
    if (!receiverFilter_) {
        receiverFilter_ = std::make_shared<AVReceiverFilter>(
            "builtin.dtbcollab.receiver", FilterType::FILTERTYPE_VENC);
    }
    if (receiverFilter_) {
        ret = pipeline_->AddHeadFilters({ receiverFilter_ });
        if (ret == Status::OK) {
            ChangeState(EngineState::INIT);
            HILOGI("success insert surface recv filter to header");
        }
    }
    return static_cast<int32_t>(ret);
}

void AVReceiverEngine::SetVideoSource(const VideoSourceType source)
{
    sourceType_ = source;
    switch (sourceType_) {
        case VideoSourceType::NV12:
            SetMetaData(*videoDecFormat_.get(), std::string(MDKey::MD_KEY_PIXEL_FORMAT), static_cast<int32_t>(Media::Plugins::VideoPixelFormat::NV12));
            HILOGI("AVReceiverEngine SetVideoSource NV12");
            break;
        case VideoSourceType::NV21:
            SetMetaData(*videoDecFormat_.get(), std::string(MDKey::MD_KEY_PIXEL_FORMAT), static_cast<int32_t>(Media::Plugins::VideoPixelFormat::NV21));
            HILOGI("AVReceiverEngine SetVideoSource NV21");
            break;
        default:
            SetMetaData(*videoDecFormat_.get(), std::string(MDKey::MD_KEY_PIXEL_FORMAT), static_cast<int32_t>(Media::Plugins::VideoPixelFormat::NV21));
            HILOGI("AVReceiverEngine SetVideoSource default NV21");
            break;
    }
    InitRecvHeaderFilter();
}

void AVReceiverEngine::ChangeState(const EngineState state)
{
    HILOGI("state change, %{public}d->%{public}d",
        static_cast<int32_t>(curState_), static_cast<int32_t>(state));
    curState_ = state;
}

int32_t AVReceiverEngine::Configure(const StreamParam& recParam)
{
    HILOGI("AVReceiverEngine Configure param enter.");
    if (isVideoParam(recParam)) {
        recParam.Configure(videoDecFormat_, ConfigureMode::Decode);
    }
    receiverFilter_->SetParameter(videoDecFormat_);
    ChangeState(EngineState::SETTING_PARAM);
    return static_cast<int32_t>(Status::OK);
}

inline bool AVReceiverEngine::isVideoParam(const StreamParam& recParam)
{
    switch (recParam.type_) {
        case StreamParamType::VID_CAPTURERATE:
        case StreamParamType::VID_RECTANGLE:
        case StreamParamType::VID_BITRATE:
        case StreamParamType::VID_FRAMERATE:
        case StreamParamType::VID_ENC_FMT:
        case StreamParamType::VID_IS_HDR:
        case StreamParamType::VID_ENABLE_TEMPORAL_SCALE:
            return true;
        default:
            return false;
    }
}

int32_t AVReceiverEngine::SetVideoSurface(uint64_t surfaceId)
{
    HILOGI("AVReceiverEngine SetSurface enter");
    sptr<Surface> surface = SurfaceUtils::GetInstance()->GetSurface(surfaceId);
    if (surface == nullptr) {
        HILOGE("surface empty");
        return static_cast<int32_t>(Status::ERROR_NULL_POINTER);
    }
#ifdef ENABLE_SURFACE_BUFFER_CACHE
    bufferCache_ = std::make_shared<AVSurfaceBufferCache>(surface);
    int32_t ret = bufferCache_->GetSurface(surface);
    if (ret != ERR_OK) {
        return ret;
    }
    bufferCache_->Init();
    bufferCache_->Start();
#endif
    surface_ = surface;
    return ERR_OK;
}

void AVReceiverEngine::SetChannelListener(int32_t channelId)
{
    HILOGI("AVReceiverEngine SetChannelListener enter");
    if (receiverFilter_ != nullptr) {
        receiverFilter_->SetChannelListener(channelId);
    }
}

cJSON* AVReceiverEngine::GetVideoCodecAbility()
{
    HILOGI("AVReceiverEngine::GetCodecAbility enter");
    std::shared_ptr<MediaAVCodec::AVCodecList> codecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    if (codecList == nullptr) {
        HILOGE("create codecList failed");
        return nullptr;
    }
    cJSON* abilityList = cJSON_CreateArray();
    for (const auto& decoder : DECODER_NAME) {
        MediaAVCodec::CapabilityData* capData = codecList->GetCapability(
            decoder, false, MediaAVCodec::AVCodecCategory::AVCODEC_HARDWARE);
        if (capData) {
            HILOGI("get codec: %{public}s, %{public}s, %{public}s", decoder.c_str(),
                capData->codecName.c_str(), capData->mimeType.c_str());
            cJSON_AddItemToArray(abilityList, cJSON_CreateString(capData->mimeType.c_str()));
        }
    }

    cJSON* result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, VIDEO_CODEC_LIST_KEY.c_str(), abilityList);
    return result;
}

#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
std::shared_ptr<IChannelListener> AVReceiverEngine::GetChannelListener()
{
    HILOGI("AVReceiverEngine GetChannelListener enter");
    if (receiverFilter_ != nullptr) {
        return receiverFilter_->GetChannelListener();
    }
    return nullptr;
}
#endif

Status AVReceiverEngine::OnCallback(const std::shared_ptr<Filter>& filter, FilterCallBackCommand cmd,
    StreamType outType)
{
    HILOGI("AVReceiverEngine OnCallback enter.");
    if (cmd == FilterCallBackCommand::NEXT_FILTER_NEEDED) {
        switch (outType) {
            case StreamType::STREAMTYPE_ENCODED_VIDEO: {
                if (videoDecoderFilter_ != nullptr) {
                    return Status::OK;
                }
                videoDecoderFilter_ = std::make_shared<SurfaceDecoderFilter>(
                    "builtin.dtbcollab.surfacedecoder", FilterType::FILTERTYPE_VDEC);
                if (videoDecoderFilter_ == nullptr) {
                    HILOGE("init decoder filter failed");
                    return Status::ERROR_NULL_POINTER;
                }
                videoDecFormat_->SetData(
                    std::string(MDKey::MD_KEY_VIDEO_ENCODE_BITRATE_MODE), Media::Plugins::VideoEncodeBitrateMode::VBR);
                videoDecoderFilter_->Init(engineEventReceiver_, engineFilterCallback_);
                pipeline_->LinkFilters(filter, { videoDecoderFilter_ }, outType);
                if (surface_ != nullptr) {
                    Status ret = videoDecoderFilter_->SetOutputSurface(surface_);
                    if (ret != Status::OK) {
                        HILOGE("set video surface failed");
                        return ret;
                    }
                }
                break;
            }
            default:
                break;
        }
    }
    return Status::OK;
}

int32_t AVReceiverEngine::Prepare()
{
    HILOGI("Prepare enter.");
    if (receiverFilter_ == nullptr) {
        HILOGE("filter not init");
        return static_cast<int32_t>(Status::ERROR_NULL_POINTER);
    }
    receiverFilter_->Init(engineEventReceiver_, engineFilterCallback_);
    std::shared_ptr<IEngineListener> listener = std::make_shared<RecvEngineListener>(shared_from_this());
    receiverFilter_->SetEngineListener(listener);
    Status ret = pipeline_->Prepare();
    if (ret != Status::OK) {
        HILOGE("prepare pipeline failed, %{public}s", engineId_.c_str());
        return static_cast<int32_t>(ret);
    }
    ChangeState(EngineState::PREPARE);
    return static_cast<int32_t>(ret);
}

int32_t AVReceiverEngine::Start()
{
    HILOGI("Start enter.");
    if (videoDecoderFilter_ == nullptr) {
        HILOGE("filter not init");
        return static_cast<int32_t>(Status::ERROR_NULL_POINTER);
    }
    Status ret = Status::OK;
    if (curState_ == EngineState::PAUSE) {
        ret = pipeline_->Resume();
    } else {
        ret = pipeline_->Start();
    }
    if (ret == Status::OK) {
        ChangeState(EngineState::RUNNING);
    }
    return static_cast<int32_t>(ret);
}

int32_t AVReceiverEngine::Pause()
{
    HILOGI("Pause enter.");
    Status ret = Status::OK;
    if (curState_ != EngineState::READY) {
        ret = pipeline_->Pause();
    }
    if (ret == Status::OK) {
        ChangeState(EngineState::PAUSE);
    }
    return static_cast<int32_t>(ret);
}

int32_t AVReceiverEngine::Resume()
{
    HILOGI("Resume enter.");
    Status ret = Status::OK;
    ret = pipeline_->Resume();
    if (ret == Status::OK) {
        ChangeState(EngineState::RUNNING);
    }
    return static_cast<int32_t>(ret);
}

int32_t AVReceiverEngine::Stop(bool isDrainAll)
{
    HILOGI("Stop enter.");
    if (curState_ == EngineState::INIT) {
        HILOGI("Stop exit.the reason is state = INIT");
        return static_cast<int32_t>(Status::OK);
    }
#ifdef ENABLE_SURFACE_BUFFER_CACHE
    bufferCache_->Stop();
#endif
    Status ret = Status::OK;
    ret = pipeline_->Stop();
    if (ret == Status::OK) {
        ChangeState(EngineState::INIT);
    }
    if (videoDecoderFilter_) {
        pipeline_->RemoveHeadFilter(videoDecoderFilter_);
    }
    return static_cast<int32_t>(ret);
}

int32_t AVReceiverEngine::Reset()
{
    HILOGI("Reset enter.");
    return Stop(false);
}

void AVReceiverEngine::SetEngineListener(const std::shared_ptr<IEngineListener>& listener)
{
    HILOGI("AVReceiverEngine::SetEngineListener enter");
    if (receiverFilter_ == nullptr) {
        HILOGE("receiverFilter empty");
        return;
    }
    receiverFilter_->SetEngineListener(listener);
}

GraphicTransformType AVReceiverEngine::ConvertToGraphicTrans(const SurfaceParam& param)
{
    if (param.filp == SurfaceFilp::FLIP_NONE) {
        switch (param.rotate) {
            case SurfaceRotate::ROTATE_NONE:
                return GraphicTransformType::GRAPHIC_ROTATE_NONE;
            case SurfaceRotate::ROTATE_90:
                return GraphicTransformType::GRAPHIC_ROTATE_90;
            case SurfaceRotate::ROTATE_180:
                return GraphicTransformType::GRAPHIC_ROTATE_180;
            case SurfaceRotate::ROTATE_270:
                return GraphicTransformType::GRAPHIC_ROTATE_270;
            default:
                return GraphicTransformType::GRAPHIC_ROTATE_BUTT; // Invalid rotation
        }
    } else if (param.filp == SurfaceFilp::FLIP_H) {
        switch (param.rotate) {
            case SurfaceRotate::ROTATE_NONE:
                return GraphicTransformType::GRAPHIC_FLIP_H;
            case SurfaceRotate::ROTATE_90:
                return GraphicTransformType::GRAPHIC_FLIP_H_ROT90;
            case SurfaceRotate::ROTATE_180:
                return GraphicTransformType::GRAPHIC_FLIP_H_ROT180;
            case SurfaceRotate::ROTATE_270:
                return GraphicTransformType::GRAPHIC_FLIP_H_ROT270;
            default:
                return GraphicTransformType::GRAPHIC_ROTATE_BUTT; // Invalid rotation
        }
    } else if (param.filp == SurfaceFilp::FLIP_V) {
        switch (param.rotate) {
            case SurfaceRotate::ROTATE_NONE:
                return GraphicTransformType::GRAPHIC_FLIP_V;
            case SurfaceRotate::ROTATE_90:
                return GraphicTransformType::GRAPHIC_FLIP_V_ROT90;
            case SurfaceRotate::ROTATE_180:
                return GraphicTransformType::GRAPHIC_FLIP_V_ROT180;
            case SurfaceRotate::ROTATE_270:
                return GraphicTransformType::GRAPHIC_FLIP_V_ROT270;
            default:
                return GraphicTransformType::GRAPHIC_ROTATE_BUTT; // Invalid rotation
        }
    }
    return GraphicTransformType::GRAPHIC_ROTATE_BUTT;
}

void AVReceiverEngine::OnRecvSurfaceParam(const SurfaceParam& param)
{
    HILOGI("AVReceiverEngine::OnRecvSurfaceParam enter");
    surfaceParam_ = param;
    GraphicTransformType graphic = ConvertToGraphicTrans(param);
    if (surface_ != nullptr && graphic != GraphicTransformType::GRAPHIC_ROTATE_BUTT) {
        HILOGI("set surface trans: %{public}d", static_cast<int32_t>(graphic));
        surface_->SetTransform(graphic);
    }
}

void AVReceiverEngine::OnEvent(const Media::Event& event)
{
    switch (event.type) {
        case Media::EventType::EVENT_ERROR: {
            HILOGI("EVENT_ERROR");
            ChangeState(EngineState::ERROR);
            Stop(true);
            break;
        }
        case Media::EventType::EVENT_READY: {
            ChangeState(EngineState::READY);
            break;
        }
        case Media::EventType::EVENT_COMPLETE:
        default:
            break;
    }
}

} // namespace DistributedCollab
} // namespace OHOS
