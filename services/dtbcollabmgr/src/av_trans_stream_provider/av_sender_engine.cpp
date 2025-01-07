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
#include "av_sender_engine.h"
#include "avcodec_info.h"
#include "avcodec_list.h"
#include "dtbcollabmgr_log.h"
#include "filter/filter_factory.h"
#include "ibuffer_consumer_listener.h"
#include "iconsumer_surface.h"
#include "osal/task/pipeline_threadpool.h"
#include "surface_type.h"
#include "surface_utils.h"
#include <vector>

namespace OHOS {
namespace DistributedCollab {
namespace {
    static const std::string TAG = "AVTransStreamSenderEngine";
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
    static const std::vector<std::string> ENCODER_NAME = {
        std::string(MediaAVCodec::CodecMimeType::VIDEO_AVC),
        std::string(MediaAVCodec::CodecMimeType::VIDEO_MPEG4),
        std::string(MediaAVCodec::CodecMimeType::VIDEO_HEVC),
    };
}

class AVSenderEngineEventReceiver : public EventReceiver {
public:
    explicit AVSenderEngineEventReceiver(std::shared_ptr<AVSenderEngine> engine)
        : engine_(engine) {};
    void OnEvent(const Media::Event& event)
    {
        if (auto ptr = engine_.lock()) {
            ptr->OnEvent(event);
        }
    }

private:
    std::weak_ptr<AVSenderEngine> engine_;
};

class AVSenderEngineFilterCallback : public FilterCallback {
public:
    explicit AVSenderEngineFilterCallback(std::shared_ptr<AVSenderEngine> engine)
        : engine_(engine) {};

    Status OnCallback(const std::shared_ptr<Filter>& filter, FilterCallBackCommand cmd,
        StreamType outType)
    {
        if (auto ptr = engine_.lock()) {
            return ptr->OnCallback(filter, cmd, outType);
        }
        return Status::ERROR_INVALID_STATE;
    }

private:
    std::weak_ptr<AVSenderEngine> engine_;
};

AVSenderEngine::~AVSenderEngine()
{
    HILOGI("AVSenderEngine destory");
    Stop();
    Media::PipeLineThreadPool::GetInstance().DestroyThread(engineId_);
}

void AVSenderEngine::Init()
{
    HILOGI("AVSenderEngine::Init enter");
    engineEventReceiver_ = std::make_shared<AVSenderEngineEventReceiver>(shared_from_this());
    engineFilterCallback_ = std::make_shared<AVSenderEngineFilterCallback>(shared_from_this());
    engineId_ = std::string("AVSenderEngine_") + std::to_string(Media::Pipeline::Pipeline::GetNextPipelineId());
    pipeline_->Init(engineEventReceiver_, engineFilterCallback_, engineId_);
}

int32_t AVSenderEngine::InitVideoHeaderFilter()
{
    HILOGI("AVSenderEngine::InitVideoHeaderFilter enter");
    Status ret = Status::ERROR_NULL_POINTER;
    if (!videoEncoderFilter_) {
        videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(
            "builtin.dtbcollab.videoencoder", FilterType::FILTERTYPE_VENC);
    }
    if (videoEncoderFilter_) {
        videoEncoderFilter_->SetCallingInfo(appUid_, appPid_, bundleName_, instanceId_);
        ret = pipeline_->AddHeadFilters({ videoEncoderFilter_ });
    }
    if (ret == Status::OK) {
        ChangeState(EngineState::INIT);
        HILOGI("success insert surface encoder filter to header");
    }
    return static_cast<int32_t>(ret);
}

void AVSenderEngine::SetVideoSource(const VideoSourceType source)
{
    sourceType_ = source;
    switch (sourceType_) {
        case VideoSourceType::NV12:
            videoEncFormat_->Set<Media::Tag::VIDEO_PIXEL_FORMAT>(Media::Plugins::VideoPixelFormat::NV12);
            HILOGI("AVSenderEngine SetVideoSource NV12");
            break;
        case VideoSourceType::NV21:
            videoEncFormat_->Set<Media::Tag::VIDEO_PIXEL_FORMAT>(Media::Plugins::VideoPixelFormat::NV21);
            HILOGI("AVSenderEngine SetVideoSource NV21");
            break;
        default:
            videoEncFormat_->Set<Media::Tag::VIDEO_PIXEL_FORMAT>(Media::Plugins::VideoPixelFormat::NV21);
            HILOGI("AVSenderEngine SetVideoSource default NV21");
            break;
    }
    InitVideoHeaderFilter();
}

int32_t AVSenderEngine::Configure(const StreamParam& recParam)
{
    HILOGI("AVSenderEngine Configure param enter.");
    if (isVideoParam(recParam)) {
        recParam.Configure(videoEncFormat_, ConfigureMode::Encode);
    }
    ChangeState(EngineState::SETTING);
    return static_cast<int32_t>(Status::OK);
}

bool AVSenderEngine::isVideoParam(const StreamParam& recParam)
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

void AVSenderEngine::SetTransChannel(int32_t channelId, const ChannelDataType channelType)
{
    HILOGI("AVSenderEngine SetTransChannel enter.");
    if (senderFilter_) {
        senderFilter_->SetTransChannel(channelId, channelType);
    }
}

#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
void AVSenderEngine::SetChannelListener(const std::shared_ptr<IChannelListener>& listener)
{
    HILOGI("AVSenderEngine SetChannelListener enter.");
    if (senderFilter_) {
        senderFilter_->SetChannelListener(listener);
    }
}
#endif

uint64_t AVSenderEngine::GetSurface()
{
    HILOGI("AVSenderEngine GetSurface enter.");
    if (videoEncoderFilter_) {
        surface_ = videoEncoderFilter_->GetInputSurface();
    }
    if (surface_ == nullptr) {
        return 0;
    }
    surface_->SetDefaultUsage(surface_->GetDefaultUsage() & (~BUFFER_USAGE_VIDEO_ENCODER));
    uint64_t id = surface_->GetUniqueId();
    SurfaceError err = SurfaceUtils::GetInstance()->Add(id, surface_);
    if (err != SURFACE_ERROR_OK) {
        HILOGE("register surface failed");
        return 0;
    }
    return id;
}

cJSON* AVSenderEngine::GetVideoCodecAbility()
{
    HILOGI("AVSenderEngine::GetCodecAbility enter");
    std::shared_ptr<MediaAVCodec::AVCodecList> codecList = MediaAVCodec::AVCodecListFactory::CreateAVCodecList();
    if (codecList == nullptr) {
        HILOGE("create codecList failed");
        return nullptr;
    }
    cJSON* abilityList = cJSON_CreateArray();
    for (const auto& encoder : ENCODER_NAME) {
        MediaAVCodec::CapabilityData* capData = codecList->GetCapability(
            encoder, true, MediaAVCodec::AVCodecCategory::AVCODEC_HARDWARE);
        if (capData) {
            HILOGI("get codec: %{public}s, %{public}s, %{public}s", encoder.c_str(),
                capData->codecName.c_str(), capData->mimeType.c_str());
            cJSON_AddItemToArray(abilityList, cJSON_CreateString(capData->mimeType.c_str()));
        }
    }

    cJSON* result = cJSON_CreateObject();
    cJSON_AddItemToObject(result, VIDEO_CODEC_LIST_KEY.c_str(), abilityList);
    return result;
}

Status AVSenderEngine::OnCallback(const std::shared_ptr<Filter>& filter, FilterCallBackCommand cmd,
    StreamType outType)
{
    HILOGI("AVSenderEngine OnCallback enter.");
    if (cmd == FilterCallBackCommand::NEXT_FILTER_NEEDED) {
        switch (outType) {
            case StreamType::STREAMTYPE_ENCODED_VIDEO: {
                if (senderFilter_ != nullptr) {
                    return Status::OK;
                }
                senderFilter_ = std::make_shared<AVSenderFilter>(
                    "builtin.dtbcollab.sender", FilterType::FILTERTYPE_SOURCE);
                if (senderFilter_ == nullptr) {
                    return Status::ERROR_NULL_POINTER;
                }
                senderFilter_->Init(engineEventReceiver_, engineFilterCallback_);
                pipeline_->LinkFilters(filter, { senderFilter_ }, outType);
                break;
            }
            default:
                break;
        }
    }
    return Status::OK;
}

int32_t AVSenderEngine::Prepare()
{
    HILOGI("AVSenderEngine Prepare enter.");
    if (videoEncoderFilter_ == nullptr) {
        HILOGE("filter not init");
        return static_cast<int32_t>(Status::ERROR_NULL_POINTER);
    }
    videoEncFormat_->Set<Media::Tag::VIDEO_ENCODE_BITRATE_MODE>(Media::Plugins::VideoEncodeBitrateMode::VBR);
    videoEncoderFilter_->SetCodecFormat(videoEncFormat_);
    videoEncoderFilter_->Init(engineEventReceiver_, engineFilterCallback_);
    Status ret = videoEncoderFilter_->Configure(videoEncFormat_);
    if (ret != Status::OK) {
        HILOGE("encoder filter set param failed");
        return static_cast<int32_t>(ret);
    }
    ret = pipeline_->Prepare();
    if (ret != Status::OK) {
        HILOGE("prepare pipeline failed, %{public}s", engineId_.c_str());
        return static_cast<int32_t>(ret);
    }
    ChangeState(EngineState::PREPARE);
    return static_cast<int32_t>(ret);
}

int32_t AVSenderEngine::Start()
{
    HILOGI("AVSenderEngine Start enter.");
    if (senderFilter_ == nullptr) {
        HILOGE("sender filter not init");
        return static_cast<int32_t>(Status::ERROR_NULL_POINTER);
    }
    if (curState_ == EngineState::START) {
        HILOGI("start no need change state");
        return static_cast<int32_t>(Status::OK);
    }
    if (curState_ != EngineState::PREPARE && curState_ != EngineState::STOP) {
        HILOGE("need prepare/stop state to start");
        return static_cast<int32_t>(Status::ERROR_WRONG_STATE);
    }
    Status ret = Status::OK;
    ret = pipeline_->Start();
    if (ret == Status::OK) {
        ChangeState(EngineState::START);
    }
    return static_cast<int32_t>(ret);
}

int32_t AVSenderEngine::Stop()
{
    HILOGI("AVSenderEngine Stop enter.");
    if (curState_ == EngineState::INIT || curState_ == EngineState::STOP) {
        HILOGI("Stop exit. no need change state");
        return static_cast<int32_t>(Status::OK);
    }
    if (curState_ != EngineState::START) {
        HILOGE("need start state to stop");
        return static_cast<int32_t>(Status::ERROR_WRONG_STATE);
    }
    Status ret = Status::OK;
    ret = pipeline_->Stop();
    if (ret == Status::OK) {
        ChangeState(EngineState::STOP);
    }
    if (videoEncoderFilter_) {
        pipeline_->RemoveHeadFilter(videoEncoderFilter_);
    }
    return static_cast<int32_t>(ret);
}

int32_t AVSenderEngine::SendPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap)
{
    HILOGI("AVSenderEngine::SendPixelMap enter");
    if (senderFilter_ == nullptr) {
        HILOGE("senderFilter empty");
        return NULL_POINTER_ERROR;
    }
    return senderFilter_->SendPixelMap(pixelMap);
}

int32_t AVSenderEngine::SetSurfaceParam(const SurfaceParam& param)
{
    HILOGI("AVSenderEngine::SetSurfaceParam enter");
    if (senderFilter_ == nullptr) {
        HILOGE("senderFilter empty");
        return NULL_POINTER_ERROR;
    }
    return senderFilter_->SetSurfaceParam(param);
}

void AVSenderEngine::OnEvent(const Media::Event& event)
{
    switch (event.type) {
        case Media::EventType::EVENT_ERROR: {
            HILOGI("EVENT_ERROR");
            ChangeState(EngineState::ERROR);
            Stop();
            break;
        }
        case Media::EventType::EVENT_READY: {
            ChangeState(EngineState::START);
            break;
        }
        case Media::EventType::EVENT_COMPLETE:
        default:
            break;
    }
}

void AVSenderEngine::ChangeState(const EngineState state)
{
    HILOGI("AVSenderEngine state: %{public}u->%{public}u",
        static_cast<uint32_t>(curState_), static_cast<uint32_t>(state));
    curState_ = state;
}

EngineState AVSenderEngine::GetState()
{
    return curState_;
}
} // namespace DistributedCollab
} // namespace OHOS
