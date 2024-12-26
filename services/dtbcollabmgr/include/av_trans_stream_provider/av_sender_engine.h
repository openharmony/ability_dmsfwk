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
#ifndef OHOS_AV_TRANS_STREAM_AV_SENDER_ENGINE_H
#define OHOS_AV_TRANS_STREAM_AV_SENDER_ENGINE_H

#include "av_sender_filter.h"
#include "av_stream_common.h"
#include "av_stream_param.h"
#include "channel_common_definition.h"
#include "common/status.h"
#include "meta/meta.h"
#include "pipeline/pipeline.h"
#include "refbase.h"
#include "surface.h"
#include "surface_encoder_filter.h"
#include <memory>
#include <string>
#include "cJSON.h"
#include "pixel_map.h"


namespace OHOS {
namespace DistributedCollab {
    class AVSenderEngine : public std::enable_shared_from_this<AVSenderEngine> {
    public:
        explicit AVSenderEngine(
            const int32_t appUid,
            const int32_t appPid,
            const std::string& bundleName,
            const uint64_t instanceId)
            : appUid_(appUid),
            appPid_(appPid),
            bundleName_(bundleName),
            instanceId_(instanceId)
            {
                pipeline_ = std::make_shared<Media::Pipeline::Pipeline>();
            };
        ~AVSenderEngine();
        void Init();
        void SetVideoSource(const VideoSourceType source);
        int32_t Configure(const StreamParam& recParam);
        void SetTransChannel(int32_t channelId, const ChannelDataType channelType);
        uint64_t GetSurface();
        cJSON* GetVideoCodecAbility();
        int32_t Prepare();
        int32_t Start();
        int32_t Pause();
        int32_t Resume();
        int32_t Stop(bool isDrainAll);
        int32_t Reset();
        Media::Status OnCallback(
            const std::shared_ptr<Media::Pipeline::Filter>& filter,
            Media::Pipeline::FilterCallBackCommand cmd,
            Media::Pipeline::StreamType outType);
        void OnEvent(const Media::Event& event);
        int32_t SendPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap);
        int32_t SetSurfaceParam(const SurfaceParam& param);
#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
        void SetChannelListener(const std::shared_ptr<IChannelListener>& listener);
#endif

    private:
        void ChangeState(const EngineState state);
        int32_t InitVideoHeaderFilter();
        bool isVideoParam(const StreamParam& recParam);

    private:
        std::shared_ptr<Media::Pipeline::Pipeline> pipeline_ = nullptr;
        std::shared_ptr<SurfaceEncoderFilter> videoEncoderFilter_ = nullptr;
        std::shared_ptr<Media::Meta> videoEncFormat_ = std::make_shared<Media::Meta>();
        std::shared_ptr<AVSenderFilter> senderFilter_ = nullptr;
        sptr<Surface> surface_ { nullptr };

        std::shared_ptr<Media::Pipeline::EventReceiver> engineEventReceiver_ = nullptr;
        std::shared_ptr<Media::Pipeline::FilterCallback> engineFilterCallback_ = nullptr;
        std::string engineId_;

        VideoSourceType sourceType_ = VideoSourceType::NV21;
        EngineState curState_ = EngineState::EMPTY;

        int32_t appUid_ { 0 };
        int32_t appPid_ { 0 };
        std::string bundleName_;
        uint64_t instanceId_ = 0;
    };
} // namespace DistributedCollab
} // namespace OHOS
#endif