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
#ifndef OHOS_AV_TRANS_STREAM_AV_RECEIVER_FILTER_LISTENER_H
#define OHOS_AV_TRANS_STREAM_AV_RECEIVER_FILTER_LISTENER_H

#include "av_receiver_filter.h"
#include "ichannel_listener.h"

namespace OHOS {
namespace DistributedCollab {
    class AVReceiverFilterListener : public IChannelListener,
        public std::enable_shared_from_this<AVReceiverFilterListener> {
    public:
        AVReceiverFilterListener(const std::shared_ptr<AVReceiverFilter>& filter)
            : filter_(filter) {};
        ~AVReceiverFilterListener();
        void OnConnect(const int32_t channelId) const override;
        void OnDisConnect(const int32_t channelId) const override;
        void OnStream(const int32_t channelId, const std::shared_ptr<AVTransStreamData>& stream) const override;
        void OnBytes(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& buffer) const override;
        void OnMessage(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& buffer) const override;
        void OnError(const int32_t channelId, const int32_t errorCode) const override;

    private:
        std::weak_ptr<AVReceiverFilter> filter_;
    };

} // namespace DistributedCollab
} // namespace OHOS
#endif