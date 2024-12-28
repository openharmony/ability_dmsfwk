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

#ifndef OHOS_DSCHED_COLLAB_CHANNEL_COMMON_DEFINITION_H
#define OHOS_DSCHED_COLLAB_CHANNEL_COMMON_DEFINITION_H
#include "data_sender_receiver.h"
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace OHOS {
namespace DistributedCollab {
enum class ChannelStatus {
    CONNECTED,
    UNCONNECTED
};

enum class ChannelDataType {
    MESSAGE = 0,
    BYTES,
    VIDEO_STREAM
};

struct ChannelPeerInfo {
    std::string peerName;
    std::string networkId;
};

struct ChannelInfo {
    int32_t channelId;
    ChannelStatus status;
    ChannelDataType dataType;
    std::string channelName;
    ChannelPeerInfo peerInfo;
    std::vector<int32_t> clientSockets;
    // socketId->sender
    std::map<int32_t, std::unique_ptr<DataSenderReceiver>> dataSenderReceivers;
};
}
}
#endif