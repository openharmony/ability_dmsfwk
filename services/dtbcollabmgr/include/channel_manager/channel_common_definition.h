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
    CONNECTED = 0,
    UNCONNECTED
};

enum class ChannelDataType {
    MESSAGE = 0,
    BYTES,
    VIDEO_STREAM,
    FILE
};

struct ChannelPeerInfo {
    std::string peerName;
    std::string networkId;
};

struct ChannelInfo {
    int32_t channelId = 0;
    ChannelStatus status = ChannelStatus::UNCONNECTED;
    ChannelDataType dataType = ChannelDataType::MESSAGE;
    std::string channelName;
    ChannelPeerInfo peerInfo;
    std::vector<int32_t> clientSockets;
    // socketId->sender
    std::map<int32_t, std::unique_ptr<DataSenderReceiver>> dataSenderReceivers;
};

enum class ChannnelFileEvent : uint32_t {
    SEND_PROCESS = 0,     /**< Sending file */
    SEND_FINISH,      /**< Send file end */
    SEND_ERROR,       /**< Send file failed */
    RECV_START,       /**< Receive file start */
    RECV_PROCESS,     /**< Receiving file */
    RECV_FINISH,      /**< Receive file end */
    RECV_ERROR,       /**< Receive file failed */
};

struct FileSendInfo {
    uint64_t bytesProcessed = 0;             /**< Send or receive bytes of the files*/
    uint64_t bytesTotal = 0;                 /**< Total bytes of the files*/
    std::optional<uint32_t> rate = std::nullopt;
};

struct FileRecvInfo {
    uint64_t bytesProcessed = 0;             /**< Send or receive bytes of the files*/
    uint64_t bytesTotal = 0;                 /**< Total bytes of the files*/
    std::optional<uint32_t> rate = std::nullopt;
};

struct FileErrorInfo {
    int32_t errorCode = 0;
};

struct FileCommonInfo {
    ChannnelFileEvent eventType = ChannnelFileEvent::SEND_PROCESS;
    std::vector<std::string> fileList;
    uint32_t fileCnt = 0;
};

struct FileInfo {
    FileCommonInfo commonInfo;
    std::optional<FileSendInfo> sendInfo = std::nullopt;
    std::optional<FileRecvInfo> recvInfo = std::nullopt;
    std::optional<FileErrorInfo> errorInfo = std::nullopt;
};
}
}
#endif