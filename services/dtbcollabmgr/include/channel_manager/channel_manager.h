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

#ifndef OHOS_DSCHED_COLLAB_CHANNEL_MANAGER_H
#define OHOS_DSCHED_COLLAB_CHANNEL_MANAGER_H
#include "ichannel_listener.h"
#include "channel_common_definition.h"
#include "data_sender_receiver.h"
#include "event_handler.h"
#include "single_instance.h"
#include "socket.h"
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <string>
#include <vector>
#include <thread>
#include <atomic>

namespace OHOS {
namespace DistributedCollab {
class ChannelManager final {
    DECLARE_SINGLE_INSTANCE_BASE(ChannelManager);

public:
    int32_t Init(const std::string& ownerName);
    void DeInit();

    int32_t GetVersion();
    int32_t CreateServerChannel(const std::string& channelName,
        const ChannelDataType dataType, const ChannelPeerInfo& peerInfo);
    int32_t CreateClientChannel(const std::string& channelName,
        const ChannelDataType dataType, const ChannelPeerInfo& peerInfo);
    bool isValidChannelId(const int32_t channelId);
    int32_t DeleteChannel(const int32_t channelId);
    int32_t RegisterChannelListener(const int32_t channelId,
        const std::shared_ptr<IChannelListener> listener);
    int32_t ConnectChannel(const int32_t channelId);

    int32_t SendBytes(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& data);
    int32_t SendStream(const int32_t channelId, const std::shared_ptr<AVTransStreamData>& data);
    int32_t SendMessage(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& data);
    int32_t SendFile(const int32_t channelId, const std::vector<std::string>& sFiles,
        const std::vector<std::string>& dFiles);

    void OnSocketError(int32_t socketId, const int32_t errorCode);
    void OnSocketConnected(int32_t socketId, const PeerSocketInfo& info);
    void OnSocketClosed(int32_t socketId, const ShutdownReason reason);
    void OnBytesReceived(int32_t socketId, const void* data, const uint32_t dataLen);
    void OnMessageReceived(int32_t socketId, const void* data, const uint32_t dataLen);
    void OnStreamReceived(int32_t socketId, const StreamData* data,
        const StreamData* ext, const StreamFrameInfo* param);
    void OnFileEventReceived(int32_t socketId, FileEvent *event);
    const char* GetRecvPathFromUser();

private:
    static constexpr int32_t VERSION_ = 0;
    static constexpr int32_t CHANNEL_ID_GAP = 1000;
    static constexpr int32_t MESSAGE_START_ID = 1001;
    static constexpr int32_t BYTES_START_ID = MESSAGE_START_ID + CHANNEL_ID_GAP;
    static constexpr int32_t STREAM_START_ID = BYTES_START_ID + CHANNEL_ID_GAP;
    static constexpr int32_t FILE_START_ID = STREAM_START_ID + CHANNEL_ID_GAP;
    static constexpr int32_t MAX_CHANNEL_NAME_LENGTH = 64;
    static constexpr int32_t CHANNEL_NAME_PREFIX_LENGTH = 64;
    static constexpr int32_t RETRY_TIME_GAP = 1000;
    static constexpr int32_t MAX_FILE_COUNT = 500;

private:
    int32_t serverSocketId_ = -1;
    std::string ownerName_;

    // for all channel res
    std::shared_mutex channelMutex_;
    // name2ids
    std::map<std::string, std::vector<int32_t>> channelIdMap_;
    // id2info
    std::map<int32_t, ChannelInfo> channelInfoMap_;

    std::atomic_uint32_t fileChannelId_;

    // for all socket res
    std::shared_mutex socketMutex_;
    // socketId2channelId
    std::map<int32_t, int32_t> socketChannelMap_;
    std::map<int32_t, ChannelStatus> socketStatusMap_;

    std::shared_mutex listenerMutex_;
    std::map<int32_t, std::vector<std::weak_ptr<IChannelListener>>> listenersMap_;

    std::map<ChannelDataType, std::mutex> typeMutex_;
    std::map<ChannelDataType, std::int32_t> nextIds_ = {
        { ChannelDataType::MESSAGE, MESSAGE_START_ID },
        { ChannelDataType::BYTES, BYTES_START_ID },
        { ChannelDataType::VIDEO_STREAM, STREAM_START_ID },
        { ChannelDataType::FILE, FILE_START_ID }
    };

    std::mutex eventMutex_;
    std::thread eventThread_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler_;
    std::condition_variable eventCon_;

    std::mutex callbackEventMutex_;
    std::thread callbackEventThread_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> callbackEventHandler_;
    std::condition_variable callbackEventCon_;

private:
    explicit ChannelManager() = default;
    ~ChannelManager();

    void Reset();
    int32_t PostTask(const AppExecFwk::InnerEvent::Callback& callback,
        const AppExecFwk::EventQueue::Priority priority);
    int32_t PostCallbackTask(const AppExecFwk::InnerEvent::Callback& callback,
            const AppExecFwk::EventQueue::Priority priority);
    void StartEvent();
    void StartCallbackEvent();

    int32_t CreateServerSocket();
    int32_t CreateClientSocket(const std::string& channelName,
        const std::string& peerName, const std::string& peerNetworkId, const ChannelDataType dataType);
    std::optional<ChannelInfo> CreateBaseChannel(const std::string& channelName,
        const ChannelDataType dataType, const ChannelPeerInfo& peerInfo);
    int32_t GenerateNextId(const ChannelDataType dataType);
    int32_t RegisterSocket(ChannelInfo& info, const ChannelDataType dataType);

    void ClearRegisterChannel(const int32_t channelId);
    void ClearRegisterListener(const int32_t channelId);
    void ClearRegisterSocket(const int32_t channelId);

    void CleanInvalidListener(std::vector<std::weak_ptr<IChannelListener>>& listeners);

    int32_t DoBindSockets(const std::vector<int32_t>& socketIds, const ChannelDataType dataType);
    ChannelStatus GetSocketStatus(const int32_t socketId);
    int32_t BindSocket(const int32_t socketId, const ChannelDataType dataType);
    int32_t SetSocketStatus(const int32_t socketId, const ChannelStatus status);
    int32_t UpdateChannelStatus(const int32_t channelId);
    int32_t SetChannelStatus(const int32_t channelId, const ChannelStatus status);
    void DoErrorCallback(const int32_t channelId, const int32_t errorCode);

    std::optional<std::string> GetChannelNameFromSocket(const std::string& socketName);
    std::optional<ChannelDataType> GetChannelDataTypeFromName(const std::string& channelName);
    int32_t GetChannelId(const std::string& channelName, const ChannelDataType dataType);
    int32_t RegisterSocket(const int32_t socketId, const int32_t channelId);
    int32_t UpdateChannel(const int32_t socketId, const int32_t channelId);
    int32_t GetChannelId(const int32_t socketId);
    ChannelStatus GetChannelStatus(const int32_t channelId);

    template <typename Func, typename... Args>
    int32_t DoSendData(const int32_t channelId, Func doSendFunc, Args&& ...args);
    template <typename Func, typename... Args>
    void NotifyListeners(const int32_t channelId, Func listenerFunc,
        const AppExecFwk::EventQueue::Priority priority, Args&& ...args);
    int32_t GetValidSocket(const int32_t channelId);
    int32_t DoSendBytes(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& data);
    int32_t DoSendMessage(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& data);
    int32_t DoSendStream(const int32_t channelId, const std::shared_ptr<AVTransStreamData>& data);
    int32_t DoSendFile(const int32_t channelId, const std::vector<std::string>& sFiles,
        const std::vector<std::string>& dFiles);
    std::shared_ptr<AVTransDataBuffer> ProcessRecvData(const int32_t channelId,
        const int32_t socketId, const void* data, const uint32_t dataLen);
    void DoConnectCallback(const int32_t channelId);
    void DoDisConnectCallback(const int32_t channelId);
    void DoBytesReceiveCallback(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& buffer);
    void DoMessageReceiveCallback(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& buffer);
    void DoStreamReceiveCallback(const int32_t channelId, const std::shared_ptr<AVTransStreamData>& data);
    void DispatchProcessFileEvent(int32_t channelId, FileEvent *event);
    void DealFileSendEvent(int32_t channelId, FileEvent *event);
    void DealFileRecvEvent(int32_t channelId, FileEvent *event);
    void DealFileErrorEvent(int32_t channelId, FileEvent *event);
    void DealFileUpdatePathEvent(int32_t channelId, FileEvent *event);
    void DoFileRecvCallback(const int32_t channelId, const FileInfo& info);
    void DoFileSendCallback(const int32_t channelId, const FileInfo& info);
};
}
}
#endif