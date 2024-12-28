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

#ifndef OHOS_DISTRIBUTED_ABILITY_CONNECTION_SESSION_H
#define OHOS_DISTRIBUTED_ABILITY_CONNECTION_SESSION_H

#include <map>
#include <string>
#include <shared_mutex>
#include <thread>

#include "ability_connection_info.h"
#include "av_receiver_engine.h"
#include "av_sender_engine.h"
#include "av_trans_data_buffer.h"
#include "channel_manager.h"
#include "event_handler.h"
#include "ichannel_listener.h"
#include "iengine_listener.h"
#include "js_ability_connection_session_listener.h"

namespace OHOS {
namespace DistributedCollab {
enum class SessionStatus : int32_t {
    UNCONNECTED,
    CONNECTING,
    CONNECTED,
};

enum class TransChannelType : int32_t {
    CONTROL_CHANNEL,
    MESSAGE_CHANNEL,
    DATA_CHANNEL,
    STREAM_CHANNEL_BYTES,
    STREAM_CHANNEL
};

enum class CollabrateDirection : int32_t {
    COLLABRATE_SOURCE,
    COLLABRATE_SINK,
};

enum class MessageType : uint32_t  {
    MESSAGE_NORMAL,
    MESSAGE_WIFI_STATUS,
    MESSAGE_UPDATE_STREAM_CHANNEL,
    MESSAGE_STREAM_STATUS,
    MESSAGE_STREAM_ENCODING
};

struct TransChannelInfo {
    int32_t channelId;
    ChannelDataType channelType;
    TransChannelType transType;
    bool isConnected;
};

class AbilityConnectionSession : public std::enable_shared_from_this<AbilityConnectionSession> {
public:
    AbilityConnectionSession(int32_t sessionId, std::string serverSocketName, PeerInfo localInfo,
         PeerInfo peerInfo, ConnectOption opt);
    ~AbilityConnectionSession();

    void Init();
    void UnInit();

    void Release();
    PeerInfo GetPeerInfo();
    PeerInfo GetLocalInfo();
    using ConnectCallback = std::function<void(const ConnectResult& result)>;
    int32_t Connect(ConnectCallback& callback);
    int32_t Disconnect();
    int32_t AcceptConnect(const std::string& token);

    int32_t HandleCollabResult(int32_t result, const std::string& peerSocketName);
    int32_t HandleDisconnect();

    int32_t SendMessage(const std::string& msg, const MessageType& messageType = MessageType::MESSAGE_NORMAL);
    int32_t SendData(const std::shared_ptr<AVTransDataBuffer>& buffer);
    int32_t SendImage(const std::shared_ptr<Media::PixelMap>& image);

    int32_t CreateStream(int32_t streamId, const StreamParams& param);
    int32_t DestroyStream(int32_t streamId);
    int32_t SetSurfaceId(const std::string& surfaceId, const SurfaceParams& param);
    int32_t GetSurfaceId(const SurfaceParams& param, std::string& surfaceId);
    int32_t UpdateSurfaceParam(const SurfaceParams& param);
    int32_t StartStream(int32_t streamId);
    int32_t StopStream(int32_t streamId);

    void OnChannelConnect(int32_t channelId);
    void OnChannelClosed(int32_t channelId);
    void OnBytesReceived(int32_t channelId, const std::shared_ptr<AVTransDataBuffer> buffer);
    void OnMessageReceived(int32_t channelId, const std::shared_ptr<AVTransDataBuffer> buffer);
    void OnRecvPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap);

    int32_t RegisterEventCallback(const std::string& eventType,
        const std::shared_ptr<JsAbilityConnectionSessionListener>& listener);
    int32_t UnregisterEventCallback(const std::string& eventType);
    int32_t NotifyRemoteWifiOpen();
    int32_t CheckWifiState();
    void UpdateEngineTransChannel();
    
private:
    void StartEvent();
    int32_t InitChannels();
    int32_t CreateChannel(const std::string& channelName, const ChannelDataType& dataType,
        const TransChannelType& channelType);
    std::string GetChannelName(const std::string& sourceModule, const std::string& sourceAbility,
        const std::string& sinkModule, const std::string& sinkAbility);
    int32_t ConnectChannels();
    int32_t GetChannelByType(const TransChannelType& dataType, int32_t& channelId);
    bool IsAllChannelConnected();
    bool IsVaildChannel(const int32_t channelId);
    void SetTimeOut(int32_t time);
    void RemoveTimeout();
    bool IsConnecting();
    bool IsConnected();

    int32_t InitSenderEngine();
    int32_t InitRecvEngine();
    int32_t GetStreamTransChannel(TransChannelInfo& info);
    template <typename T>
    int32_t ConfigEngineParam(std::shared_ptr<T> &engine, const SurfaceParams& param);
    void UpdateTransChannelStatus(int32_t channelId, bool isConnect);
    int32_t GetTransChannelInfo(const TransChannelType& type, TransChannelInfo& info);

    void ExeuteConnectCallback(const ConnectResult& result);
    int32_t ExeuteEventCallback(const std::string& eventType, const EventCallbackInfo& info);

private:
    class CollabChannelListener : public IChannelListener {
    public:
        CollabChannelListener() = default;
        explicit CollabChannelListener(const std::shared_ptr<AbilityConnectionSession>& AbilityConnectionSession);
        virtual ~CollabChannelListener() = default;

        void OnConnect(const int32_t channelId) const override;
        void OnDisConnect(const int32_t channelId) const override;
        void OnStream(const int32_t channelId, const std::shared_ptr<AVTransStreamData>& sendData) const override;
        void OnBytes(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& buffer) const override;
        void OnMessage(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& buffer) const override;
        void OnError(const int32_t channelId, const int32_t errorCode) const override;

    private:
        std::weak_ptr<AbilityConnectionSession> abilityConnectionSession_;
    };

private:
    class PixelMapListener : public IEngineListener {
    public:
        PixelMapListener() = default;
        explicit PixelMapListener(const std::shared_ptr<AbilityConnectionSession>& AbilityConnectionSession);
        virtual ~PixelMapListener() = default;
        void OnRecvPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap) override;
        void OnRecvSurfaceParam(const SurfaceParam& param) override;
        
    private:
        std::weak_ptr<AbilityConnectionSession> abilityConnectionSession_;
    };

private:
    int32_t sessionId_ = 0;
    int32_t streamId_ = 0;
    int32_t version_ = 0;
    std::string dmsServerToken_;
    std::string localSocketName_;
    std::string peerSocketName_;
    PeerInfo localInfo_;
    PeerInfo peerInfo_;
    ConnectOption connectOption_;
    CollabrateDirection direction_;
    
    std::shared_ptr<CollabChannelListener> channelListener_ = nullptr;

    std::shared_mutex transChannelMutex_;
    std::map<TransChannelType, TransChannelInfo> transChannels_;

    std::shared_mutex sessionMutex_;
    SessionStatus sessionStatus_ = SessionStatus::UNCONNECTED;
    ConnectCallback connectCallback_ = nullptr;

    std::thread eventThread_;
    std::condition_variable eventCon_;
    std::mutex eventMutex_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler_ = nullptr;

    std::shared_mutex listenerMutex_;
    std::map<std::string, std::shared_ptr<JsAbilityConnectionSessionListener>> listeners_;

    std::shared_mutex engineMutex_;
    std::shared_ptr<AVSenderEngine> senderEngine_ = nullptr;
    std::shared_ptr<AVReceiverEngine> recvEngine_ = nullptr;
    std::shared_ptr<IEngineListener> pixelMapListener = nullptr;
};
} // namespace DistributedCollab
} // namespace OHOS
#endif //OHOS_DISTRIBUTED_ABILITY_CONNECTION_SESSION_H