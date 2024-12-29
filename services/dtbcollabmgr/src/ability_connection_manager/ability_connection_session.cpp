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

#include "ability_connection_session.h"

#include <map>
#include <sys/prctl.h>
#include <sstream>
#include <iomanip>

#include "dtbcollabmgr_log.h"
#include "distributed_client.h"
#include "openssl/sha.h"
#include "message_data_header.h"
#include "wifi_state_listener.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
const std::string TAG = "AbilityConnectionSession";
const std::string CONNECT_SESSION_TIMEOUT_END_TASK = "connect_session_timeout_end_task";
const std::u16string DMS_PROXY_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
constexpr const char* EVENT_CONNECT = "connect";
constexpr const char* EVENT_DISCONNECT = "disconnect";
constexpr const char* EVENT_RECEIVE_MESSAGE = "receiveMessage";
constexpr const char* EVENT_RECEIVE_DATA = "receiveData";
constexpr const char* EVENT_RECEIVE_IMAGE = "receiveImage";
constexpr int32_t DSCHED_COLLAB_PROTOCOL_VERSION = 1;
static constexpr uint16_t PROTOCOL_VERSION = 1;
constexpr int32_t CHANNEL_NAME_LENGTH = 48;
constexpr int32_t VIDEO_BIT_RATE = 640000;
constexpr int32_t VIDEO_FRAME_RATE = 30;
constexpr int32_t MIN_CHANNEL_ID = 1000;
constexpr int32_t MAX_CHANNEL_ID = 5000;
constexpr int32_t DEFAULT_APP_UID = 0;
constexpr int32_t DEFAULT_APP_PID = 0;
constexpr int32_t DEFAULT_INSTANCE_ID = 0;
constexpr int32_t HEX_WIDTH = 2;
constexpr char FILL_CHAR = '0';
}

AbilityConnectionSession::AbilityConnectionSession(int32_t sessionId, std::string serverSocketName, PeerInfo localInfo,
    PeerInfo peerInfo, ConnectOption opt)
{
    sessionId_ = sessionId;
    localSocketName_ = serverSocketName;
    localInfo_ = localInfo;
    peerInfo_ = peerInfo;
    connectOption_ = opt;
    version_ = DSCHED_COLLAB_PROTOCOL_VERSION;
}

AbilityConnectionSession::~AbilityConnectionSession()
{
}

void AbilityConnectionSession::Init()
{
    HILOGI("Init AbilityConnectionSession start");
    if (eventHandler_ != nullptr) {
        HILOGI("AbilityConnectionSession already inited, end.");
        return;
    }
    eventThread_ = std::thread(&AbilityConnectionSession::StartEvent, this);
    std::unique_lock<std::mutex> lock(eventMutex_);
    eventCon_.wait(lock, [this] {
        return eventHandler_ != nullptr;
    });
    HILOGI("Init AbilityConnectionSession end");
}

void AbilityConnectionSession::StartEvent()
{
    HILOGI("StartEvent start");
    std::string name = localSocketName_ + std::to_string(sessionId_);
    prctl(PR_SET_NAME, name.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    runner->Run();
    HILOGI("StartEvent end");
}

void AbilityConnectionSession::UnInit()
{
    HILOGI("UnInit start");
    if (eventHandler_ != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        eventThread_.join();
        eventHandler_ = nullptr;
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("UnInit end");
}

void AbilityConnectionSession::Release()
{
    HILOGD("called.");
    {
        std::unique_lock<std::shared_mutex> sessionStatusWriteLock(sessionMutex_);
        if (sessionStatus_ == SessionStatus::UNCONNECTED) {
            HILOGI("The session resource has been released.");
            return;
        }
        sessionStatus_ = SessionStatus::UNCONNECTED;
    }
    senderEngine_ = nullptr;
    recvEngine_ = nullptr;
    
    std::unique_lock<std::shared_mutex> channelLock(transChannelMutex_);
    for (auto iter = transChannels_.begin(); iter != transChannels_.end(); iter++) {
        ChannelManager::GetInstance().DeleteChannel(iter->second.channelId);
    }
    transChannels_.clear();
}

PeerInfo AbilityConnectionSession::GetPeerInfo()
{
    return peerInfo_;
}

PeerInfo AbilityConnectionSession::GetLocalInfo()
{
    return localInfo_;
}

int32_t AbilityConnectionSession::Connect(ConnectCallback& callback)
{
    HILOGD("called.");
    {
        std::unique_lock<std::shared_mutex> sessionStatusWriteLock(sessionMutex_);
        if (sessionStatus_ != SessionStatus::UNCONNECTED) {
            HILOGE("session has start to connect, sessionStatus is %{public}d", sessionStatus_);
            return INVALID_PARAMETERS_ERR;
        }
        sessionStatus_ = SessionStatus::CONNECTING;
        connectCallback_ = callback;
    }
    direction_ = CollabrateDirection::COLLABRATE_SOURCE;
    
    DistributedClient dmsClient;
    int32_t ret = dmsClient.CollabMission(sessionId_, localSocketName_, localInfo_, peerInfo_, connectOption_);
    if (ret != ERR_OK) {
        HILOGE("collab mission start failed.");
        ConnectResult connectResult;
        connectResult.isConnected = false;
        ExeuteConnectCallback(connectResult);
    }
    return ret;
}

int32_t AbilityConnectionSession::Disconnect()
{
    HILOGD("called.");
    Release();

    DistributedClient dmsClient;
    int32_t ret = dmsClient.NotifyCloseCollabSession(dmsServerToken_);
    HILOGI("Notify Server DisConnect result is %{public}d", ret);
    return ERR_OK;
}

int32_t AbilityConnectionSession::AcceptConnect(const std::string& token)
{
    HILOGD("called.");
    {
        std::unique_lock<std::shared_mutex> sessionStatusWriteLock(sessionMutex_);
        if (sessionStatus_ != SessionStatus::UNCONNECTED) {
            HILOGE("session has start to connect, sessionStatus is %{public}d", sessionStatus_);
            return INVALID_PARAMETERS_ERR;
        }
        sessionStatus_ = SessionStatus::CONNECTING;
    }

    dmsServerToken_ = token;
    direction_ = CollabrateDirection::COLLABRATE_SINK;

    DistributedClient dmsClient;
    int32_t ret = InitChannels();
    if (ret != ERR_OK) {
        HILOGE("init sink client failed!");
        dmsClient.NotifyPrepareResult(token, ret, sessionId_, localSocketName_);
        return ret;
    }
    dmsClient.NotifyPrepareResult(token, ERR_OK, sessionId_, localSocketName_);
    return ERR_OK;
}

int32_t AbilityConnectionSession::HandleCollabResult(int32_t result, const std::string& peerSocketName,
    const std::string& dmsServerToken)
{
    HILOGD("called.");
    if (result != ERR_OK) {
        HILOGE("collab result is failed, ret = %{public}d", result);
        ConnectResult connectResult;
        connectResult.isConnected = false;
        ExeuteConnectCallback(connectResult);
        return INVALID_PARAMETERS_ERR;
    }

    dmsServerToken_ = dmsServerToken;
    peerSocketName_ = peerSocketName;
    if (InitChannels() != ERR_OK) {
        DistributedClient dmsClient;
        dmsClient.NotifyCloseCollabSession(dmsServerToken_);
        ConnectResult connectResult;
        connectResult.isConnected = false;
        ExeuteConnectCallback(connectResult);
        return INVALID_PARAMETERS_ERR;
    }

    if (ConnectChannels() != ERR_OK) {
        DistributedClient dmsClient;
        dmsClient.NotifyCloseCollabSession(dmsServerToken_);
        ConnectResult connectResult;
        connectResult.isConnected = false;
        ExeuteConnectCallback(connectResult);
        return INVALID_PARAMETERS_ERR;
    }

    std::unique_lock<std::shared_mutex> sessionStatusWriteLock(sessionMutex_);
    sessionStatus_ = SessionStatus::CONNECTED;
    ConnectResult connectResult;
    connectResult.isConnected = true;
    ExeuteConnectCallback(connectResult);
    return ERR_OK;
}

int32_t AbilityConnectionSession::HandleDisconnect()
{
    HILOGD("called.");
    {
        std::shared_lock<std::shared_mutex> sessionStatusReadLock(sessionMutex_);
        if (sessionStatus_ == SessionStatus::UNCONNECTED) {
            HILOGI("The session resource has been released.");
            return ERR_OK;
        }
    }

    EventCallbackInfo callbackInfo;
    callbackInfo.sessionId = sessionId_;
    callbackInfo.reason = DisconnectReason::PEER_APP_EXIT;

    ExeuteEventCallback(EVENT_DISCONNECT, callbackInfo);
    Release();
    return ERR_OK;
}

int32_t AbilityConnectionSession::SendMessage(const std::string& msg, const MessageType& messageType)
{
    HILOGD("called.");
    auto sendData = std::make_shared<AVTransDataBuffer>(msg.length() + 1);
    int32_t ret = memcpy_s(sendData->Data(), sendData->Capacity(), msg.c_str(), msg.length());
    if (ret != ERR_OK) {
        HILOGE("memory copy failed, ret %{public}d", ret);
        return ret;
    }

    uint32_t totalLen = sendData->Size() + MessageDataHeader::HEADER_LEN;

    MessageDataHeader headerPara(PROTOCOL_VERSION, static_cast<uint32_t>(messageType), totalLen);
    auto headerBuffer = headerPara.Serialize();
    auto sendBuffer = std::make_shared<AVTransDataBuffer>(totalLen);
    uint8_t* header = sendBuffer->Data();

    if (memcpy_s(header, sendBuffer->Size(), headerBuffer->Data(), MessageDataHeader::HEADER_LEN) != ERR_OK) {
        HILOGE("Write header failed");
        return WRITE_SESSION_HEADER_FAILED;
    }

    ret = memcpy_s(header + MessageDataHeader::HEADER_LEN, sendBuffer->Size() - MessageDataHeader::HEADER_LEN,
        sendData->Data(), sendData->Size());
    if (ret != ERR_OK) {
        HILOGE("Write data failed");
        return WRITE_SEND_DATA_BUFFER_FAILED;
    }

    TransChannelInfo transChannelInfo;
    ret = GetTransChannelInfo(TransChannelType::MESSAGE_CHANNEL, transChannelInfo);
    if (ret != ERR_OK) {
        HILOGE("message channel not exit");
        return ret;
    }

    int32_t channelId = transChannelInfo.channelId;
    ret = ChannelManager::GetInstance().SendMessage(channelId, sendBuffer);
    if (ret != ERR_OK) {
        HILOGE("send message failed, channelId is %{public}d", channelId);
        return ret;
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::SendData(const std::shared_ptr<AVTransDataBuffer>& buffer)
{
    HILOGD("called.");
    TransChannelInfo transChannelInfo;
    int32_t ret = GetTransChannelInfo(TransChannelType::DATA_CHANNEL, transChannelInfo);
    if (ret != ERR_OK) {
        HILOGE("data channel not exit");
        return ret;
    }
    
    int32_t channelId = transChannelInfo.channelId;
    ret = ChannelManager::GetInstance().SendBytes(channelId, buffer);
    if (ret != ERR_OK) {
        HILOGE("send bytes failed, channelId is %{public}d", channelId);
        return ret;
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::SendImage(const std::shared_ptr<Media::PixelMap>& image)
{
    HILOGD("called.");
    if (senderEngine_ == nullptr) {
        HILOGE("senderEngine_ is nullptr.");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t ret = senderEngine_->SendPixelMap(image);
    if (ret != ERR_OK) {
        HILOGE("Send image failed, ret is %{public}d.", ret);
        return ret;
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::CreateStream(int32_t streamId, const StreamParams& param)
{
    HILOGI("called. StreamParams role is %{public}d", static_cast<int32_t>(param.role));
    switch (param.role) {
        case StreamRole::SOURCE:
            streamId_ = streamId;
            return InitSenderEngine();
        case StreamRole::SINK:
            streamId_ = streamId;
            return InitRecvEngine();
        default:
            HILOGE("Unrecognized streamRole.");
            return INVALID_PARAMETERS_ERR;
        }
}

int32_t AbilityConnectionSession::InitSenderEngine()
{
    if (!connectOption_.needSendStream) {
        HILOGE("The stream sending option is not configured.");
        return INVALID_PARAMETERS_ERR;
    }
    std::unique_lock<std::shared_mutex> listenerWriteLock(engineMutex_);
    if (senderEngine_ != nullptr) {
        HILOGE("The stream sender engine has init.");
        return INVALID_PARAMETERS_ERR;
    }
    senderEngine_ = std::make_shared<AVSenderEngine>(DEFAULT_APP_UID, DEFAULT_APP_PID,
        localInfo_.bundleName, DEFAULT_INSTANCE_ID);
    senderEngine_->Init();
    return ERR_OK;
}

int32_t AbilityConnectionSession::InitRecvEngine()
{
    if (!connectOption_.needReceiveStream) {
        HILOGE("The stream receive option is not configured.");
        return INVALID_PARAMETERS_ERR;
    }
    std::unique_lock<std::shared_mutex> listenerWriteLock(engineMutex_);
    if (recvEngine_ != nullptr) {
        HILOGE("The stream receive has init.");
        return INVALID_PARAMETERS_ERR;
    }

    recvEngine_ = std::make_shared<AVReceiverEngine>();
    recvEngine_->Init();
    return ERR_OK;
}

int32_t AbilityConnectionSession::DestroyStream(int32_t streamId)
{
    HILOGD("called.");
    return ERR_OK;
}

template <typename T>
int32_t AbilityConnectionSession::ConfigEngineParam(std::shared_ptr<T> &engine, const SurfaceParams& param)
{
    engine->SetVideoSource(static_cast<VideoSourceType>(param.format));

    int32_t ret = ERR_OK;
    ret = engine->Configure(VidEnc(VideoCodecFormat::H264));
    if (ret != ERR_OK) {
        HILOGE("configure videnc failed");
        return ret;
    }
    ret = engine->Configure(VidRectangle(param.width, param.height));
    if (ret != ERR_OK) {
        HILOGE("configure VidRectangle failed");
        return ret;
    }
    ret = engine->Configure(VidBitRate(VIDEO_BIT_RATE));
    if (ret != ERR_OK) {
        HILOGE("configure VidBitRate failed");
        return ret;
    }
    ret = engine->Configure(VidFrameRate(VIDEO_FRAME_RATE));
    if (ret != ERR_OK) {
        HILOGE("configure VidFrameRate failed");
        return ret;
    }
    ret = engine->Configure(VidIsHdr(false));
    if (ret != ERR_OK) {
        HILOGE("configure VidIsHdr failed");
        return ret;
    }
    ret = engine->Configure(VidEnableTemporalScale(false));
    if (ret != ERR_OK) {
        HILOGE("configure VidEnableTemporalScale failed");
        return ret;
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::GetSurfaceId(const SurfaceParams& param, std::string& surfaceId)
{
    HILOGD("called.");
    if (senderEngine_ == nullptr) {
        HILOGE("senderEngine_ Uninitialized.");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t ret = ConfigEngineParam(senderEngine_, param);
    if (ret != ERR_OK) {
        HILOGE("config senderEngine param failed.");
        return ret;
    }

    ret = senderEngine_->Prepare();
    if (ret != ERR_OK) {
        HILOGE("error prepare senderEngine_");
        return ret;
    }

    TransChannelInfo info;
    if (GetStreamTransChannel(info) != ERR_OK) {
        HILOGE("senderEngine_ SetChannelListener failed");
        return INVALID_PARAMETERS_ERR;
    }

    HILOGI("SetChannelListener channelId is %{public}d, channelType is %{public}d",
        info.channelId, static_cast<int32_t>(info.channelType));
    senderEngine_->SetTransChannel(info.channelId, info.channelType);
    surfaceId = std::to_string(senderEngine_->GetSurface());
    return ERR_OK;
}

int32_t AbilityConnectionSession::SetSurfaceId(const std::string& surfaceId,
    const SurfaceParams& param)
{
    HILOGD("called.");
    if (recvEngine_ == nullptr) {
        HILOGE("recvEngine_ Uninitialized.");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t ret = ConfigEngineParam(recvEngine_, param);
    if (ret != ERR_OK) {
        HILOGE("recvEngine_ ConfigEngineParam failed.");
        return ret;
    }

    recvEngine_->SetVideoSurface(std::stoull(surfaceId));
    ret = recvEngine_->Prepare();
    if (ret != ERR_OK) {
        HILOGE("error prepare recvEngine_");
        return ret;
    }

    TransChannelInfo info;
    if (GetStreamTransChannel(info) != ERR_OK) {
        HILOGE("recvEngine_ SetChannelListener failed");
        return INVALID_PARAMETERS_ERR;
    }
    HILOGE("SetChannelListener channelId is %{public}d, channelType is %{public}d",
        info.channelId, static_cast<int32_t>(info.channelType));
    recvEngine_->SetChannelListener(info.channelId);
    pixelMapListener = std::make_shared<PixelMapListener>(shared_from_this());
    recvEngine_->SetEngineListener(pixelMapListener);
    return ERR_OK;
}

int32_t AbilityConnectionSession::UpdateSurfaceParam(const SurfaceParams& surfaceParam)
{
    HILOGD("called.");
    if (senderEngine_ == nullptr) {
        HILOGE("recvEngine_ Uninitialized.");
        return INVALID_PARAMETERS_ERR;
    }

    SurfaceParam param;
    param.rotate = static_cast<SurfaceRotate>(surfaceParam.rotation);
    param.filp = static_cast<SurfaceFilp>(surfaceParam.flip);

    senderEngine_->SetSurfaceParam(param);
    return ERR_OK;
}

int32_t AbilityConnectionSession::GetStreamTransChannel(TransChannelInfo& info)
{
    std::shared_lock<std::shared_mutex> channelReadLock(transChannelMutex_);
    auto item = transChannels_.find(TransChannelType::STREAM_CHANNEL);
    if (item != transChannels_.end() && item->second.isConnected) {
        info = item->second;
        return ERR_OK;
    }
    HILOGW("stream channel unconnected");
    item = transChannels_.find(TransChannelType::STREAM_CHANNEL_BYTES);
    if (item != transChannels_.end() && item->second.isConnected) {
        info = item->second;
        return ERR_OK;
    }
    HILOGE("bytes stream channel unconnected");
    return INVALID_PARAMETERS_ERR;
}

int32_t AbilityConnectionSession::StartStream(int32_t streamId)
{
    HILOGD("called.");
    if (connectOption_.needSendStream && senderEngine_ != nullptr) {
        HILOGI("senderEngine_ Start.");
        return senderEngine_->Start();
    }

    if (connectOption_.needReceiveStream && recvEngine_ != nullptr) {
        HILOGI("recvEngine_ Start.");
        return recvEngine_->Start();
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::StopStream(int32_t streamId)
{
    HILOGD("called.");
    if (connectOption_.needSendStream && senderEngine_ != nullptr) {
        HILOGI("senderEngine_ Stop.");
        return senderEngine_->Stop(false);
    }

    if (connectOption_.needReceiveStream && recvEngine_ != nullptr) {
        HILOGI("recvEngine_ Stop.");
        return recvEngine_->Stop(false);
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::RegisterEventCallback(const std::string& eventType,
    const std::shared_ptr<JsAbilityConnectionSessionListener>& listener)
{
    HILOGD("called.");
    std::unique_lock<std::shared_mutex> listenerWriteLock(listenerMutex_);
    listeners_[eventType] = listener;
    return ERR_OK;
}

int32_t AbilityConnectionSession::UnregisterEventCallback(const std::string& eventType)
{
    HILOGD("called.");
    std::unique_lock<std::shared_mutex> listenerWriteLock(listenerMutex_);
    listeners_.erase(eventType);
    return ERR_OK;
}

int32_t AbilityConnectionSession::ExeuteEventCallback(const std::string& eventType, const EventCallbackInfo& info)
{
    HILOGD("called.");
    std::shared_lock<std::shared_mutex> listenerReadLock(listenerMutex_);
    if (listeners_.empty()) {
        HILOGE("listeners_ is empty");
        return INVALID_PARAMETERS_ERR;
    }

    auto item = listeners_.find(eventType);
    if (item == listeners_.end()) {
        HILOGE("The event callback is not registered. event is %{public}s", eventType.c_str());
        return INVALID_PARAMETERS_ERR;
    }

    auto eventCallback = item->second;
    if (eventCallback == nullptr) {
        HILOGE("eventCallback is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    eventCallback->CallJsMethod(info);
    return ERR_OK;
}

int32_t AbilityConnectionSession::InitChannels()
{
    HILOGD("called.");
    std::string channelName = (direction_ == CollabrateDirection::COLLABRATE_SOURCE) ?
        GetChannelName(localInfo_.moduleName, localInfo_.abilityName, peerInfo_.moduleName, peerInfo_.abilityName) :
        GetChannelName(peerInfo_.moduleName, peerInfo_.abilityName, localInfo_.moduleName, localInfo_.abilityName);

    channelListener_ = std::make_shared<CollabChannelListener>(shared_from_this());
    int32_t ret = CreateChannel(channelName, ChannelDataType::MESSAGE, TransChannelType::MESSAGE_CHANNEL);
    if (ret != ERR_OK) {
        HILOGE("init message channel failed!");
        return INVALID_PARAMETERS_ERR;
    }

    if (connectOption_.needSendBigData) {
        ret = CreateChannel(channelName, ChannelDataType::BYTES, TransChannelType::DATA_CHANNEL);
        if (ret != ERR_OK) {
            HILOGE("init bytes channel failed!");
            return INVALID_PARAMETERS_ERR;
        }
    }

    if (!connectOption_.needSendStream && !connectOption_.needReceiveStream) {
        HILOGI("Streaming is not required.");
        return ret;
    }

    std::string streamChannelName = channelName + "stream";
    ret = CreateChannel(streamChannelName, ChannelDataType::BYTES, TransChannelType::STREAM_CHANNEL_BYTES);
    if (ret != ERR_OK) {
        HILOGE("init bytes channel failed!");
        return INVALID_PARAMETERS_ERR;
    }

    ret = CreateChannel(streamChannelName, ChannelDataType::VIDEO_STREAM, TransChannelType::STREAM_CHANNEL);
    if (ret != ERR_OK) {
        HILOGE("init bytes channel failed!");
        return INVALID_PARAMETERS_ERR;
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::CreateChannel(const std::string& channelName, const ChannelDataType& dataType,
    const TransChannelType& channelType)
{
    HILOGD("called.");
    ChannelPeerInfo channelPeerInfo = { peerSocketName_, peerInfo_.deviceId };
    ChannelManager &channelManager = ChannelManager::GetInstance();
    int32_t channelId = (direction_ == CollabrateDirection::COLLABRATE_SOURCE) ?
        channelManager.CreateClientChannel(channelName, dataType, channelPeerInfo) :
        channelManager.CreateServerChannel(channelName, dataType, channelPeerInfo);
    if (channelId < MIN_CHANNEL_ID || channelId > MAX_CHANNEL_ID) {
        HILOGE("CreateChannel failed, channelId is %{public}d", channelId);
        return INVALID_PARAMETERS_ERR;
    }

    if (channelType != TransChannelType::STREAM_CHANNEL_BYTES) {
        if (channelManager.RegisterChannelListener(channelId, channelListener_) != ERR_OK) {
            HILOGE("register channel listener failed, channelId is %{public}d", channelId);
            return INVALID_PARAMETERS_ERR;
        }
    }
    
    std::unique_lock<std::shared_mutex> channelWriteLock(transChannelMutex_);
    TransChannelInfo channelInfo = {channelId, dataType, channelType, false};
    transChannels_.emplace(channelType, channelInfo);
    return ERR_OK;
}

std::string AbilityConnectionSession::GetChannelName(const std::string& sourceModule, const std::string& sourceAbility,
    const std::string& sinkModule, const std::string& sinkAbility)
{
    std::string input = sourceModule + sourceAbility + sinkModule + sinkAbility;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input.c_str(), input.length(), hash);

    std::stringstream hashStr;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashStr << std::hex << std::setw(HEX_WIDTH) << std::setfill(FILL_CHAR) << (int)hash[i];
    }

    std::string channelName = hashStr.str().substr(0, CHANNEL_NAME_LENGTH);
    return channelName;
}

int32_t AbilityConnectionSession::ConnectChannels()
{
    std::unique_lock<std::shared_mutex> channelWriteLock(transChannelMutex_);
    int32_t ret;
    auto item = transChannels_.find(TransChannelType::MESSAGE_CHANNEL);
    if (item != transChannels_.end()) {
        ret = ChannelManager::GetInstance().ConnectChannel(item->second.channelId);
        if (ret != ERR_OK) {
            HILOGE("message channel bind failed, ret is %{public}d", ret);
            return ret;
        } else {
            item->second.isConnected = true;
            HILOGI("message channel bind success");
        }
    }
    
    item = transChannels_.find(TransChannelType::DATA_CHANNEL);
    if (item != transChannels_.end()) {
        ret = ChannelManager::GetInstance().ConnectChannel(item->second.channelId);
        if (ret != ERR_OK) {
            HILOGE("data channel bind failed, ret is %{public}d", ret);
            return ret;
        } else {
            item->second.isConnected = true;
            HILOGI("data channel bind success");
        }
    }

    item = transChannels_.find(TransChannelType::STREAM_CHANNEL);
    if (item != transChannels_.end()) {
        ret = ChannelManager::GetInstance().ConnectChannel(item->second.channelId);
        if (ret != ERR_OK) {
            HILOGE("stream channel bind failed, ret is %{public}d", ret);
        } else {
            item->second.isConnected = true;
            HILOGI("stream channel bind success");
        }
    }

    item = transChannels_.find(TransChannelType::STREAM_CHANNEL_BYTES);
    if (item != transChannels_.end()) {
        ret = ChannelManager::GetInstance().ConnectChannel(item->second.channelId);
        if (ret != ERR_OK) {
            HILOGE("bytes channel bind failed, ret is %{public}d", ret);
            return ret;
        } else {
            item->second.isConnected = true;
            HILOGI("bytes channel bind success");
        }
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::GetTransChannelInfo(const TransChannelType& type, TransChannelInfo& info)
{
    HILOGD("called.");
    std::shared_lock<std::shared_mutex> channelReadLock(transChannelMutex_);
    auto item = transChannels_.find(type);
    if (item == transChannels_.end()) {
        return INVALID_PARAMETERS_ERR;
    }
    info = item->second;
    return ERR_OK;
}

void AbilityConnectionSession::OnChannelConnect(int32_t channelId)
{
    HILOGD("called.");
    UpdateTransChannelStatus(channelId, true);
    if (IsAllChannelConnected()) {
        std::unique_lock<std::shared_mutex> sessionStatusWriteLock(sessionMutex_);
        if (sessionStatus_ == SessionStatus::CONNECTED) {
            HILOGI("session has connected.");
            return;
        }
        sessionStatus_ = SessionStatus::CONNECTED;
        
        EventCallbackInfo callbackInfo;
        callbackInfo.sessionId = sessionId_;
        ExeuteEventCallback(EVENT_CONNECT, callbackInfo);
    }
}

void AbilityConnectionSession::UpdateTransChannelStatus(int32_t channelId, bool isConnected)
{
    std::unique_lock<std::shared_mutex> channelWriteLock(transChannelMutex_);
    for (auto& iter : transChannels_) {
        if (iter.second.channelId == channelId) {
            HILOGI("transType is %{public}d.", static_cast<int32_t>(iter.second.transType));
            iter.second.isConnected = isConnected;
        }
    }
}

bool AbilityConnectionSession::IsAllChannelConnected()
{
    HILOGD("called.");
    std::shared_lock<std::shared_mutex> channelReadLock(transChannelMutex_);
    for (auto& iter : transChannels_) {
        TransChannelInfo info = iter.second;
        if (!info.isConnected && info.transType != TransChannelType::STREAM_CHANNEL) {
            HILOGI("transType is %{public}d.", static_cast<int32_t>(info.transType));
            return false;
        }
    }
    HILOGI("AllChannelConnected.");
    return true;
}

void AbilityConnectionSession::OnChannelClosed(int32_t channelId)
{
    HILOGI("called. channelId is %{public}d", channelId);
    if (!IsVaildChannel(channelId)) {
        HILOGE("is vaild channelId");
        return;
    }

    if (IsConnected()) {
        HILOGI("notidy app disconnect");
        EventCallbackInfo callbackInfo;
        callbackInfo.sessionId = sessionId_;
        callbackInfo.reason = DisconnectReason::PEER_APP_EXIT;
        ExeuteEventCallback(EVENT_DISCONNECT, callbackInfo);

        Release();
    }
}

void AbilityConnectionSession::OnMessageReceived(int32_t channelId, const std::shared_ptr<AVTransDataBuffer> dataBuffer)
{
    HILOGD("called.");
    if (!IsVaildChannel(channelId)) {
        return;
    }
    uint8_t *data = dataBuffer->Data();
    auto headerPara = MessageDataHeader::Deserialize(data, dataBuffer->Size());
    if (!headerPara) {
        HILOGE("read session header from buffer failed");
        return;
    }
    HILOGI("headerPara type is %{public}d", headerPara->dataType_);
    switch (headerPara->dataType_) {
        case uint32_t(MessageType::MESSAGE_NORMAL): {
            HILOGI("on wifi SEMI_ACTIVE");
            std::string msg(reinterpret_cast<const char *>(data + MessageDataHeader::HEADER_LEN),
                dataBuffer->Size() - MessageDataHeader::HEADER_LEN);
            EventCallbackInfo callbackInfo;
            callbackInfo.sessionId = sessionId_;
            callbackInfo.msg = msg;
            ExeuteEventCallback(EVENT_RECEIVE_MESSAGE, callbackInfo);
            break;
        }

        case uint32_t(MessageType::MESSAGE_WIFI_STATUS): {
            CheckWifiState();
            break;
        }

        case uint32_t(MessageType::MESSAGE_UPDATE_STREAM_CHANNEL): {
            UpdateEngineTransChannel();
            break;
        }

        default: {
            HILOGI("unhandled code");
            break;
        }
    }
}

int32_t AbilityConnectionSession::NotifyRemoteWifiOpen()
{
    HILOGD("called.");
    if (!(connectOption_.needSendStream || connectOption_.needReceiveStream)) {
        HILOGE("no stream option.");
        return INVALID_PARAMETERS_ERR;
    }

    return SendMessage("WifiOpen", MessageType::MESSAGE_WIFI_STATUS);
}

int32_t AbilityConnectionSession::CheckWifiState()
{
    HILOGD("called.");
    if (!(connectOption_.needSendStream || connectOption_.needReceiveStream)) {
        HILOGE("no stream option.");
        return INVALID_PARAMETERS_ERR;
    }

    WifiStateListener listener;
    if (!listener.CheckWifiStateIsActived()) {
        HILOGE("wifi close.");
        return INVALID_PARAMETERS_ERR;
    }

    TransChannelInfo info;
    int32_t ret = GetTransChannelInfo(TransChannelType::STREAM_CHANNEL, info);
    if (ret != ERR_OK || info.isConnected) {
        HILOGE("stream chennel has connected.");
        return INVALID_PARAMETERS_ERR;
    }

    if (direction_ == CollabrateDirection::COLLABRATE_SINK) {
        SendMessage("WifiOpen", MessageType::MESSAGE_WIFI_STATUS);
        return ERR_OK;
    }

    ret = ChannelManager::GetInstance().ConnectChannel(info.channelId);
    if (ret != ERR_OK) {
        HILOGE("stream channel bind failed, ret is %{public}d", ret);
        return ret;
    } else {
        UpdateTransChannelStatus(info.channelId, true);
        HILOGI("message channel bind success");
    }

    if (recvEngine_) {
        HILOGI("recvEngine update channel listener");
        recvEngine_->SetChannelListener(info.channelId);
    }

    SendMessage("updateTransChannel", MessageType::MESSAGE_UPDATE_STREAM_CHANNEL);
    return ERR_OK;
}

void AbilityConnectionSession::UpdateEngineTransChannel()
{
    HILOGD("called.");
    if (senderEngine_ == nullptr || recvEngine_ == nullptr) {
        HILOGE("engine_ is nullptr.");
        return;
    }

    TransChannelInfo info;
    int32_t ret = GetTransChannelInfo(TransChannelType::STREAM_CHANNEL, info);
    if (ret != ERR_OK) {
        HILOGI("not find stream chennel.");
        return;
    }

    if (senderEngine_) {
        senderEngine_->SetTransChannel(info.channelId, info.channelType);
    }

    if (recvEngine_) {
        recvEngine_->SetChannelListener(info.channelId);
        SendMessage("updateTransChannel", MessageType::MESSAGE_UPDATE_STREAM_CHANNEL);
    }
}

void AbilityConnectionSession::OnRecvPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap)
{
    HILOGD("called.");
    if (pixelMap == nullptr) {
        HILOGE("pixelMap is nullptr.");
    }

    EventCallbackInfo callbackInfo;
    callbackInfo.sessionId = sessionId_;
    callbackInfo.image = pixelMap;
    ExeuteEventCallback(EVENT_RECEIVE_IMAGE, callbackInfo);
}

void AbilityConnectionSession::OnBytesReceived(int32_t channelId, const std::shared_ptr<AVTransDataBuffer> dataBuffer)
{
    HILOGD("called.");
    if (!IsVaildChannel(channelId)) {
        return;
    }

    EventCallbackInfo callbackInfo;
    callbackInfo.sessionId = sessionId_;
    callbackInfo.data = dataBuffer;

    ExeuteEventCallback(EVENT_RECEIVE_DATA, callbackInfo);
}

bool AbilityConnectionSession::IsVaildChannel(const int32_t channelId)
{
    HILOGD("called");
    std::shared_lock<std::shared_mutex> channelReadLock(transChannelMutex_);
    if (transChannels_.empty()) {
        HILOGE("transChannels_ is empty");
        return false;
    }
    
    for (auto& iter : transChannels_) {
        if (iter.second.channelId == channelId) {
            return true;
        }
    }

    return false;
}

void AbilityConnectionSession::SetTimeOut(int32_t time)
{
    HILOGD("called.");
    auto func = [this]() {
        Release();
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->PostTask(func, CONNECT_SESSION_TIMEOUT_END_TASK, time);
}

void AbilityConnectionSession::RemoveTimeout()
{
    HILOGD("called.");
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->RemoveTask(CONNECT_SESSION_TIMEOUT_END_TASK);
}

bool AbilityConnectionSession::IsConnecting()
{
    std::shared_lock<std::shared_mutex> sessionStatusReadLock(sessionMutex_);
    return sessionStatus_ == SessionStatus::CONNECTING;
}

bool AbilityConnectionSession::IsConnected()
{
    std::shared_lock<std::shared_mutex> sessionStatusReadLock(sessionMutex_);
    return sessionStatus_ == SessionStatus::CONNECTED;
}

void AbilityConnectionSession::ExeuteConnectCallback(const ConnectResult& result)
{
    HILOGD("called.");
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }

    auto task = [this, result, connectCallback = connectCallback_]() {
        if (connectCallback) {
            connectCallback(result);
        }
        if (!result.isConnected) {
            Release();
        }
    };
    eventHandler_->PostTask(task, "ExeuteConnectCallback");
}

AbilityConnectionSession::CollabChannelListener::CollabChannelListener(
    const std::shared_ptr<AbilityConnectionSession>& abilityConnectionSession)
    : abilityConnectionSession_(abilityConnectionSession)
{
}

void AbilityConnectionSession::CollabChannelListener::OnConnect(const int32_t channelId) const
{
    HILOGD("called.");
    std::shared_ptr<AbilityConnectionSession> abilityConnectionSession = abilityConnectionSession_.lock();
    if (abilityConnectionSession == nullptr) {
        HILOGE("abilityConnectionSession is null");
        return;
    }

    abilityConnectionSession->OnChannelConnect(channelId);
}

void AbilityConnectionSession::CollabChannelListener::OnDisConnect(const int32_t channelId) const
{
    HILOGD("called.");
    std::shared_ptr<AbilityConnectionSession> abilityConnectionSession = abilityConnectionSession_.lock();
    if (abilityConnectionSession == nullptr) {
        HILOGE("abilityConnectionSession is null");
        return;
    }

    abilityConnectionSession->OnChannelClosed(channelId);
}

void AbilityConnectionSession::CollabChannelListener::OnMessage(const int32_t channelId,
    const std::shared_ptr<AVTransDataBuffer>& buffer) const
{
    HILOGD("called.");
    std::shared_ptr<AbilityConnectionSession> abilityConnectionSession = abilityConnectionSession_.lock();
    if (abilityConnectionSession == nullptr) {
        HILOGE("abilityConnectionSession is null");
        return;
    }

    abilityConnectionSession->OnMessageReceived(channelId, buffer);
}

void AbilityConnectionSession::CollabChannelListener::OnBytes(const int32_t channelId,
    const std::shared_ptr<AVTransDataBuffer>& buffer) const
{
    HILOGD("called.");
    std::shared_ptr<AbilityConnectionSession> abilityConnectionSession = abilityConnectionSession_.lock();
    if (abilityConnectionSession == nullptr) {
        HILOGE("abilityConnectionSession is null");
        return;
    }

    abilityConnectionSession->OnBytesReceived(channelId, buffer);
}

void AbilityConnectionSession::CollabChannelListener::OnStream(const int32_t channelId,
    const std::shared_ptr<AVTransStreamData>& sendData) const
{
}

void AbilityConnectionSession::CollabChannelListener::OnError(const int32_t channelId, const int32_t errorCode) const
{
}

AbilityConnectionSession::PixelMapListener::PixelMapListener(
    const std::shared_ptr<AbilityConnectionSession>& session) : abilityConnectionSession_(session)
{
}

void AbilityConnectionSession::PixelMapListener::OnRecvPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap)
{
    HILOGD("called.");
    std::shared_ptr<AbilityConnectionSession> abilityConnectionSession = abilityConnectionSession_.lock();
    if (abilityConnectionSession == nullptr) {
        HILOGE("abilityConnectionSession is null");
        return;
    }

    abilityConnectionSession->OnRecvPixelMap(pixelMap);
}

void AbilityConnectionSession::PixelMapListener::OnRecvSurfaceParam(const SurfaceParam& param)
{
    HILOGD("called.");
}
}  // namespace DistributedCollab
}  // namespace OHOS