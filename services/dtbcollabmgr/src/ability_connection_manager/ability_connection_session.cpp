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

namespace OHOS {
namespace DistributedCollab {
namespace {
const std::string TAG = "AbilityConnectionSession";
const std::string CONNECT_SESSION_TIMEOUT_END_TASK = "connect_session_timeout_end_task";
const std::u16string DMS_PROXY_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
const std::string EVENT_CONNECT = "connect";
const std::string EVENT_DISCONNECT = "disconnect";
const std::string EVENT_RECEIVE_MESSAGE = "receiveMessage";
const std::string EVENT_RECEIVE_DATA = "receiveData";
const std::string EVENT_RECEIVE_IMAGE = "receiveImage";
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
    HILOGI("called.");
    {
        std::unique_lock<std::shared_mutex> sessionStatusWriteLock(sessionMutex_);
        if (sessionStatus_ == SessionStatus::UNCONNECTED) {
            HILOGI("The session resource has been released.");
            return;
        }
        sessionStatus_ = SessionStatus::UNCONNECTED;
    }
    DestroyStream();
    
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
    HILOGI("called.");
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
        Release();
        return ret;
    }
    ret = dmsClient.NotifyPrepareResult(token, ERR_OK, sessionId_, localSocketName_);
    if (ret != ERR_OK) {
        HILOGE("notify prepare result failed!");
        Release();
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::HandleCollabResult(int32_t result, const std::string& peerSocketName,
    const std::string& dmsServerToken, const std::string& reason)
{
    HILOGI("called.");
    dmsServerToken_ = dmsServerToken;
    peerSocketName_ = peerSocketName;
    if (result != ERR_OK) {
        HILOGE("collab result is failed, ret = %{public}d, reason = %{public}s", result, reason.c_str());
        NotifyAppConnectResult(false, reason);
        return INVALID_PARAMETERS_ERR;
    }
    
    if (InitChannels() != ERR_OK || ConnectChannels() != ERR_OK) {
        NotifyAppConnectResult(false);
        return INVALID_PARAMETERS_ERR;
    }

    if (!connectOption_.needReceiveFile) {
        NotifyAppConnectResult(true);
        return ERR_OK;
    }

    HILOGI("notify the peer end bind file.");
    if (SendMessage(localSocketName_, MessageType::CONNECT_FILE_CHANNEL) != ERR_OK) {
        NotifyAppConnectResult(false);
        return INVALID_PARAMETERS_ERR;
    }
    return ERR_OK;
}

void AbilityConnectionSession::NotifyAppConnectResult(bool isConnected, const std::string& reason)
{
    if (isConnected) {
        std::unique_lock<std::shared_mutex> sessionStatusWriteLock(sessionMutex_);
        sessionStatus_ = SessionStatus::CONNECTED;
    } else {
        Release();
        DistributedClient dmsClient;
        dmsClient.NotifyCloseCollabSession(dmsServerToken_);
    }
    ConnectResult connectResult;
    connectResult.isConnected = isConnected;
    connectResult.reason = reason;
    ExeuteConnectCallback(connectResult);
}

int32_t AbilityConnectionSession::HandleDisconnect()
{
    HILOGI("called.");
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
    ret = GetTransChannelInfo(TransChannelType::MESSAGE, transChannelInfo);
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
    int32_t ret = GetTransChannelInfo(TransChannelType::DATA, transChannelInfo);
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
    HILOGI("called.");
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

int32_t AbilityConnectionSession::SendFile(const std::vector<std::string>& sFiles,
    const std::vector<std::string>& dFiles)
{
    HILOGI("called.");
    TransChannelInfo transChannelInfo;
    int32_t ret = GetTransChannelInfo(TransChannelType::SEND_FILE, transChannelInfo);
    if (ret != ERR_OK) {
        HILOGE("data channel not exit");
        return ret;
    }
    
    int32_t channelId = transChannelInfo.channelId;
    ret = ChannelManager::GetInstance().SendFile(channelId, sFiles, dFiles);
    if (ret != ERR_OK) {
        HILOGE("send bytes failed, channelId is %{public}d", channelId);
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
        return ONLY_SUPPORT_ONE_STREAM;
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
        return ONLY_SUPPORT_ONE_STREAM;
    }

    recvEngine_ = std::make_shared<AVReceiverEngine>();
    recvEngine_->Init();
    return ERR_OK;
}

int32_t AbilityConnectionSession::DestroyStream()
{
    HILOGD("called.");
    senderEngine_ = nullptr;
    recvEngine_ = nullptr;
    recvEngineState_ = EngineState::EMPTY;
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
    ret = engine->Configure(VidSurfaceParam(ConvertToSurfaceParam(param)));
    if (ret != ERR_OK) {
        HILOGE("configure VidSurfaceParam failed");
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

    ret = recvEngine_->SetVideoSurface(std::stoull(surfaceId));
    if (ret != ERR_OK) {
        HILOGE("error set video surface!");
        return ret;
    }

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
    SurfaceParam param = ConvertToSurfaceParam(surfaceParam);
    HILOGI("SurfaceParam rotate is %{public}d, filp is %{public}d.",
        static_cast<int32_t>(param.rotate), static_cast<int32_t>(param.filp));
    if (senderEngine_ != nullptr) {
        HILOGI("Update senderEngine_ SurfaceParam.");
        senderEngine_->SetSurfaceParam(param);
        return ERR_OK;
    }

    if (recvEngine_ != nullptr) {
        HILOGI("Update recvEngine_ SurfaceParam.");
        recvEngine_ -> OnRecvSurfaceParam(param);
        return ERR_OK;
    }

    HILOGE("senderEngine_ and recvEngine_ is nullptr!");
    return INVALID_PARAMETERS_ERR;
}

SurfaceParam AbilityConnectionSession::ConvertToSurfaceParam(const SurfaceParams& param)
{
    SurfaceParam surfaveParam;
    switch (param.rotation) {
        case SURFACE_ROTATE_NONE:
            surfaveParam.rotate = SurfaceRotate::ROTATE_NONE;
            break;
        case SURFACE_ROTATE_90:
            surfaveParam.rotate = SurfaceRotate::ROTATE_90;
            break;
        case SURFACE_ROTATE_180:
            surfaveParam.rotate = SurfaceRotate::ROTATE_180;
            break;
        case SURFACE_ROTATE_270:
            surfaveParam.rotate = SurfaceRotate::ROTATE_270;
            break;
        default:
            surfaveParam.rotate = SurfaceRotate::ROTATE_NONE;
            break;
    }

    switch (param.flip) {
        case FlipOption::HORIZONTAL:
            surfaveParam.filp = SurfaceFilp::FLIP_H;
            break;
        case FlipOption::VERTICAL:
            surfaveParam.filp = SurfaceFilp::FLIP_V;
            break;
        default:
            surfaveParam.filp = SurfaceFilp::FLIP_NONE;
            break;
    }

    return surfaveParam;
}

int32_t AbilityConnectionSession::GetStreamTransChannel(TransChannelInfo& info)
{
    std::shared_lock<std::shared_mutex> channelReadLock(transChannelMutex_);
    auto item = transChannels_.find(TransChannelType::STREAM);
    if (item != transChannels_.end() && item->second.isConnected) {
        info = item->second;
        return ERR_OK;
    }
    HILOGW("stream channel unconnected");
    item = transChannels_.find(TransChannelType::STREAM_BYTES);
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
        return StartSenderEngine();
    }

    if (connectOption_.needReceiveStream && recvEngine_ != nullptr) {
        return StartRecvEngine();
    }
    HILOGE("not config stream option or engine is null.");
    return INVALID_PARAMETERS_ERR;
}

int32_t AbilityConnectionSession::StartRecvEngine()
{
    HILOGI("recvEngine_ Start.");
    int32_t ret = recvEngine_->Start();
    if (ret != ERR_OK) {
        HILOGE("recvEngine_ start failed.");
        return ret;
    }
    return SendMessage("recvEngineStart", MessageType::RECEIVE_STREAM_START);
}

int32_t AbilityConnectionSession::StartSenderEngine()
{
    HILOGI("senderEngine_ Start.");
    return senderEngine_->Start();
}

int32_t AbilityConnectionSession::StopStream(int32_t streamId)
{
    HILOGD("called.");
    if (connectOption_.needSendStream && senderEngine_ != nullptr) {
        HILOGI("senderEngine_ Stop.");
        return senderEngine_->Stop();
    }

    if (connectOption_.needReceiveStream && recvEngine_ != nullptr) {
        HILOGI("recvEngine_ Stop.");
        return recvEngine_->Stop();
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::RegisterEventCallback(const std::string& eventType,
    const std::shared_ptr<JsAbilityConnectionSessionListener>& listener)
{
    HILOGI("called.");
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

int32_t AbilityConnectionSession::RegisterEventCallback(
    const std::shared_ptr<IAbilityConnectionSessionListener>& listener)
{
    sessionListener_ = listener;
    return ERR_OK;
}

int32_t AbilityConnectionSession::ExeuteEventCallback(const std::string& eventType, const EventCallbackInfo& info)
{
    HILOGI("called, eventType is %{public}s", eventType.c_str());
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
    bool isClientChannel = direction_ == CollabrateDirection::COLLABRATE_SOURCE;
    channelName_ = isClientChannel ?
        GetChannelName(localInfo_.moduleName, localInfo_.abilityName, peerInfo_.moduleName, peerInfo_.abilityName) :
        GetChannelName(peerInfo_.moduleName, peerInfo_.abilityName, localInfo_.moduleName, localInfo_.abilityName);

    channelListener_ = std::make_shared<CollabChannelListener>(shared_from_this());
    int32_t ret = CreateChannel(channelName_, ChannelDataType::MESSAGE, TransChannelType::MESSAGE, isClientChannel);
    if (ret != ERR_OK) {
        HILOGE("create message channel failed!");
        return FAILED_TO_CREATE_MESSAGE_CHANNEL;
    }

    if (connectOption_.needSendData &&
        CreateChannel(channelName_, ChannelDataType::BYTES, TransChannelType::DATA, isClientChannel) != ERR_OK) {
        HILOGE("create data channel failed!");
        return FAILED_TO_CREATE_DATA_CHANNEL;
    }

    if ((connectOption_.needSendStream || connectOption_.needReceiveStream) &&
        CreateStreamChannel(channelName_, isClientChannel) != ERR_OK) {
        HILOGE("create stream channel failed!");
        return FAILED_TO_CREATE_STREAM_CHANNEL;
    }

    if (connectOption_.needSendFile && isClientChannel &&
        CreateChannel(channelName_, ChannelDataType::FILE, TransChannelType::SEND_FILE, true) != ERR_OK) {
        HILOGE("create send file channel failed!");
        return FAILED_TO_CREATE_SEND_FILE_CHANNEL;
    }

    if (connectOption_.needReceiveFile &&
        CreateChannel(channelName_, ChannelDataType::FILE, TransChannelType::RECEIVE_FILE, false) != ERR_OK) {
        HILOGE("create receive file channel failed!");
        return FAILED_TO_CREATE_RECEIVE_FILE_CHANNEL;
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::CreateStreamChannel(const std::string& channelName, bool isClientChannel)
{
    std::string streamChannelName = channelName + "stream";
    int32_t ret = CreateChannel(streamChannelName, ChannelDataType::BYTES, TransChannelType::STREAM_BYTES,
        isClientChannel);
    if (ret != ERR_OK) {
        HILOGE("init bytes channel failed!");
        return INVALID_PARAMETERS_ERR;
    }

    ret = CreateChannel(streamChannelName, ChannelDataType::VIDEO_STREAM, TransChannelType::STREAM, isClientChannel);
    if (ret != ERR_OK) {
        HILOGE("init bytes channel failed!");
        return INVALID_PARAMETERS_ERR;
    }
    return ERR_OK;
}

int32_t AbilityConnectionSession::CreateChannel(const std::string& channelName, const ChannelDataType& dataType,
    const TransChannelType& channelType, bool isClientChannel)
{
    HILOGD("called.");
    ChannelPeerInfo channelPeerInfo = { peerSocketName_, peerInfo_.deviceId };
    ChannelManager &channelManager = ChannelManager::GetInstance();
    int32_t channelId = isClientChannel ?
        channelManager.CreateClientChannel(channelName, dataType, channelPeerInfo) :
        channelManager.CreateServerChannel(channelName, dataType, channelPeerInfo);
    if (channelId < MIN_CHANNEL_ID || channelId > MAX_CHANNEL_ID) {
        HILOGE("CreateChannel failed, channelId is %{public}d", channelId);
        return INVALID_PARAMETERS_ERR;
    }

    if (channelManager.RegisterChannelListener(channelId, channelListener_) != ERR_OK) {
        HILOGE("register channel listener failed, channelId is %{public}d", channelId);
        return INVALID_PARAMETERS_ERR;
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
    if (ConnectTransChannel(TransChannelType::MESSAGE) != ERR_OK) {
        HILOGE("connect message channel failed.");
        return CONNECT_MESSAGE_CHANNEL_FAILED;
    }

    if (connectOption_.needSendData && ConnectTransChannel(TransChannelType::DATA) != ERR_OK) {
        HILOGE("connect data channel failed.");
        return CONNECT_DATA_CHANNEL_FAILED;
    }

    if ((connectOption_.needSendStream || connectOption_.needReceiveStream)) {
        if (ConnectTransChannel(TransChannelType::STREAM_BYTES) != ERR_OK) {
            HILOGE("connect stream channel failed.");
            return CONNECT_STREAM_CHANNEL_FAILED;
        }
        ConnectStreamChannel();
    }

    if (connectOption_.needSendFile && ConnectTransChannel(TransChannelType::SEND_FILE) != ERR_OK) {
        HILOGE("connect send file channel failed.");
        return CONNECT_SEND_FILE_CHANNEL_FAILED;
    }

    return ERR_OK;
}

int32_t AbilityConnectionSession::ConnectTransChannel(const TransChannelType channelType)
{
    TransChannelInfo info;
    int32_t ret = GetTransChannelInfo(channelType, info);
    if (ret != ERR_OK) {
        HILOGE("stream channel not exits!");
        return STREAM_CHANNEL_NOT_EXITS;
    }

    ret = ChannelManager::GetInstance().ConnectChannel(info.channelId);
    if (ret != ERR_OK) {
        HILOGE("connect channel failed. ret is %{public}d", ret);
        return ret;
    }
    HILOGI("connect channel success, channel type is %{public}d", static_cast<int32_t>(channelType));
    UpdateTransChannelStatus(info.channelId, true);
    return ERR_OK;
}

int32_t AbilityConnectionSession::ConnectStreamChannel()
{
    HILOGI("called.");
    if (!connectOption_.needSendStream && !connectOption_.needReceiveStream) {
        HILOGI("Streaming is not required.");
        return ERR_OK;
    }

    TransChannelInfo info;
    int32_t ret = GetTransChannelInfo(TransChannelType::STREAM, info);
    if (ret != ERR_OK) {
        HILOGE("stream channel not exits!");
        return INVALID_PARAMETERS_ERR;
    }

    if (info.isConnected) {
        HILOGE("stream channel has connected.");
        return ERR_OK;
    }

    if (direction_ != CollabrateDirection::COLLABRATE_SOURCE) {
        HILOGI("notify source connect stream channel.");
        SendMessage("WIFI_OPEN", MessageType::WIFI_OPEN);
        return ERR_OK;
    }

    std::thread task([this, info]() {
        DoConnectStreamChannel(info.channelId);
    });
    task.detach();
    return ERR_OK;
}

int32_t AbilityConnectionSession::DoConnectStreamChannel(int32_t channelId)
{
    HILOGI("called.");
    int32_t ret = ChannelManager::GetInstance().ConnectChannel(channelId);
    if (ret != ERR_OK) {
        HILOGE("stream channel bind failed, ret is %{public}d", ret);
        return ret;
    }
    HILOGI("stream channel bind success");
    UpdateTransChannelStatus(channelId, true);

    if (recvEngine_ == nullptr) {
        HILOGI("notify peer update recvEngine channel.");
        SendMessage("updateRecvEngineTransChannel", MessageType::UPDATE_RECV_ENGINE_CHANNEL);
        return ERR_OK;
    }
    UpdateRecvEngineTransChannel();
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
    HILOGI("called. channelId is %{public}d", channelId);
    if (!IsVaildChannel(channelId)) {
        HILOGE("is vaild channelId");
        return;
    }

    UpdateTransChannelStatus(channelId, true);
    if (IsAllChannelConnected() && !connectOption_.needSendFile) {
        HandleSessionConnect();
    }
}

void AbilityConnectionSession::HandleSessionConnect()
{
    HILOGI("called.");
    std::unique_lock<std::shared_mutex> sessionStatusWriteLock(sessionMutex_);
    if (sessionStatus_ == SessionStatus::CONNECTED) {
        HILOGI("session has connected.");
        return;
    }
    sessionStatus_ = SessionStatus::CONNECTED;
    
    if (sessionListener_ != nullptr) {
        HILOGI("handler sessionListener");
        sessionListener_->OnConnect(sessionId_);
    } else {
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
        if (!info.isConnected && info.transType != TransChannelType::STREAM) {
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

    if (!IsConnected()) {
        HILOGE("session is not connected.");
        return;
    }

    HILOGI("notidy app disconnect");
    Disconnect();

    if (sessionListener_ != nullptr) {
        HILOGI("handler sessionListener");
        sessionListener_->OnDisConnect(sessionId_);
    } else {
        EventCallbackInfo callbackInfo;
        callbackInfo.sessionId = sessionId_;
        callbackInfo.reason = DisconnectReason::PEER_APP_EXIT;
        ExeuteEventCallback(EVENT_DISCONNECT, callbackInfo);
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
    std::string msg(reinterpret_cast<const char *>(data + MessageDataHeader::HEADER_LEN),
        dataBuffer->Size() - MessageDataHeader::HEADER_LEN);
    HILOGI("headerPara type is %{public}d", headerPara->dataType_);
    switch (headerPara->dataType_) {
        case uint32_t(MessageType::NORMAL): {
            return ExeuteMessageEventCallback(msg);
        }
        case uint32_t(MessageType::WIFI_OPEN): {
            ConnectStreamChannel();
            return;
        }
        case uint32_t(MessageType::UPDATE_RECV_ENGINE_CHANNEL): {
            return UpdateRecvEngineTransChannel();
        }
        case uint32_t(MessageType::UPDATE_SENDER_ENGINE_CHANNEL): {
            return UpdateSenderEngineTransChannel();
        }
        case uint32_t(MessageType::RECEIVE_STREAM_START): {
            recvEngineState_ = EngineState::START;
            return;
        }
        case uint32_t(MessageType::CONNECT_FILE_CHANNEL): {
            return ConnectFileChannel(msg);
        }
        case uint32_t(MessageType::FILE_CHANNEL_CONNECT_SUCCESS): {
            return NotifyAppConnectResult(true);
        }
        case uint32_t(MessageType::FILE_CHANNEL_CONNECT_FAILED): {
            return NotifyAppConnectResult(false);
        }
        default: {
            HILOGE("unhandled code");
            return;
        }
    }
}

void AbilityConnectionSession::OnSendFile(const int32_t channelId, const FileInfo& info)
{
    HILOGD("called.");
    if (!IsVaildChannel(channelId)) {
        return;
    }
    if (sessionListener_ == nullptr) {
        HILOGE("sessionListener_ is nullptr");
        return;
    }
    sessionListener_->OnSendFile(sessionId_, info);
}

void AbilityConnectionSession::OnRecvFile(const int32_t channelId, const FileInfo& info)
{
    HILOGD("called.");
    if (!IsVaildChannel(channelId)) {
        return;
    }
    if (sessionListener_ == nullptr) {
        HILOGE("sessionListener_ is nullptr");
        return;
    }
    sessionListener_->OnRecvFile(sessionId_, info);
}

const char* AbilityConnectionSession::GetRecvPath(const int32_t channelId)
{
    HILOGD("called.");
    if (!IsVaildChannel(channelId)) {
        return nullptr;
    }
    if (sessionListener_ == nullptr) {
        HILOGE("sessionListener_ is nullptr");
        return nullptr;
    }
    return sessionListener_->GetRecvPath(sessionId_);
}

void AbilityConnectionSession::ExeuteMessageEventCallback(const std::string msg)
{
    HILOGD("called.");
    if (sessionListener_ != nullptr) {
        HILOGI("handler sessionListener");
        sessionListener_->OnMessage(sessionId_, msg);
    } else {
        EventCallbackInfo callbackInfo;
        callbackInfo.sessionId = sessionId_;
        callbackInfo.msg = msg;
        ExeuteEventCallback(EVENT_RECEIVE_MESSAGE, callbackInfo);
    }
}

void AbilityConnectionSession::UpdateRecvEngineTransChannel()
{
    HILOGI("called.");
    if (recvEngine_ == nullptr) {
        HILOGE("recvEngine_ is nullptr.");
        return;
    }

    TransChannelInfo info;
    int32_t ret = GetTransChannelInfo(TransChannelType::STREAM, info);
    if (ret != ERR_OK) {
        HILOGI("not find stream chennel.");
        return;
    }
    recvEngine_->SetChannelListener(info.channelId);
    SendMessage("updateSenderEngineTransChannel", MessageType::UPDATE_SENDER_ENGINE_CHANNEL);
}

void AbilityConnectionSession::UpdateSenderEngineTransChannel()
{
    HILOGI("called.");
    if (senderEngine_ == nullptr) {
        HILOGE("senderEngine_ is nullptr.");
        return;
    }

    TransChannelInfo info;
    int32_t ret = GetTransChannelInfo(TransChannelType::STREAM, info);
    if (ret != ERR_OK) {
        HILOGI("not find stream chennel.");
        return;
    }
    HILOGI("SetChannelListener channelId is %{public}d, channelType is %{public}d",
        info.channelId, static_cast<int32_t>(info.channelType));
    senderEngine_->SetTransChannel(info.channelId, info.channelType);
}

void AbilityConnectionSession::ConnectFileChannel(const std::string& peerSocketName)
{
    HILOGI("called.");
    peerSocketName_ = peerSocketName;
    int32_t ret = CreateChannel(channelName_, ChannelDataType::FILE, TransChannelType::SEND_FILE, true);
    if (ret != ERR_OK) {
        HILOGE("create send file channel failed!");
        return;
    }

    ret = ConnectTransChannel(TransChannelType::SEND_FILE);
    if (ret != ERR_OK) {
        HILOGI("connect file chennel failed.");
        SendMessage("FILE_CHANNEL_CONNECT_FAILED", MessageType::FILE_CHANNEL_CONNECT_FAILED);
        return;
    }
    SendMessage("FILE_CHANNEL_CONNECT_SUCCESS", MessageType::FILE_CHANNEL_CONNECT_SUCCESS);
    HandleSessionConnect();
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

    if (IsStreamBytesChannel(channelId)) {
        HILOGE("is stream bytes channel, no need to send.");
        return;
    }

    if (sessionListener_ != nullptr) {
        HILOGI("handler sessionListener");
        sessionListener_->OnData(sessionId_, dataBuffer);
    } else {
        EventCallbackInfo callbackInfo;
        callbackInfo.sessionId = sessionId_;
        callbackInfo.data = dataBuffer;
        ExeuteEventCallback(EVENT_RECEIVE_DATA, callbackInfo);
    }
}

bool AbilityConnectionSession::IsStreamBytesChannel(const int32_t channelId)
{
    TransChannelInfo transChannelInfo;
    int32_t ret = GetTransChannelInfo(TransChannelType::STREAM_BYTES, transChannelInfo);
    if (ret != ERR_OK) {
        HILOGE("stream bytes channel not exit!");
        return false;
    }

    return transChannelInfo.channelId == channelId;
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
    HILOGI("called.");
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }

    auto task = [this, result, connectCallback = connectCallback_]() {
        HILOGI("execute connect callback task.");
        if (connectCallback == nullptr) {
            HILOGE("connect callback is nullptr.");
            return;
        }
        connectCallback(result);
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

void AbilityConnectionSession::CollabChannelListener::OnSendFile(const int32_t channelId, const FileInfo& info) const
{
    HILOGD("called.");
    std::shared_ptr<AbilityConnectionSession> abilityConnectionSession = abilityConnectionSession_.lock();
    if (abilityConnectionSession == nullptr) {
        HILOGE("abilityConnectionSession is null");
        return;
    }

    abilityConnectionSession->OnSendFile(channelId, info);
}

void AbilityConnectionSession::CollabChannelListener::OnRecvFile(const int32_t channelId, const FileInfo& info) const
{
    HILOGD("called.");
    std::shared_ptr<AbilityConnectionSession> abilityConnectionSession = abilityConnectionSession_.lock();
    if (abilityConnectionSession == nullptr) {
        HILOGE("abilityConnectionSession is null");
        return;
    }

    abilityConnectionSession->OnRecvFile(channelId, info);
}

const char* AbilityConnectionSession::CollabChannelListener::GetRecvPath(const int32_t channelId) const
{
    HILOGD("called.");
    std::shared_ptr<AbilityConnectionSession> abilityConnectionSession = abilityConnectionSession_.lock();
    if (abilityConnectionSession == nullptr) {
        HILOGE("abilityConnectionSession is null");
        return nullptr;
    }

    return abilityConnectionSession->GetRecvPath(channelId);
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