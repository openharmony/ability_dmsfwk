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

#include "channel_manager.h"

#include <algorithm>
#include <chrono>
#include <dlfcn.h>
#include <future>
#include <sys/prctl.h>
#include <unistd.h>
#include <unordered_set>

#include "dtbcollabmgr_log.h"
#include "securec.h"
#include "softbus_error_code.h"

namespace OHOS {
namespace DistributedCollab {
IMPLEMENT_SINGLE_INSTANCE(ChannelManager);
namespace {
    static const std::string TAG = "DSchedCollabChannelManager";
    constexpr int32_t BIND_RETRY_INTERVAL = 500;
    constexpr int32_t MAX_BIND_RETRY_TIME = 1500;
    constexpr int32_t MAX_RETRY_TIMES = 3;
    constexpr int32_t MS_TO_US = 1000;
    enum class QosSpeedType {
        HIGH,
        LOW
    };

    static std::map<ChannelDataType, TransDataType> CHANNEL_SOFTBUS_DATATYPE_MAP = {
        { ChannelDataType::MESSAGE, DATA_TYPE_MESSAGE },
        { ChannelDataType::BYTES, DATA_TYPE_BYTES },
        { ChannelDataType::VIDEO_STREAM, DATA_TYPE_VIDEO_STREAM },
        { ChannelDataType::FILE, DATA_TYPE_FILE }
    };

    static std::map<ChannelDataType, QosSpeedType> CHANNEL_DATATYPE_SPEED_MAP = {
        { ChannelDataType::MESSAGE, QosSpeedType::LOW },
        { ChannelDataType::BYTES, QosSpeedType::LOW },
        { ChannelDataType::VIDEO_STREAM, QosSpeedType::HIGH },
        { ChannelDataType::FILE, QosSpeedType::HIGH }
    };

    static const std::string SPLIT_FLAG = "_";
    static const std::string COLLAB_PGK_NAME = "dms";
    static const std::string SESSION_NAME_PREFIX = "ohos.dtbcollab.dms";

    static std::map<ChannelDataType, std::string> CHANNEL_DATATYPE_PREFIX_MAP = {
        { ChannelDataType::MESSAGE, "M" },
        { ChannelDataType::BYTES, "B" },
        { ChannelDataType::VIDEO_STREAM, "V" },
        { ChannelDataType::FILE, "F" }
    };

    static constexpr int32_t DSCHED_COLLAB_LOW_QOS_TYPE_MIN_BW = 4 * 1024 * 1024;
    static constexpr int32_t DSCHED_COLLAB_LOW_QOS_TYPE_MAX_LATENCY = 10000;
    static constexpr int32_t DSCHED_COLLAB_LOW_QOS_TYPE_MIN_LATENCY = 2000;

    static QosTV g_low_qosInfo[] = {
        { .qos = QOS_TYPE_MIN_BW, .value = DSCHED_COLLAB_LOW_QOS_TYPE_MIN_BW },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = DSCHED_COLLAB_LOW_QOS_TYPE_MAX_LATENCY },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = DSCHED_COLLAB_LOW_QOS_TYPE_MIN_LATENCY },
        { .qos = QOS_TYPE_MAX_IDLE_TIMEOUT, .value = 60 * 60 * 1000 }
    };

    static constexpr int32_t DSCHED_COLLAB_HIGH_QOS_TYPE_MIN_BW = 80 * 1024 * 1024;
    static constexpr int32_t DSCHED_COLLAB_HIGH_QOS_TYPE_MAX_LATENCY = 10000;
    static constexpr int32_t DSCHED_COLLAB_HIGH_QOS_TYPE_MIN_LATENCY = 2000;

    static QosTV g_high_qosInfo[] = {
        { .qos = QOS_TYPE_MIN_BW, .value = DSCHED_COLLAB_HIGH_QOS_TYPE_MIN_BW },
        { .qos = QOS_TYPE_MAX_LATENCY, .value = DSCHED_COLLAB_HIGH_QOS_TYPE_MAX_LATENCY },
        { .qos = QOS_TYPE_MIN_LATENCY, .value = DSCHED_COLLAB_HIGH_QOS_TYPE_MIN_LATENCY },
        { .qos = QOS_TYPE_MAX_IDLE_TIMEOUT, .value = 60 * 60 * 1000 }
    };

    static std::map<QosSpeedType, QosTV*> qos_config = {
        { QosSpeedType::HIGH, g_high_qosInfo },
        { QosSpeedType::LOW, g_low_qosInfo }
    };

    static uint32_t g_lowQosTvParamIndex = static_cast<uint32_t>(sizeof(g_low_qosInfo) / sizeof(QosTV));
    static uint32_t g_highQosTvParamIndex = static_cast<uint32_t>(sizeof(g_high_qosInfo) / sizeof(QosTV));
    static std::map<QosSpeedType, uint32_t> qos_speed_config = {
        { QosSpeedType::HIGH, g_highQosTvParamIndex },
        { QosSpeedType::LOW, g_lowQosTvParamIndex }
    };

#define CHECK_SOCKET_ID(socketId)                          \
do {                                                       \
    if ((socketId) <= 0) {                                 \
        HILOGE("invalid socket id, %{public}d", socketId); \
        return;                                            \
    }                                                      \
} while (0)

#define CHECK_CHANNEL_ID(socketId, channelId)                                 \
do {                                                                          \
    (channelId) = GetChannelId(socketId);                                     \
    if (!isValidChannelId(channelId)) {                                       \
        HILOGE("invalid socket id %{public}d, can't find channel", socketId); \
        return;                                                               \
    }                                                                         \
} while (0)

#define CHECK_DATA_NULL(socketId, data, errorHandler)                      \
do {                                                                       \
    if ((data) == nullptr) {                                               \
        HILOGE("receive empty bytes data, socketId=%{public}d", socketId); \
        (errorHandler)(socketId, RECV_DATA_EMPTY);                        \
        return;                                                            \
    }                                                                      \
} while (0)
}

namespace {
    constexpr int32_t MAX_LEN = 10 * 1024;
}

static void OnSocketConnected(int32_t socket, PeerSocketInfo info)
{
    ChannelManager::GetInstance().OnSocketConnected(socket, info);
}

static void OnSocketClosed(int32_t socket, ShutdownReason reason)
{
    ChannelManager::GetInstance().OnSocketClosed(socket, reason);
}

static void OnBytesRecv(int32_t socket, const void* data, uint32_t dataLen)
{
    ChannelManager::GetInstance().OnBytesReceived(socket, data, dataLen);
}

static void OnMessageRecv(int32_t socket, const void* data, uint32_t dataLen)
{
    ChannelManager::GetInstance().OnMessageReceived(socket, data, dataLen);
}

static void OnStreamRecv(int32_t socket, const StreamData* data, const StreamData* ext,
    const StreamFrameInfo* param)
{
    ChannelManager::GetInstance().OnStreamReceived(socket, data, ext, param);
}

static void OnError(int32_t socket, int32_t errCode)
{
    ChannelManager::GetInstance().OnSocketError(socket, errCode);
}

static void OnFileEvent(int32_t socket, FileEvent *event)
{
    ChannelManager::GetInstance().OnFileEventReceived(socket, event);
}

static const char* GetRecvPath()
{
    return ChannelManager::GetInstance().GetRecvPathFromUser();
}

ISocketListener channelManagerListener = {
    .OnBind = OnSocketConnected,
    .OnShutdown = OnSocketClosed,
    .OnBytes = OnBytesRecv,
    .OnMessage = OnMessageRecv,
    .OnStream = OnStreamRecv,
    .OnFile = OnFileEvent,
    .OnError = OnError,
};

ChannelManager::~ChannelManager()
{
    DeInit();
};

int32_t ChannelManager::Init(const std::string& ownerName)
{
    HILOGI("start init channel manager");
    if (eventHandler_ != nullptr && callbackEventHandler_ != nullptr && msgEventHandler_ != nullptr &&
        callbackEventHandlerNew_ != nullptr) {
        HILOGW("server channel already init");
        return ERR_OK;
    }
    if (serverSocketId_ > 0) {
        HILOGW("server socket already init");
        return ERR_OK;
    }
    ownerName_ = ownerName;

    eventThread_ = std::thread(&ChannelManager::StartEvent, this);
    std::unique_lock<std::mutex> lock(eventMutex_);
    eventCon_.wait(lock, [this] {
        return eventHandler_ != nullptr;
    });

    callbackEventThread_ = std::thread(&ChannelManager::StartCallbackEvent, this);
    std::unique_lock<std::mutex> callbackLock(callbackEventMutex_);
    callbackEventCon_.wait(callbackLock, [this] {
        return callbackEventHandler_ != nullptr;
    });

    msgEventThread_ = std::thread(&ChannelManager::StartMsgEvent, this);
    std::unique_lock<std::mutex> msgLock(msgEventMutex_);
    msgEventCon_.wait(msgLock, [this] {
        return msgEventHandler_ != nullptr;
    });

    callbackEventNewThread_ = std::thread(&ChannelManager::StartCallbackEventNew, this);
    std::unique_lock<std::mutex> callbackNewLock(callbackEventNewMutex_);
    callbackEventNewCon_.wait(callbackNewLock, [this] {
        return callbackEventHandlerNew_ != nullptr;
    });
    
    int32_t socketServerId = CreateServerSocket();
    if (socketServerId <= 0) {
        HILOGE("create socket failed, ret: %{public}d", socketServerId);
        return CREATE_SOCKET_FAILED;
    }
    int32_t ret = Listen(socketServerId, g_low_qosInfo, g_lowQosTvParamIndex, &channelManagerListener);
    if (ret != ERR_OK) {
        HILOGE("service listen failed, ret: %{public}d", ret);
        return LISTEN_SOCKET_FAILED;
    }
    serverSocketId_ = socketServerId;
    int32_t result = GetDmsInteractiveAdapterProxy();
    if (result != ERR_OK) {
        HILOGE("Get remote dms interactive adapter proxy fail, ret %{public}d.", ret);
    }
    HILOGI("end");
    return ERR_OK;
}

void ChannelManager::StartEvent()
{
    HILOGI("StartEvent start");
    prctl(PR_SET_NAME, ownerName_.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    runner->Run();
    HILOGI("StartEvent end");
}

void ChannelManager::StartCallbackEvent()
{
    HILOGI("Start callback event start");
    std::string callbackName = ownerName_ + "callback";
    prctl(PR_SET_NAME, callbackName.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(callbackEventMutex_);
        callbackEventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    callbackEventCon_.notify_one();
    runner->Run();
    HILOGI("callback event end");
}

void ChannelManager::StartCallbackEventNew()
{
    HILOGI("Start new callback event start");
    std::string callbackName = ownerName_ + "callbackNew";
    prctl(PR_SET_NAME, callbackName.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(callbackEventNewMutex_);
        callbackEventHandlerNew_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    callbackEventNewCon_.notify_one();
    runner->Run();
    HILOGI("new callback event end");
}

void ChannelManager::StartMsgEvent()
{
    HILOGI("Start msg event start");
    std::string msgName = ownerName_ + "msg";
    prctl(PR_SET_NAME, msgName.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(msgEventMutex_);
        msgEventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    msgEventCon_.notify_one();
    runner->Run();
    HILOGI("msg event end");
}

int32_t ChannelManager::PostTask(const AppExecFwk::InnerEvent::Callback& callback,
    const AppExecFwk::EventQueue::Priority priority, const std::string& name)
{
    if (eventHandler_ == nullptr) {
        HILOGE("event handler empty");
        return NULL_EVENT_HANDLER;
    }
    if (eventHandler_->PostTask(callback, name, 0, priority)) {
        return ERR_OK;
    }
    HILOGE("add task failed");
    return POST_TASK_FAILED;
}

int32_t ChannelManager::PostCallbackTask(const AppExecFwk::InnerEvent::Callback& callback,
    const AppExecFwk::EventQueue::Priority priority)
{
    if (callbackEventHandler_ == nullptr) {
        HILOGE("callback event handler empty");
        return NULL_EVENT_HANDLER;
    }
    if (callbackEventHandler_->PostTask(callback, priority)) {
        return ERR_OK;
    }
    HILOGE("add callback task failed");
    return POST_TASK_FAILED;
}

int32_t ChannelManager::PostCallbackTaskNew(const AppExecFwk::InnerEvent::Callback& callback,
    const AppExecFwk::EventQueue::Priority priority)
{
    if (callbackEventHandlerNew_ == nullptr) {
        HILOGE("new callback event handler empty");
        return NULL_EVENT_HANDLER;
    }
    if (callbackEventHandlerNew_->PostTask(callback, priority)) {
        return ERR_OK;
    }
    HILOGE("add new callback task failed");
    return POST_TASK_FAILED;
}

int32_t ChannelManager::PostMsgTask(const AppExecFwk::InnerEvent::Callback& callback,
    const AppExecFwk::EventQueue::Priority priority)
{
    if (msgEventHandler_ == nullptr) {
        HILOGE("msg event handler empty");
        return NULL_EVENT_HANDLER;
    }
    if (msgEventHandler_->PostTask(callback, priority)) {
        return ERR_OK;
    }
    HILOGE("add msg task failed");
    return POST_TASK_FAILED;
}

int32_t ChannelManager::CreateServerSocket()
{
    HILOGI("start create server socket");
    std::string sessionName = SESSION_NAME_PREFIX + ownerName_;
    HILOGI("sessionName: %{public}s, size: %{public}zu", sessionName.c_str(),
        sessionName.length());
    SocketInfo info = {
        .name = const_cast<char*>(sessionName.c_str()),
        .pkgName = const_cast<char*>(COLLAB_PGK_NAME.c_str()),
    };
    int32_t socket = Socket(info);
    HILOGI("finish, socket id: %{public}d", socket);
    return socket;
}

void ChannelManager::DeInit()
{
    HILOGI("start deinit channel manager");
    // stop all task
    if (eventHandler_ != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        if (eventThread_.joinable()) {
            eventThread_.join();
        }
        eventHandler_ = nullptr;
    } else {
        HILOGE("eventHandler_ is nullptr");
    }

    // stop callback task
    if (callbackEventHandler_ != nullptr) {
        callbackEventHandler_->GetEventRunner()->Stop();
        if (callbackEventThread_.joinable()) {
            callbackEventThread_.join();
        }
        callbackEventHandler_ = nullptr;
    } else {
        HILOGE("callbackEventHandler_ is nullptr");
    }

    // stop msg task
    if (msgEventHandler_ != nullptr) {
        msgEventHandler_->GetEventRunner()->Stop();
        if (msgEventThread_.joinable()) {
            msgEventThread_.join();
        }
        msgEventHandler_ = nullptr;
    }

    // stop new callback task
    if (callbackEventHandlerNew_ != nullptr) {
        callbackEventHandlerNew_->GetEventRunner()->Stop();
        if (callbackEventNewThread_.joinable()) {
            callbackEventNewThread_.join();
        }
        callbackEventHandlerNew_ = nullptr;
    }

    // release channels
    std::unordered_set<int32_t> channelIds;
    for (const auto& entry : channelIdMap_) {
        for (int32_t id : entry.second) {
            channelIds.insert(id);
        }
    }
    for (const int32_t id : channelIds) {
        DeleteChannel(id);
    }
    dlclose(dllHandle_);
    dllHandle_ = nullptr;
    dmsFileAdapetr_.SetFileSchema = nullptr;
    Shutdown(serverSocketId_);
    Reset();
    HILOGI("end");
}

int32_t ChannelManager::GetDmsInteractiveAdapterProxy()
{
    HILOGI("Get remote dms interactive adapter proxy.");
    std::lock_guard<std::mutex> autoLock(dmsAdapetrLock_);
#if (defined(__aarch64__) || defined(__x86_64__))
    char resolvedPath[100] = "/system/lib64/libdms_interactive_adapter.z.so";
#else
    char resolvedPath[100] = "/system/lib/libdms_interactive_adapter.z.so";
#endif
    int32_t (*GetSoftbusFile)(ISoftbusFileAdpater &dmsFileHandle) = nullptr;

    dllHandle_ = dlopen(resolvedPath, RTLD_LAZY);
    if (dllHandle_ == nullptr) {
        HILOGE("Open dms interactive adapter shared object fail, resolvedPath [%{public}s].", resolvedPath);
        return NOT_FIND_SERVICE_REGISTRY;
    }

    int32_t ret = ERR_OK;
    do {
        GetSoftbusFile = reinterpret_cast<int32_t (*)(ISoftbusFileAdpater &dmsFileHandle)>(
            dlsym(dllHandle_, "GetSoftbusFile"));
        if (GetSoftbusFile == nullptr) {
            HILOGE("Link the GetDmsInteractiveAdapter symbol in dms interactive adapter fail.");
            ret = NOT_FIND_SERVICE_REGISTRY;
            break;
        }

        if (GetSoftbusFile(dmsFileAdapetr_)) {
            HILOGE("Init remote dms interactive adapter proxy fail, ret %{public}d.", ret);
            ret = INVALID_PARAMETERS_ERR;
            break;
        }
        ret = ERR_OK;
    } while (false);

    if (ret != ERR_OK) {
        HILOGE("Get remote dms interactive adapter proxy fail, dlclose handle.");
        dlclose(dllHandle_);
        dllHandle_ = nullptr;
    }
    return ret;
}

void ChannelManager::Reset()
{
    HILOGI("reset channel manager");
    serverSocketId_ = -1;
    ownerName_ = "";
    nextIds_ = {
        { ChannelDataType::MESSAGE, MESSAGE_START_ID },
        { ChannelDataType::BYTES, BYTES_START_ID },
        { ChannelDataType::VIDEO_STREAM, STREAM_START_ID },
        { ChannelDataType::FILE, FILE_START_ID }
    };
}

int32_t ChannelManager::GetVersion()
{
    return VERSION_;
}

int32_t ChannelManager::CreateServerChannel(const std::string& channelName,
    const ChannelDataType dataType, const ChannelPeerInfo& peerInfo)
{
    HILOGI("start to creat server channel waiting for connect");
    std::optional<ChannelInfo> info = CreateBaseChannel(channelName, dataType, peerInfo);
    if (!info) {
        HILOGE("Create server channel failed");
        return CREATE_SERVER_CHANNEL_FAILED;
    }
    std::unique_lock<std::shared_mutex> writeLock(channelMutex_);
    channelIdMap_[channelName].push_back(info->channelId);
    channelInfoMap_.emplace(info->channelId, std::move(*info));
    // save file channel
    fileChannelId_.store(info->channelId);
    HILOGI("end");
    return info->channelId;
}

int32_t ChannelManager::CreateClientChannel(const std::string& channelName,
    const ChannelDataType dataType, const ChannelPeerInfo& peerInfo)
{
    HILOGI("start to creat client channel to connect other");
    std::optional<ChannelInfo> info = CreateBaseChannel(channelName, dataType, peerInfo);
    if (!info) {
        HILOGE("Create client channel failed");
        return CREATE_CLIENT_CHANNEL_FAILED;
    }
    int32_t ret = RegisterSocket(*info, dataType);
    HILOGI("end");
    return ret == ERR_OK ? info->channelId : ret;
};

std::optional<ChannelInfo> ChannelManager::CreateBaseChannel(const std::string& channelName,
    const ChannelDataType dataType, const ChannelPeerInfo& peerInfo)
{
    HILOGI("start create base channel, dataType=%{public}d, name=%{public}s",
        static_cast<int32_t>(dataType), channelName.c_str());
    int32_t channelId = GenerateNextId(dataType);
    if (!isValidChannelId(channelId)) {
        HILOGE("Get channel id failed, id=%{public}d", channelId);
        return std::nullopt;
    }
    ChannelInfo info;
    info.channelId = channelId;
    info.channelName = channelName;
    info.status = ChannelStatus::UNCONNECTED;
    info.dataType = dataType;
    info.peerInfo = peerInfo;
    return info;
}

int32_t ChannelManager::GenerateNextId(const ChannelDataType dataType)
{
    int32_t channelId = 0;
    // lock for each type
    std::lock_guard<std::mutex> typeLock(typeMutex_[dataType]);
    HILOGI("create socket for %{public}d", static_cast<int32_t>(dataType));
    channelId = nextIds_[dataType];
    if (channelId - CHANNEL_ID_GAP * (static_cast<int32_t>(dataType) + 1)
        >= CHANNEL_ID_GAP) {
        HILOGE("type %{public}d exceed max channel",
            static_cast<int32_t>(dataType));
        return CHANNEL_NUM_EXCEED_LIMIT;
    }
    nextIds_[dataType]++;
    return channelId;
}

int32_t ChannelManager::RegisterSocket(ChannelInfo& info, const ChannelDataType dataType)
{
    int32_t clientSocketId = CreateClientSocket(info.channelName,
        info.peerInfo.peerName, info.peerInfo.networkId, dataType);
    if (clientSocketId <= 0) {
        HILOGE("create socket failed, ret: %{public}d", clientSocketId);
        return CREATE_SOCKET_FAILED;
    }
    // save info to each map
    {
        std::unique_lock<std::shared_mutex> writeLock(socketMutex_);
        socketChannelMap_.emplace(clientSocketId, info.channelId);
        socketStatusMap_.emplace(clientSocketId, ChannelStatus::UNCONNECTED);
    }
    HILOGI("register channel name: %{public}s", info.channelName.c_str());
    {
        std::unique_lock<std::shared_mutex> writeLock(channelMutex_);
        info.clientSockets.push_back(clientSocketId);
        info.dataSenderReceivers[clientSocketId] = std::make_unique<DataSenderReceiver>(clientSocketId);
        channelIdMap_[info.channelName].push_back(info.channelId);
        channelInfoMap_.emplace(info.channelId, std::move(info));
    }
    return ERR_OK;
}

int32_t ChannelManager::CreateClientSocket(const std::string& channelName,
    const std::string& peerName, const std::string& peerNetworkId, const ChannelDataType dataType)
{
    HILOGI("start");
    if (channelName.length() > MAX_CHANNEL_NAME_LENGTH) {
        HILOGE("channel name too long, %{public}s", channelName.c_str());
        return -INVALID_CHANNEL_NAME;
    }
    // ohos.dtbcollab.dms64_F_64
    std::string name = SESSION_NAME_PREFIX + ownerName_ +
        SPLIT_FLAG + CHANNEL_DATATYPE_PREFIX_MAP[dataType] + SPLIT_FLAG + channelName;
    std::string peerSocketName = SESSION_NAME_PREFIX + peerName;
    HILOGI("self-name: %{public}s, peerName: %{public}s", name.c_str(), peerSocketName.c_str());
    SocketInfo socketInfo = {
        .name = const_cast<char*>(name.c_str()),
        .peerName = const_cast<char*>(peerSocketName.c_str()),
        .peerNetworkId = const_cast<char*>(peerNetworkId.c_str()),
        .pkgName = const_cast<char*>(COLLAB_PGK_NAME.c_str()),
        .dataType = CHANNEL_SOFTBUS_DATATYPE_MAP[dataType]
    };
    int32_t sessionId = Socket(socketInfo);
    HILOGI("finish, socket session id: %{public}d", sessionId);
    return sessionId;
}

bool ChannelManager::isValidChannelId(const int32_t channelId)
{
    return channelId > CHANNEL_ID_GAP && channelId <= (FILE_START_ID + CHANNEL_ID_GAP);
}

int32_t ChannelManager::DeleteChannel(const int32_t channelId)
{
    HILOGI("start delete channel");
    if (!isValidChannelId(channelId)) {
        HILOGE("invalid channel id");
        return INVALID_CHANNEL_ID;
    }
    ClearRegisterListener(channelId);
    ClearSendTask(channelId);
    ClearRegisterChannel(channelId);
    ClearRegisterSocket(channelId);
    HILOGI("end delete channel");
    return channelId;
}

void ChannelManager::ClearRegisterChannel(const int32_t channelId)
{
    HILOGI("start clear channel info, channelId=%{public}d", channelId);
    std::unique_lock<std::shared_mutex> writeLock(channelMutex_);
    std::string channelName;
    auto infoIt = channelInfoMap_.find(channelId);
    if (infoIt != channelInfoMap_.end()) {
        channelName = infoIt->second.channelName;
    }
    channelInfoMap_.erase(channelId);

    auto idIt = channelIdMap_.find(channelName);
    if (idIt != channelIdMap_.end()) {
        idIt->second.erase(std::remove(idIt->second.begin(), idIt->second.end(), channelId), idIt->second.end());
    }
}

void ChannelManager::ClearRegisterListener(const int32_t channelId)
{
    HILOGI("start release listener, channelId=%{public}d", channelId);
    std::unique_lock<std::shared_mutex> writeLock(listenerMutex_);
    listenersMap_.erase(channelId);
}

void ChannelManager::ClearRegisterSocket(const int32_t channelId)
{
    HILOGI("start release socket, channelId=%{public}d", channelId);
    std::vector<int32_t> socketIds;
    {
        std::unique_lock<std::shared_mutex> writeLock(socketMutex_);
        if (!socketChannelMap_.empty()) {
            for (auto&& socket : socketChannelMap_) {
                if (socket.second == channelId) {
                    socketIds.push_back(socket.first);
                }
            }
        }
        for (const auto socketId : socketIds) {
            HILOGI("start release socket, %{public}d", socketId);
            socketChannelMap_.erase(socketId);
            socketStatusMap_.erase(socketId);
        }
    }
    HILOGI("start to shutdown socket");
    for (const auto socketId : socketIds) {
        Shutdown(socketId);
    }
}

void ChannelManager::ClearSendTask(int32_t channelId)
{
    HILOGI("clear send task for=%{public}d", channelId);
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(std::to_string(channelId));
    }
}

int32_t ChannelManager::RegisterChannelListener(const int32_t channelId,
    const std::shared_ptr<IChannelListener> listener)
{
    HILOGI("start register listener, channelId=%{public}d", channelId);
    if (listener == nullptr) {
        HILOGE("listener empty");
        return INVALID_LISTENER;
    }
    std::unique_lock<std::shared_mutex> writeLock(listenerMutex_);
    auto listenIt = listenersMap_.find(channelId);
    if (listenIt == listenersMap_.end()) {
        listenersMap_[channelId].emplace_back(listener);
        return ERR_OK;
    }
    CleanInvalidListener(listenIt->second);
    auto it = std::find_if(listenIt->second.begin(), listenIt->second.end(),
        [&listener](const std::weak_ptr<IChannelListener> weakListener) {
            if (auto ptr = weakListener.lock()) {
                return listener == ptr;
            }
            return false;
        });
    if (it != listenIt->second.end()) {
        HILOGI("already exist listener");
        return ERR_OK;
    }
    listenIt->second.emplace_back(listener);
    return ERR_OK;
}

inline void ChannelManager::CleanInvalidListener(std::vector<std::weak_ptr<IChannelListener>>& listeners)
{
    listeners.erase(std::remove_if(listeners.begin(), listeners.end(),
        [](const std::weak_ptr<IChannelListener> listener) {
            return listener.expired();
        }),
        listeners.end());
}

int32_t ChannelManager::ConnectChannel(const int32_t channelId)
{
    HILOGI("start to connect channel %{public}d, only allow client", channelId);
    std::vector<int32_t> socketIds;
    ChannelDataType dataType;
    {
        std::shared_lock<std::shared_mutex> channelReadLock(channelMutex_);
        auto infoIt = channelInfoMap_.find(channelId);
        if (infoIt == channelInfoMap_.end() || infoIt->second.clientSockets.empty()) {
            HILOGE("invalid channel id");
            return INVALID_CHANNEL_ID;
        }
        dataType = infoIt->second.dataType;
        socketIds.insert(socketIds.begin(), infoIt->second.clientSockets.begin(), infoIt->second.clientSockets.end());
    }
    HILOGI("end");
    return DoBindSockets(socketIds, dataType);
}

int32_t ChannelManager::DoBindSockets(const std::vector<int32_t>& socketIds,
    const ChannelDataType dataType)
{
    HILOGI("start to connect sockets");
    std::vector<std::future<int32_t>> bindTasks;
    for (const auto& socketId : socketIds) {
        if (GetSocketStatus(socketId) == ChannelStatus::UNCONNECTED) {
            bindTasks.emplace_back(std::async(std::launch::async, [this, socketId, dataType]() {
                return BindSocket(socketId, dataType);
            }));
        }
    }
    if (bindTasks.empty()) {
        return ERR_OK;
    }
    for (auto&& task : bindTasks) {
        int32_t ret = task.get();
        HILOGI("bind task ret=%{public}d", ret);
        if (ret == ERR_OK) {
            return ERR_OK;
        }
    }

    return CONNECT_CHANNEL_FAILED;
}

ChannelStatus ChannelManager::GetSocketStatus(const int32_t socketId)
{
    std::shared_lock<std::shared_mutex> readLock(socketMutex_);
    auto it = socketStatusMap_.find(socketId);
    if (it != socketStatusMap_.end()) {
        return it->second;
    }
    return ChannelStatus::CONNECTED;
}

int32_t ChannelManager::BindSocket(const int32_t socketId, const ChannelDataType dataType)
{
    QosSpeedType speedType = CHANNEL_DATATYPE_SPEED_MAP[dataType];
    const QosTV* qos = qos_config[speedType];
    const uint32_t qosCount = qos_speed_config[speedType];
    int32_t ret = ERR_OK;
    int retryCount = 0;
    HILOGI("start to bind socket, id:%{public}d, speed:%{public}d", socketId, speedType);
    do {
        ret = Bind(socketId, qos, qosCount, &channelManagerListener);
        if (ret == ERR_OK) {
            break;
        }
        if (ret != SOFTBUS_LANE_WIFI_NOT_ONLINE) {
            HILOGE("bind failed, err=%{public}d", ret);
            return ret;
        }
        if (retryCount * BIND_RETRY_INTERVAL >= MAX_BIND_RETRY_TIME) {
            HILOGE("bind failed after max retry time %{public}d ms", MAX_BIND_RETRY_TIME);
            return ret;
        }
        HILOGI("bind failed, retrying after %{public}d ms, retry %{public}d", BIND_RETRY_INTERVAL, retryCount + 1);
        usleep(BIND_RETRY_INTERVAL * MS_TO_US);
        retryCount++;
    } while (retryCount < MAX_RETRY_TIMES);
    HILOGI("bind end");
    if (ret != ERR_OK) {
        HILOGE("client bind failed, ret: %{public}d", ret);
        return BIND_SOCKET_FAILED;
    }
    if (dataType == ChannelDataType::FILE) {
        if (dmsFileAdapetr_.SetFileSchema == nullptr) {
            HILOGE("SetFileSchema is null.");
            return INVALID_PARAMETERS_ERR;
        }
        ret = dmsFileAdapetr_.SetFileSchema(socketId);
    }
    if (ret != ERR_OK) {
        HILOGE("register %{public}d file schema failed", socketId);
        return REGISTER_FILE_SCHEMA_FAILED;
    }
    SetSocketStatus(socketId, ChannelStatus::CONNECTED);
    return ret;
}

int32_t ChannelManager::SetSocketStatus(const int32_t socketId, const ChannelStatus status)
{
    HILOGI("start set socket id:%{public}d status %{public}d", socketId, static_cast<int32_t>(status));
    int32_t channelId = 0;
    {
        std::unique_lock<std::shared_mutex> writeLock(socketMutex_);
        auto it = socketStatusMap_.find(socketId);
        if (it == socketStatusMap_.end()) {
            HILOGE("no valid socket in socketStatusMap");
            return INVALID_SOCKET_ID;
        }
        it->second = status;
        auto channelIt = socketChannelMap_.find(socketId);
        if (channelIt == socketChannelMap_.end()) {
            HILOGE("no valid socket in socketChannelMap");
            return INVALID_SOCKET_ID;
        }
        channelId = channelIt->second;
    }
    auto func = [channelId, this]() {
        UpdateChannelStatus(channelId);
    };
    return PostCallbackTask(func, AppExecFwk::EventQueue::Priority::IMMEDIATE);
}

int32_t ChannelManager::UpdateChannelStatus(const int32_t channelId)
{
    HILOGI("update channel id=%{public}d", channelId);
    std::vector<int32_t> socketIds;
    ChannelStatus curStatus = ChannelStatus::UNCONNECTED;
    {
        std::shared_lock<std::shared_mutex> readLock(channelMutex_);
        auto infoIt = channelInfoMap_.find(channelId);
        if (infoIt == channelInfoMap_.end()) {
            HILOGE("no valid channelInfo for %{public}d", channelId);
            return INVALID_CHANNEL_ID;
        }
        for (const auto socket : infoIt->second.clientSockets) {
            socketIds.push_back(socket);
        }
        curStatus = infoIt->second.status;
    }

    ChannelStatus newStatus = ChannelStatus::UNCONNECTED;
    for (const auto id : socketIds) {
        if (GetSocketStatus(id) == ChannelStatus::CONNECTED) {
            newStatus = ChannelStatus::CONNECTED;
            break;
        }
    }
    HILOGI("curStatus:%{public}d, newStatus:%{public}d",
        static_cast<int32_t>(curStatus), static_cast<int32_t>(newStatus));
    if (newStatus != curStatus) {
        return SetChannelStatus(channelId, newStatus);
    }
    return ERR_OK;
}

int32_t ChannelManager::SetChannelStatus(const int32_t channelId, const ChannelStatus status)
{
    HILOGI("set channel:%{public}d, status:%{public}d", channelId, static_cast<int32_t>(status));
    std::unique_lock<std::shared_mutex> writeLock(channelMutex_);
    auto infoIt = channelInfoMap_.find(channelId);
    if (infoIt == channelInfoMap_.end()) {
        HILOGE("no valid channelInfo for %{public}d", channelId);
        return INVALID_CHANNEL_ID;
    }
    infoIt->second.status = status;
    return ERR_OK;
}

void ChannelManager::OnSocketConnected(int32_t socketId, const PeerSocketInfo& info)
{
    if (socketId <= 0) {
        HILOGE("invalid socketId: %{public}d", socketId);
        return;
    }
    HILOGI("socket %{public}d binded", socketId);
    std::optional<std::string> channelNameOpt = GetChannelNameFromSocket(info.name);
    if (!channelNameOpt) {
        HILOGE("error socket name, %{public}s", info.name);
        return;
    }
    auto& channelName = *channelNameOpt;
    std::optional<ChannelDataType> channelType = GetChannelDataTypeFromName(channelName);
    if (!channelType) {
        HILOGE("error channel name, %{public}s", channelName.c_str());
        return;
    }
    // remove datatype flag
    constexpr int32_t namePrefix = 2;
    channelName = channelName.substr(namePrefix);
    int32_t channelId = GetChannelId(channelName, *channelType);
    if (!isValidChannelId(channelId)) {
        HILOGE("invalid channelid=%{public}d with channelName %{public}s", channelId, channelName.c_str());
        return;
    }
    auto func = [socketId, channelId, this]() {
        UpdateChannel(socketId, channelId);
    };
    PostTask(func, AppExecFwk::EventQueue::Priority::IMMEDIATE);
    HILOGI("add update channel task into handler");
}

int32_t ChannelManager::UpdateChannel(const int32_t socketId, const int32_t channelId)
{
    int32_t ret = RegisterSocket(socketId, channelId);
    if (ret != ERR_OK) {
        HILOGE("failed to save binded socket to matching channel");
        DoErrorCallback(channelId, ret);
        return ret;
    }
    ret = SetSocketStatus(socketId, ChannelStatus::CONNECTED);
    if (ret != ERR_OK) {
        HILOGE("failed to set socket status, %{public}d->%{public}d", channelId, ret);
        DoErrorCallback(channelId, ret);
        return ret;
    }
    DoConnectCallback(channelId);
    return ret;
}

std::optional<std::string> ChannelManager::GetChannelNameFromSocket(const std::string& socketName)
{
    size_t splitPos = socketName.find(SPLIT_FLAG, CHANNEL_NAME_PREFIX_LENGTH);
    if (splitPos == std::string::npos) {
        HILOGE("peer socket name invalid");
        return std::nullopt;
    }
    return socketName.substr(splitPos + SPLIT_FLAG.length());
}

std::optional<ChannelDataType> ChannelManager::GetChannelDataTypeFromName(const std::string& channelName)
{
    std::string prefix = channelName.substr(0, 1);
    for (auto&& dataType : CHANNEL_DATATYPE_PREFIX_MAP) {
        if (prefix == dataType.second) {
            return dataType.first;
        }
    }
    return std::nullopt;
}

int32_t ChannelManager::GetChannelId(const std::string& channelName, const ChannelDataType dataType)
{
    HILOGI("channelName: %{public}s, dataType: %{public}d", channelName.c_str(),
        static_cast<int32_t>(dataType));
    std::shared_lock<std::shared_mutex> readLock(channelMutex_);
    auto it = channelIdMap_.find(channelName);
    if (it == channelIdMap_.end()) {
        HILOGE("no valid channel exist");
        return INVALID_CHANNEL_NAME;
    }
    for (const auto channelId : it->second) {
        auto infoIt = channelInfoMap_.find(channelId);
        if (infoIt == channelInfoMap_.end()) {
            HILOGE("no valid channel exist");
            return INVALID_CHANNEL_ID;
        }
        // find matching dataType
        if (infoIt->second.dataType == dataType) {
            return infoIt->second.channelId;
        }
    }
    HILOGE("no matching channel");
    return NO_SUCH_CHANNEL;
}

int32_t ChannelManager::RegisterSocket(const int32_t socketId, const int32_t channelId)
{
    // update channelInfo
    HILOGI("register socket with channel, channelId=%{public}d, socketId=%{public}d", channelId, socketId);
    ChannelDataType dataType = ChannelDataType::BYTES;
    {
        std::unique_lock<std::shared_mutex> writeLock(channelMutex_);
        auto infoIt = channelInfoMap_.find(channelId);
        if (infoIt == channelInfoMap_.end()) {
            HILOGE("no valid channel");
            return INVALID_CHANNEL_ID;
        }
        dataType = infoIt->second.dataType;
        infoIt->second.clientSockets.push_back(socketId);
        infoIt->second.dataSenderReceivers[socketId] = std::make_unique<DataSenderReceiver>(socketId);
    }
    // update socket
    {
        std::unique_lock<std::shared_mutex> writeLock(socketMutex_);
        socketChannelMap_[socketId] = channelId;
        socketStatusMap_[socketId] = ChannelStatus::CONNECTED;
    }
    if (dataType == ChannelDataType::FILE) {
        HILOGI("file socket, regist softbus file schema");
        if (dmsFileAdapetr_.SetFileSchema == nullptr) {
            HILOGE("SetFileSchema is null.");
            return INVALID_PARAMETERS_ERR;
        }
        int32_t ret = dmsFileAdapetr_.SetFileSchema(socketId);
        if (ret != ERR_OK) {
            HILOGE("register %{public}d file schema failed", socketId);
            return REGISTER_FILE_SCHEMA_FAILED;
        }
    }
    return ERR_OK;
}

template <typename Func, typename... Args>
void ChannelManager::NotifyListeners(const int32_t channelId, Func listenerFunc,
    const AppExecFwk::EventQueue::Priority priority, Args&&... args)
{
    std::shared_lock<std::shared_mutex> readLock(listenerMutex_);
    auto it = listenersMap_.find(channelId);
    if (it == listenersMap_.end() || it->second.empty()) {
        HILOGE("no matching listener to %{public}d", channelId);
        return;
    }
    auto& listeners = it->second;
    for (const auto& listener : listeners) {
        if (auto ptr = listener.lock()) {
            auto func = [ptr, listenerFunc, channelId, args...]() {
                (ptr.get()->*listenerFunc)(channelId, std::forward<Args>(args)...);
            };
            PostCallbackTask(func, priority);
        }
    }
}

template <typename Func, typename... Args>
void ChannelManager::NotifyListenersNew(const int32_t channelId, Func listenerFunc,
    const AppExecFwk::EventQueue::Priority priority, Args&&... args)
{
    std::shared_lock<std::shared_mutex> readLock(listenerMutex_);
    auto it = listenersMap_.find(channelId);
    if (it == listenersMap_.end() || it->second.empty()) {
        HILOGE("no matching listener to %{public}d", channelId);
        return;
    }
    auto& listeners = it->second;
    for (const auto& listener : listeners) {
        if (auto ptr = listener.lock()) {
            auto func = [ptr, listenerFunc, channelId, args...]() {
                (ptr.get()->*listenerFunc)(channelId, std::forward<Args>(args)...);
            };
            PostCallbackTaskNew(func, priority);
        }
    }
}

void ChannelManager::OnSocketError(int32_t socketId, const int32_t errorCode)
{
    int32_t channelId = 0;
    CHECK_SOCKET_ID(socketId);
    CHECK_CHANNEL_ID(socketId, channelId);
    DoErrorCallback(channelId, errorCode);
}

void ChannelManager::DoErrorCallback(const int32_t channelId, const int32_t errorCode)
{
    NotifyListeners(channelId, &IChannelListener::OnError,
        AppExecFwk::EventQueue::Priority::IMMEDIATE, errorCode);
}

void ChannelManager::DoConnectCallback(const int32_t channelId)
{
    NotifyListeners(channelId, &IChannelListener::OnConnect,
        AppExecFwk::EventQueue::Priority::IMMEDIATE);
}

void ChannelManager::OnSocketClosed(int32_t socketId, const ShutdownReason& reason)
{
    int32_t channelId = 0;
    CHECK_SOCKET_ID(socketId);
    CHECK_CHANNEL_ID(socketId, channelId);
    HILOGI("socket %{public}d closed, reason:%{public}d", socketId, reason);
    int32_t ret = SetSocketStatus(socketId, ChannelStatus::UNCONNECTED);
    if (ret != ERR_OK) {
        HILOGE("failed to set socket status, %{public}d->%{public}d", channelId, ret);
        DoErrorCallback(channelId, ret);
        return;
    }
    // delete channel when all socket shutdown
    auto func = [channelId, reason, this]() {
        if (GetChannelStatus(channelId) == ChannelStatus::UNCONNECTED) {
            DoDisConnectCallback(channelId, reason);
            DeleteChannel(channelId);
        }
    };
    PostCallbackTask(func, AppExecFwk::EventQueue::Priority::IMMEDIATE);
}

int32_t ChannelManager::GetChannelId(const int32_t socketId)
{
    std::shared_lock<std::shared_mutex> readLock(socketMutex_);
    auto it = socketChannelMap_.find(socketId);
    if (it == socketChannelMap_.end()) {
        HILOGE("no proper channelId to %{public}d", socketId);
        return INVALID_SOCKET_ID;
    }
    return it->second;
}

void ChannelManager::DoDisConnectCallback(const int32_t channelId, const ShutdownReason& reason)
{
    NotifyListeners(channelId, &IChannelListener::OnDisConnect,
        AppExecFwk::EventQueue::Priority::IMMEDIATE, reason);
}

ChannelStatus ChannelManager::GetChannelStatus(const int32_t channelId)
{
    std::shared_lock<std::shared_mutex> readLock(channelMutex_);
    auto it = channelInfoMap_.find(channelId);
    if (it != channelInfoMap_.end()) {
        return it->second.status;
    }
    return ChannelStatus::UNCONNECTED;
}

template <typename Func, typename... Args>
int32_t ChannelManager::DoSendData(const int32_t channelId, Func doSendFunc, Args&&... args)
{
    HILOGD("start to send data");
    int32_t socketId = GetValidSocket(channelId);
    if (socketId <= 0) {
        HILOGE("no avaliable sockets, %{public}d", channelId);
        return NO_CONNECTED_SOCKET_ID;
    }
    int32_t ret = ERR_OK;
    {
        std::shared_lock<std::shared_mutex> channelReadLock(channelMutex_);
        auto infoIt = channelInfoMap_.find(channelId);
        if (infoIt == channelInfoMap_.end()) {
            HILOGE("no valid channel info exist");
            DoErrorCallback(channelId, INVALID_CHANNEL_ID);
            return INVALID_CHANNEL_ID;
        }
        auto socketIt = infoIt->second.dataSenderReceivers.find(socketId);
        if (socketIt == infoIt->second.dataSenderReceivers.end()) {
            HILOGE("no valid socket");
            DoErrorCallback(channelId, INVALID_SOCKET_ID);
            return INVALID_SOCKET_ID;
        }
        auto& senderReceiver = *(socketIt->second);
        ret = (senderReceiver.*doSendFunc)(std::forward<Args>(args)...);
    }
    if (ret != ERR_OK) {
        HILOGE("failed send data, %{public}d", ret);
        DoErrorCallback(channelId, ret);
        return ret;
    }
    return ERR_OK;
}

int32_t ChannelManager::SendBytes(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& data)
{
    if (!isValidChannelId(channelId) || data == nullptr) {
        HILOGE("invalid channel id. %{public}d", channelId);
        return INVALID_CHANNEL_ID;
    }
    HILOGI("start to send bytes, %{public}u", static_cast<uint32_t>(data->Size()));
    auto func = [channelId, data, this]() {
        DoSendBytes(channelId, data);
    };
    int32_t ret = PostTask(func, AppExecFwk::EventQueue::Priority::LOW,
        std::to_string(channelId));
    if (ret != ERR_OK) {
        HILOGE("failed to add send bytes task, ret=%{public}d", ret);
        return ret;
    }
    HILOGI("send bytes task added to handler");
    return ERR_OK;
}

inline int32_t ChannelManager::DoSendBytes(const int32_t channelId,
    const std::shared_ptr<AVTransDataBuffer>& data)
{
    HILOGD("start to send bytes");
    return DoSendData(channelId, &DataSenderReceiver::SendBytesData, data);
}

int32_t ChannelManager::GetValidSocket(const int32_t channelId)
{
    std::vector<int32_t> socketIds;
    {
        std::shared_lock<std::shared_mutex> channelReadLock(channelMutex_);
        auto infoIt = channelInfoMap_.find(channelId);
        if (infoIt == channelInfoMap_.end() || infoIt->second.status == ChannelStatus::UNCONNECTED) {
            HILOGE("invalid channelId, %{public}d", channelId);
            return -1;
        }
        socketIds.insert(socketIds.begin(),
            infoIt->second.clientSockets.begin(), infoIt->second.clientSockets.end());
    }

    for (const auto socketId : socketIds) {
        if (GetSocketStatus(socketId) == ChannelStatus::CONNECTED) {
            return socketId;
        }
    }
    return -1;
}

int32_t ChannelManager::SendStream(const int32_t channelId,
    const std::shared_ptr<AVTransStreamData>& data)
{
    if (!isValidChannelId(channelId) || data == nullptr) {
        HILOGE("invalid channel id");
        DoErrorCallback(channelId, INVALID_CHANNEL_ID);
        return INVALID_CHANNEL_ID;
    }
    HILOGD("start to send stream");
    auto func = [=]() {
        DoSendStream(channelId, data);
    };
    int32_t ret = PostTask(func, AppExecFwk::EventQueue::Priority::LOW,
        std::to_string(channelId));
    if (ret != ERR_OK) {
        HILOGE("failed to add send stream task, ret=%{public}d", ret);
        return POST_TASK_FAILED;
    }
    HILOGD("send stream task added to handler");
    return ERR_OK;
}

int32_t ChannelManager::DoSendStream(const int32_t channelId, const std::shared_ptr<AVTransStreamData>& data)
{
    HILOGD("start to send stream");
    return DoSendData(channelId, &DataSenderReceiver::SendStreamData, data);
}

int32_t ChannelManager::SendMessage(const int32_t channelId,
    const std::shared_ptr<AVTransDataBuffer>& data)
{
    if (!isValidChannelId(channelId) || data == nullptr) {
        HILOGE("invalid channel id. %{public}d", channelId);
        return INVALID_CHANNEL_ID;
    }
    HILOGD("start to send message, %{public}u", static_cast<uint32_t>(data->Size()));
    auto func = [channelId, data, this]() {
        DoSendMessage(channelId, data);
    };
    int32_t ret = PostMsgTask(func, AppExecFwk::EventQueue::Priority::HIGH);
    if (ret != ERR_OK) {
        HILOGE("failed to add send bytes task, ret=%{public}d", ret);
        return ret;
    }
    HILOGD("send message task added to handler");
    return ERR_OK;
}

int32_t ChannelManager::DoSendMessage(const int32_t channelId,
    const std::shared_ptr<AVTransDataBuffer>& data)
{
    HILOGI("start to send message");
    return DoSendData(channelId, &DataSenderReceiver::SendMessageData, data);
}

int32_t ChannelManager::SendFile(const int32_t channelId, const std::vector<std::string>& sFiles,
    const std::vector<std::string>& dFiles)
{
    HILOGI("start to send files, %{public}d", channelId);
    if (!isValidChannelId(channelId) || sFiles.empty() || dFiles.empty()) {
        HILOGE("invalid channel id. %{public}d or empty sfiles", channelId);
        return INVALID_PARAMETERS_ERR;
    }
    if (sFiles.size() != dFiles.size() || sFiles.size() > MAX_FILE_COUNT) {
        HILOGE("src size:%{public}d, dst size:%{public}d illegal",
            static_cast<int32_t>(sFiles.size()),
            static_cast<int32_t>(dFiles.size()));
    }
    int32_t ret = ERR_OK;
    auto func = [channelId, sFiles, dFiles, this]() {
        DoSendFile(channelId, sFiles, dFiles);
    };
    ret = PostTask(func, AppExecFwk::EventQueue::Priority::LOW);
    if (ret != ERR_OK) {
        HILOGE("failed to add send bytes task, ret=%{public}d", ret);
        return ret;
    }
    HILOGI("send files task added to handler");
    return ERR_OK;
}

int32_t ChannelManager::DoSendFile(const int32_t channelId, const std::vector<std::string>& sFiles,
    const std::vector<std::string>& dFiles)
{
    HILOGI("start to do send files");
    return DoSendData(channelId, &DataSenderReceiver::SendFileData, sFiles, dFiles);
}

void ChannelManager::OnBytesReceived(int32_t socketId,
    const void* data, const uint32_t dataLen)
{
    int32_t channelId = 0;
    CHECK_SOCKET_ID(socketId);
    CHECK_CHANNEL_ID(socketId, channelId);
    CHECK_DATA_NULL(socketId, data, OnError);
    HILOGI("receive data: %{public}d, len=%{public}d", socketId, dataLen);
    std::shared_ptr<AVTransDataBuffer> packedData = ProcessRecvData(channelId, socketId, data, dataLen);
    if (!packedData) {
        return;
    }
    DoBytesReceiveCallback(channelId, packedData);
}

std::shared_ptr<AVTransDataBuffer> ChannelManager::ProcessRecvData(const int32_t channelId,
    const int32_t socketId, const void* data, const uint32_t dataLen)
{
    std::shared_lock<std::shared_mutex> readLock(channelMutex_);
    const uint8_t* header = static_cast<const uint8_t*>(data);
    auto infoIt = channelInfoMap_.find(channelId);
    if (infoIt == channelInfoMap_.end()) {
        DoErrorCallback(channelId, INVALID_CHANNEL_ID);
        return nullptr;
    }

    int32_t ret = infoIt->second.dataSenderReceivers[socketId]->PackRecvPacketData(header, dataLen);
    if (ret != ERR_OK) {
        HILOGE("pack recv data failed");
        DoErrorCallback(channelId, ret);
        return nullptr;
    }
    return infoIt->second.dataSenderReceivers[socketId]->GetPacketedData();
}

void ChannelManager::DoBytesReceiveCallback(const int32_t channelId,
    const std::shared_ptr<AVTransDataBuffer>& buffer)
{
    NotifyListeners(channelId, &IChannelListener::OnBytes,
        AppExecFwk::EventQueue::Priority::LOW, buffer);
}

void ChannelManager::OnMessageReceived(int32_t socketId, const void* data, const uint32_t dataLen)
{
    HILOGI("data len = %{public}d", dataLen);
    if (dataLen > MAX_LEN) {
        HILOGE("dataLen is too long");
        return;
    }
    int32_t channelId = 0;
    CHECK_SOCKET_ID(socketId);
    CHECK_CHANNEL_ID(socketId, channelId);
    CHECK_DATA_NULL(socketId, data, OnError);
    HILOGI("receive data: %{public}d, len=%{public}d", socketId, dataLen);
    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(dataLen);
    int32_t ret = memcpy_s(buffer->Data(),
        buffer->Size(), data, dataLen);
    if (ret != ERR_OK) {
        HILOGE("pack recv data failed");
        DoErrorCallback(channelId, COPY_DATA_TO_BUFFER_FAILED);
        return;
    }
    DoMessageReceiveCallback(channelId, buffer);
}

void ChannelManager::DoMessageReceiveCallback(const int32_t channelId,
    const std::shared_ptr<AVTransDataBuffer>& buffer)
{
    NotifyListenersNew(channelId, &IChannelListener::OnMessage,
        AppExecFwk::EventQueue::Priority::HIGH, buffer);
}

void ChannelManager::OnStreamReceived(int32_t socketId, const StreamData* data,
    const StreamData* ext, const StreamFrameInfo* param)
{
    int32_t channelId = 0;
    CHECK_SOCKET_ID(socketId);
    CHECK_CHANNEL_ID(socketId, channelId);
    CHECK_DATA_NULL(socketId, data, OnError);
    CHECK_DATA_NULL(socketId, ext, OnError);
    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(data->bufLen);
    int32_t ret = memcpy_s(buffer->Data(), buffer->Size(), data->buf, data->bufLen);
    if (ret != ERR_OK) {
        HILOGE("copy stream data failed, %{public}d", socketId);
        DoErrorCallback(channelId, COPY_DATA_TO_BUFFER_FAILED);
        return;
    }
    AVTransStreamDataExt streamDataExt;
    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(buffer, streamDataExt);
    ret = streamData->DeserializeStreamDataExt(ext->buf);
    if (ret != ERR_OK) {
        HILOGE("deserialize stream ext failed, %{public}d", socketId);
        DoErrorCallback(channelId, PARSE_AV_TRANS_STREAM_EXT_FAILED);
        return;
    }
    DoStreamReceiveCallback(channelId, streamData);
}

void ChannelManager::DoStreamReceiveCallback(const int32_t channelId, const std::shared_ptr<AVTransStreamData>& data)
{
    NotifyListeners(channelId, &IChannelListener::OnStream,
        AppExecFwk::EventQueue::Priority::LOW, data);
}

void ChannelManager::OnFileEventReceived(int32_t socketId, FileEvent *event)
{
    int32_t channelId = 0;
    CHECK_SOCKET_ID(socketId);
    // update recv path before onbind
    if (event == nullptr) {
        HILOGE("socket %{public}d event empty", socketId);
        return;
    }
    if (event->type == FileEventType::FILE_EVENT_RECV_UPDATE_PATH) {
        HILOGI("start to set update path func, %{public}d", socketId);
        return DispatchProcessFileEvent(fileChannelId_.load(), event);
    }
    CHECK_CHANNEL_ID(socketId, channelId);
    CHECK_DATA_NULL(socketId, event, OnError);
    HILOGI("start to dispatch file event, %{public}d", channelId);
    DispatchProcessFileEvent(channelId, event);
}

void ChannelManager::DispatchProcessFileEvent(int32_t channelId, FileEvent *event)
{
    HILOGI("start to dispatch file event");
    switch (event->type) {
        case FileEventType::FILE_EVENT_SEND_PROCESS:
        case FileEventType::FILE_EVENT_SEND_FINISH: {
            DealFileSendEvent(channelId, event);
            break;
        }
        case FileEventType::FILE_EVENT_RECV_START:
        case FileEventType::FILE_EVENT_RECV_PROCESS:
        case FileEventType::FILE_EVENT_RECV_FINISH: {
            DealFileRecvEvent(channelId, event);
            break;
        }
        case FileEventType::FILE_EVENT_BUTT:
        case FileEventType::FILE_EVENT_SEND_ERROR:
        case FileEventType::FILE_EVENT_RECV_ERROR: {
            DealFileErrorEvent(channelId, event);
            break;
        }
        case FileEventType::FILE_EVENT_RECV_UPDATE_PATH: {
            DealFileUpdatePathEvent(channelId, event);
            break;
        }
        default:
            break;
    }
}

void ChannelManager::DealFileSendEvent(int32_t channelId, FileEvent *event)
{
    HILOGI("start to deal file send event, %{public}d", channelId);
    FileInfo info;
    if (event->type == FileEventType::FILE_EVENT_SEND_PROCESS) {
        info.commonInfo.eventType = ChannelFileEvent::SEND_PROCESS;
    } else {
        info.commonInfo.eventType = ChannelFileEvent::SEND_FINISH;
    }
    info.commonInfo.fileCnt = event->fileCnt;
    for (uint32_t i = 0; i < event->fileCnt; ++i) {
        info.commonInfo.fileList.push_back(std::string(event->files[i]));
    }

    FileSendInfo sendInfo;
    sendInfo.bytesProcessed = event->bytesProcessed;
    sendInfo.bytesTotal = event->bytesTotal;
    if (event->type == FileEventType::FILE_EVENT_SEND_PROCESS) {
        sendInfo.rate = event->rate;
    }
    info.sendInfo = sendInfo;
    DoFileSendCallback(channelId, info);
    HILOGI("end");
}

void ChannelManager::DealFileRecvEvent(int32_t channelId, FileEvent *event)
{
    HILOGI("start to deal file recv event, %{public}d", channelId);
    FileInfo info;
    if (event->type == FileEventType::FILE_EVENT_RECV_START) {
        info.commonInfo.eventType = ChannelFileEvent::RECV_START;
    } else if (event->type == FileEventType::FILE_EVENT_RECV_PROCESS) {
        info.commonInfo.eventType = ChannelFileEvent::RECV_PROCESS;
    } else {
        info.commonInfo.eventType = ChannelFileEvent::RECV_FINISH;
    }
    info.commonInfo.fileCnt = event->fileCnt;
    for (uint32_t i = 0; i < event->fileCnt; ++i) {
        info.commonInfo.fileList.push_back(std::string(event->files[i]));
    }

    FileRecvInfo recvInfo;
    recvInfo.bytesProcessed = event->bytesProcessed;
    recvInfo.bytesTotal = event->bytesTotal;
    if (event->type == FileEventType::FILE_EVENT_RECV_PROCESS) {
        recvInfo.rate = event->rate;
    }
    info.recvInfo = recvInfo;
    DoFileRecvCallback(channelId, info);
    HILOGI("end");
}

void ChannelManager::DealFileErrorEvent(int32_t channelId, FileEvent *event)
{
    HILOGI("start to deal file error event, %{public}d", channelId);
    FileInfo info;
    if (event->type == FileEventType::FILE_EVENT_SEND_ERROR) {
        info.commonInfo.eventType = ChannelFileEvent::SEND_ERROR;
    } else {
        info.commonInfo.eventType = ChannelFileEvent::RECV_ERROR;
    }
    info.commonInfo.fileCnt = event->fileCnt;
    for (uint32_t i = 0; i < event->fileCnt; ++i) {
        info.commonInfo.fileList.push_back(std::string(event->files[i]));
    }

    FileErrorInfo errorInfo;
    errorInfo.errorCode = event->errorCode;
    info.errorInfo = errorInfo;
    if (info.commonInfo.eventType == ChannelFileEvent::RECV_ERROR) {
        DoFileRecvCallback(channelId, info);
    } else {
        DoFileSendCallback(channelId, info);
    }
    HILOGI("end");
}

void ChannelManager::DealFileUpdatePathEvent(int32_t channelId, FileEvent *event)
{
    HILOGI("start to deal file update path event, %{public}d", channelId);
    event->UpdateRecvPath = GetRecvPath;
    HILOGI("end");
}

const char* ChannelManager::GetRecvPathFromUser()
{
    HILOGI("get recv path from user");
    int32_t channelId = static_cast<int32_t>(fileChannelId_.load());
    std::shared_lock<std::shared_mutex> readLock(listenerMutex_);
    auto it = listenersMap_.find(channelId);
    if (it == listenersMap_.end() || it->second.empty()) {
        HILOGE("no matching listener to %{public}d", channelId);
        return nullptr;
    }
    auto& listeners = it->second;
    for (const auto& listener : listeners) {
        if (auto ptr = listener.lock()) {
            return ptr->GetRecvPath(channelId);
        }
    }
    return nullptr;
}

void ChannelManager::DoFileRecvCallback(const int32_t channelId, const FileInfo& info)
{
    NotifyListeners(channelId, &IChannelListener::OnRecvFile,
        AppExecFwk::EventQueue::Priority::HIGH, info);
}

void ChannelManager::DoFileSendCallback(const int32_t channelId, const FileInfo& info)
{
    NotifyListeners(channelId, &IChannelListener::OnSendFile,
        AppExecFwk::EventQueue::Priority::HIGH, info);
}
}
}
