/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "distributed_intent_dsoftbus_adapter.h"

#include "distributed_intent_error_code.h"
#include "distributed_intent_provider.h"
#include "distributed_sched_utils.h"
#include "dsched_transport_softbus_adapter.h"
#include "dtbschedmgr_log.h"
#include "intent_all_connect_manager.h"
#include "remote_intent_manager.h"
#include "securec.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "socket.h"
#include "session.h"
#include "trans_type.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedIntentDsoftbusAdapter";
constexpr int32_t SOFTBUS_OK = 0;
constexpr int32_t BIND_RETRY_INTERVAL_MS = 500;
constexpr int32_t MAX_BIND_RETRY_TIMES = 8;
constexpr int32_t MS_TO_US = 1000;
constexpr uint32_t SEND_DATA_MAX_LEN = 4 * 1024 * 1024;

bool WriteFragHeader(uint8_t* buf, size_t bufLen, const FragHeader& header)
{
    size_t off = 0;
    if (memcpy_s(buf + off, bufLen - off, &header.typeValue, INTENT_FRAG_TYPE_SIZE) != EOK) {
        HILOGE("WriteFragHeader typeValue failed");
        return false;
    }
    off += INTENT_FRAG_TYPE_SIZE;
    if (memcpy_s(buf + off, bufLen - off, &header.totalLen, INTENT_FRAG_TOTAL_LEN_SIZE) != EOK) {
        HILOGE("WriteFragHeader totalLen failed");
        return false;
    }
    off += INTENT_FRAG_TOTAL_LEN_SIZE;
    if (memcpy_s(buf + off, bufLen - off, &header.seq, INTENT_FRAG_SEQ_SIZE) != EOK) {
        HILOGE("WriteFragHeader seq failed");
        return false;
    }
    off += INTENT_FRAG_SEQ_SIZE;
    if (memcpy_s(buf + off, bufLen - off, &header.flag, INTENT_FRAG_FLAG_SIZE) != EOK) {
        HILOGE("WriteFragHeader flag failed");
        return false;
    }
    return true;
}

bool ReadFragHeader(const uint8_t* buf, size_t bufLen, FragHeader& header)
{
    size_t off = 0;
    if (memcpy_s(&header.typeValue, INTENT_FRAG_TYPE_SIZE, buf + off, INTENT_FRAG_TYPE_SIZE) != EOK) {
        HILOGE("ReadFragHeader typeValue failed");
        return false;
    }
    off += INTENT_FRAG_TYPE_SIZE;
    if (memcpy_s(&header.totalLen, INTENT_FRAG_TOTAL_LEN_SIZE, buf + off, INTENT_FRAG_TOTAL_LEN_SIZE) != EOK) {
        HILOGE("ReadFragHeader totalLen failed");
        return false;
    }
    off += INTENT_FRAG_TOTAL_LEN_SIZE;
    if (memcpy_s(&header.seq, INTENT_FRAG_SEQ_SIZE, buf + off, INTENT_FRAG_SEQ_SIZE) != EOK) {
        HILOGE("ReadFragHeader seq failed");
        return false;
    }
    off += INTENT_FRAG_SEQ_SIZE;
    if (memcpy_s(&header.flag, INTENT_FRAG_FLAG_SIZE, buf + off, INTENT_FRAG_FLAG_SIZE) != EOK) {
        HILOGE("ReadFragHeader flag failed");
        return false;
    }
    return true;
}
}

static void OnIntentBindCallback(int32_t socket, PeerSocketInfo info)
{
    if (info.networkId == nullptr) {
        HILOGE("networkId is null");
        return;
    }
    std::string peerDeviceId(info.networkId);
    DistributedIntentDsoftbusAdapter::GetInstance().OnIntentBind(socket, peerDeviceId);
}

static void OnIntentShutdownCallback(int32_t socket, ShutdownReason reason)
{
    DistributedIntentDsoftbusAdapter::GetInstance().OnIntentShutdown(socket);
}

static void OnIntentBytesCallback(int32_t socket, const void *data, uint32_t dataLen)
{
    DistributedIntentDsoftbusAdapter::GetInstance().OnIntentBytes(socket, data, dataLen);
}

static ISocketListener g_intentSocketListener = {
    .OnBind = OnIntentBindCallback,
    .OnShutdown = OnIntentShutdownCallback,
    .OnBytes = OnIntentBytesCallback
};

static QosTV g_intentQosInfo[] = {
    { .qos = QOS_TYPE_MIN_BW, .value = INTENT_QOS_MIN_BW },
    { .qos = QOS_TYPE_MAX_LATENCY, .value = INTENT_QOS_MAX_LATENCY },
    { .qos = QOS_TYPE_MIN_LATENCY, .value = INTENT_QOS_MIN_LATENCY }
};

static uint32_t g_intentQosCount = sizeof(g_intentQosInfo) / sizeof(QosTV);

IMPLEMENT_SINGLE_INSTANCE(DistributedIntentDsoftbusAdapter);

DistributedIntentDsoftbusAdapter::DistributedIntentDsoftbusAdapter()
{
    HILOGI("DistributedIntentDsoftbusAdapter construct");
}

DistributedIntentDsoftbusAdapter::~DistributedIntentDsoftbusAdapter()
{
    StopSessionCleanupThread();
    std::lock_guard<std::mutex> lock(sessionMutex_);
    for (auto& iter : sessions_) {
        if (iter.second != nullptr && iter.second->socketFd > 0) {
            Shutdown(iter.second->socketFd);
        }
    }
    sessions_.clear();
}

void DistributedIntentDsoftbusAdapter::StopSessionCleanupThread()
{
    sessionCleanupRunning_.store(false);
    sessionCleanupCv_.notify_all();
    if (sessionCleanupThread_.joinable()) {
        if (sessionCleanupThread_.get_id() == std::this_thread::get_id()) {
            sessionCleanupThread_.detach();
        } else {
            sessionCleanupThread_.join();
        }
    }
}

std::shared_ptr<IntentSocketSession> DistributedIntentDsoftbusAdapter::FindClientSession(
    const std::string& deviceId)
{
    for (auto& [fd, session] : sessions_) {
        if (session && !session->isServer && session->isConnected && session->peerDeviceId == deviceId) {
            return session;
        }
    }
    return nullptr;
}

std::shared_ptr<std::mutex> DistributedIntentDsoftbusAdapter::GetDeviceMutex(const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(deviceIdMapMutex_);
    auto it = deviceIdMutexMap_.find(deviceId);
    if (it != deviceIdMutexMap_.end()) {
        return it->second;
    }
    auto mutex = std::make_shared<std::mutex>();
    deviceIdMutexMap_[deviceId] = mutex;
    return mutex;
}

void DistributedIntentDsoftbusAdapter::RemoveDeviceMutex(const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(deviceIdMapMutex_);
    deviceIdMutexMap_.erase(deviceId);
}

int32_t DistributedIntentDsoftbusAdapter::CreateIntentSocket(const std::string& deviceId)
{
    HILOGI("CreateIntentSocket for deviceId=%{public}s", GetAnonymStr(deviceId).c_str());

    SocketInfo info = {
        .name = const_cast<char*>(SOCKET_DMS_INTENT_NAME),
        .peerName = const_cast<char*>(SOCKET_DMS_INTENT_NAME),
        .peerNetworkId = const_cast<char*>(deviceId.c_str()),
        .pkgName = const_cast<char*>(SOCKET_DMS_PKG_NAME),
        .dataType = DATA_TYPE_BYTES
    };

    int32_t socketFd = Socket(info);
    if (socketFd <= 0) {
        HILOGE("Create socket failed, ret=%{public}d", socketFd);
        return ERR_DI_SOCKET_CREATE_FAILED;
    }

    HILOGI("Create socket success, socketFd=%{public}d", socketFd);
    return socketFd;
}

int32_t DistributedIntentDsoftbusAdapter::BindIntentSocket(int32_t socketFd)
{
    HILOGI("BindIntentSocket: socketFd=%{public}d", socketFd);

    int32_t ret = SOFTBUS_OK;
    int32_t retryCount = 0;
    do {
        ret = Bind(socketFd, g_intentQosInfo, g_intentQosCount, &g_intentSocketListener);
        if (ret == SOFTBUS_OK) {
            HILOGI("Bind success, socketFd=%{public}d", socketFd);
            return ERR_DI_OK;
        }

        HILOGE("Bind failed, ret=%{public}d, retry=%{public}d", ret, retryCount);
        if (ret != SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED) {
            break;
        }

        if (retryCount >= MAX_BIND_RETRY_TIMES) {
            HILOGE("Bind failed after max retries");
            break;
        }

        usleep(BIND_RETRY_INTERVAL_MS * MS_TO_US);
        retryCount++;
    } while (retryCount < MAX_BIND_RETRY_TIMES);

    return ERR_DI_SOCKET_BIND_FAILED;
}

void DistributedIntentDsoftbusAdapter::CreateSessionRecord(int32_t socketFd,
    const std::string& peerDeviceId)
{
    auto session = std::make_shared<IntentSocketSession>();
    session->peerDeviceId = peerDeviceId;
    session->socketFd = socketFd;
    session->isConnected = true;
    session->isServer = false;
    session->refCount = 1;
    session->lastActivityTime = std::chrono::steady_clock::now();

    sessions_[socketFd] = session;

    if (!sessionCleanupRunning_.load()) {
        StartSessionCleanupThread();
    }

    HILOGI("CreateSessionRecord(Client): socketFd=%{public}d, deviceId=%{public}s",
        socketFd, GetAnonymStr(peerDeviceId).c_str());
}

void DistributedIntentDsoftbusAdapter::CleanupSocketIfNeeded(int32_t socketFd)
{
    auto sessionIt = sessions_.find(socketFd);
    if (sessionIt == sessions_.end() || sessionIt->second == nullptr) {
        HILOGW("CleanupSocketIfNeeded: session not found, socketFd=%{public}d", socketFd);
        return;
    }

    std::string deviceId = sessionIt->second->peerDeviceId;
    bool isServer = sessionIt->second->isServer;
    sessions_.erase(socketFd);

    if (!isServer) {
        RemoveDeviceMutex(deviceId);
    }

    HILOGI("CleanupSocketIfNeeded: socketFd=%{public}d, deviceId=%{public}s, isServer=%{public}d",
        socketFd, GetAnonymStr(deviceId).c_str(), isServer);
}

int32_t DistributedIntentDsoftbusAdapter::ReuseOrCreateSession(const std::string& deviceId,
    int32_t& socketFd)
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    auto existingSession = FindClientSession(deviceId);
    if (existingSession != nullptr) {
        existingSession->refCount++;
        socketFd = existingSession->socketFd;
        HILOGI("Reuse Client connection, socket=%{public}d, refCount=%{public}d",
            socketFd, existingSession->refCount);
        return ERR_DI_OK;
    }

    int32_t clientSocket = CreateIntentSocket(deviceId);
    if (clientSocket <= 0) {
        HILOGE("CreateIntentSocket failed");
        return ERR_DI_SOCKET_CREATE_FAILED;
    }

    int32_t ret = BindIntentSocket(clientSocket);
    if (ret != ERR_DI_OK) {
        HILOGE("BindIntentSocket failed, ret=%{public}d", ret);
        Shutdown(clientSocket);
        return ret;
    }

    CreateSessionRecord(clientSocket, deviceId);
    socketFd = clientSocket;
    return ERR_DI_OK;
}

int32_t DistributedIntentDsoftbusAdapter::BindIntentSession(const std::string& deviceId,
    int32_t& socketFd)
{
    HILOGI("BindIntentSession: deviceId=%{public}s", GetAnonymStr(deviceId).c_str());

    if (deviceId.empty()) {
        HILOGE("deviceId is empty");
        return ERR_DI_INVALID_PARAMETER;
    }

    auto deviceMutex = GetDeviceMutex(deviceId);
    std::lock_guard<std::mutex> deviceLock(*deviceMutex);

#ifdef DMSFWK_ALL_CONNECT_MGR
    if (IntentAllConnectManager::GetInstance().IsAllConnectAvailable()
        && provider_ != nullptr && provider_->IsWifiActive()) {
        int32_t allConnectRet = IntentAllConnectManager::GetInstance().ApplyResource(deviceId);
        if (allConnectRet != ERR_OK) {
            HILOGE("AllConnect apply resource fail, ret=%{public}d", allConnectRet);
            return allConnectRet;
        }
    }
#endif

    int32_t ret = ReuseOrCreateSession(deviceId, socketFd);
    if (ret != ERR_DI_OK) {
#ifdef DMSFWK_ALL_CONNECT_MGR
        IntentAllConnectManager::GetInstance().PublishServiceState(deviceId, SCM_IDLE);
#endif
        return ret;
    }

#ifdef DMSFWK_ALL_CONNECT_MGR
    IntentAllConnectManager::GetInstance().PublishServiceState(deviceId, SCM_CONNECTED);
#endif

    HILOGI("BindIntentSession success, socketFd=%{public}d", socketFd);
    return ERR_DI_OK;
}

void DistributedIntentDsoftbusAdapter::ShutdownDeviceSession(const std::string& deviceId)
{
    HILOGI("ShutdownDeviceSession: deviceId=%{public}s", GetAnonymStr(deviceId).c_str());
    std::vector<int32_t> socketsToShutdown;
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        for (auto& [socketFd, session] : sessions_) {
            if (session != nullptr && session->peerDeviceId == deviceId) {
                socketsToShutdown.push_back(socketFd);
            }
        }
    }
    for (int32_t socketFd : socketsToShutdown) {
        HILOGI("ShutdownDeviceSession: shutdown socket=%{public}d", socketFd);
        Shutdown(socketFd);
    }
}

void DistributedIntentDsoftbusAdapter::ForceCleanupDeviceSessions(const std::string& deviceId,
    std::vector<int32_t>& closedSockets)
{
    HILOGI("ForceCleanupDeviceSessions: deviceId=%{public}s", GetAnonymStr(deviceId).c_str());
    bool shouldStopThread = false;
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            if (it->second != nullptr && it->second->peerDeviceId == deviceId) {
                closedSockets.push_back(it->first);
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
        if (sessions_.empty()) {
            shouldStopThread = true;
        }
    }
    for (int32_t socketFd : closedSockets) {
        HILOGI("ForceCleanupDeviceSessions: shutdown socket=%{public}d", socketFd);
        Shutdown(socketFd);
    }
    if (shouldStopThread) {
        StopSessionCleanupThread();
    }
    HILOGI("ForceCleanupDeviceSessions: cleaned=%{public}zu sockets", closedSockets.size());
}

void DistributedIntentDsoftbusAdapter::UnbindIntentSession(int32_t socketFd)
{
    HILOGI("UnbindIntentSession: socketFd=%{public}d", socketFd);

    bool shouldStopThread = false;
    bool needShutdown = false;
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);

        auto sessionIt = sessions_.find(socketFd);
        if (sessionIt == sessions_.end() || sessionIt->second == nullptr) {
            HILOGW("Session not found, socketFd=%{public}d", socketFd);
            return;
        }

        auto& session = sessionIt->second;

        if (session->isServer) {
            HILOGI("Server socket=%{public}d, skip unbind, wait for peer shutdown", socketFd);
            return;
        }

        session->refCount--;
        HILOGI("UnbindIntentSession: socketFd=%{public}d, refCount=%{public}d",
            socketFd, session->refCount);

        if (session->refCount <= 0) {
#ifdef DMSFWK_ALL_CONNECT_MGR
            IntentAllConnectManager::GetInstance().PublishServiceState(
                session->peerDeviceId, SCM_IDLE);
#endif
            CleanupSocketIfNeeded(socketFd);
            needShutdown = true;
            if (sessions_.empty()) {
                shouldStopThread = true;
            }
        }
    }

    if (needShutdown) {
        Shutdown(socketFd);
    }
    if (shouldStopThread) {
        StopSessionCleanupThread();
    }
}

int32_t DistributedIntentDsoftbusAdapter::SendNoFrag(int32_t socketFd,
    uint32_t typeValue, uint32_t totalLen, const std::string& data)
{
    std::vector<uint8_t> frame(INTENT_FRAG_HEADER_SIZE + totalLen);
    if (!WriteFragHeader(frame.data(), frame.size(), {typeValue, totalLen, 0, FRAG_START_END})) {
        HILOGE("WriteFragHeader failed");
        return ERR_DI_DATA_SEND_FAILED;
    }
    if (totalLen > 0 && memcpy_s(frame.data() + INTENT_FRAG_HEADER_SIZE,
        frame.size() - INTENT_FRAG_HEADER_SIZE, data.data(), totalLen) != EOK) {
        HILOGE("memcpy_s payload failed");
        return ERR_DI_DATA_SEND_FAILED;
    }

    int32_t ret = SendBytes(socketFd, frame.data(), frame.size());
    if (ret != SOFTBUS_OK) {
        HILOGE("SendBytes failed, ret=%{public}d", ret);
        return ERR_DI_DATA_SEND_FAILED;
    }
    UpdateSessionActivity(socketFd);
    HILOGI("SendIntentDataBySession success(no frag), socketFd=%{public}d, size=%{public}u",
        socketFd, totalLen);
    return ERR_DI_OK;
}

int32_t DistributedIntentDsoftbusAdapter::SendFrag(int32_t socketFd, uint32_t typeValue,
    uint32_t totalLen, const std::string& data, uint32_t maxSendSize)
{
    uint32_t fragPayload = maxSendSize - INTENT_FRAG_HEADER_SIZE;
    uint16_t seq = 0;
    uint32_t offset = 0;

    while (offset < totalLen) {
        uint32_t remain = totalLen - offset;
        uint32_t chunkLen = (remain > fragPayload) ? fragPayload : remain;
        uint8_t flag;
        if (offset == 0) {
            flag = FRAG_START;
        } else if (offset + chunkLen >= totalLen) {
            flag = FRAG_END;
        } else {
            flag = FRAG_MID;
        }

        std::vector<uint8_t> frame(INTENT_FRAG_HEADER_SIZE + chunkLen);
        if (!WriteFragHeader(frame.data(), frame.size(), {typeValue, totalLen, seq, flag})) {
            HILOGE("WriteFragHeader failed, seq=%{public}u", seq);
            return ERR_DI_DATA_SEND_FAILED;
        }
        if (memcpy_s(frame.data() + INTENT_FRAG_HEADER_SIZE,
            frame.size() - INTENT_FRAG_HEADER_SIZE,
            data.data() + offset, chunkLen) != EOK) {
            HILOGE("memcpy_s frag payload failed, seq=%{public}u", seq);
            return ERR_DI_DATA_SEND_FAILED;
        }

        int32_t ret = SendBytes(socketFd, frame.data(), frame.size());
        if (ret != SOFTBUS_OK) {
            HILOGE("SendBytes frag failed, ret=%{public}d, seq=%{public}u", ret, seq);
            return ERR_DI_DATA_SEND_FAILED;
        }

        offset += chunkLen;
        seq++;
    }

    UpdateSessionActivity(socketFd);
    HILOGI("SendIntentDataBySession success(frag), socketFd=%{public}d, totalSize=%{public}u, frags=%{public}u",
        socketFd, totalLen, seq);
    return ERR_DI_OK;
}

int32_t DistributedIntentDsoftbusAdapter::SendIntentDataBySession(int32_t socketFd,
    IntentDataType dataType, const std::string& data)
{
    if (socketFd < 0) {
        HILOGE("Invalid socketFd=%{public}d", socketFd);
        return ERR_DI_INVALID_PARAMETER;
    }

    if (data.empty() || data.size() > MAX_SEND_BYTES_SIZE) {
        HILOGE("Invalid data, size=%{public}zu", data.size());
        return ERR_DI_INVALID_PARAMETER;
    }

    std::lock_guard<std::mutex> lock(sessionMutex_);

    auto sessionIt = sessions_.find(socketFd);
    if (sessionIt == sessions_.end() || sessionIt->second == nullptr) {
        HILOGE("Session not found, socketFd=%{public}d", socketFd);
        return ERR_DI_SOCKET_NOT_CONNECTED;
    }

    if (!sessionIt->second->isConnected) {
        HILOGE("Session not connected, socketFd=%{public}d", socketFd);
        return ERR_DI_SOCKET_NOT_CONNECTED;
    }

    uint32_t typeValue = static_cast<uint32_t>(dataType);
    uint32_t totalLen = static_cast<uint32_t>(data.size());

    uint32_t maxSendSize = 0;
    int32_t ret = GetSessionOption(socketFd, SESSION_OPTION_MAX_SENDBYTES_SIZE,
        &maxSendSize, sizeof(maxSendSize));
    if (ret != SOFTBUS_OK || maxSendSize <= INTENT_MIN_SEND_SIZE) {
        HILOGW("GetSessionOption failed, use default maxSendSize");
        maxSendSize = SEND_DATA_MAX_LEN;
    }

    if (totalLen + INTENT_FRAG_HEADER_SIZE <= maxSendSize) {
        return SendNoFrag(socketFd, typeValue, totalLen, data);
    }

    return SendFrag(socketFd, typeValue, totalLen, data, maxSendSize);
}

void DistributedIntentDsoftbusAdapter::OnIntentBind(int32_t socket,
    const std::string& peerDeviceId)
{
    HILOGI("OnIntentBind: socket=%{public}d, peerDeviceId=%{public}s",
        socket, GetAnonymStr(peerDeviceId).c_str());

    if (stopped_.load()) {
        HILOGW("Adapter stopped, ignore OnIntentBind");
        return;
    }

    std::lock_guard<std::mutex> lock(sessionMutex_);

    auto session = std::make_shared<IntentSocketSession>();
    session->peerDeviceId = peerDeviceId;
    session->socketFd = socket;
    session->isConnected = true;
    session->isServer = true;
    session->refCount = 0;
    session->lastActivityTime = std::chrono::steady_clock::now();
    sessions_[socket] = session;

    HILOGI("OnIntentBind(Server): socket=%{public}d, deviceId=%{public}s",
        socket, GetAnonymStr(peerDeviceId).c_str());
}

void DistributedIntentDsoftbusAdapter::OnIntentShutdown(int32_t socket)
{
    HILOGI("OnIntentShutdown: socket=%{public}d", socket);

    if (stopped_.load()) {
        HILOGW("Adapter stopped, ignore OnIntentShutdown");
        return;
    }

    std::string deviceId;
    bool shouldStopThread = false;
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);

        auto sessionIt = sessions_.find(socket);
        if (sessionIt == sessions_.end() || sessionIt->second == nullptr) {
            HILOGW("Session not found, socket=%{public}d", socket);
            return;
        }

        deviceId = sessionIt->second->peerDeviceId;
        CleanupSocketIfNeeded(socket);

        if (sessions_.empty()) {
            shouldStopThread = true;
        }
    }

    Shutdown(socket);
#ifdef DMSFWK_ALL_CONNECT_MGR
    IntentAllConnectManager::GetInstance().PublishServiceState(deviceId, SCM_IDLE);
#endif
    RemoteIntentManager::GetInstance().CleanupSocketMapping(deviceId, socket);
    RemoteIntentManager::GetInstance().NotifyLinkDisconnected(
        deviceId, INTENT_LINK_DISCONNECT_REASON_SHUTDOWN);
    HILOGI("OnIntentShutdown: cleaned up, socket=%{public}d, deviceId=%{public}s",
        socket, GetAnonymStr(deviceId).c_str());

    if (shouldStopThread) {
        StopSessionCleanupThread();
    }
}

void DistributedIntentDsoftbusAdapter::OnIntentBytes(int32_t socket,
    const void* data, uint32_t dataLen)
{
    HILOGD("OnIntentBytes: socket=%{public}d, dataLen=%{public}u", socket, dataLen);

    if (stopped_.load()) {
        return;
    }
    ProcessReceivedData(socket, data, dataLen);
}

void DistributedIntentDsoftbusAdapter::DeliverIntentData(int32_t socketFd,
    IntentDataType dataType, const std::string& payload)
{
    std::string peerDeviceId;
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        peerDeviceId = GetPeerDeviceIdBySocket(socketFd);
        if (peerDeviceId.empty()) {
            HILOGE("Failed to get peerDeviceId, socketFd=%{public}d", socketFd);
            return;
        }
        UpdateSessionActivity(socketFd);
    }
    RemoteIntentManager::GetInstance().OnIntentDataReceived(peerDeviceId, dataType, payload, socketFd);
}

void DistributedIntentDsoftbusAdapter::ProcessReceivedData(int32_t socketFd,
    const void* data, uint32_t dataLen)
{
    if (data == nullptr || dataLen < INTENT_FRAG_HEADER_SIZE) {
        HILOGE("Invalid data, dataLen=%{public}u, minRequired=%{public}zu", dataLen, INTENT_FRAG_HEADER_SIZE);
        return;
    }

    const uint8_t* bytes = static_cast<const uint8_t*>(data);

    FragHeader header;
    if (!ReadFragHeader(bytes, dataLen, header)) {
        HILOGE("ReadFragHeader failed, socketFd=%{public}d", socketFd);
        return;
    }

    uint32_t payloadLen = dataLen - INTENT_FRAG_HEADER_SIZE;
    std::string payload;
    if (payloadLen > 0 && payloadLen <= MAX_SEND_BYTES_SIZE) {
        payload.resize(payloadLen);
        if (memcpy_s(payload.data(), payloadLen, bytes + INTENT_FRAG_HEADER_SIZE, payloadLen) != EOK) {
            HILOGE("memcpy_s payload failed, socketFd=%{public}d", socketFd);
            return;
        }
    }

    IntentDataType dataType = static_cast<IntentDataType>(header.typeValue);

    if (header.flag == FRAG_START_END) {
        DeliverIntentData(socketFd, dataType, payload);
        return;
    }

    ProcessFragFrame(socketFd, header.typeValue, header.totalLen, header.seq, header.flag, payload);
}

std::string DistributedIntentDsoftbusAdapter::AssembleFragPayload(int32_t socketFd,
    std::shared_ptr<IntentFragBuffer>& fragBuf)
{
    std::string fullPayload;
    fullPayload.reserve(fragBuf->totalLen);
    for (auto& [s, frag] : fragBuf->fragments) {
        fullPayload.append(frag);
    }

    {
        std::lock_guard<std::mutex> lock(fragMutex_);
        fragBuffers_.erase(socketFd);
    }

    HILOGI("Frag reassembly complete, socketFd=%{public}d, totalSize=%{public}zu",
        socketFd, fullPayload.size());
    return fullPayload;
}

void DistributedIntentDsoftbusAdapter::ProcessFragFrame(int32_t socketFd, uint32_t dataType,
    uint32_t totalLen, uint16_t seq, uint8_t flag, const std::string& payload)
{
    HILOGI("ProcessFragFrame: socketFd=%{public}d, dataType=%{public}u, totalLen=%{public}u, "
        "seq=%{public}u, flag=%{public}u, payloadLen=%{public}zu",
        socketFd, dataType, totalLen, seq, flag, payload.size());

    if (flag == FRAG_START) {
        std::lock_guard<std::mutex> lock(fragMutex_);
        auto fragBuf = std::make_shared<IntentFragBuffer>();
        fragBuf->dataType = dataType;
        fragBuf->totalLen = totalLen;
        fragBuf->expectedSeq = 1;
        fragBuf->fragments[seq] = payload;
        fragBuffers_[socketFd] = fragBuf;
        return;
    }

    std::shared_ptr<IntentFragBuffer> fragBuf;
    {
        std::lock_guard<std::mutex> lock(fragMutex_);
        auto it = fragBuffers_.find(socketFd);
        if (it == fragBuffers_.end() || it->second == nullptr) {
            HILOGE("No frag buffer for socketFd=%{public}d", socketFd);
            return;
        }
        fragBuf = it->second;
    }

    if (seq != fragBuf->expectedSeq) {
        HILOGE("Unexpected seq=%{public}u, expected=%{public}u, socketFd=%{public}d",
            seq, fragBuf->expectedSeq, socketFd);
        std::lock_guard<std::mutex> lock(fragMutex_);
        fragBuffers_.erase(socketFd);
        return;
    }

    fragBuf->fragments[seq] = payload;
    fragBuf->expectedSeq++;

    if (flag != FRAG_END) {
        return;
    }

    std::string fullPayload = AssembleFragPayload(socketFd, fragBuf);
    IntentDataType intentDataType = static_cast<IntentDataType>(dataType);
    DeliverIntentData(socketFd, intentDataType, fullPayload);
}

std::string DistributedIntentDsoftbusAdapter::GetPeerDeviceIdBySocket(int32_t socketFd)
{
    auto sessionIt = sessions_.find(socketFd);
    if (sessionIt != sessions_.end() && sessionIt->second != nullptr) {
        return sessionIt->second->peerDeviceId;
    }
    return "";
}

int32_t DistributedIntentDsoftbusAdapter::GetSocketFdByDeviceId(const std::string& deviceId)
{
    std::lock_guard<std::mutex> lock(sessionMutex_);
    auto session = FindClientSession(deviceId);
    if (session != nullptr) {
        return session->socketFd;
    }
    return INVALID_SOCKET_FD;
}

void DistributedIntentDsoftbusAdapter::UpdateSessionActivity(int32_t socketFd)
{
    auto it = sessions_.find(socketFd);
    if (it != sessions_.end() && it->second != nullptr) {
        it->second->lastActivityTime = std::chrono::steady_clock::now();
    }
}

void DistributedIntentDsoftbusAdapter::CleanupIdleSessions()
{
    auto now = std::chrono::steady_clock::now();
    std::vector<std::pair<int32_t, std::string>> closedSessions;
    
    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        for (auto it = sessions_.begin(); it != sessions_.end();) {
            auto& session = it->second;
            if (session == nullptr) {
                ++it;
                continue;
            }

            if (session->isServer) {
                ++it;
                continue;
            }

            auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                now - session->lastActivityTime).count();
            if (elapsed > SESSION_IDLE_TIMEOUT_MS) {
                HILOGW("Session idle expired, socketFd=%{public}d, elapsed=%{public}lldms, refCount=%{public}d",
                    session->socketFd, static_cast<long long>(elapsed), session->refCount);

                closedSessions.emplace_back(session->socketFd, session->peerDeviceId);
                RemoveDeviceMutex(session->peerDeviceId);
                it = sessions_.erase(it);
            } else {
                ++it;
            }
        }
    }

    for (auto& [socketFd, deviceId] : closedSessions) {
        Shutdown(socketFd);
#ifdef DMSFWK_ALL_CONNECT_MGR
        IntentAllConnectManager::GetInstance().PublishServiceState(deviceId, SCM_IDLE);
#endif
        RemoteIntentManager::GetInstance().CleanupSocketMapping(deviceId, socketFd);
        RemoteIntentManager::GetInstance().NotifyLinkDisconnected(
            deviceId, INTENT_LINK_DISCONNECT_REASON_IDLE_TIMEOUT);
    }

    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        if (sessions_.empty()) {
            sessionCleanupRunning_.store(false);
            HILOGI("All sessions cleaned, cleanup thread will exit");
        }
    }
}

void DistributedIntentDsoftbusAdapter::StartSessionCleanupThread()
{
    if (sessionCleanupRunning_.exchange(true)) {
        return;
    }
    if (sessionCleanupThread_.joinable()) {
        sessionCleanupThread_.detach();
    }
    sessionCleanupThread_ = std::thread([]() {
        auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
        HILOGI("Session cleanup thread started");
        while (adapter.sessionCleanupRunning_.load()) {
            {
                std::unique_lock<std::mutex> lock(adapter.sessionCleanupMutex_);
                adapter.sessionCleanupCv_.wait_for(lock,
                    std::chrono::milliseconds(SESSION_CLEANUP_INTERVAL_MS),
                    [&adapter]() { return !adapter.sessionCleanupRunning_.load(); });
            }
            if (!adapter.sessionCleanupRunning_.load()) {
                break;
            }
            adapter.CleanupIdleSessions();
        }
        HILOGI("Session cleanup thread stopped");
    });
}

} // namespace DistributedSchedule
} // namespace OHOS
