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

#include "dtbschedmgr_log.h"
#include "distributed_sched_utils.h"
#include "dsched_transport_softbus_adapter.h"
#include "remote_intent_manager.h"
#include "distributed_intent_error_code.h"
#include "securec.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#ifdef DMSFWK_ALL_CONNECT_MGR
#include "dsched_all_connect_manager.h"
#endif

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedIntentDsoftbusAdapter";
constexpr int32_t SOFTBUS_OK = 0;
constexpr int32_t BIND_RETRY_INTERVAL_MS = 500;
constexpr int32_t MAX_BIND_RETRY_TIMES = 8;
constexpr int32_t MS_TO_US = 1000;
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

std::shared_ptr<IntentSocketSession> DistributedIntentDsoftbusAdapter::FindClientSession(
    const std::string& deviceId)
{
    for (auto& [fd, session] : sessions_) {
        if (session && !session->isServer && session->isConnected
            && session->peerDeviceId == deviceId) {
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

    {
        std::lock_guard<std::mutex> lock(sessionMutex_);
        CreateSessionRecord(clientSocket, deviceId);
    }
    socketFd = clientSocket;
    HILOGI("BindIntentSession success, socketFd=%{public}d", socketFd);
    return ERR_DI_OK;
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
    size_t headerSize = sizeof(uint32_t);
    size_t frameSize = headerSize + data.size();
    std::vector<uint8_t> frame(frameSize);

    size_t offset = 0;
    int32_t ret = memcpy_s(frame.data() + offset, sizeof(uint32_t), &typeValue, sizeof(uint32_t));
    if (ret != 0) {
        HILOGE("memcpy_s type failed, ret=%{public}d", ret);
        return ERR_DI_DATA_SEND_FAILED;
    }
    offset += sizeof(uint32_t);

    ret = memcpy_s(frame.data() + offset, data.size(), data.data(), data.size());
    if (ret != 0) {
        HILOGE("memcpy_s data failed, ret=%{public}d", ret);
        return ERR_DI_DATA_SEND_FAILED;
    }

    ret = SendBytes(socketFd, frame.data(), frameSize);
    if (ret != SOFTBUS_OK) {
        HILOGE("SendBytes failed, ret=%{public}d, socketFd=%{public}d", ret, socketFd);
        return ERR_DI_DATA_SEND_FAILED;
    }

    UpdateSessionActivity(socketFd);

    HILOGI("SendIntentDataBySession success, socketFd=%{public}d, dataType=%{public}u, size=%{public}zu",
        socketFd, typeValue, data.size());
    return ERR_DI_OK;
}

void DistributedIntentDsoftbusAdapter::OnIntentBind(int32_t socket,
    const std::string& peerDeviceId)
{
    HILOGI("OnIntentBind: socket=%{public}d, peerDeviceId=%{public}s",
        socket, GetAnonymStr(peerDeviceId).c_str());

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
    ProcessReceivedData(socket, data, dataLen);
}

void DistributedIntentDsoftbusAdapter::ProcessReceivedData(int32_t socketFd,
    const void* data, uint32_t dataLen)
{
    size_t headerSize = sizeof(uint32_t);
    if (data == nullptr || dataLen < headerSize) {
        HILOGE("Invalid data, dataLen=%{public}u, minRequired=%{public}zu", dataLen, headerSize);
        return;
    }

    const uint8_t* bytes = static_cast<const uint8_t*>(data);

    uint32_t typeValue = 0;
    int32_t ret = memcpy_s(&typeValue, sizeof(uint32_t), bytes, sizeof(uint32_t));
    if (ret != 0) {
        HILOGE("memcpy_s type failed");
        return;
    }

    uint32_t payloadLen = dataLen - headerSize;
    std::string payload;
    if (payloadLen > 0 &&  payloadLen <= MAX_SEND_BYTES_SIZE) {
        payload.resize(payloadLen);
        ret = memcpy_s(payload.data(), payloadLen, bytes + headerSize, payloadLen);
        if (ret != 0) {
            HILOGE("memcpy_s payload failed");
            return;
        }
    }

    IntentDataType dataType = static_cast<IntentDataType>(typeValue);

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
    sessionCleanupThread_ = std::thread([this]() {
        HILOGI("Session cleanup thread started");
        while (sessionCleanupRunning_.load()) {
            {
                std::unique_lock<std::mutex> lock(sessionCleanupMutex_);
                sessionCleanupCv_.wait_for(lock,
                    std::chrono::milliseconds(SESSION_CLEANUP_INTERVAL_MS),
                    [this]() { return !sessionCleanupRunning_.load(); });
            }
            if (!sessionCleanupRunning_.load()) {
                break;
            }
            CleanupIdleSessions();
        }
        HILOGI("Session cleanup thread stopped");
    });
}

void DistributedIntentDsoftbusAdapter::StopSessionCleanupThread()
{
    sessionCleanupRunning_.store(false);
    sessionCleanupCv_.notify_all();
    if (sessionCleanupThread_.joinable()) {
        sessionCleanupThread_.join();
    }
}

} // namespace DistributedSchedule
} // namespace OHOS
