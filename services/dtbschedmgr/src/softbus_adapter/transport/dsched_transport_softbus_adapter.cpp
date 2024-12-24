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

#include "dsched_transport_softbus_adapter.h"

#include "distributed_sched_utils.h"
#include "dsched_all_connect_manager.h"
#include "dsched_collab_manager.h"
#include "dsched_continue_manager.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "mission/wifi_state_adapter.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "token_setproc.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedTransportSoftbusAdapter";
constexpr int32_t INVALID_SESSION_ID = -1;
}

IMPLEMENT_SINGLE_INSTANCE(DSchedTransportSoftbusAdapter);

static QosTV g_qosInfo[] = {
    { .qos = QOS_TYPE_MIN_BW, .value = DSCHED_QOS_TYPE_MIN_BW },
    { .qos = QOS_TYPE_MAX_LATENCY, .value = DSCHED_QOS_TYPE_MAX_LATENCY },
    { .qos = QOS_TYPE_MIN_LATENCY, .value = DSCHED_QOS_TYPE_MIN_LATENCY }
};
static uint32_t g_QosTV_Param_Index = static_cast<uint32_t>(sizeof(g_qosInfo) / sizeof(QosTV));

static void OnBind(int32_t socket, PeerSocketInfo info)
{
    std::string peerDeviceId(info.networkId);
    DSchedTransportSoftbusAdapter::GetInstance().OnBind(socket, peerDeviceId);
}

static void OnShutdown(int32_t socket, ShutdownReason reason)
{
    DSchedTransportSoftbusAdapter::GetInstance().OnShutdown(socket, false);
}

static void OnBytes(int32_t socket, const void *data, uint32_t dataLen)
{
    DSchedTransportSoftbusAdapter::GetInstance().OnBytes(socket, data, dataLen);
}

ISocketListener iSocketListener = {
    .OnBind = OnBind,
    .OnShutdown = OnShutdown,
    .OnBytes = OnBytes
};

DSchedTransportSoftbusAdapter::DSchedTransportSoftbusAdapter()
{
}

DSchedTransportSoftbusAdapter::~DSchedTransportSoftbusAdapter()
{
}

int32_t DSchedTransportSoftbusAdapter::InitChannel()
{
    HILOGI("start init channel");
    int32_t ret = ERR_OK;
#ifdef DMSFWK_ALL_CONNECT_MGR
    ret = DSchedAllConnectManager::GetInstance().InitAllConnectManager();
    if (ret != ERR_OK) {
        HILOGE("Init all connect manager fail, ret: %{public}d.", ret);
        isAllConnectExist_ = false;
    }
#endif

    serverSocket_ = CreateServerSocket();
    if (serverSocket_ <= 0) {
        HILOGE("create socket failed, ret: %{public}d", serverSocket_);
        return serverSocket_;
    }

    ret = Listen(serverSocket_, g_qosInfo, g_QosTV_Param_Index, &iSocketListener);
    if (ret != ERR_OK) {
        HILOGE("service listen failed, ret: %{public}d", ret);
        return ret;
    }
    HILOGI("end");
    return ERR_OK;
}

int32_t DSchedTransportSoftbusAdapter::CreateServerSocket()
{
    HILOGI("start");
    localSessionName_ = SOCKET_DMS_SESSION_NAME;
    SocketInfo info = {
        .name = const_cast<char*>(localSessionName_.c_str()),
        .pkgName = const_cast<char*>(SOCKET_DMS_PKG_NAME.c_str()),
        .dataType = DATA_TYPE_BYTES
    };
    int32_t socket = Socket(info);
    HILOGI("finish, socket session id: %{public}d", socket);
    return socket;
}

int32_t DSchedTransportSoftbusAdapter::ConnectDevice(const std::string &peerDeviceId,
    int32_t &sessionId, DSchedServiceType type)
{
    HILOGI("try to connect peer: %{public}s.", GetAnonymStr(peerDeviceId).c_str());
    {
        std::lock_guard<std::mutex> sessionLock(sessionMutex_);
        if (!sessions_.empty()) {
            for (auto iter = sessions_.begin(); iter != sessions_.end(); iter++) {
                if (iter->second != nullptr && peerDeviceId == iter->second->GetPeerDeviceId()) {
                    HILOGI("peer device already connected");
                    iter->second->OnConnect();
                    sessionId = iter->first;
#ifdef DMSFWK_ALL_CONNECT_MGR
                    NotifyConnectDecision(peerDeviceId, type);
#endif
                    return ERR_OK;
                }
            }
        }
    }
    int32_t ret = ERR_OK;
    if (IsNeedAllConnect()) {
        HILOGI("waiting all connect decision");
        ret = DecisionByAllConnect(peerDeviceId, type);
        if (ret != ERR_OK) {
            HILOGE("decision fail, ret: %{public}d", ret);
            return ret;
        }
    }
    ret = AddNewPeerSession(peerDeviceId, sessionId);
    if (ret != ERR_OK || sessionId <= 0) {
        HILOGE("Add new peer connect session fail, ret: %{public}d, sessionId: %{public}d.", ret, sessionId);
    }
    return ret;
}

void DSchedTransportSoftbusAdapter::NotifyConnectDecision(const std::string &peerDeviceId, DSchedServiceType type)
{
    if (!IsNeedAllConnect()) {
        HILOGW("don't need notify all connect decision");
        return;
    }
    if (type == SERVICE_TYPE_CONTINUE) {
        DSchedContinueManager::GetInstance().NotifyAllConnectDecision(peerDeviceId, true);
    } else if (type == SERVICE_TYPE_COLLAB) {
        DSchedCollabManager::GetInstance().NotifyAllConnectDecision(peerDeviceId, true);
    }
}

int32_t DSchedTransportSoftbusAdapter::DecisionByAllConnect(const std::string &peerDeviceId, DSchedServiceType type)
{
#ifdef DMSFWK_ALL_CONNECT_MGR
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    DSchedAllConnectManager::GetInstance().GetResourceRequest(reqInfoSets);
    int32_t ret = DSchedAllConnectManager::GetInstance().ApplyAdvanceResource(peerDeviceId, reqInfoSets);
    if (ret != ERR_OK) {
        HILOGE("Apply advance resource fail, ret: %{public}d.", ret);
        NotifyConnectDecision(peerDeviceId, type);
        return ret;
    }
    NotifyConnectDecision(peerDeviceId, type);
    ret = DSchedAllConnectManager::GetInstance().PublishServiceState(peerDeviceId, "", SCM_PREPARE);
    if (ret != ERR_OK) {
        HILOGE("Publish prepare state fail, ret %{public}d, peerDeviceId %{public}s.",
            ret, GetAnonymStr(peerDeviceId).c_str());
    }
#endif
    return ERR_OK;
}


bool DSchedTransportSoftbusAdapter::IsNeedAllConnect()
{
    bool result = isAllConnectExist_ && WifiStateAdapter::GetInstance().IsWifiActive();
    HILOGI("called, result: %{public}d", result);
    return result;
}

int32_t DSchedTransportSoftbusAdapter::AddNewPeerSession(const std::string &peerDeviceId, int32_t &sessionId)
{
    int32_t ret = ERR_OK;
    sessionId = CreateClientSocket(peerDeviceId);
    if (sessionId <= 0) {
        HILOGE("create socket failed, sessionId: %{public}d.", sessionId);
#ifdef DMSFWK_ALL_CONNECT_MGR
        ret = DSchedAllConnectManager::GetInstance().PublishServiceState(peerDeviceId, "", SCM_IDLE);
        if (ret != ERR_OK) {
            HILOGE("Publish idle state fail, ret %{public}d, peerDeviceId %{public}s, sessionId %{public}d.",
                ret, GetAnonymStr(peerDeviceId).c_str(), sessionId);
        }
#endif
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }

    ret = SetFirstCallerTokenID(callingTokenId_);
    HILOGD("SetFirstCallerTokenID callingTokenId: %{public}s, ret: %{public}d",
        GetAnonymStr(std::to_string(callingTokenId_)).c_str(), ret);
    callingTokenId_ = 0;

    do {
        HILOGI("bind begin");
        ret = Bind(sessionId, g_qosInfo, g_QosTV_Param_Index, &iSocketListener);
        HILOGI("bind end");
        if (ret != ERR_OK) {
            HILOGE("client bind failed, ret: %{public}d", ret);
            break;
        }

        ret = CreateSessionRecord(sessionId, peerDeviceId, false);
        if (ret != ERR_OK) {
            HILOGE("Client create session record fail, ret %{public}d, peerDeviceId %{public}s, sessionId %{public}d.",
                ret, GetAnonymStr(peerDeviceId).c_str(), sessionId);
            break;
        }
    } while (false);

    if (ret != ERR_OK) {
        ShutdownSession(peerDeviceId, sessionId);
        sessionId = INVALID_SESSION_ID;
    }
    return ret;
}

int32_t DSchedTransportSoftbusAdapter::CreateClientSocket(const std::string &peerDeviceId)
{
    HILOGI("start");
    SocketInfo info = {
        .name = const_cast<char*>(SOCKET_DMS_SESSION_NAME.c_str()),
        .peerName = const_cast<char*>(SOCKET_DMS_SESSION_NAME.c_str()),
        .peerNetworkId = const_cast<char*>(peerDeviceId.c_str()),
        .pkgName = const_cast<char*>(SOCKET_DMS_PKG_NAME.c_str()),
        .dataType = DATA_TYPE_BYTES
    };
    int32_t sessionId = Socket(info);
    HILOGI("finish, socket session id: %{public}d", sessionId);
    return sessionId;
}

int32_t DSchedTransportSoftbusAdapter::CreateSessionRecord(int32_t sessionId, const std::string &peerDeviceId,
    bool isServer)
{
    std::string localDeviceId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId)) {
        HILOGE("GetLocalDeviceId failed");
        ShutdownSession(peerDeviceId, sessionId);
        return GET_LOCAL_DEVICE_ERR;
    }
    {
        std::lock_guard<std::mutex> sessionLock(sessionMutex_);
        std::string sessionName = SOCKET_DMS_SESSION_NAME;
        SessionInfo info = { sessionId, localDeviceId, peerDeviceId, sessionName, isServer };
        auto session = std::make_shared<DSchedSoftbusSession>(info);
        sessions_[sessionId] = session;
    }

#ifdef DMSFWK_ALL_CONNECT_MGR
    int32_t ret = DSchedAllConnectManager::GetInstance().PublishServiceState(peerDeviceId, "", SCM_CONNECTED);
    if (ret != ERR_OK) {
        HILOGE("Publish connected state fail, ret %{public}d, peerDeviceId %{public}s, sessionId %{public}d.",
            ret, GetAnonymStr(peerDeviceId).c_str(), sessionId);
    }
#endif
    return ERR_OK;
}

void DSchedTransportSoftbusAdapter::DisconnectDevice(const std::string &peerDeviceId)
{
    HILOGI("try to disconnect peer: %{public}s.", GetAnonymStr(peerDeviceId).c_str());
    int32_t sessionId = 0;
    std::lock_guard<std::mutex> sessionLock(sessionMutex_);
    for (auto iter = sessions_.begin(); iter != sessions_.end(); iter++) {
        if (iter->second != nullptr && peerDeviceId == iter->second->GetPeerDeviceId()) {
            sessionId = iter->first;
            break;
        }
    }
    if (sessionId != 0 && sessions_[sessionId] != nullptr && sessions_[sessionId]->OnDisconnect()) {
        HILOGI("peer %{public}s shutdown, socket sessionId: %{public}d.",
            GetAnonymStr(sessions_[sessionId]->GetPeerDeviceId()).c_str(), sessionId);
        ShutdownSession(peerDeviceId, sessionId);
        sessions_.erase(sessionId);
        NotifyListenersSessionShutdown(sessionId, true);
    }
    HILOGI("finish, socket session id: %{public}d", sessionId);
    return;
}

void DSchedTransportSoftbusAdapter::ShutdownSession(const std::string &peerDeviceId, int32_t sessionId)
{
    Shutdown(sessionId);
#ifdef DMSFWK_ALL_CONNECT_MGR
    int32_t ret = DSchedAllConnectManager::GetInstance().PublishServiceState(peerDeviceId, "", SCM_IDLE);
    if (ret != ERR_OK) {
        HILOGE("Publish idle state fail, ret %{public}d, peerDeviceId %{public}s, sessionId %{public}d.",
            ret, GetAnonymStr(peerDeviceId).c_str(), sessionId);
    }
#endif
}

bool DSchedTransportSoftbusAdapter::GetSessionIdByDeviceId(const std::string &peerDeviceId, int32_t &sessionId)
{
    std::lock_guard<std::mutex> sessionLock(sessionMutex_);
    for (auto iter = sessions_.begin(); iter != sessions_.end(); iter++) {
        if (iter->second != nullptr && peerDeviceId == iter->second->GetPeerDeviceId()) {
            sessionId = iter->first;
            return true;
        }
    }
    return false;
}

void DSchedTransportSoftbusAdapter::OnBind(int32_t sessionId, const std::string &peerDeviceId)
{
    int32_t ret = CreateSessionRecord(sessionId, peerDeviceId, true);
    if (ret != ERR_OK) {
        HILOGE("Service create session record fail, ret %{public}d, peerDeviceId %{public}s, sessionId %{public}d.",
            ret, GetAnonymStr(peerDeviceId).c_str(), sessionId);
    }
}

void DSchedTransportSoftbusAdapter::OnShutdown(int32_t sessionId, bool isSelfcalled)
{
    {
        std::lock_guard<std::mutex> sessionLock(sessionMutex_);
        if (sessions_.empty() || sessions_.count(sessionId) == 0 || sessions_[sessionId] == nullptr) {
            HILOGE("error, invalid sessionId %{public}d", sessionId);
            return;
        }
        std::string peerDeviceId = sessions_[sessionId]->GetPeerDeviceId();
        HILOGI("peerDeviceId: %{public}s shutdown, socket sessionId: %{public}d.",
            GetAnonymStr(peerDeviceId).c_str(), sessionId);
        ShutdownSession(peerDeviceId, sessionId);
        sessions_.erase(sessionId);
    }
    NotifyListenersSessionShutdown(sessionId, isSelfcalled);
}

void DSchedTransportSoftbusAdapter::NotifyListenersSessionShutdown(int32_t sessionId, bool isSelfcalled)
{
    std::lock_guard<std::mutex> listenerMapLock(listenerMutex_);
    if (listeners_.empty()) {
        HILOGE("no listener has registered");
        return;
    }
    for (auto iterItem = listeners_.begin(); iterItem != listeners_.end(); iterItem++) {
        std::vector<std::shared_ptr<IDataListener>> objs = iterItem->second;
        for (auto iter : objs) {
            iter->OnShutdown(sessionId, isSelfcalled);
        }
    }
    return;
}

int32_t DSchedTransportSoftbusAdapter::ReleaseChannel()
{
    HILOGI("start");
    {
        std::lock_guard<std::mutex> sessionLock(sessionMutex_);
        for (auto iter = sessions_.begin(); iter != sessions_.end(); iter++) {
            std::string peerDeviceId = (iter->second != nullptr) ? iter->second->GetPeerDeviceId() : "";
            HILOGI("shutdown client: %{public}s, socket sessionId: %{public}d.",
                GetAnonymStr(peerDeviceId).c_str(), iter->first);
            ShutdownSession(peerDeviceId, iter->first);
        }
        sessions_.clear();
    }
    HILOGI("shutdown server, socket session id: %{public}d", serverSocket_);
    Shutdown(serverSocket_);
    serverSocket_ = 0;

#ifdef DMSFWK_ALL_CONNECT_MGR
    int32_t ret = DSchedAllConnectManager::GetInstance().UninitAllConnectManager();
    if (ret != ERR_OK) {
        HILOGE("Uninit all connect manager fail, ret: %{public}d.", ret);
    }
#endif
    return ERR_OK;
}

int32_t DSchedTransportSoftbusAdapter::SendData(int32_t sessionId, int32_t dataType,
    std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    std::lock_guard<std::mutex> sessionLock(sessionMutex_);
    if (!sessions_.count(sessionId) || sessions_[sessionId] == nullptr) {
        HILOGE("error, invalid session id %{public}d", sessionId);
        return INVALID_SESSION_ID;
    }
    return sessions_[sessionId]->SendData(dataBuffer, dataType);
}

int32_t DSchedTransportSoftbusAdapter::SendBytesBySoftbus(int32_t sessionId,
    std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    if (dataBuffer != nullptr) {
        return SendBytes(sessionId, dataBuffer->Data(), dataBuffer->Size());
    } else {
        HILOGE("dataBuffer is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
}

void DSchedTransportSoftbusAdapter::OnBytes(int32_t sessionId, const void *data, uint32_t dataLen)
{
    if (dataLen == 0 || dataLen > DSCHED_MAX_RECV_DATA_LEN || data == nullptr) {
        HILOGE("error, dataLen: %{public}d, session id: %{public}d", dataLen, sessionId);
        return;
    }
    HILOGD("start, sessionId: %{public}d", sessionId);
    {
        std::lock_guard<std::mutex> sessionLock(sessionMutex_);
        if (!sessions_.count(sessionId) || sessions_[sessionId] == nullptr) {
            HILOGE("invalid session id %{public}d", sessionId);
            return;
        }
        std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(dataLen);
        int32_t ret = memcpy_s(buffer->Data(), buffer->Capacity(), data, dataLen);
        if (ret != ERR_OK) {
            HILOGE("memcpy_s failed ret: %{public}d", ret);
            return;
        }
        sessions_[sessionId]->OnBytesReceived(buffer);
    }
    HILOGD("end, session id: %{public}d", sessionId);
    return;
}

void DSchedTransportSoftbusAdapter::OnDataReady(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer,
    uint32_t dataType)
{
    std::lock_guard<std::mutex> listenerMapLock(listenerMutex_);
    if (listeners_.empty()) {
        HILOGE("no listener has registered");
        return;
    }
    auto iterItem = listeners_.find(dataType);
    if (iterItem == listeners_.end()) {
        HILOGE("get iterItem failed from listeners_, type %{public}d, sessionId: %{public}d", dataType, sessionId);
        return;
    }
    std::vector<std::shared_ptr<IDataListener>> objs = iterItem->second;
    for (auto iter : objs) {
        iter->OnDataRecv(sessionId, dataBuffer);
    }
    return;
}

void DSchedTransportSoftbusAdapter::RegisterListener(int32_t serviceType, std::shared_ptr<IDataListener> listener)
{
    HILOGI("start, service type: %{public}d", serviceType);
    if (listener == nullptr) {
        HILOGE("listener is null, type: %{public}d", serviceType);
        return;
    }
    std::lock_guard<std::mutex> listenerMapLock(listenerMutex_);
    if (listeners_.empty() || listeners_.find(serviceType) == listeners_.end()) {
        HILOGD("service type %{public}d does not exist in the listeners, adding", serviceType);
        std::vector<std::shared_ptr<IDataListener>> newListeners;
        newListeners.emplace_back(listener);
        listeners_[serviceType] = newListeners;
        HILOGI("listener register success");
        return;
    }
    auto iterItem = listeners_.find(serviceType);
    for (auto iter : iterItem->second) {
        if (iter == listener) {
            HILOGI("listener already registed");
            return;
        }
    }
    iterItem->second.emplace_back(listener);
    HILOGI("listener register success");
    return;
}

void DSchedTransportSoftbusAdapter::UnregisterListener(int32_t serviceType, std::shared_ptr<IDataListener> listener)
{
    HILOGI("start, service type: %{public}d", serviceType);
    if (listener == nullptr) {
        HILOGE("listener is null, type: %{public}d", serviceType);
        return;
    }
    std::lock_guard<std::mutex> listenerMapLock(listenerMutex_);
    if (listeners_.empty() || listeners_.find(serviceType) == listeners_.end()) {
        HILOGD("service type %{public}d does not exist in the listeners, ignore", serviceType);
        return;
    }
    auto typeListeners = listeners_.find(serviceType);
    for (size_t i = 0; i < typeListeners->second.size(); i++) {
        if (typeListeners->second[i] == listener) {
            typeListeners->second.erase(typeListeners->second.begin() + i);
            if (typeListeners->second.empty()) {
                listeners_.erase(typeListeners);
            }
            break;
        }
    }
    HILOGI("listener unregister success");
    return;
}

void DSchedTransportSoftbusAdapter::SetCallingTokenId(int32_t callingTokenId)
{
    callingTokenId_ = callingTokenId;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
