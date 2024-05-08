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

#include "adapter/dnetwork_adapter.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

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
    DSchedTransportSoftbusAdapter::GetInstance().CreateSessionRecord(socket, peerDeviceId);
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
    HILOGI("start");
    serverSocket_ = CreateServerSocket();
    if (serverSocket_ <= 0) {
        HILOGE("create socket failed, ret: %d", serverSocket_);
        return serverSocket_;
    }

    int32_t ret = Listen(serverSocket_, g_qosInfo, g_QosTV_Param_Index, &iSocketListener);
    if (ret != ERR_OK) {
        HILOGE("service listen failed, ret: %d", ret);
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
    HILOGI("finish, socket session id: %d", socket);
    return socket;
}

int32_t DSchedTransportSoftbusAdapter::ConnectDevice(const std::string &peerDeviceId)
{
    HILOGI("try to connect peer: %s", DnetworkAdapter::AnonymizeNetworkId(peerDeviceId).c_str());
    {
        std::lock_guard<std::mutex> sessionLock(sessionMutex_);
        if (!sessions_.empty()) {
            for (auto iter = sessions_.begin(); iter != sessions_.end(); iter++) {
                if (iter->second != nullptr && peerDeviceId == iter->second->GetPeerDeviceId()) {
                    HILOGI("peer device already connected");
                    sessions_[iter->first]->OnConnect();
                    return iter->first;
                }
            }
        }
    }

    int32_t sessionId = CreateClientSocket(peerDeviceId);
    if (sessionId <= 0) {
        HILOGE("create socket failed, ret: %d", sessionId);
        return sessionId;
    }

    int32_t ret = Bind(sessionId, g_qosInfo, g_QosTV_Param_Index, &iSocketListener);
    if (ret != ERR_OK) {
        HILOGE("client bind failed, ret: %d", ret);
        Shutdown(sessionId);
        return INVALID_SESSION_ID;
    }
    std::string localDeviceId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId)) {
        HILOGE("GetLocalDeviceId failed");
        Shutdown(sessionId);
        return INVALID_SESSION_ID;
    }
    {
        std::lock_guard<std::mutex> sessionLock(sessionMutex_);
        SessionInfo info = { sessionId, localDeviceId, peerDeviceId, SOCKET_DMS_SESSION_NAME, false };
        auto session = std::make_shared<DSchedSoftbusSession>(info);
        sessions_[sessionId] = session;
    }
    return sessionId;
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
    HILOGI("finish, socket session id: %d", sessionId);
    return sessionId;
}

int32_t DSchedTransportSoftbusAdapter::CreateSessionRecord(int32_t sessionId, const std::string &peerDeviceId)
{
    std::string localDeviceId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId)) {
        HILOGE("GetLocalDeviceId failed");
        Shutdown(sessionId);
        return INVALID_SESSION_ID;
    }
    {
        std::lock_guard<std::mutex> sessionLock(sessionMutex_);
        std::string sessionName = SOCKET_DMS_SESSION_NAME;
        SessionInfo info = { sessionId, localDeviceId, peerDeviceId, sessionName, true };
        auto session = std::make_shared<DSchedSoftbusSession>(info);
        sessions_[sessionId] = session;
    }
    return sessionId;
}

void DSchedTransportSoftbusAdapter::DisconnectDevice(const std::string &peerDeviceId)
{
    HILOGI("try to disconnect peer: %s", DnetworkAdapter::AnonymizeNetworkId(peerDeviceId).c_str());
    int32_t sessionId = 0;
    std::lock_guard<std::mutex> sessionLock(sessionMutex_);
    for (auto iter = sessions_.begin(); iter != sessions_.end(); iter++) {
        if (iter->second != nullptr && peerDeviceId == iter->second->GetPeerDeviceId()) {
            sessionId = iter->first;
            break;
        }
    }
    if (sessionId != 0 && sessions_[sessionId]->OnDisconnect()) {
        HILOGI("peer %s shutdown, socket session id: %d",
            DnetworkAdapter::AnonymizeNetworkId(sessions_[sessionId]->GetPeerDeviceId()).c_str(), sessionId);
        Shutdown(sessionId);
        sessions_.erase(sessionId);
        NotifyListenersSessionShutdown(sessionId, true);
    }
    HILOGI("finish, socket session id: %d", sessionId);
    return;
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

void DSchedTransportSoftbusAdapter::OnShutdown(int32_t sessionId, bool isSelfcalled)
{
    {
        std::lock_guard<std::mutex> sessionLock(sessionMutex_);
        if (sessions_.empty() || sessions_.count(sessionId) == 0) {
            HILOGE("error, invalid sessionId %d", sessionId);
            return;
        }
        HILOGI("peer %s shutdown, socket session id: %d",
            DnetworkAdapter::AnonymizeNetworkId(sessions_[sessionId]->GetPeerDeviceId()).c_str(), sessionId);
        Shutdown(sessionId);
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
            HILOGI("shutdown client: %s, socket session id: %d",
                DnetworkAdapter::AnonymizeNetworkId(iter->second->GetPeerDeviceId()).c_str(), iter->first);
            Shutdown(iter->first);
        }
        sessions_.clear();
    }
    HILOGI("shutdown server, socket session id: %d", serverSocket_);
    Shutdown(serverSocket_);
    serverSocket_ = 0;
    return ERR_OK;
}

int32_t DSchedTransportSoftbusAdapter::SendData(int32_t sessionId, int32_t dataType,
    std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    std::lock_guard<std::mutex> sessionLock(sessionMutex_);
    if (!sessions_.count(sessionId)) {
        HILOGE("error, invalid session id %d", sessionId);
        return INVALID_SESSION_ID;
    }
    return sessions_[sessionId]->SendData(dataBuffer, dataType);
}

int32_t DSchedTransportSoftbusAdapter::SendBytesBySoftbus(int32_t sessionId,
    std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    return SendBytes(sessionId, dataBuffer->Data(), dataBuffer->Size());
}

void DSchedTransportSoftbusAdapter::OnBytes(int32_t sessionId, const void *data, uint32_t dataLen)
{
    if (dataLen == 0 || dataLen > DSCHED_MAX_RECV_DATA_LEN || data == nullptr) {
        HILOGE("error, dataLen: %d, session id: %d", dataLen, sessionId);
        return;
    }
    HILOGD("start, sessionId: %d", sessionId);
    {
        std::lock_guard<std::mutex> sessionLock(sessionMutex_);
        if (!sessions_.count(sessionId)) {
            HILOGE("invalid session id %d", sessionId);
            return;
        }
        std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(dataLen);
        int32_t ret = memcpy_s(buffer->Data(), buffer->Capacity(), data, dataLen);
        if (ret != ERR_OK) {
            HILOGE("memcpy_s failed ret: %d", ret);
            return;
        }
        sessions_[sessionId]->OnBytesReceived(buffer);
    }
    HILOGD("end, session id: %d", sessionId);
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
        HILOGE("get iterItem failed from listeners_, type %d, sessionId: %d", dataType, sessionId);
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
    HILOGI("start, service type: %d", serviceType);
    if (listener == nullptr) {
        HILOGE("listener is null, type: %d", serviceType);
        return;
    }
    std::lock_guard<std::mutex> listenerMapLock(listenerMutex_);
    if (listeners_.empty() || listeners_.find(serviceType) == listeners_.end()) {
        HILOGD("service type %d does not exist in the listeners, adding", serviceType);
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
    HILOGI("start, service type: %d", serviceType);
    if (listener == nullptr) {
        HILOGE("listener is null, type: %d", serviceType);
        return;
    }
    std::lock_guard<std::mutex> listenerMapLock(listenerMutex_);
    if (listeners_.empty() || listeners_.find(serviceType) == listeners_.end()) {
        HILOGD("service type %d does not exist in the listeners, ignore", serviceType);
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
}  // namespace DistributedSchedule
}  // namespace OHOS
