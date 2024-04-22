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

#ifndef OHOS_DSCHED_TRANSPORT_SOFTBUS_ADAPTER_H
#define OHOS_DSCHED_TRANSPORT_SOFTBUS_ADAPTER_H

#include <map>
#include <string>

#include "dsched_softbus_session.h"
#include "idata_listener.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr uint32_t INTERCEPT_STRING_LENGTH = 20;
constexpr uint32_t DSCHED_MAX_RECV_DATA_LEN = 104857600;

constexpr int32_t DSCHED_QOS_TYPE_MIN_BW = 40 * 1024 * 1024;
constexpr int32_t DSCHED_QOS_TYPE_MAX_LATENCY = 6000;
constexpr int32_t DSCHED_QOS_TYPE_MIN_LATENCY = 1000;

const std::string SOCKET_DMS_SESSION_NAME = "ohos.distributedschedule.dms.connect";
const std::string SOCKET_DMS_PKG_NAME = "dms";
}

typedef enum {
    SERVICE_TYPE_INVALID = -1,
    SERVICE_TYPE_CONTINUE = 0,
    SERVICE_TYPE_COLLABORATION = 1,
} DSchedServiceType;

class DSchedTransportSoftbusAdapter {
DECLARE_SINGLE_INSTANCE_BASE(DSchedTransportSoftbusAdapter);
public:
    int32_t InitChannel();
    int32_t ConnectDevice(const std::string &peerDeviceId);
    void DisconnectDevice(const std::string &peerDeviceId);
    int32_t ReleaseChannel();
    int32_t SendData(int32_t sessionId, int32_t dataType, std::shared_ptr<DSchedDataBuffer> dataBuffer);
    int32_t SendBytesBySoftbus(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer);
    int32_t CreateSessionRecord(int32_t sessionId, const std::string &peerDeviceId);
    void OnShutdown(int32_t sessionId, bool isSelfCalled);
    void OnBytes(int32_t sessionId, const void *data, uint32_t dataLen);
    void OnDataReady(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer, uint32_t dataType);
    void RegisterListener(int32_t serviceType, std::shared_ptr<IDataListener> listener);
    void NotifyListenersSessionShutdown(int32_t sessionId, bool isSelfCalled);
    void UnregisterListener(int32_t serviceType, std::shared_ptr<IDataListener> listener);

private:
    DSchedTransportSoftbusAdapter();
    ~DSchedTransportSoftbusAdapter();
    int32_t CreateServerSocket();
    int32_t CreateClientSocket(const std::string &peerDeviceId);
    int32_t AddClientSession(int32_t sessionId, std::string &peerDeviceId);
    bool GetSessionIdByDeviceId(const std::string &peerDeviceId, int32_t &sessionId);

private:
    std::map<int32_t, std::shared_ptr<DSchedSoftbusSession>> sessions_;
    std::map<int32_t, std::vector<std::shared_ptr<IDataListener>>> listeners_;

    std::mutex sessionMutex_;
    std::mutex listenerMutex_;
    int32_t serverSocket_ = 0;
    std::string localSessionName_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_TRANSPORT_SOFTBUS_ADAPTER_H
