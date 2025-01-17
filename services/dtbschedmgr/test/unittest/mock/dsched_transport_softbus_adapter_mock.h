/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_DSCHED_TRANSPORT_SOFTBUS_ADAPTER_MOCK_H
#define OHOS_DSCHED_TRANSPORT_SOFTBUS_ADAPTER_MOCK_H

#include <gmock/gmock.h>

#include "dsched_transport_softbus_adapter.h"

namespace OHOS {
namespace DistributedSchedule {
class IDSchedTransportSoftbusAdapter {
public:
    virtual ~IDSchedTransportSoftbusAdapter() = default;
    virtual int32_t InitChannel() = 0;
    virtual int32_t ConnectDevice(const std::string &peerDeviceId, int32_t &sessionId, DSchedServiceType type) = 0;
    virtual void DisconnectDevice(const std::string &peerDeviceId) = 0;
    virtual int32_t ReleaseChannel() = 0;
    virtual int32_t SendData(int32_t sessionId, int32_t dataType, std::shared_ptr<DSchedDataBuffer> dataBuffer) = 0;
    virtual int32_t SendBytesBySoftbus(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer) = 0;
    virtual void OnBind(int32_t sessionId, const std::string &peerDeviceId) = 0;
    virtual void OnShutdown(int32_t sessionId, bool isSelfCalled) = 0;
    virtual void OnBytes(int32_t sessionId, const void *data, uint32_t dataLen) = 0;
    virtual void OnDataReady(int32_t, std::shared_ptr<DSchedDataBuffer>, uint32_t) = 0;
    virtual void RegisterListener(int32_t serviceType, std::shared_ptr<IDataListener> listener) = 0;
    virtual void UnregisterListener(int32_t serviceType, std::shared_ptr<IDataListener> listener) = 0;
    virtual void SetCallingTokenId(int32_t callingTokenId) = 0;
    virtual bool GetSessionIdByDeviceId(const std::string &peerDeviceId, int32_t &sessionId) = 0;
    virtual bool IsNeedAllConnect(DSchedServiceType type) = 0;
public:
    static inline std::shared_ptr<IDSchedTransportSoftbusAdapter> adapterMock = nullptr;
};

class DSchedTransportSoftbusAdapterMock : public IDSchedTransportSoftbusAdapter {
public:
    MOCK_METHOD0(InitChannel, int32_t());
    MOCK_METHOD3(ConnectDevice, int32_t(const std::string &peerDeviceId, int32_t &sessionId, DSchedServiceType type));
    MOCK_METHOD1(DisconnectDevice, void(const std::string &peerDeviceId));
    MOCK_METHOD0(ReleaseChannel, int32_t());
    MOCK_METHOD3(SendData, int32_t(int32_t sessionId, int32_t dataType, std::shared_ptr<DSchedDataBuffer> dataBuffer));
    MOCK_METHOD2(SendBytesBySoftbus, int32_t(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer));
    MOCK_METHOD2(OnBind, void(int32_t sessionId, const std::string &peerDeviceId));
    MOCK_METHOD2(OnShutdown, void(int32_t sessionId, bool isSelfCalled));
    MOCK_METHOD3(OnBytes, void(int32_t sessionId, const void *data, uint32_t dataLen));
    MOCK_METHOD3(OnDataReady, void(int32_t, std::shared_ptr<DSchedDataBuffer>, uint32_t));
    MOCK_METHOD2(RegisterListener, void(int32_t serviceType, std::shared_ptr<IDataListener> listener));
    MOCK_METHOD2(UnregisterListener, void(int32_t serviceType, std::shared_ptr<IDataListener> listener));
    MOCK_METHOD1(SetCallingTokenId, void(int32_t callingTokenId));
    MOCK_METHOD2(GetSessionIdByDeviceId, bool(const std::string &peerDeviceId, int32_t &sessionId));
    MOCK_METHOD1(IsNeedAllConnect, bool(DSchedServiceType type));
};
}
}
#endif