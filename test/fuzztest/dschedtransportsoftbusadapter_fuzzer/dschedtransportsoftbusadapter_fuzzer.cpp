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

#include "dschedtransportsoftbusadapter_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "dsched_continue_manager.h"
#include "dsched_data_buffer.h"
#include "dsched_transport_softbus_adapter.h"
#include "idata_listener.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr uint32_t MAX_BUFFER_SIZE = 80 * 1024 * 1024;
}

void FuzzOnBind(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    std::string peerDeviceId(reinterpret_cast<const char*>(data), size);
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.OnBind(sessionId, peerDeviceId);
}

void FuzzOnShutdown(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    bool isSelfcalled = *(reinterpret_cast<const bool*>(data));
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.OnShutdown(sessionId, isSelfcalled);
}

void FuzzOnBytes(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    const void* newdata = reinterpret_cast<const void*>(data);
    FuzzedDataProvider fdp(data, size);
    int32_t sessionId = fdp.ConsumeIntegral<int32_t>();
    int32_t dataLen = fdp.ConsumeIntegral<int32_t>();
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.OnBytes(sessionId, newdata, dataLen);
}

void FuzzConnectDevice(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t)) || size >= MAX_BUFFER_SIZE) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t sessionId = fdp.ConsumeIntegral<int32_t>();
    int32_t dataType = fdp.ConsumeIntegral<int32_t>();
    std::string peerDeviceId = fdp.ConsumeRandomLengthString();

    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.ConnectDevice(peerDeviceId, sessionId);
    std::shared_ptr<DSchedDataBuffer> dataBuffer = std::make_shared<DSchedDataBuffer>(size);
    dschedTransportSoftbusAdapter.SendData(sessionId, dataType, dataBuffer);
    dschedTransportSoftbusAdapter.SendBytesBySoftbus(sessionId, dataBuffer);
    dschedTransportSoftbusAdapter.InitChannel();
    dschedTransportSoftbusAdapter.CreateServerSocket();
    dschedTransportSoftbusAdapter.CreateClientSocket(peerDeviceId);
    bool isServer = sessionId % 2;
    DSchedServiceType type = *(reinterpret_cast<DSchedServiceType*>(isServer));
    dschedTransportSoftbusAdapter.CreateSessionRecord(sessionId, peerDeviceId, isServer, type);
    dschedTransportSoftbusAdapter.AddNewPeerSession(peerDeviceId, sessionId, type);
    dschedTransportSoftbusAdapter.ShutdownSession(peerDeviceId, sessionId);
    bool isSelfCalled = sessionId % 2;
    dschedTransportSoftbusAdapter.NotifyListenersSessionShutdown(sessionId, isSelfCalled);
    dschedTransportSoftbusAdapter.ReleaseChannel();
}

void FuzzDisconnectDevice(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    std::string peerDeviceId(reinterpret_cast<const char*>(data), size);
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.DisconnectDevice(peerDeviceId);
}


void FuzzOnDataReady(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t)) || size >= MAX_BUFFER_SIZE) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    std::shared_ptr<DSchedDataBuffer> dataBuffer = std::make_shared<DSchedDataBuffer>(size);
    uint32_t dataType = *(reinterpret_cast<const uint32_t*>(data));
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.OnDataReady(sessionId, dataBuffer, dataType);
}

void FuzzRegisterListener(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    int32_t serviceType = *(reinterpret_cast<const int32_t*>(data));
    std::shared_ptr<DSchedContinueManager::SoftbusListener> listener =
        std::make_shared<DSchedContinueManager::SoftbusListener>();
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.RegisterListener(serviceType, listener);
}

void FuzzUnregisterListener(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    int32_t serviceType = *(reinterpret_cast<const int32_t*>(data));
    std::shared_ptr<DSchedContinueManager::SoftbusListener> listener =
        std::make_shared<DSchedContinueManager::SoftbusListener>();
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.UnregisterListener(serviceType, listener);
}

void FuzzSetCallingTokenId(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    int32_t callingTokenId = *(reinterpret_cast<const int32_t*>(data));
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.SetCallingTokenId(callingTokenId);
}

void FuzzGetSessionIdByDeviceId(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    std::string peerDeviceId(reinterpret_cast<const char*>(data), size);
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.GetSessionIdByDeviceId(peerDeviceId, sessionId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzOnBind(data, size);
    OHOS::DistributedSchedule::FuzzOnShutdown(data, size);
    OHOS::DistributedSchedule::FuzzOnBytes(data, size);
    OHOS::DistributedSchedule::FuzzConnectDevice(data, size);
    OHOS::DistributedSchedule::FuzzDisconnectDevice(data, size);
    OHOS::DistributedSchedule::FuzzOnDataReady(data, size);
    OHOS::DistributedSchedule::FuzzRegisterListener(data, size);
    OHOS::DistributedSchedule::FuzzUnregisterListener(data, size);
    OHOS::DistributedSchedule::FuzzSetCallingTokenId(data, size);
    OHOS::DistributedSchedule::FuzzGetSessionIdByDeviceId(data, size);
    return 0;
}
