/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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
constexpr uint32_t FUZZ_TEST_CASE_COUNT = 10;

enum FuzzTestCase : uint32_t {
    CASE_FUZZ_ON_BIND,
    CASE_FUZZ_ON_SHUTDOWN,
    CASE_FUZZ_ON_BYTES,
    CASE_FUZZ_CONNECT_DEVICE,
    CASE_FUZZ_DISCONNECT_DEVICE,
    CASE_FUZZ_ON_DATA_READY,
    CASE_FUZZ_REGISTER_LISTENER,
    CASE_FUZZ_UNREGISTER_LISTENER,
    CASE_FUZZ_SET_CALLING_TOKEN_ID,
    CASE_FUZZ_GET_SESSION_ID_BY_DEVICE_ID,
};
}

void FuzzOnBind(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t sessionId = fdp.ConsumeIntegral<int32_t>();
    std::string peerDeviceId = fdp.ConsumeRandomLengthString();
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.OnBind(sessionId, peerDeviceId);
}

void FuzzOnShutdown(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    bool isSelfcalled = fdp.ConsumeBool();
    int32_t sessionId = fdp.ConsumeIntegral<int32_t>();
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
    dschedTransportSoftbusAdapter.CreateSessionRecord(sessionId, peerDeviceId, isServer, SERVICE_TYPE_CONTINUE);
    dschedTransportSoftbusAdapter.AddNewPeerSession(peerDeviceId, sessionId, SERVICE_TYPE_CONTINUE);
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
    FuzzedDataProvider fdp(data, size);
    std::string peerDeviceId = fdp.ConsumeRandomLengthString();
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.DisconnectDevice(peerDeviceId);
}


void FuzzOnDataReady(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t)) || size >= MAX_BUFFER_SIZE) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t sessionId = fdp.ConsumeIntegral<int32_t>();
    uint32_t dataType = fdp.ConsumeIntegral<uint32_t>();
    std::shared_ptr<DSchedDataBuffer> dataBuffer = std::make_shared<DSchedDataBuffer>(size);
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.OnDataReady(sessionId, dataBuffer, dataType);
}

void FuzzRegisterListener(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t serviceType = fdp.ConsumeIntegral<int32_t>();
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
    FuzzedDataProvider fdp(data, size);
    int32_t serviceType = fdp.ConsumeIntegral<int32_t>();
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
    FuzzedDataProvider fdp(data, size);
    int32_t callingTokenId = fdp.ConsumeIntegral<int32_t>();
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.SetCallingTokenId(callingTokenId);
}

void FuzzGetSessionIdByDeviceId(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t sessionId = fdp.ConsumeIntegral<int32_t>();
    std::string peerDeviceId = fdp.ConsumeRandomLengthString();
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.GetSessionIdByDeviceId(peerDeviceId, sessionId);
}

void RunDSchedTransportSoftbusAdapterFuzzTest(uint32_t testCase, const uint8_t* data, size_t size)
{
    switch (testCase) {
        case CASE_FUZZ_ON_BIND:
            FuzzOnBind(data, size);
            break;
        case CASE_FUZZ_ON_SHUTDOWN:
            FuzzOnShutdown(data, size);
            break;
        case CASE_FUZZ_ON_BYTES:
            FuzzOnBytes(data, size);
            break;
        case CASE_FUZZ_CONNECT_DEVICE:
            FuzzConnectDevice(data, size);
            break;
        case CASE_FUZZ_DISCONNECT_DEVICE:
            FuzzDisconnectDevice(data, size);
            break;
        case CASE_FUZZ_ON_DATA_READY:
            FuzzOnDataReady(data, size);
            break;
        case CASE_FUZZ_REGISTER_LISTENER:
            FuzzRegisterListener(data, size);
            break;
        case CASE_FUZZ_UNREGISTER_LISTENER:
            FuzzUnregisterListener(data, size);
            break;
        case CASE_FUZZ_SET_CALLING_TOKEN_ID:
            FuzzSetCallingTokenId(data, size);
            break;
        case CASE_FUZZ_GET_SESSION_ID_BY_DEVICE_ID:
            FuzzGetSessionIdByDeviceId(data, size);
            break;
        default:
            break;
    }
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FuzzedDataProvider fdp(data, size);
    uint32_t testCase = fdp.ConsumeIntegralInRange<uint32_t>(0, OHOS::DistributedSchedule::FUZZ_TEST_CASE_COUNT - 1);
    OHOS::DistributedSchedule::RunDSchedTransportSoftbusAdapterFuzzTest(testCase, data, size);
    return 0;
}
