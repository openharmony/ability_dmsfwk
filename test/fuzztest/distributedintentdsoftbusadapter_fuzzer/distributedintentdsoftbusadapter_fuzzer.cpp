/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "distributedintentdsoftbusadapter_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <vector>

#include "distributed_intent_dsoftbus_adapter.h"
#include "securec.h"
#include "softbus_stub.h"

namespace OHOS {
namespace DistributedSchedule {

namespace {
constexpr size_t FRAG_HEADER_SIZE = sizeof(uint32_t) + sizeof(uint32_t) +
    sizeof(uint16_t) + sizeof(uint8_t);
constexpr size_t FUZZ_DEVICE_ID_MAX_LEN = 64;
constexpr size_t FUZZ_PAYLOAD_MAX_LEN = 256;
constexpr size_t FUZZ_PAYLOAD_MID_LEN = 128;
constexpr int32_t FUZZ_FAKE_SOCKET_FD = 10001;
constexpr uint32_t FUZZ_MOCK_MAX_SEND_SIZE = 256;
constexpr uint8_t FUZZ_FRAG_SCENARIO_COUNT = 3;

std::vector<uint8_t> BuildFragFrame(uint32_t typeValue, uint32_t totalLen,
    uint16_t seq, uint8_t flag, const std::string& payload)
{
    std::vector<uint8_t> frame(FRAG_HEADER_SIZE + payload.size());
    size_t off = 0;
    if (memcpy_s(frame.data() + off, frame.size() - off, &typeValue, sizeof(uint32_t)) != EOK) {
        return frame;
    }
    off += sizeof(uint32_t);
    if (memcpy_s(frame.data() + off, frame.size() - off, &totalLen, sizeof(uint32_t)) != EOK) {
        return frame;
    }
    off += sizeof(uint32_t);
    if (memcpy_s(frame.data() + off, frame.size() - off, &seq, sizeof(uint16_t)) != EOK) {
        return frame;
    }
    off += sizeof(uint16_t);
    if (memcpy_s(frame.data() + off, frame.size() - off, &flag, sizeof(uint8_t)) != EOK) {
        return frame;
    }
    off += sizeof(uint8_t);
    if (!payload.empty()) {
        if (memcpy_s(frame.data() + off, frame.size() - off, payload.data(), payload.size()) != EOK) {
            return frame;
        }
    }
    return frame;
}
}

void FuzzBindIntentSession(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string deviceId = fdp.ConsumeRandomLengthString();
    int32_t socketFd = 0;
    DistributedIntentDsoftbusAdapter::GetInstance().BindIntentSession(deviceId, socketFd);
    if (socketFd > 0) {
        DistributedIntentDsoftbusAdapter::GetInstance().UnbindIntentSession(socketFd);
    }
}

void FuzzUnbindIntentSession(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t socketFd = fdp.ConsumeIntegral<int32_t>();
    DistributedIntentDsoftbusAdapter::GetInstance().UnbindIntentSession(socketFd);
}

void FuzzSendIntentDataBySession(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t socketFd = fdp.ConsumeIntegral<int32_t>();
    uint32_t typeValue = fdp.ConsumeIntegral<uint32_t>();
    std::string payload = fdp.ConsumeRemainingBytesAsString();
    IntentDataType dataType = static_cast<IntentDataType>(typeValue);
    DistributedIntentDsoftbusAdapter::GetInstance().SendIntentDataBySession(socketFd, dataType, payload);
}

void FuzzGetSocketFdByDeviceId(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string deviceId = fdp.ConsumeRandomLengthString();
    DistributedIntentDsoftbusAdapter::GetInstance().GetSocketFdByDeviceId(deviceId);
}

void FuzzOnIntentBind(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string peerDeviceId = fdp.ConsumeRandomLengthString();
    DistributedIntentDsoftbusAdapter::GetInstance().OnIntentBind(socket, peerDeviceId);
}

void FuzzOnIntentShutdown(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    DistributedIntentDsoftbusAdapter::GetInstance().OnIntentShutdown(socket);
}

void FuzzOnIntentBytes(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::vector<uint8_t> bytes = fdp.ConsumeRemainingBytes<uint8_t>();
    const void* rawData = bytes.empty() ? nullptr : bytes.data();
    DistributedIntentDsoftbusAdapter::GetInstance().OnIntentBytes(socket, rawData, bytes.size());
}

void FuzzBindThenSend(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(false);

    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (deviceId.empty()) {
        deviceId = "fuzz_device_id";
    }
    adapter.OnIntentBind(socket, deviceId);

    uint32_t typeValue = fdp.ConsumeIntegral<uint32_t>();
    IntentDataType dataType = static_cast<IntentDataType>(typeValue);
    std::string payload = fdp.ConsumeRandomLengthString(FUZZ_PAYLOAD_MAX_LEN);
    adapter.SendIntentDataBySession(socket, dataType, payload);
}

void FuzzOnIntentBytesWithFrag(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint8_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(false);

    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (deviceId.empty()) {
        deviceId = "fuzz_device_id";
    }
    adapter.OnIntentBind(socket, deviceId);

    uint8_t scenario = fdp.ConsumeIntegral<uint8_t>();
    std::vector<uint8_t> frame;
    if (scenario % FUZZ_FRAG_SCENARIO_COUNT == 0) {
        uint32_t typeValue = fdp.ConsumeIntegral<uint32_t>();
        uint32_t totalLen = fdp.ConsumeIntegral<uint32_t>();
        std::string payload = fdp.ConsumeRandomLengthString(FUZZ_PAYLOAD_MAX_LEN);
        frame = BuildFragFrame(typeValue, totalLen, 0, FRAG_START_END, payload);
    } else if (scenario % FUZZ_FRAG_SCENARIO_COUNT == 1) {
        uint32_t typeValue1 = fdp.ConsumeIntegral<uint32_t>();
        uint32_t totalLen1 = fdp.ConsumeIntegral<uint32_t>();
        std::string payload1 = fdp.ConsumeRandomLengthString(FUZZ_PAYLOAD_MID_LEN);
        frame = BuildFragFrame(typeValue1, totalLen1, 0, FRAG_START, payload1);
        adapter.OnIntentBytes(socket, frame.data(), frame.size());
        uint32_t typeValue2 = fdp.ConsumeIntegral<uint32_t>();
        uint32_t totalLen2 = fdp.ConsumeIntegral<uint32_t>();
        std::string payload2 = fdp.ConsumeRemainingBytesAsString();
        frame = BuildFragFrame(typeValue2, totalLen2, 1, FRAG_END, payload2);
    } else {
        uint32_t typeValue = fdp.ConsumeIntegral<uint32_t>();
        uint32_t totalLen = fdp.ConsumeIntegral<uint32_t>();
        std::string payload = fdp.ConsumeRandomLengthString(FUZZ_PAYLOAD_MAX_LEN);
        frame = BuildFragFrame(typeValue, totalLen, 0, FRAG_MID, payload);
    }
    adapter.OnIntentBytes(socket, frame.data(), frame.size());
    adapter.OnIntentShutdown(socket);
}

void FuzzShutdownAndCleanup(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(false);

    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (deviceId.empty()) {
        deviceId = "fuzz_device_id";
    }
    adapter.OnIntentBind(socket, deviceId);
    adapter.ShutdownDeviceSession(deviceId);

    std::vector<int32_t> closedSockets;
    adapter.ForceCleanupDeviceSessions(deviceId, closedSockets);
    adapter.OnIntentShutdown(socket);
}
} // namespace DistributedSchedule
} // namespace OHOS

extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv)
{
    OHOS::DistributedSchedule::SetSoftbusMockSocketFd(
        OHOS::DistributedSchedule::FUZZ_FAKE_SOCKET_FD);
    OHOS::DistributedSchedule::SetSoftbusMockMaxSendSize(
        OHOS::DistributedSchedule::FUZZ_MOCK_MAX_SEND_SIZE);
    OHOS::DistributedSchedule::SetSoftbusMockEnabled(true);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzBindIntentSession(data, size);
    OHOS::DistributedSchedule::FuzzBindThenSend(data, size);
    OHOS::DistributedSchedule::FuzzOnIntentBytesWithFrag(data, size);
    OHOS::DistributedSchedule::FuzzShutdownAndCleanup(data, size);
    OHOS::DistributedSchedule::FuzzUnbindIntentSession(data, size);
    OHOS::DistributedSchedule::FuzzSendIntentDataBySession(data, size);
    OHOS::DistributedSchedule::FuzzGetSocketFdByDeviceId(data, size);
    OHOS::DistributedSchedule::FuzzOnIntentBind(data, size);
    OHOS::DistributedSchedule::FuzzOnIntentShutdown(data, size);
    OHOS::DistributedSchedule::FuzzOnIntentBytes(data, size);
    return 0;
}
