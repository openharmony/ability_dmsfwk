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
constexpr size_t FUZZ_FRAG_MULTI_PAYLOAD_LEN = 512;
constexpr int64_t FUZZ_IDLE_BACKDATE_MS = SESSION_IDLE_TIMEOUT_MS + 5000;
constexpr int32_t FUZZ_SERVER_SESSION_FD_OFFSET = 1;
constexpr int32_t FUZZ_NULL_SESSION_FD_OFFSET = 2;

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

void FuzzSendFragMulti(const uint8_t* data, size_t size)
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
        deviceId = "fuzz_frag_send_device";
    }
    adapter.OnIntentBind(socket, deviceId);

    uint32_t typeValue = fdp.ConsumeIntegral<uint32_t>();
    IntentDataType dataType = static_cast<IntentDataType>(typeValue);
    std::string payload = fdp.ConsumeRandomLengthString(FUZZ_FRAG_MULTI_PAYLOAD_LEN);
    if (payload.size() < FUZZ_MOCK_MAX_SEND_SIZE + 1) {
        payload.append(FUZZ_MOCK_MAX_SEND_SIZE + 1 - payload.size(), 'X');
    }
    adapter.SendIntentDataBySession(socket, dataType, payload);
    adapter.OnIntentShutdown(socket);
}

void FuzzFragReassemblyComplete(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(false);

    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (deviceId.empty()) {
        deviceId = "fuzz_reassemble_device";
    }
    adapter.OnIntentBind(socket, deviceId);

    uint32_t typeValue = fdp.ConsumeIntegral<uint32_t>();
    std::string p1 = fdp.ConsumeRandomLengthString(FUZZ_PAYLOAD_MID_LEN);
    std::string p2 = fdp.ConsumeRandomLengthString(FUZZ_PAYLOAD_MID_LEN);
    std::string p3 = fdp.ConsumeRemainingBytesAsString();
    if (p3.empty()) {
        p3 = "z";
    }
    uint32_t totalLen = static_cast<uint32_t>(p1.size() + p2.size() + p3.size());

    auto frame1 = BuildFragFrame(typeValue, totalLen, 0, FRAG_START, p1);
    adapter.OnIntentBytes(socket, frame1.data(), frame1.size());

    auto frame2 = BuildFragFrame(typeValue, totalLen, 1, FRAG_MID, p2);
    adapter.OnIntentBytes(socket, frame2.data(), frame2.size());

    auto frame3 = BuildFragFrame(typeValue, totalLen, 2, FRAG_END, p3);
    adapter.OnIntentBytes(socket, frame3.data(), frame3.size());

    adapter.OnIntentShutdown(socket);
}

void FuzzFragErrorPaths(const uint8_t* data, size_t size)
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
        deviceId = "fuzz_frag_err_device";
    }
    adapter.OnIntentBind(socket, deviceId);

    uint32_t typeValue = fdp.ConsumeIntegral<uint32_t>();
    uint32_t totalLen = fdp.ConsumeIntegral<uint32_t>();
    std::string payload = fdp.ConsumeRandomLengthString(FUZZ_PAYLOAD_MAX_LEN);

    auto frameMid = BuildFragFrame(typeValue, totalLen, 0, FRAG_MID, payload);
    adapter.OnIntentBytes(socket, frameMid.data(), frameMid.size());

    auto frameEnd = BuildFragFrame(typeValue, totalLen, 0, FRAG_END, payload);
    adapter.OnIntentBytes(socket, frameEnd.data(), frameEnd.size());

    auto frameStart = BuildFragFrame(typeValue, totalLen, 0, FRAG_START, payload);
    adapter.OnIntentBytes(socket, frameStart.data(), frameStart.size());
    auto frameWrongSeq = BuildFragFrame(typeValue, totalLen, 5, FRAG_END, payload);
    adapter.OnIntentBytes(socket, frameWrongSeq.data(), frameWrongSeq.size());

    uint32_t mismatchLen = 999;
    auto frameStart2 = BuildFragFrame(typeValue, mismatchLen, 0, FRAG_START, payload);
    adapter.OnIntentBytes(socket, frameStart2.data(), frameStart2.size());
    auto frameEnd2 = BuildFragFrame(typeValue, mismatchLen, 1, FRAG_END, payload);
    adapter.OnIntentBytes(socket, frameEnd2.data(), frameEnd2.size());

    adapter.OnIntentShutdown(socket);
}

void FuzzCleanupIdleSessions(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(false);

    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (deviceId.empty()) {
        deviceId = "fuzz_idle_device";
    }

    {
        std::lock_guard<std::mutex> lock(adapter.sessionMutex_);
        auto idleSession = std::make_shared<IntentSocketSession>();
        idleSession->peerDeviceId = deviceId;
        idleSession->socketFd = socket;
        idleSession->isConnected = true;
        idleSession->isServer = false;
        idleSession->refCount = 1;
        idleSession->lastActivityTime = std::chrono::steady_clock::now()
            - std::chrono::milliseconds(FUZZ_IDLE_BACKDATE_MS);
        adapter.sessions_[socket] = idleSession;

        auto serverSession = std::make_shared<IntentSocketSession>();
        serverSession->peerDeviceId = deviceId;
        serverSession->socketFd = socket + FUZZ_SERVER_SESSION_FD_OFFSET;
        serverSession->isConnected = true;
        serverSession->isServer = true;
        serverSession->refCount = 0;
        serverSession->lastActivityTime = std::chrono::steady_clock::now()
            - std::chrono::milliseconds(FUZZ_IDLE_BACKDATE_MS);
        adapter.sessions_[socket + FUZZ_SERVER_SESSION_FD_OFFSET] = serverSession;

        adapter.sessions_[socket + FUZZ_NULL_SESSION_FD_OFFSET] = nullptr;
    }

    adapter.sessionCleanupRunning_.store(true);
    adapter.CleanupIdleSessions();
}

void FuzzCleanupIdleSessionsAllClosed(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(false);

    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (deviceId.empty()) {
        deviceId = "fuzz_idle_only_device";
    }

    {
        std::lock_guard<std::mutex> lock(adapter.sessionMutex_);
        adapter.sessions_.clear();
        auto idleSession = std::make_shared<IntentSocketSession>();
        idleSession->peerDeviceId = deviceId;
        idleSession->socketFd = socket;
        idleSession->isConnected = true;
        idleSession->isServer = false;
        idleSession->refCount = 1;
        idleSession->lastActivityTime = std::chrono::steady_clock::now()
            - std::chrono::milliseconds(FUZZ_IDLE_BACKDATE_MS);
        adapter.sessions_[socket] = idleSession;
    }

    adapter.sessionCleanupRunning_.store(true);
    adapter.CleanupIdleSessions();
}

void FuzzSendBytesFail(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(false);

    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (deviceId.empty()) {
        deviceId = "fuzz_send_fail_device";
    }
    adapter.OnIntentBind(socket, deviceId);

    uint32_t typeValue = fdp.ConsumeIntegral<uint32_t>();
    IntentDataType dataType = static_cast<IntentDataType>(typeValue);
    std::string payload = fdp.ConsumeRemainingBytesAsString();

    SetSoftbusMockSendBytesFail(true);
    adapter.SendIntentDataBySession(socket, dataType, payload);
    SetSoftbusMockSendBytesFail(false);
    adapter.OnIntentShutdown(socket);
}

void FuzzSocketFail(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(false);

    std::string deviceId = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (deviceId.empty()) {
        deviceId = "fuzz_socket_fail_device";
    }

    SetSoftbusMockSocketFail(true);
    int32_t socketFd = 0;
    adapter.BindIntentSession(deviceId, socketFd);
    if (socketFd > 0) {
        adapter.UnbindIntentSession(socketFd);
    }
    SetSoftbusMockSocketFail(false);
}

void FuzzStoppedCallbacks(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(true);
    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    adapter.OnIntentBind(socket, deviceId);
    adapter.OnIntentShutdown(socket);
    const void* nullData = nullptr;
    adapter.OnIntentBytes(socket, nullData, 0);
    adapter.SetStopped(false);
}

void FuzzUnbindServerSession(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(false);
    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (deviceId.empty()) {
        deviceId = "fuzz_unbind_server_device";
    }
    adapter.OnIntentBind(socket, deviceId);
    adapter.UnbindIntentSession(socket);
    adapter.OnIntentShutdown(socket);
}

void FuzzUnbindRefCountPositive(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(false);
    std::string deviceId = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (deviceId.empty()) {
        deviceId = "fuzz_refcount_device";
    }
    int32_t fd1 = 0;
    int32_t fd2 = 0;
    adapter.BindIntentSession(deviceId, fd1);
    adapter.BindIntentSession(deviceId, fd2);
    if (fd1 > 0) {
        adapter.UnbindIntentSession(fd1);
    }
    if (fd1 > 0) {
        adapter.UnbindIntentSession(fd1);
    }
}

void FuzzShutdownDeviceNoMatch(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.SetStopped(false);
    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string bindDevice = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (bindDevice.empty()) {
        bindDevice = "fuzz_shutdown_match_device";
    }
    std::string otherDevice = fdp.ConsumeRandomLengthString(FUZZ_DEVICE_ID_MAX_LEN);
    if (otherDevice.empty() || otherDevice == bindDevice) {
        otherDevice = "fuzz_shutdown_other_device";
    }
    adapter.OnIntentBind(socket, bindDevice);
    adapter.ShutdownDeviceSession(otherDevice);
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
    OHOS::DistributedSchedule::FuzzSendFragMulti(data, size);
    OHOS::DistributedSchedule::FuzzFragReassemblyComplete(data, size);
    OHOS::DistributedSchedule::FuzzFragErrorPaths(data, size);
    OHOS::DistributedSchedule::FuzzCleanupIdleSessions(data, size);
    OHOS::DistributedSchedule::FuzzCleanupIdleSessionsAllClosed(data, size);
    OHOS::DistributedSchedule::FuzzSendBytesFail(data, size);
    OHOS::DistributedSchedule::FuzzSocketFail(data, size);
    OHOS::DistributedSchedule::FuzzStoppedCallbacks(data, size);
    OHOS::DistributedSchedule::FuzzUnbindServerSession(data, size);
    OHOS::DistributedSchedule::FuzzUnbindRefCountPositive(data, size);
    OHOS::DistributedSchedule::FuzzShutdownDeviceNoMatch(data, size);
    return 0;
}
