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

#ifndef DISTRIBUTED_INTENT_DSOFTBUS_ADAPTER_H
#define DISTRIBUTED_INTENT_DSOFTBUS_ADAPTER_H

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>

#include "distributed_intent_error_code.h"
#include "intent_socket_listener.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

enum class IntentDataType {
    INTENT_DATA_TYPE_EXECUTE = 1,
    INTENT_DATA_TYPE_DMS_RESULT = 2,
    INTENT_DATA_TYPE_AMGR_RESULT = 3,
    INTENT_DATA_TYPE_EXECUTE_RESULT = 4,
    INTENT_DATA_TYPE_DISCONNECT = 5,
};

struct IntentSocketSession {
    std::string peerDeviceId;
    int32_t socketFd = -1;
    bool isConnected = false;
    bool isServer = false;
    int32_t refCount = 0;
    std::chrono::steady_clock::time_point lastActivityTime;
};

constexpr int32_t INVALID_SOCKET_FD = -1;
constexpr int32_t INTENT_BIND_RETRY_INTERVAL_MS = 500;
constexpr int32_t INTENT_MAX_BIND_RETRY_TIMES = 8;
constexpr int32_t INTENT_QOS_MIN_BW = 40 * 1024 * 1024;
constexpr int32_t INTENT_QOS_MAX_LATENCY = 6000;
constexpr int32_t INTENT_QOS_MIN_LATENCY = 1000;
constexpr size_t MAX_SEND_BYTES_SIZE = 200 * 1024;
constexpr int64_t SESSION_IDLE_TIMEOUT_MS = 30000;
constexpr int64_t SESSION_CLEANUP_INTERVAL_MS = 1000;

enum IntentFragFlag : uint8_t {
    FRAG_START_END = 0,
    FRAG_START     = 1,
    FRAG_MID       = 2,
    FRAG_END       = 3,
};

struct FragHeader {
    uint32_t typeValue = 0;
    uint32_t totalLen = 0;
    uint16_t seq = 0;
    uint8_t flag = 0;
};

constexpr size_t INTENT_FRAG_TYPE_SIZE = sizeof(uint32_t);
constexpr size_t INTENT_FRAG_TOTAL_LEN_SIZE = sizeof(uint32_t);
constexpr size_t INTENT_FRAG_SEQ_SIZE = sizeof(uint16_t);
constexpr size_t INTENT_FRAG_FLAG_SIZE = sizeof(uint8_t);
constexpr size_t INTENT_FRAG_HEADER_SIZE =
    INTENT_FRAG_TYPE_SIZE + INTENT_FRAG_TOTAL_LEN_SIZE + INTENT_FRAG_SEQ_SIZE + INTENT_FRAG_FLAG_SIZE;
constexpr size_t INTENT_MIN_SEND_SIZE = INTENT_FRAG_HEADER_SIZE + 1;

struct IntentFragBuffer {
    uint32_t dataType = 0;
    uint32_t totalLen = 0;
    uint16_t expectedSeq = 0;
    std::map<uint16_t, std::string> fragments;
};

class IIntentProvider;

class DistributedIntentDsoftbusAdapter : public IIntentSocketEventListener {
    DECLARE_SINGLE_INSTANCE_BASE(DistributedIntentDsoftbusAdapter);

public:
    void SetProvider(IIntentProvider* provider) { provider_ = provider; }
    IIntentProvider* GetProvider() const { return provider_; }
    void SetStopped(bool stopped) { stopped_.store(stopped); }
    bool IsStopped() const { return stopped_.load(); }
    int32_t BindIntentSession(const std::string& deviceId, int32_t& socketFd);
    void UnbindIntentSession(int32_t socketFd);
    void ShutdownDeviceSession(const std::string& deviceId);
    void ForceCleanupDeviceSessions(const std::string& deviceId, std::vector<int32_t>& closedSockets);
    int32_t SendIntentDataBySession(int32_t socketFd, IntentDataType dataType, const std::string& data);
    int32_t GetSocketFdByDeviceId(const std::string& deviceId);

    void OnIntentBind(int32_t socket, const std::string& peerDeviceId);
    void OnIntentShutdown(int32_t socket);
    void OnIntentBytes(int32_t socket, const void* data, uint32_t dataLen);

    // IIntentSocketEventListener
    void OnIntentSocketBind(int32_t socket, const std::string& peerDeviceId) override {
        OnIntentBind(socket, peerDeviceId);
    }
    void OnIntentSocketShutdown(int32_t socket) override {
        OnIntentShutdown(socket);
    }
    void OnIntentSocketBytes(int32_t socket, const void* data, uint32_t dataLen) override {
        OnIntentBytes(socket, data, dataLen);
    }

private:
    DistributedIntentDsoftbusAdapter();
    ~DistributedIntentDsoftbusAdapter();

    int32_t CreateIntentSocket(const std::string& deviceId);
    int32_t BindIntentSocket(int32_t socketFd);
    void CreateSessionRecord(int32_t socketFd, const std::string& peerDeviceId);
    void CleanupSocketIfNeeded(int32_t socketFd);
    void ProcessReceivedData(int32_t socketFd, const void* data, uint32_t dataLen);
    void ProcessFragFrame(int32_t socketFd, uint32_t dataType, uint32_t totalLen,
        uint16_t seq, uint8_t flag, const std::string& payload);
    void DeliverIntentData(int32_t socketFd, IntentDataType dataType, const std::string& payload);
    std::string AssembleFragPayload(int32_t socketFd, std::shared_ptr<IntentFragBuffer>& fragBuf);
    int32_t ReuseOrCreateSession(const std::string& deviceId, int32_t& socketFd);
    int32_t SendNoFrag(int32_t socketFd, uint32_t typeValue, uint32_t totalLen, const std::string& data);
    int32_t SendFrag(int32_t socketFd, uint32_t typeValue, uint32_t totalLen,
        const std::string& data, uint32_t maxSendSize);
    std::string GetPeerDeviceIdBySocket(int32_t socketFd);
    std::shared_ptr<IntentSocketSession> FindClientSession(const std::string& deviceId);
    std::shared_ptr<std::mutex> GetDeviceMutex(const std::string& deviceId);
    void RemoveDeviceMutex(const std::string& deviceId);

    void UpdateSessionActivity(int32_t socketFd);
    void CleanupIdleSessions();
    void StartSessionCleanupThread();
    void StopSessionCleanupThread();

    std::mutex sessionMutex_;
    std::map<int32_t, std::shared_ptr<IntentSocketSession>> sessions_;
    std::map<std::string, std::shared_ptr<std::mutex>> deviceIdMutexMap_;
    std::mutex deviceIdMapMutex_;
    std::thread sessionCleanupThread_;
    std::atomic<bool> sessionCleanupRunning_{false};
    std::condition_variable sessionCleanupCv_;
    std::mutex sessionCleanupMutex_;
    std::mutex fragMutex_;
    std::map<int32_t, std::shared_ptr<IntentFragBuffer>> fragBuffers_;
    std::atomic<bool> stopped_{false};
    IIntentProvider* provider_ = nullptr;
};

} // namespace DistributedSchedule
} // namespace OHOS

#endif // DISTRIBUTED_INTENT_DSOFTBUS_ADAPTER_H
