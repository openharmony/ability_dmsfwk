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

#include <string>
#include <memory>
#include <mutex>
#include <map>
#include <chrono>
#include <thread>
#include <atomic>
#include <condition_variable>

#include "single_instance.h"
#include "distributed_intent_error_code.h"

namespace OHOS {
namespace DistributedSchedule {

enum class IntentDataType {
    INTENT_DATA_TYPE_EXECUTE = 1,
    INTENT_DATA_TYPE_DMS_RESULT = 2,
    INTENT_DATA_TYPE_AMGR_RESULT = 3,
    INTENT_DATA_TYPE_EXECUTE_RESULT = 4,
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
constexpr size_t MAX_SEND_BYTES_SIZE = 100 * 1024 * 1024;
constexpr int64_t SESSION_IDLE_TIMEOUT_MS = 30000;
constexpr int64_t SESSION_CLEANUP_INTERVAL_MS = 1000;

class DistributedIntentDsoftbusAdapter {
    DECLARE_SINGLE_INSTANCE_BASE(DistributedIntentDsoftbusAdapter);

public:
    int32_t BindIntentSession(const std::string& deviceId, int32_t& socketFd);
    void UnbindIntentSession(int32_t socketFd);
    int32_t SendIntentDataBySession(int32_t socketFd, IntentDataType dataType, const std::string& data);
    int32_t GetSocketFdByDeviceId(const std::string& deviceId);

    void OnIntentBind(int32_t socket, const std::string& peerDeviceId);
    void OnIntentShutdown(int32_t socket);
    void OnIntentBytes(int32_t socket, const void* data, uint32_t dataLen);

private:
    DistributedIntentDsoftbusAdapter();
    ~DistributedIntentDsoftbusAdapter();

    int32_t CreateIntentSocket(const std::string& deviceId);
    int32_t BindIntentSocket(int32_t socketFd);
    void CreateSessionRecord(int32_t socketFd, const std::string& peerDeviceId);
    void CleanupSocketIfNeeded(int32_t socketFd);
    void ProcessReceivedData(int32_t socketFd, const void* data, uint32_t dataLen);
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
};

} // namespace DistributedSchedule
} // namespace OHOS

#endif // DISTRIBUTED_INTENT_DSOFTBUS_ADAPTER_H
