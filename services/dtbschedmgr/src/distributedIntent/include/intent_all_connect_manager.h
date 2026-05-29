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

#ifndef OHOS_INTENT_ALL_CONNECT_MANAGER_H
#define OHOS_INTENT_ALL_CONNECT_MANAGER_H

#include <atomic>
#include <condition_variable>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <vector>

#include "service_collaboration_manager_capi.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

class IntentAllConnectManager {
DECLARE_SINGLE_INSTANCE_BASE(IntentAllConnectManager);
public:
    int32_t Init();
    int32_t Uninit();
    int32_t ApplyResource(const std::string &peerNetworkId);
    int32_t PublishServiceState(const std::string &peerNetworkId,
        ServiceCollaborationManagerBussinessStatus state);
    bool IsAllConnectAvailable();

private:
    IntentAllConnectManager() = default;
    ~IntentAllConnectManager() = default;

    int32_t LoadAllConnectSo();
    int32_t RegisterLifecycleCallback();
    int32_t UnregisterLifecycleCallback();
    int32_t WaitForApplyResult(const std::string &peerNetworkId);

    void NotifyApplyResult(const std::string &peerNetworkId, bool isApproved);

    static int32_t OnStopCallback(const char *peerNetworkId);
    static int32_t ApplyResultCallback(int32_t errorcode, int32_t result, const char *reason);

    int32_t HandleOnStop(const std::string &peerNetworkId);

    static constexpr int32_t QOS_MIN_BW = 40 * 1024 * 1024;
    static constexpr int32_t QOS_MAX_LATENCY = 6000;
    static constexpr int32_t QOS_MIN_LATENCY = 1000;
    static constexpr int32_t WAIT_TIMEOUT_S = 60;
    const char *INTENT_SRV_NAME = "DistributedIntent";

    std::mutex mutex_;
    void *dllHandle_ = nullptr;
    bool isAvailable_ = false;

    ServiceCollaborationManager_API api_ = {
        .ServiceCollaborationManager_PublishServiceState = nullptr,
        .ServiceCollaborationManager_ApplyAdvancedResource = nullptr,
        .ServiceCollaborationManager_RegisterLifecycleCallback = nullptr,
        .ServiceCollaborationManager_UnRegisterLifecycleCallback = nullptr,
    };

    static ServiceCollaborationManager_HardwareRequestInfo locReqInfo_;
    static ServiceCollaborationManager_HardwareRequestInfo rmtReqInfo_;
    static ServiceCollaborationManager_CommunicationRequestInfo commReqInfo_;
    static std::queue<std::string> applyQueue_;

    std::mutex decisionMutex_;
    std::condition_variable decisionCv_;
    std::map<std::string, std::atomic<bool>> decisions_;
};

} // namespace DistributedSchedule
} // namespace OHOS

#endif // OHOS_INTENT_ALL_CONNECT_MANAGER_H
