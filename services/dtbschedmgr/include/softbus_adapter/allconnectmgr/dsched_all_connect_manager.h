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

#ifndef OHOS_DSCHED_ALL_CONNECT_MANAGER_H
#define OHOS_DSCHED_ALL_CONNECT_MANAGER_H

#include <map>
#include <mutex>
#include <queue>
#include <string>

#include "service_collaboration_manager_capi.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
class DSchedAllConnectManager {
DECLARE_SINGLE_INSTANCE_BASE(DSchedAllConnectManager);
public:
    int32_t InitAllConnectManager();
    int32_t UninitAllConnectManager();
    int32_t PublishServiceState(const std::string &peerNetworkId, const std::string &extraInfo,
        ServiceCollaborationManagerBussinessStatus state);
    int32_t ApplyAdvanceResource(const std::string &peerNetworkId,
        ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets);
    void GetResourceRequest(ServiceCollaborationManager_ResourceRequestInfoSets &reqInfoSets);

private:
    DSchedAllConnectManager() = default;
    ~DSchedAllConnectManager() = default;
    int32_t GetServiceCollaborationManagerProxy();
    int32_t RegistLifecycleCallback();
    int32_t UnregistLifecycleCallback();
    int32_t WaitAllConnectApplyCb(const std::string &peerNetworkId);
    void NotifyAllConnectDecision(const std::string &peerNetworkId, bool isSupport);

    static int32_t OnStop(const char *peerNetworkId);
    static int32_t ApplyResult(int32_t errorcode, int32_t result, const char *reason);

private:
    static constexpr int32_t DSCHED_QOS_TYPE_MIN_BW = 40 * 1024 * 1024;
    static constexpr int32_t DSCHED_QOS_TYPE_MAX_LATENCY = 6000;
    static constexpr int32_t DSCHED_QOS_TYPE_MIN_LATENCY = 1000;
    static ServiceCollaborationManager_HardwareRequestInfo locReqInfo_;
    static ServiceCollaborationManager_HardwareRequestInfo rmtReqInfo_;
    static ServiceCollaborationManager_CommunicationRequestInfo communicationRequest_;
    static std::queue<std::string> peerConnectCbQueue_;
    const char *DMS_BIND_MGR_SRV_NAME = "TaskContinue";

    std::mutex allConnectMgrLock_;
    void *dllHandle_ = nullptr;
    ServiceCollaborationManager_API allConnectMgrApi_ = {
        .ServiceCollaborationManager_PublishServiceState = nullptr,
        .ServiceCollaborationManager_ApplyAdvancedResource = nullptr,
        .ServiceCollaborationManager_RegisterLifecycleCallback = nullptr,
        .ServiceCollaborationManager_UnRegisterLifecycleCallback = nullptr,
    };

    std::mutex connectDecisionMutex_;
    std::condition_variable connectDecisionCond_;
    std::map<std::string, std::atomic<bool>> peerConnectDecision_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DSCHED_ALL_CONNECT_MANAGER_H
