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

#include "dsched_all_connect_manager.h"

#include <dlfcn.h>

#include "distributed_sched_utils.h"
#include "dsched_continue_manager.h"
#include "dsched_transport_softbus_adapter.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedAllConnectManager";
constexpr int32_t CONNECT_DECISION_WAIT_S = 60;
}

IMPLEMENT_SINGLE_INSTANCE(DSchedAllConnectManager);

ServiceCollaborationManager_HardwareRequestInfo DSchedAllConnectManager::locReqInfo_ = {
    .hardWareType = ServiceCollaborationManagerHardwareType::SCM_DISPLAY,
    .canShare = true,
};
ServiceCollaborationManager_HardwareRequestInfo DSchedAllConnectManager::rmtReqInfo_ = {
    .hardWareType = ServiceCollaborationManagerHardwareType::SCM_DISPLAY,
    .canShare = true,
};
ServiceCollaborationManager_CommunicationRequestInfo DSchedAllConnectManager::communicationRequest_ = {
    .minBandwidth = DSCHED_QOS_TYPE_MIN_BW,
    .maxLatency = DSCHED_QOS_TYPE_MAX_LATENCY,
    .minLatency = DSCHED_QOS_TYPE_MIN_LATENCY,
    .maxWaitTime = 0,
    .dataType = "DATA_TYPE_BYTES",
};
std::queue<std::string> DSchedAllConnectManager::peerConnectCbQueue_;

int32_t DSchedAllConnectManager::InitAllConnectManager()
{
    HILOGI("Init bind manager.");
    int32_t ret = GetServiceCollaborationManagerProxy();
    if (ret != ERR_OK) {
        HILOGE("GetServiceCollaborationManagerProxy fail, ret %{public}d.", ret);
        return ret;
    }

    ret = RegistLifecycleCallback();
    if (ret != ERR_OK) {
        HILOGE("Regist lifecycle callback fail, ret %{public}d.", ret);
        return ret;
    }
    return ERR_OK;
}

int32_t DSchedAllConnectManager::UninitAllConnectManager()
{
    HILOGI("Uninit bind manager enter.");
    int32_t ret = UnregistLifecycleCallback();
    if (ret != ERR_OK) {
        HILOGE("Unregist lifecycle callback fail, ret %{public}d.", ret);
    }
    dlclose(dllHandle_);
    dllHandle_ = nullptr;
    allConnectMgrApi_ = {
        .ServiceCollaborationManager_PublishServiceState = nullptr,
        .ServiceCollaborationManager_ApplyAdvancedResource = nullptr,
        .ServiceCollaborationManager_RegisterLifecycleCallback = nullptr,
        .ServiceCollaborationManager_UnRegisterLifecycleCallback = nullptr,
    };
    return ERR_OK;
}

int32_t DSchedAllConnectManager::GetServiceCollaborationManagerProxy()
{
    HILOGI("Get service collaboration manager proxy for all connect.");
    std::lock_guard<std::mutex> autoLock(allConnectMgrLock_);
#if (defined(__aarch64__) || defined(__x86_64__))
    std::string resolvedPath = "/system/lib64/libcfwk_allconnect_client.z.so";
#else
    std::string resolvedPath = "/system/lib/libcfwk_allconnect_client.z.so";
#endif
    char path[PATH_MAX + 1] = {0};
    if (resolvedPath.length() > PATH_MAX || realpath(resolvedPath.c_str(), path) == nullptr) {
        HILOGE("Check all connect so real path failed, resolvedPath [%{public}s].", resolvedPath.c_str());
        return INVALID_PARAMETERS_ERR;
    }
    int32_t (*ServiceCollaborationManagerExport)(ServiceCollaborationManager_API *exportapi) = nullptr;

    dllHandle_ = dlopen(resolvedPath.c_str(), RTLD_LAZY);
    if (dllHandle_ == nullptr) {
        HILOGE("Open dms interactive adapter shared object fail, resolvedPath [%{public}s].", resolvedPath.c_str());
        return NOT_FIND_SERVICE_REGISTRY;
    }

    int32_t ret = ERR_OK;
    do {
        ServiceCollaborationManagerExport =
            reinterpret_cast<int32_t (*)(ServiceCollaborationManager_API *exportapi)>(
            dlsym(dllHandle_, "ServiceCollaborationManager_Export"));
        if (ServiceCollaborationManagerExport == nullptr) {
            HILOGE("Link the ServiceCollaborationManagerExport symbol in dms interactive adapter fail.");
            ret = NOT_FIND_SERVICE_REGISTRY;
            break;
        }

        ret = ServiceCollaborationManagerExport(&allConnectMgrApi_);
        if (ret != ERR_OK) {
            HILOGE("Init remote dms interactive adapter proxy fail, ret %{public}d.", ret);
            break;
        }
        HILOGI("Init remote dms interactive adapter proxy success.");
    } while (false);

    if (ret != ERR_OK) {
        HILOGE("Get remote dms interactive adapter proxy fail, dlclose handle.");
        dlclose(dllHandle_);
        dllHandle_ = nullptr;
    }
    return ret;
}

int32_t DSchedAllConnectManager::RegistLifecycleCallback()
{
    std::lock_guard<std::mutex> autoLock(allConnectMgrLock_);
    HILOGI("Regist lifecycle callback.");
    if (allConnectMgrApi_.ServiceCollaborationManager_RegisterLifecycleCallback == nullptr) {
        HILOGE("Dms all connect manager RegisterLifecycleCallback api is null.");
        return INVALID_PARAMETERS_ERR;
    }

    ServiceCollaborationManager_Callback bindMgrRegLfCB = {
        .OnStop = &DSchedAllConnectManager::OnStop,
        .ApplyResult = &DSchedAllConnectManager::ApplyResult,
    };

    int32_t ret = allConnectMgrApi_.ServiceCollaborationManager_RegisterLifecycleCallback(
        DMS_BIND_MGR_SRV_NAME, &bindMgrRegLfCB);
    if (ret != ERR_OK) {
        HILOGE("Dms all connect manager regist lifecycle callback fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t DSchedAllConnectManager::UnregistLifecycleCallback()
{
    std::lock_guard<std::mutex> autoLock(allConnectMgrLock_);
    HILOGI("Unregist lifecycle callback.");
    if (allConnectMgrApi_.ServiceCollaborationManager_UnRegisterLifecycleCallback == nullptr) {
        HILOGE("Dms all connect manager UnRegisterLifecycleCallback api is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = allConnectMgrApi_.ServiceCollaborationManager_UnRegisterLifecycleCallback(
        DMS_BIND_MGR_SRV_NAME);
    if (ret != ERR_OK) {
        HILOGE("Dms all connect manager unregist lifecycle callback fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t DSchedAllConnectManager::PublishServiceState(const std::string &peerNetworkId, const std::string &extraInfo,
    ServiceCollaborationManagerBussinessStatus state)
{
    std::lock_guard<std::mutex> autoLock(allConnectMgrLock_);
    HILOGI("Publish service state enter, peerNetworkId %{public}s, extraInfo %{public}s, state %{public}d.",
        GetAnonymStr(peerNetworkId).c_str(), extraInfo.c_str(), state);
    if (allConnectMgrApi_.ServiceCollaborationManager_PublishServiceState == nullptr) {
        HILOGE("Dms all connect manager PublishServiceState api is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = allConnectMgrApi_.ServiceCollaborationManager_PublishServiceState(peerNetworkId.c_str(),
        DMS_BIND_MGR_SRV_NAME, extraInfo.c_str(), state);
    if (ret != ERR_OK) {
        HILOGE("Dms all connect manager publish service state fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t DSchedAllConnectManager::ApplyAdvanceResource(const std::string &peerNetworkId,
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets)
{
    int32_t ret = ERR_OK;
    {
        std::lock_guard<std::mutex> autoLock(allConnectMgrLock_);
        HILOGI("Apply advance resource enter, peerNetworkId %{public}s.", GetAnonymStr(peerNetworkId).c_str());
        if (allConnectMgrApi_.ServiceCollaborationManager_ApplyAdvancedResource == nullptr) {
            HILOGE("Dms all connect manager ApplyAdvancedResource api is null.");
            return ERR_OK;
        }

        peerConnectCbQueue_.push(peerNetworkId);
        ServiceCollaborationManager_Callback applyScmCbApi = {
            .OnStop = &DSchedAllConnectManager::OnStop,
            .ApplyResult = &DSchedAllConnectManager::ApplyResult,
        };
        ret = allConnectMgrApi_.ServiceCollaborationManager_ApplyAdvancedResource(peerNetworkId.c_str(),
            DMS_BIND_MGR_SRV_NAME, &reqInfoSets, &applyScmCbApi);
        if (ret != ERR_OK) {
            HILOGE("Dms all connect manager apply advanced resource fail, ret %{public}d.", ret);
            return ret;
        }
    }

    ret = WaitAllConnectApplyCb(peerNetworkId);
    if (ret != ERR_OK) {
        HILOGE("Wait all connect manager apply callback fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t DSchedAllConnectManager::WaitAllConnectApplyCb(const std::string &peerNetworkId)
{
    std::unique_lock<std::mutex> decisionLock(connectDecisionMutex_);
    connectDecisionCond_.wait_for(decisionLock, std::chrono::seconds(CONNECT_DECISION_WAIT_S),
        [this, peerNetworkId]() {
            return peerConnectDecision_.find(peerNetworkId) != peerConnectDecision_.end();
        });

    if (peerConnectDecision_.find(peerNetworkId) == peerConnectDecision_.end()) {
        HILOGE("Not find peerNetworkId %{public}s in peerConnectDecision.", GetAnonymStr(peerNetworkId).c_str());
        return CONTINUE_ABILITY_TIMEOUT_ERR;
    }
    int32_t ret = peerConnectDecision_.at(peerNetworkId).load() ? ERR_OK : DMS_CONNECT_APPLY_REJECT_FAILED;
    HILOGI("Wait all connect apply decision callback end, peerNetworkId %{public}s, isSupport %{public}d.",
        GetAnonymStr(peerNetworkId).c_str(), peerConnectDecision_.at(peerNetworkId).load());
    peerConnectDecision_.erase(peerNetworkId);
    return ret;
}

void DSchedAllConnectManager::NotifyAllConnectDecision(const std::string &peerNetworkId, bool isSupport)
{
    HILOGI("Notify all connect decision, peerNetworkId %{public}s, isSupport %{public}d.",
        GetAnonymStr(peerNetworkId).c_str(), isSupport);
    std::lock_guard<std::mutex> decisionLock(connectDecisionMutex_);
    peerConnectDecision_[peerNetworkId] = isSupport;
    connectDecisionCond_.notify_all();
}

void DSchedAllConnectManager::GetResourceRequest(ServiceCollaborationManager_ResourceRequestInfoSets &reqInfoSets)
{
    reqInfoSets.remoteHardwareListSize = 1;
    reqInfoSets.remoteHardwareList = &rmtReqInfo_;
    reqInfoSets.localHardwareListSize = 1;
    reqInfoSets.localHardwareList = &locReqInfo_;
    reqInfoSets.communicationRequest = &communicationRequest_;
}

int32_t DSchedAllConnectManager::OnStop(const char *peerNetworkId)
{
    HILOGI("OnStop, when other task prepare to seize bind, disconnect DMS bind with peerNetworkId %{public}s.",
        GetAnonymStr(peerNetworkId).c_str());
    int32_t sessionId = -1;
    if (!DSchedTransportSoftbusAdapter::GetInstance().GetSessionIdByDeviceId(peerNetworkId, sessionId)) {
        HILOGW("Not find any sessionId by peerNetworkId %{public}s.", GetAnonymStr(peerNetworkId).c_str());
        return ERR_OK;
    }
    DSchedTransportSoftbusAdapter::GetInstance().OnShutdown(sessionId, false);
    return ERR_OK;
}

int32_t DSchedAllConnectManager::ApplyResult(int32_t errorcode, int32_t result, const char *reason)
{
    HILOGI("Apply result start, errorcode %{public}d, result %{public}s, reason %{public}s.",
        errorcode, result == ServiceCollaborationManagerResultCode::PASS ? "PASS" : "REJECT", reason);

    bool isSupport = result == ServiceCollaborationManagerResultCode::PASS ? true : false;
    if (peerConnectCbQueue_.empty()) {
        HILOGE("Apply result start, peerConnectCbQueue is empty.");
        return ERR_OK;
    }
    std::string peerNetworkId = peerConnectCbQueue_.front();
    DSchedContinueManager::GetInstance().NotifyAllConnectDecision(peerNetworkId, isSupport);
    DSchedAllConnectManager::GetInstance().NotifyAllConnectDecision(peerNetworkId, isSupport);
    peerConnectCbQueue_.pop();
    return ERR_OK;
}
} // namespace DistributedSchedule
} // namespace OHOS