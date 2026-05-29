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

#include "intent_all_connect_manager.h"

#include <dlfcn.h>
#include "distributed_intent_dsoftbus_adapter.h"
#include "distributed_intent_error_code.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_log.h"
#include "remote_intent_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "IntentAllConnectManager";
}

IMPLEMENT_SINGLE_INSTANCE(IntentAllConnectManager);

ServiceCollaborationManager_HardwareRequestInfo IntentAllConnectManager::locReqInfo_ = {
    .hardWareType = SCM_DISPLAY,
    .canShare = true,
};
ServiceCollaborationManager_HardwareRequestInfo IntentAllConnectManager::rmtReqInfo_ = {
    .hardWareType = SCM_DISPLAY,
    .canShare = true,
};
ServiceCollaborationManager_CommunicationRequestInfo IntentAllConnectManager::commReqInfo_ = {
    .minBandwidth = QOS_MIN_BW,
    .maxLatency = QOS_MAX_LATENCY,
    .minLatency = QOS_MIN_LATENCY,
    .maxWaitTime = 0,
    .dataType = "DATA_TYPE_BYTES",
};
std::queue<std::string> IntentAllConnectManager::applyQueue_;

int32_t IntentAllConnectManager::Init()
{
    HILOGI("Init intent all connect manager.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = LoadAllConnectSo();
    if (ret != ERR_OK) {
        HILOGE("LoadAllConnectSo fail, ret %{public}d.", ret);
        return ret;
    }

    ret = RegisterLifecycleCallback();
    if (ret != ERR_OK) {
        HILOGE("RegisterLifecycleCallback fail, ret %{public}d.", ret);
        return ret;
    }
    isAvailable_ = true;
    return ERR_OK;
}

int32_t IntentAllConnectManager::Uninit()
{
    HILOGI("Uninit intent all connect manager.");
    std::lock_guard<std::mutex> lock(mutex_);
    int32_t ret = UnregisterLifecycleCallback();
    if (ret != ERR_OK) {
        HILOGE("UnregisterLifecycleCallback fail, ret %{public}d.", ret);
    }
    if (dllHandle_ != nullptr) {
        dlclose(dllHandle_);
        dllHandle_ = nullptr;
    }
    api_ = {};
    isAvailable_ = false;
    return ERR_OK;
}

int32_t IntentAllConnectManager::LoadAllConnectSo()
{
#if (defined(__aarch64__) || defined(__x86_64__))
    std::string resolvedPath = "/system/lib64/libcfwk_allconnect_client.z.so";
#else
    std::string resolvedPath = "/system/lib/libcfwk_allconnect_client.z.so";
#endif
    char path[PATH_MAX + 1] = {0};
    if (resolvedPath.length() > PATH_MAX || realpath(resolvedPath.c_str(), path) == nullptr) {
        HILOGE("Check so real path failed, resolvedPath [%{public}s].",
            GetAnonymStr(resolvedPath).c_str());
        return INVALID_PARAMETERS_ERR;
    }

    dllHandle_ = dlopen(resolvedPath.c_str(), RTLD_LAZY);
    if (dllHandle_ == nullptr) {
        HILOGE("dlopen failed, resolvedPath [%{public}s].",
            GetAnonymStr(resolvedPath).c_str());
        return NOT_FIND_SERVICE_REGISTRY;
    }

    auto exportFunc = reinterpret_cast<int32_t (*)(ServiceCollaborationManager_API *)>(
        dlsym(dllHandle_, "ServiceCollaborationManager_Export"));
    if (exportFunc == nullptr) {
        HILOGE("ServiceCollaborationManager_Export symbol not found.");
        dlclose(dllHandle_);
        dllHandle_ = nullptr;
        return NOT_FIND_SERVICE_REGISTRY;
    }

    int32_t ret = exportFunc(&api_);
    if (ret != ERR_OK) {
        HILOGE("Export API fail, ret: %{public}d.", ret);
        dlclose(dllHandle_);
        dllHandle_ = nullptr;
        return ret;
    }

    HILOGI("Load all connect so success.");
    return ERR_OK;
}

int32_t IntentAllConnectManager::RegisterLifecycleCallback()
{
    if (api_.ServiceCollaborationManager_RegisterLifecycleCallback == nullptr) {
        HILOGE("RegisterLifecycleCallback api is null.");
        return INVALID_PARAMETERS_ERR;
    }

    ServiceCollaborationManager_Callback cb = {
        .OnStop = &IntentAllConnectManager::OnStopCallback,
        .ApplyResult = &IntentAllConnectManager::ApplyResultCallback,
    };

    int32_t ret = api_.ServiceCollaborationManager_RegisterLifecycleCallback(INTENT_SRV_NAME, &cb);
    if (ret != ERR_OK) {
        HILOGE("RegisterLifecycleCallback fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t IntentAllConnectManager::UnregisterLifecycleCallback()
{
    if (api_.ServiceCollaborationManager_UnRegisterLifecycleCallback == nullptr) {
        HILOGE("UnRegisterLifecycleCallback api is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = api_.ServiceCollaborationManager_UnRegisterLifecycleCallback(INTENT_SRV_NAME);
    if (ret != ERR_OK) {
        HILOGE("UnregisterLifecycleCallback fail, ret %{public}d.", ret);
    }
    return ret;
}

bool IntentAllConnectManager::IsAllConnectAvailable()
{
    return isAvailable_;
}

int32_t IntentAllConnectManager::ApplyResource(const std::string &peerNetworkId)
{
    std::lock_guard<std::mutex> lock(mutex_);
    HILOGI("ApplyResource enter, peerNetworkId %{public}s.", GetAnonymStr(peerNetworkId).c_str());
    if (api_.ServiceCollaborationManager_ApplyAdvancedResource == nullptr) {
        HILOGE("ApplyAdvancedResource api is null.");
        return INVALID_PARAMETERS_ERR;
    }

    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    reqInfoSets.remoteHardwareListSize = 1;
    reqInfoSets.remoteHardwareList = &rmtReqInfo_;
    reqInfoSets.localHardwareListSize = 1;
    reqInfoSets.localHardwareList = &locReqInfo_;
    reqInfoSets.communicationRequest = &commReqInfo_;

    applyQueue_.push(peerNetworkId);

    ServiceCollaborationManager_Callback cb = {
        .OnStop = &IntentAllConnectManager::OnStopCallback,
        .ApplyResult = &IntentAllConnectManager::ApplyResultCallback,
    };

    int32_t ret = api_.ServiceCollaborationManager_ApplyAdvancedResource(
        peerNetworkId.c_str(), INTENT_SRV_NAME, &reqInfoSets, &cb);
    if (ret != ERR_OK) {
        HILOGE("ApplyAdvancedResource fail, ret %{public}d.", ret);
        return ret;
    }

    return WaitForApplyResult(peerNetworkId);
}

int32_t IntentAllConnectManager::WaitForApplyResult(const std::string &peerNetworkId)
{
    std::unique_lock<std::mutex> lock(decisionMutex_);
    decisionCv_.wait_for(lock, std::chrono::seconds(WAIT_TIMEOUT_S),
        [this, peerNetworkId]() {
            return decisions_.find(peerNetworkId) != decisions_.end();
        });

    if (decisions_.find(peerNetworkId) == decisions_.end()) {
        HILOGE("Wait apply result timeout, peerNetworkId %{public}s.",
            GetAnonymStr(peerNetworkId).c_str());
        return DMS_CONNECT_APPLY_TIMEOUT_FAILED;
    }

    bool approved = decisions_.at(peerNetworkId).load();
    HILOGI("Apply result, peerNetworkId %{public}s, approved %{public}d.",
        GetAnonymStr(peerNetworkId).c_str(), approved);
    decisions_.erase(peerNetworkId);
    return approved ? ERR_OK : DMS_CONNECT_APPLY_REJECT_FAILED;
}

void IntentAllConnectManager::NotifyApplyResult(const std::string &peerNetworkId, bool isApproved)
{
    std::lock_guard<std::mutex> lock(decisionMutex_);
    decisions_[peerNetworkId] = isApproved;
    decisionCv_.notify_all();
}

int32_t IntentAllConnectManager::PublishServiceState(const std::string &peerNetworkId,
    ServiceCollaborationManagerBussinessStatus state)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (api_.ServiceCollaborationManager_PublishServiceState == nullptr) {
        HILOGE("PublishServiceState api is null.");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = api_.ServiceCollaborationManager_PublishServiceState(
        peerNetworkId.c_str(), INTENT_SRV_NAME, "", state);
    if (ret != ERR_OK) {
        HILOGE("PublishServiceState fail, ret %{public}d.", ret);
    }
    return ret;
}

int32_t IntentAllConnectManager::OnStopCallback(const char *peerNetworkId)
{
    if (peerNetworkId == nullptr) {
        return ERR_OK;
    }
    HILOGI("OnStop, peerNetworkId %{public}s.", GetAnonymStr(peerNetworkId).c_str());
    IntentAllConnectManager::GetInstance().HandleOnStop(std::string(peerNetworkId));
    return ERR_OK;
}

int32_t IntentAllConnectManager::HandleOnStop(const std::string &peerNetworkId)
{
    HILOGI("HandleOnStop, peerNetworkId %{public}s.", GetAnonymStr(peerNetworkId).c_str());

    // 1. 断开该设备的Socket
    DistributedIntentDsoftbusAdapter::GetInstance().ShutdownDeviceSession(peerNetworkId);

    // 2. 通知业务该设备连接被抢占断开
    RemoteIntentManager::GetInstance().NotifyLinkDisconnected(
        peerNetworkId, ERR_DI_LINK_DISCONNECTED);

    // 3. 发布状态为IDLE
    PublishServiceState(peerNetworkId, SCM_IDLE);

    return ERR_OK;
}

int32_t IntentAllConnectManager::ApplyResultCallback(int32_t errorcode, int32_t result, const char *reason)
{
    HILOGI("ApplyResult, errorcode %{public}d, result %{public}d.", errorcode, result);
    bool isApproved = (result == ServiceCollaborationManagerResultCode::PASS);
    if (applyQueue_.empty()) {
        HILOGE("ApplyResult but applyQueue is empty.");
        return ERR_OK;
    }
    std::string peerNetworkId = applyQueue_.front();
    IntentAllConnectManager::GetInstance().NotifyApplyResult(peerNetworkId, isApproved);
    applyQueue_.pop();
    return ERR_OK;
}

} // namespace DistributedSchedule
} // namespace OHOS
