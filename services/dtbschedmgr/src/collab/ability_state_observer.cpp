/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "ability_state_observer.h"

#include "distributed_sched_service.h"
#include "dsched_collab_manager.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "AbilityLifecycleObserver";
}

void AbilityLifecycleObserver::OnForegroundApplicationChanged(const AppExecFwk::AppStateData& appStateData)
{
    HILOGI("called.");
}

void AbilityLifecycleObserver::OnAbilityStateChanged(const AppExecFwk::AbilityStateData& abilityStateData)
{
    HILOGI("called, abilityState: %{public}d", abilityStateData.abilityState);
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
     if (abilityStateData.abilityState == static_cast<int32_t>(SliteAbilityState::STATE_BACKGROUND)) {
        std::vector<std::shared_ptr<BackgroundTaskMgr::ContinuousTaskCallbackInfo>> continuousTasksInfos;
        int32_t result = BackgroundTaskMgr::BackgroundTaskMgrHelper::GetContinuousTaskApps(continuousTasksInfos);
        if (result != ERR_OK) {
            HILOGE("failed to GetContinuousTaskApps, err: %{public}d", result);
            return;
        }
        for (auto continuousTasksInfo : continuousTasksInfos) {
            if (continuousTasksInfo == nullptr) {
                continue;
            }
            if (continuousTasksInfo->GetCreatorPid() == abilityStateData.pid) {
                HILOGW("called, find the pid in continuous tasks");
                return;
            }
        }
        HILOGW("called, can't find the pid in continuous tasks");
        DSchedCollabManager::GetInstance().ReleaseAbilityLink(abilityStateData.bundleName, abilityStateData.pid);
    } else if (abilityStateData.abilityState == static_cast<int32_t>(SliteAbilityState::STATE_FOREGROUND) ||
        abilityStateData.abilityState == static_cast<int32_t>(SliteAbilityState::STATE_INITIAL)) {
        DSchedCollabManager::GetInstance().CancleReleaseAbilityLink(abilityStateData.bundleName, abilityStateData.pid);
    }
#else
    HILOGE("failed to check continuousTaskApps");
#endif
    HILOGI("end.");
}

void AbilityLifecycleObserver::OnExtensionStateChanged(const AppExecFwk::AbilityStateData& extensionStateData)
{
    HILOGI("called.");
}

void AbilityLifecycleObserver::OnProcessCreated(const AppExecFwk::ProcessData& processData)
{
    HILOGI("called.");
}

void AbilityLifecycleObserver::OnProcessDied(const AppExecFwk::ProcessData& processData)
{
    HILOGI("called, bundleName: %{public}s", processData.bundleName.c_str());
    DSchedCollabManager::GetInstance().NotifyAbilityDied(processData.bundleName, processData.pid);
    HILOGI("end.");
}
} // namespace DistributedSchedule
} // namespace OHOS
