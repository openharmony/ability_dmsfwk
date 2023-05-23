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

#include "app_state_observer.h"
#include "distributed_sched_service.h"
#include "dtbschedmgr_log.h"
#include "element_name.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "AppStateObserver";
constexpr int32_t FOREGROUND = 2;
constexpr int32_t BACKGROUND = 4;
constexpr int32_t NOTIFY_COUNT = 2;
}

void AppStateObserver::OnForegroundApplicationChanged(const AppExecFwk::AppStateData& appStateData)
{
}

void AppStateObserver::OnAbilityStateChanged(const AppExecFwk::AbilityStateData& abilityStateData)
{
    HILOGD("OnAbilityStateChanged called.");
    if (abilityStateData.abilityState != FOREGROUND && abilityStateData.abilityState != BACKGROUND) {
        HILOGD("ability state neither foreground nor background");
        return;
    }
    {
        std::lock_guard<std::mutex> autoLock(countLock_);
        if (connectAbilityMap_.count(abilityStateData.token) == 0) {
            connectAbilityMap_[abilityStateData.token] = 1;
        } else {
            connectAbilityMap_[abilityStateData.token]++;
        }
        if (connectAbilityMap_[abilityStateData.token] != NOTIFY_COUNT &&
            abilityStateData.abilityState == FOREGROUND) {
            HILOGD("ignore first notify");
            return;
        }
        connectAbilityMap_[abilityStateData.token] = 0;
    }
    HILOGD("abilityState = %{public}d", abilityStateData.abilityState);
    AppExecFwk::ElementName element("", abilityStateData.bundleName, abilityStateData.abilityName,
        abilityStateData.moduleName);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChanged(abilityStateData.abilityState,
        element, abilityStateData.token);
    HILOGD("notify callee state changed, ret = %{public}d", ret);
}

void AppStateObserver::OnExtensionStateChanged(const AppExecFwk::AbilityStateData& extensionStateData)
{
}

void AppStateObserver::OnProcessCreated(const AppExecFwk::ProcessData& processData)
{
}

void AppStateObserver::OnProcessDied(const AppExecFwk::ProcessData& processData)
{
}
} // namespace DistributedSchedule
} // namespace OHOS