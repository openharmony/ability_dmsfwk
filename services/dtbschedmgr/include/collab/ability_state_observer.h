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

#ifndef OHOS_ABILITY_STATE_OBSERVER_H
#define OHOS_ABILITY_STATE_OBSERVER_H

#include "application_state_observer_stub.h"
#ifdef BGTASKMGR_CONTINUOUS_TASK_ENABLE
#include "background_task_mgr_helper.h"
#endif

namespace OHOS {
namespace DistributedSchedule {
enum class SliteAbilityState {
    STATE_UNKNOWN = 0,
    /**
     * Uninitialized state: An ability is in this state when it has not been initialized.
     */
    STATE_UNINITIALIZED = 1,

    /**
     * Initial state: An ability is in this state after it is initialized.
     */
    STATE_INITIAL = 2,

    /**
     * Foreground state: An ability is in this state when it is switched to the foreground.
     */
    STATE_FOREGROUND = 3,

    /**
     * Background state: An ability is in this state after it returns to the background.
     */
    STATE_BACKGROUND = 4,
};

class AbilityLifecycleObserver : public AppExecFwk::ApplicationStateObserverStub {
public:
    /**
     * Application foreground state changed callback.
     *
     * @param appStateData Application Process data.
     */
    void OnForegroundApplicationChanged(const AppExecFwk::AppStateData& appStateData) override;

    /**
     * Will be called when the ability state changes.
     *
     * @param abilityStateData Ability state data.
     */
    void OnAbilityStateChanged(const AppExecFwk::AbilityStateData& abilityStateData) override;

    /**
     * Will be called when the extension state changes.
     *
     * @param abilityStateData Extension state data.
     */
    void OnExtensionStateChanged(const AppExecFwk::AbilityStateData& abilityStateData) override;

    /**
     * Will be called when the process start.
     *
     * @param processData Process data.
     */
    void OnProcessCreated(const AppExecFwk::ProcessData& processData) override;

    /**
     * Will be called when the process die.
     *
     * @param processData Process data.
     */
    void OnProcessDied(const AppExecFwk::ProcessData& processData) override;

    void ReportDistributedComponentChange(const AppExecFwk::AbilityStateData& abilityStateData,
    int32_t changeType);
private:
    std::mutex countLock_;
    std::map<sptr<IRemoteObject>, int32_t> connectAbilityMap_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_ABILITY_STATE_OBSERVER_H
