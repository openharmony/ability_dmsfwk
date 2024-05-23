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

#include "dsched_continue_data_state.h"

#include "dsched_continue.h"
#include "dsched_continue_event.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedContinueDataState";
}
DSchedContinueDataState::DSchedContinueDataState(std::shared_ptr<DSchedContinueStateMachine> stateMachine)
    : stateMachine_(stateMachine)
{
    memberFuncMap_[DSCHED_CONTINUE_DATA_EVENT] = &DSchedContinueDataState::DoContinueDataTask;
    memberFuncMap_[DSCHED_CONTINUE_END_EVENT] = &DSchedContinueDataState::DoContinueEndTask;
}

DSchedContinueDataState::~DSchedContinueDataState()
{
}

int32_t DSchedContinueDataState::Execute(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    auto iterFunc = memberFuncMap_.find(event->GetInnerEventId());
    if (iterFunc == memberFuncMap_.end()) {
        HILOGI("DSchedContinueDataState execute %{public}d in wrong state", event->GetInnerEventId());
        return CONTINUE_STATE_MACHINE_INVALID_STATE;
    }

    auto memberFunc = iterFunc->second;
    int32_t ret = (this->*memberFunc)(dContinue, event);
    if (ret != ERR_OK) {
        HILOGI("DSchedContinueDataState execute %{public}d failed, ret: %{public}d", event->GetInnerEventId(), ret);
    }
    return ret;
}

DSchedContinueStateType DSchedContinueDataState::GetStateType()
{
    return DSCHED_CONTINUE_DATA_STATE;
}

int32_t DSchedContinueDataState::DoContinueDataTask(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    auto stateMachine = stateMachine_.lock();
    if (stateMachine == nullptr) {
        HILOGE("DSchedContinueDataState stateMachine is null");
        return INVALID_PARAMETERS_ERR;
    }
    auto syncContinueData = event->GetSharedObject<DSchedContinueDataCmd>();
    int32_t ret = dContinue->ExecuteContinueData(syncContinueData);
    if (ret != ERR_OK) {
        HILOGE("DSchedContinueAbilityState ExecuteContinueSend failed, ret: %{public}d", ret);
    }
    return ret;
}

int32_t DSchedContinueDataState::DoContinueEndTask(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    auto stateMachine = stateMachine_.lock();
    if (stateMachine == nullptr) {
        HILOGE("DSchedContinueDataState stateMachine is null");
        return INVALID_PARAMETERS_ERR;
    }
    auto syncContinueData = event->GetSharedObject<int32_t>();
    int32_t ret = dContinue->ExecuteContinueError(*syncContinueData);
    if (ret != ERR_OK) {
        HILOGE("DSchedContinueDataState ExecuteContinueSend failed, ret: %{public}d", ret);
    }
    return ret;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
