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

#include "dsched_continue_sink_start_state.h"

#include "dsched_continue.h"
#include "dsched_continue_event.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedContinueSinkStartState";
}
DSchedContinueSinkStartState::DSchedContinueSinkStartState(std::shared_ptr<DSchedContinueStateMachine> stateMachine)
    : stateMachine_(stateMachine)
{
    memberFuncMap_[DSCHED_CONTINUE_REQ_PULL_EVENT] = &DSchedContinueSinkStartState::DoContinuePullReqTask;
    memberFuncMap_[DSHCED_CONTINUE_ABILITY_EVENT] = &DSchedContinueSinkStartState::DoContinueAbilityTask;
    memberFuncMap_[DSCHED_CONTINUE_COMPLETE_EVENT] = &DSchedContinueSinkStartState::DoContinueEndTask;
    memberFuncMap_[DSCHED_CONTINUE_END_EVENT] = &DSchedContinueSinkStartState::DoContinueErrorTask;
}

DSchedContinueSinkStartState::~DSchedContinueSinkStartState()
{
}

int32_t DSchedContinueSinkStartState::Execute(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        HILOGE("event is null");
        return INVALID_PARAMETERS_ERR;
    }
    auto iterFunc = memberFuncMap_.find(event->GetInnerEventId());
    if (iterFunc == memberFuncMap_.end()) {
        HILOGI("DSchedContinueSinkStartState execute %{public}d in wrong state", event->GetInnerEventId());
        return CONTINUE_STATE_MACHINE_INVALID_STATE;
    }

    auto memberFunc = iterFunc->second;
    int32_t ret = (this->*memberFunc)(dContinue, event);
    if (ret != ERR_OK) {
        HILOGI("DSchedContinueSinkStartState execute %{public}d failed, ret: %{public}d",
            event->GetInnerEventId(), ret);
    }
    return ret;
}

DSchedContinueStateType DSchedContinueSinkStartState::GetStateType()
{
    return DSCHED_CONTINUE_SINK_START_STATE;
}

int32_t DSchedContinueSinkStartState::DoContinuePullReqTask(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    if (dContinue == nullptr || event == nullptr) {
        HILOGE("dContinue or event is null");
        return INVALID_PARAMETERS_ERR;
    }
    auto syncContinueData = event->GetSharedObject<DistributedWantParams>();
    int32_t ret = dContinue->ExecuteContinueReq(syncContinueData);
    if (ret != ERR_OK) {
        HILOGE("DSchedContinueSinkStartState ExecuteContinueSend failed, ret: %{public}d", ret);
    }
    return ret;
}

int32_t DSchedContinueSinkStartState::DoContinueAbilityTask(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    if (dContinue == nullptr || event == nullptr) {
        HILOGE("dContinue or event is null");
        return INVALID_PARAMETERS_ERR;
    }
    return dContinue->ExecuteContinueReply();
}

int32_t DSchedContinueSinkStartState::DoContinueErrorTask(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    if (dContinue == nullptr || event == nullptr) {
        HILOGE("dContinue or event is null");
        return INVALID_PARAMETERS_ERR;
    }
    auto syncContinueData = event->GetSharedObject<int32_t>();
    int32_t ret = dContinue->ExecuteContinueError(*syncContinueData);
    if (ret != ERR_OK) {
        HILOGE("DSchedContinueSinkStartState ExecuteContinueSend failed, ret: %{public}d", ret);
    }
    dContinue->ExecuteQuickStartFailed(*syncContinueData);
    return ret;
}

int32_t DSchedContinueSinkStartState::DoContinueEndTask(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    if (dContinue == nullptr || event == nullptr) {
        HILOGE("dContinue or event is null");
        return INVALID_PARAMETERS_ERR;
    }
    auto syncContinueData = event->GetSharedObject<int32_t>();
    int32_t ret = dContinue->ExecuteContinueEnd(*syncContinueData);
    if (ret != ERR_OK) {
        HILOGE("DSchedContinueSinkStartState ExecuteContinueSend failed, ret: %{public}d", ret);
    }
    dContinue->ExecuteQuickStartFailed(*syncContinueData);
    return ret;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
