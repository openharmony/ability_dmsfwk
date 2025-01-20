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

#include "dsched_collab_sink_start_state.h"

#include "dsched_collab.h"
#include "dsched_collab_event.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "CollabSinkStartState";
}
CollabSinkStartState::CollabSinkStartState(std::shared_ptr<DSchedCollabStateMachine> stateMachine)
    : stateMachine_(stateMachine)
{
    memberFuncMap_[START_ABILITY_EVENT] = &CollabSinkStartState::DoStartAbility;
    memberFuncMap_[ERR_END_EVENT] = &CollabSinkStartState::DoSinkStartError;
}

CollabSinkStartState::~CollabSinkStartState()
{
}

int32_t CollabSinkStartState::Execute(std::shared_ptr<DSchedCollab> dCollab,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        HILOGE("event is null");
        return INVALID_PARAMETERS_ERR;
    }
    auto iterFunc = memberFuncMap_.find(event->GetInnerEventId());
    if (iterFunc == memberFuncMap_.end()) {
        HILOGI("CollabSinkStartState execute %{public}d in wrong state", event->GetInnerEventId());
        return COLLAB_STATE_MACHINE_INVALID_STATE;
    }

    auto memberFunc = iterFunc->second;
    int32_t ret = (this->*memberFunc)(dCollab, event);
    if (ret != ERR_OK) {
        HILOGI("CollabSinkStartState execute %{public}d failed, ret: %{public}d",
            event->GetInnerEventId(), ret);
    }
    return ret;
}

CollabStateType CollabSinkStartState::GetStateType()
{
    return SINK_START_STATE;
}

int32_t CollabSinkStartState::DoStartAbility(std::shared_ptr<DSchedCollab> dCollab,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    if (dCollab == nullptr || event == nullptr) {
        HILOGE("dCollab or event is null");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t ret = dCollab->ExeStartAbility();
    if (ret != ERR_OK) {
        HILOGE("failed, ret: %{public}d", ret);
    }
    return ret;
}

int32_t CollabSinkStartState::DoSinkStartError(std::shared_ptr<DSchedCollab> dCollab,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    if (dCollab == nullptr || event == nullptr) {
        HILOGE("dCollab or event is null");
        return INVALID_PARAMETERS_ERR;
    }
    auto syncCollabData = event->GetSharedObject<int32_t>();
    if (syncCollabData == nullptr) {
        HILOGE("syncCollabData is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t ret = dCollab->ExeSinkStartError(*syncCollabData);
    if (ret != ERR_OK) {
        HILOGE("failed, ret: %{public}d", ret);
    }
    return ret;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
