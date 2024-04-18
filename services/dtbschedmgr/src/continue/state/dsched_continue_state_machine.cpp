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

#include "dsched_continue_state_machine.h"

#include "dsched_continue.h"
#include "dtbschedmgr_log.h"
#include "sink_state/dsched_continue_data_state.h"
#include "sink_state/dsched_continue_sink_end_state.h"
#include "sink_state/dsched_continue_sink_start_state.h"
#include "sink_state/dsched_continue_sink_wait_end_state.h"
#include "source_state/dsched_continue_ability_state.h"
#include "source_state/dsched_continue_source_end_state.h"
#include "source_state/dsched_continue_source_start_state.h"
#include "source_state/dsched_continue_source_wait_end_state.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedContinueStateMachine";
}
DSchedContinueStateMachine::DSchedContinueStateMachine(std::shared_ptr<DSchedContinue> dContinue)
    : dContinue_(dContinue)
{
}

DSchedContinueStateMachine::~DSchedContinueStateMachine()
{
}

int32_t DSchedContinueStateMachine::Execute(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<DSchedContinue> dContinue = dContinue_.lock();
    if (dContinue == nullptr || currentState_ == nullptr) {
        HILOGE("DSchedContinueStateMachine excute failed, continue or currentState is null");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t ret = currentState_->Execute(dContinue, event);
    if (ret != ERR_OK) {
        HILOGE("DSchedContinueStateMachine currentState: %d excute event %d failed, ret %d",
            currentState_->GetStateType(), event->GetInnerEventId(), ret);
    }
    return ret;
}

void DSchedContinueStateMachine::UpdateState(DSchedContinueStateType stateType)
{
    if (stateType != DSCHED_CONTINUE_SOURCE_START_STATE && stateType != DSCHED_CONTINUE_SINK_START_STATE) {
        HILOGI("DSchedContinueStateMachine update state from %d to %d", currentState_->GetStateType(), stateType);
    } else {
        HILOGI("DSchedContinueStateMachine update state %d", stateType);
    }
    currentState_ = CreateState(stateType);
    return;
}

std::shared_ptr<DSchedContinueState> DSchedContinueStateMachine::CreateState(DSchedContinueStateType stateType)
{
    std::shared_ptr<DSchedContinueState> state = nullptr;
    auto stateMachine = std::shared_ptr<DSchedContinueStateMachine>(shared_from_this());
    switch (stateType) {
        case DSCHED_CONTINUE_SOURCE_START_STATE: {
            state = std::make_shared<DSchedContinueSourceStartState>(stateMachine);
            break;
        }
        case DSCHED_CONTINUE_ABILITY_STATE: {
            state = std::make_shared<DSchedContinueAbilityState>(stateMachine);
            break;
        }
        case DSCHED_CONTINUE_SOURCE_WAIT_END_STATE: {
            state = std::make_shared<DSchedContinueWaitEndState>(stateMachine);
            break;
        }
        case DSCHED_CONTINUE_SOURCE_END_STATE: {
            state = std::make_shared<DSchedContinueEndState>(stateMachine);
            break;
        }
        case DSCHED_CONTINUE_SINK_START_STATE: {
            state = std::make_shared<DSchedContinueSinkStartState>(stateMachine);
            break;
        }
        case DSCHED_CONTINUE_DATA_STATE: {
            state = std::make_shared<DSchedContinueDataState>(stateMachine);
            break;
        }
        case DSCHED_CONTINUE_SINK_WAIT_END_STATE: {
            state = std::make_shared<DSchedContinueSinkWaitEndState>(stateMachine);
            break;
        }
        case DSCHED_CONTINUE_SINK_END_STATE: {
            state = std::make_shared<DSchedContinueSinkEndState>(stateMachine);
            break;
        }
        default:
            HILOGE("DSchedContinueStateMachine create state failed, stateType: %d", stateType);
            break;
    }
    return state;
}

DSchedContinueStateType DSchedContinueStateMachine::GetStateType()
{
    if (currentState_ == nullptr) {
        return DSCHED_CONTINUE_SOURCE_START_STATE;
    }
    return currentState_->GetStateType();
}
}  // namespace DistributedSchedule
}  // namespace OHOS
