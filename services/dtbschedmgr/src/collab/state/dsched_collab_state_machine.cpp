/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "dsched_collab_state_machine.h"

#include "dsched_collab.h"
#include "dtbschedmgr_log.h"
#include "sink_state/dsched_collab_sink_get_version_state.h"
#include "sink_state/dsched_collab_sink_start_state.h"
#include "sink_state/dsched_collab_sink_connect_state.h"
#include "sink_state/dsched_collab_sink_wait_end_state.h"
#include "source_state/dsched_collab_source_get_peer_version_state.h"
#include "source_state/dsched_collab_source_start_state.h"
#include "source_state/dsched_collab_source_wait_result_state.h"
#include "source_state/dsched_collab_source_wait_end_state.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedCollabStateMachine";
std::map<int32_t, std::string> STATEDATA = {
    {SOURCE_GET_PEER_VERSION_STATE, "SOURCE_GET_PEER_VERSION_STATE"},
    {SOURCE_START_STATE, "SOURCE_START_STATE"},
    {SOURCE_WAIT_RESULT_STATE, "SOURCE_WAIT_RESULT_STATE"},
    {SOURCE_WAIT_END_STATE, "SOURCE_WAIT_END_STATE"},
    {SINK_GET_VERSION_STATE, "SINK_GET_VERSION_STATE"},
    {SINK_START_STATE, "SINK_START_STATE"},
    {SINK_CONNECT_STATE, "SINK_CONNECT_STATE"},
    {SINK_WAIT_END_STATE, "SINK_WAIT_END_STATE"},
};
std::map<int32_t, std::string> EVENTDATA = {
    {SOURCE_GET_PEER_VERSION_EVENT, "SOURCE_GET_PEER_VERSION_EVENT"},
    {SOURCE_START_EVENT, "SOURCE_START_EVENT"},
    {NOTIFY_RESULT_EVENT, "NOTIFY_RESULT_EVENT"},
    {GET_SINK_VERSION_EVENT, "GET_SINK_VERSION_EVENT"},
    {START_ABILITY_EVENT, "START_ABILITY_EVENT"},
    {NOTIFY_PREPARE_RESULT_EVENT, "NOTIFY_PREPARE_RESULT_EVENT"},
    {ERR_END_EVENT, "ERR_END_EVENT"},
    {END_EVENT, "END_EVENT"},
};
}
DSchedCollabStateMachine::DSchedCollabStateMachine(std::shared_ptr<DSchedCollab> dCollab)
    : dCollab_(dCollab)
{
}

DSchedCollabStateMachine::~DSchedCollabStateMachine()
{
}

int32_t DSchedCollabStateMachine::Execute(const AppExecFwk::InnerEvent::Pointer &event)
{
    std::shared_ptr<DSchedCollab> dCollab = dCollab_.lock();
    if (dCollab == nullptr || currentState_ == nullptr) {
        HILOGE("excute failed, collab or currentState is null");
        return INVALID_PARAMETERS_ERR;
    }

    auto state = currentState_;
    int32_t ret = state->Execute(dCollab, event);
    if (ret != ERR_OK) {
        HILOGE("currentState: %{public}s, excute event: %{public}s failed, ret %{public}d",
            STATEDATA[state->GetStateType()].c_str(), EVENTDATA[event->GetInnerEventId()].c_str(), ret);
    }
    return ret;
}

void DSchedCollabStateMachine::UpdateState(CollabStateType stateType)
{
    HILOGI("called");
    if (stateType != SOURCE_GET_PEER_VERSION_STATE && stateType != SINK_GET_VERSION_STATE
        && currentState_ != nullptr) {
        HILOGI("update state from %{public}s to %{public}s",
            STATEDATA[currentState_->GetStateType()].c_str(), STATEDATA[stateType].c_str());
    } else {
        HILOGI("update state: %{public}s", STATEDATA[stateType].c_str());
    }
    currentState_ = CreateState(stateType);
    HILOGI("end");
    return;
}

std::shared_ptr<DSchedCollabState> DSchedCollabStateMachine::CreateState(CollabStateType stateType)
{
    std::shared_ptr<DSchedCollabState> state = nullptr;
    auto stateMachine = std::shared_ptr<DSchedCollabStateMachine>(shared_from_this());
    switch (stateType) {
        case SOURCE_GET_PEER_VERSION_STATE: {
            state = std::make_shared<CollabSrcGetPeerVersionState>(stateMachine);
            break;
        }
        case SOURCE_START_STATE: {
            state = std::make_shared<CollabSrcStartState>(stateMachine);
            break;
        }
        case SOURCE_WAIT_RESULT_STATE: {
            state = std::make_shared<CollabSrcWaitResultState>(stateMachine);
            break;
        }
        case SOURCE_WAIT_END_STATE: {
            state = std::make_shared<CollabSrcWaitEndState>(stateMachine);
            break;
        }
        case SINK_GET_VERSION_STATE: {
            state = std::make_shared<CollabSinkGetVersionState>(stateMachine);
            break;
        }
        case SINK_START_STATE: {
            state = std::make_shared<CollabSinkStartState>(stateMachine);
            break;
        }
        case SINK_CONNECT_STATE: {
            state = std::make_shared<CollabSinkConnectState>(stateMachine);
            break;
        }
        case SINK_WAIT_END_STATE: {
            state = std::make_shared<CollabSinkWaitEndState>(stateMachine);
            break;
        }
        default:
            HILOGE("DSchedCollabStateMachine create state failed, stateType: %{public}s", STATEDATA[stateType].c_str());
            break;
    }
    return state;
}

CollabStateType DSchedCollabStateMachine::GetStateType()
{
    if (currentState_ == nullptr) {
        return SOURCE_START_STATE;
    }
    return currentState_->GetStateType();
}
}  // namespace DistributedSchedule
}  // namespace OHOS
