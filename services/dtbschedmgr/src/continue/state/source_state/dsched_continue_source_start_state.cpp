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

#include "dsched_continue_source_start_state.h"

namespace OHOS {
namespace DistributedSchedule {
DSchedContinueSourceStartState::DSchedContinueSourceStartState(std::shared_ptr<DSchedContinueStateMachine> stateMachine)
    : stateMachine_(stateMachine)
{
}

DSchedContinueSourceStartState::~DSchedContinueSourceStartState()
{
}

int32_t DSchedContinueSourceStartState::Execute(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    return ERR_OK;
}

DSchedContinueStateType DSchedContinueSourceStartState::GetStateType()
{
    return DSCHED_CONTINUE_SOURCE_START_STATE;
}

int32_t DSchedContinueSourceStartState::DoContinueAbiityTask(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    return ERR_OK;
}

int32_t DSchedContinueSourceStartState::DoContinuePushReqTask(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    return ERR_OK;
}

int32_t DSchedContinueSourceStartState::DoContinueEndTask(std::shared_ptr<DSchedContinue> dContinue,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    return ERR_OK;
}
}  // namespace DistributedSchedule
}  // namespace OHOS