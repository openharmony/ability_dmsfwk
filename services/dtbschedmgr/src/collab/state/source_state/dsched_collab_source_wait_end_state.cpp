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

#include "dsched_collab_source_wait_end_state.h"

#include "dsched_collab.h"
#include "dsched_collab_event.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "CollabSrcWaitEndState";
}
CollabSrcWaitEndState::CollabSrcWaitEndState(std::shared_ptr<DSchedCollabStateMachine> stateMachine)
    : stateMachine_(stateMachine)
{
    memberFuncMap_[ERR_END_EVENT] = &CollabSrcWaitEndState::DoDisconnect;
    memberFuncMap_[END_EVENT] = &CollabSrcWaitEndState::DoDisconnect;
}

CollabSrcWaitEndState::~CollabSrcWaitEndState()
{
}

int32_t CollabSrcWaitEndState::Execute(std::shared_ptr<DSchedCollab> dCollab,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    if (event == nullptr) {
        HILOGE("event is null");
        return INVALID_PARAMETERS_ERR;
    }
    auto iterFunc = memberFuncMap_.find(event->GetInnerEventId());
    if (iterFunc == memberFuncMap_.end()) {
        HILOGI("CollabSrcWaitEndState execute %{public}d in wrong state", event->GetInnerEventId());
        return COLLAB_STATE_MACHINE_INVALID_STATE;
    }

    auto memberFunc = iterFunc->second;
    int32_t ret = (this->*memberFunc)(dCollab, event);
    if (ret != ERR_OK) {
        HILOGI("CollabSrcWaitEndState execute %{public}d failed, ret: %{public}d",
            event->GetInnerEventId(), ret);
    }
    return ret;
}

CollabStateType CollabSrcWaitEndState::GetStateType()
{
    return SOURCE_WAIT_END_STATE;
}

int32_t CollabSrcWaitEndState::DoDisconnect(std::shared_ptr<DSchedCollab> dCollab,
    const AppExecFwk::InnerEvent::Pointer &event)
{
    if (dCollab == nullptr || event == nullptr) {
        HILOGE("dCollab or event is null");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t ret = dCollab->ExeDisconnect();
    if (ret != ERR_OK) {
        HILOGE("failed, ret: %{public}d", ret);
    }
    return ret;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
