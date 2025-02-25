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

#ifndef OHOS_DSCHED_COLLAB_SINK_GET_VERSION_STATE_H
#define OHOS_DSCHED_COLLAB_SINK_GET_VERSION_STATE_H

#include <map>

#include "dsched_collab_state.h"

namespace OHOS {
namespace DistributedSchedule {
class CollabSinkGetVersionState : public DSchedCollabState {
public:
    explicit CollabSinkGetVersionState(std::shared_ptr<DSchedCollabStateMachine> stateMachine);
    ~CollabSinkGetVersionState();
 
    int32_t Execute(std::shared_ptr<DSchedCollab> dCollab, const AppExecFwk::InnerEvent::Pointer &event) override;
    CollabStateType GetStateType() override;

private:
    int32_t DoSinkGetVersion(std::shared_ptr<DSchedCollab> dCollab, const AppExecFwk::InnerEvent::Pointer &event);
    int32_t DoSinkGetVersionError(std::shared_ptr<DSchedCollab> dCollab, const AppExecFwk::InnerEvent::Pointer &event);

private:
    using DSchedStateFunc = int32_t (CollabSinkGetVersionState::*)(std::shared_ptr<DSchedCollab> dCollab,
        const AppExecFwk::InnerEvent::Pointer &event);

    std::weak_ptr<DSchedCollabStateMachine> stateMachine_;
    std::map<uint32_t, DSchedStateFunc> memberFuncMap_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_COLLAB_SINK_GET_VERSION_STATE_H
