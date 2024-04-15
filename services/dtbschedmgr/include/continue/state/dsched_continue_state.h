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

#ifndef OHOS_DSCHED_CONTINUE_STATE_H
#define OHOS_DSCHED_CONTINUE_STATE_H

#include "ability_manager_client.h"
#include "event_handler.h"
#include "distributedWant/distributed_want.h"
#include "distributedWant/distributed_want_params_wrapper.h"
#include "distributed_sched_interface.h"

namespace OHOS {
namespace DistributedSchedule {
typedef enum {
    DSCHED_CONTINUE_SOURCE_START_STATE = 0,
    DSCHED_CONTINUE_ABILITY_STATE = 1,
    DSCHED_CONTINUE_SOURCE_WAIT_END_STATE = 2,
    DSCHED_CONTINUE_SOURCE_END_STATE = 3,

    DSCHED_CONTINUE_SINK_START_STATE = 4,
    DSCHED_CONTINUE_DATA_STATE = 5,
    DSCHED_CONTINUE_SINK_WAIT_END_STATE = 6,
    DSCHED_CONTINUE_SINK_END_STATE = 7
} DSchedContinueStateType;

class DSchedContinue;
class DSchedContinueStateMachine;
class DSchedContinueState {
public:
    DSchedContinueState() {}
    virtual ~DSchedContinueState() {}

    virtual int32_t Execute(std::shared_ptr<DSchedContinue> dContinue,
        const AppExecFwk::InnerEvent::Pointer &event) = 0;
    virtual DSchedContinueStateType GetStateType() = 0;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_CONTINUE_STATE_H
