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

#ifndef OHOS_DSCHED_COLLAB_STATE_H
#define OHOS_DSCHED_COLLAB_STATE_H

#include "event_handler.h"

namespace OHOS {
namespace DistributedSchedule {
typedef enum {
    SOURCE_GET_PEER_VERSION_STATE = 0,
    SOURCE_START_STATE,
    SOURCE_WAIT_RESULT_STATE,
    SOURCE_WAIT_END_STATE,
    SINK_GET_VERSION_STATE,
    SINK_START_STATE,
    SINK_CONNECT_STATE,
    SINK_WAIT_END_STATE,
} CollabStateType;

class DSchedCollab;
class DSchedCollabStateMachine;
class DSchedCollabState {
public:
    DSchedCollabState() {}
    virtual ~DSchedCollabState() {}

    virtual int32_t Execute(std::shared_ptr<DSchedCollab> dCollab, const AppExecFwk::InnerEvent::Pointer &event) = 0;
    virtual CollabStateType GetStateType() = 0;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_COLLAB_STATE_H