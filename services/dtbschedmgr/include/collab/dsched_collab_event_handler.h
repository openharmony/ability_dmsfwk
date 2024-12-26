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

#ifndef OHOS_DSCHED_COLLAB_EVENT_HANDLER_H
#define OHOS_DSCHED_COLLAB_EVENT_HANDLER_H

#include <string>

#include "event_handler.h"

namespace OHOS {
namespace DistributedSchedule {
class DSchedCollab;
class DSchedCollabEventHandler : public AppExecFwk::EventHandler {
public:
    explicit DSchedCollabEventHandler(const std::shared_ptr<AppExecFwk::EventRunner> &runner,
        const std::shared_ptr<DSchedCollab>& dschedCollab);
    ~DSchedCollabEventHandler() override;

    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event) override;

private:
    std::weak_ptr<DSchedCollab> dschedCollab_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_COLLAB_EVENT_HANDLER_H