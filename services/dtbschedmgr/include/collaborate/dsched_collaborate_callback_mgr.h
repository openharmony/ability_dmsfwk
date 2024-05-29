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

#ifndef OHOS_DSCHED_COLLABORATION_H
#define OHOS_DSCHED_COLLABORATION_H

#include <cstdint>
#include <map>
#include <mutex>

#include "event_handler.h"
#include "iremote_object.h"
#include "refbase.h"

#include "distributed_event_died_listener.h"
#include "distributed_sched_types.h"

namespace OHOS {
namespace DistributedSchedule {
class DSchedCollaborationCallbackMgr : public std::enable_shared_from_this<DSchedCollaborationCallbackMgr> {
public:
    void Init();
    bool PushCallback(const sptr<IRemoteObject>& callback);
    std::vector<sptr<IRemoteObject>> GetCallback();
    bool CleanupCallback(const sptr<IRemoteObject>& callback);
    int32_t NotifyDSchedEventResult(int32_t resultCode, const EventNotify& event);

private:
    int32_t NotifyDSchedEventForOneCB(const sptr<IRemoteObject> &cb, const EventNotify& event);

private:
    std::mutex collaborateCbLock_;
    std::vector<sptr<IRemoteObject>> collaborateCbArr_;
    sptr<DistributedEventDiedListener> diedListener_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DSCHED_COLLABORATION_H
