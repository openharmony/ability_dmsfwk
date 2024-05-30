/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DMS_HANDLER_H
#define OHOS_DMS_HANDLER_H

#include <condition_variable>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include "refbase.h"

#include "distributed_event_listener.h"
#include "distributed_sched_types.h"
#include "dms_sa_client.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
class DmsHandler {
DECLARE_SINGLE_INSTANCE(DmsHandler);

public:
    int32_t RegisterDSchedEventListener(const DSchedEventType& type, sptr<IDSchedEventListener> &listener);
    int32_t UnRegisterDSchedEventListener(const DSchedEventType& type, sptr<IDSchedEventListener> &listener);
    int32_t GetContinueInfo(ContinueInfo &continueInfo);
    int32_t GetDSchedEventInfo(const DSchedEventType &type, std::vector<EventNotify> &events);
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DMS_HANDLER_H