/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DTBSCHEDMGR_COMMON_EVENT_LISTENER_H
#define OHOS_DTBSCHEDMGR_COMMON_EVENT_LISTENER_H

#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS {
namespace DistributedSchedule {
class CommonEventListener : public EventFwk::CommonEventSubscriber,
                             public std::enable_shared_from_this<CommonEventListener> {
public:
    CommonEventListener(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
        : EventFwk::CommonEventSubscriber(subscribeInfo) {}
    virtual ~CommonEventListener() = default;

    void OnReceiveEvent(const EventFwk::CommonEventData &eventData);
    int32_t GetForegroundOsAccountLocalId();
    ErrCode GetOsAccountType(int32_t &accountId);
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DTBSCHEDMGR_COMMON_EVENT_LISTENER_H
