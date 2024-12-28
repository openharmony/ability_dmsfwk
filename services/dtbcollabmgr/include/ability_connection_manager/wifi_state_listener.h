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

#ifndef OHOS_DISTRIBUTED_COLLAB_WIFI_STATE_LISTENER_H
#define OHOS_DISTRIBUTED_COLLAB_WIFI_STATE_LISTENER_H

#include "common_event_data.h"
#include "common_event_manager.h"
#include "common_event_support.h"

namespace OHOS {
namespace DistributedCollab {
class WifiStateListener : public EventFwk::CommonEventSubscriber,
    public std::enable_shared_from_this<WifiStateListener> {
public:
    WifiStateListener() = default;
    WifiStateListener(const EventFwk::CommonEventSubscribeInfo &subscribeInfo)
        : EventFwk::CommonEventSubscriber(subscribeInfo) {}
    virtual ~WifiStateListener() = default;

    void OnReceiveEvent(const EventFwk::CommonEventData &eventData);
    bool CheckWifiStateIsActived();
};
} // DistributedSchedule
} // OHOS

#endif // OHOS_DISTRIBUTED_COLLAB_WIFI_STATE_LISTENER_H