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

#ifndef OHOS_DISTRIBUTED_EVENT_LISTENER_H
#define OHOS_DISTRIBUTED_EVENT_LISTENER_H

#include <memory>

#include "iremote_broker.h"

namespace OHOS {
namespace DistributedSchedule {
enum DSchedEventType {
    DMS_CONTINUE = 0,
    DMS_COLLABRATION = 1,
    DMS_ALL = 2,
};

enum DSchedEventState {
    DMS_DSCHED_EVENT_START = 0,
    DMS_DSCHED_EVENT_PROCESSING = 1,
    DMS_DSCHED_EVENT_STOP = 2,
    DMS_DSCHED_EVENT_FINISH = 3,
};

class EventNotify {
public:
    int32_t eventResult_ = -1;
    std::string srcNetworkId_;
    std::string dstNetworkId_;
    std::string srcBundleName_;
    std::string srcModuleName_;
    std::string srcAbilityName_;
    std::string destBundleName_;
    std::string destModuleName_;
    std::string destAbilityName_;
    DSchedEventType dSchedEventType_;
    DSchedEventState state_;
};

class IDSchedEventListener : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.distributedSchedule.dschedeventlistener");
    virtual ~IDSchedEventListener() {};
    virtual void DSchedEventNotify(EventNotify &notify) = 0;

    enum class Message {
        // ipc id for DSchedEventCallback
        DSCHED_EVENT_CALLBACK = 0,
    };
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_EVENT_LISTENER_H