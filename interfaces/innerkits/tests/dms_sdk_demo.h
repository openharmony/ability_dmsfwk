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
#ifndef OHOS_DMS_SDK_DEMO_H
#define OHOS_DMS_SDK_DEMO_H
 
#include "dms_handler.h"
#include "distributed_event_listener.h"
#include "dms_sa_client.h"
#include "dms_listener_stub.h"
 
namespace OHOS {
namespace DistributedSchedule {

class Business : public DSchedEventListenerStub {
public:
    void DSchedEventNotify(EventNotify &notify) override;
    void Register(DSchedEventType type);
    void UnRegister(DSchedEventType type);
    void GetContinueDeviceInfo();
    void GetDSchedEventInfo(DSchedEventType type);
};
}
}
#endif // OHOS_DMS_SDK_DEMO_H