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

#ifndef OHOS_DMS_LISTENER_STUB_H
#define OHOS_DMS_LISTENER_STUB_H

#include <cstdint>
#include <map>

#include "distributed_event_listener.h"
#include "dtbschedmgr_log.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "refbase.h"
#include "sam_log.h"

namespace OHOS {
namespace DistributedSchedule {
class DSchedEventListenerStub : public IRemoteStub<IDSchedEventListener> {
public:
    DSchedEventListenerStub();
    virtual ~DSchedEventListenerStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    void DSchedEventNotifyInner(MessageParcel &data, MessageParcel &reply);

    using DistributedScheduleFunc = void (DSchedEventListenerStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, DistributedScheduleFunc> memberFuncMap_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DMS_LISTENER_STUB_H