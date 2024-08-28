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

#include "dms_listener_stub.h"

#include <cstring>
#include <memory>
#include <string>

#include "ipc_object_stub.h"
#include "ipc_types.h"
#include "message_option.h"
#include "message_parcel.h"
#include "securec.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsListenerStub";
}

DSchedEventListenerStub::DSchedEventListenerStub()
{
    memberFuncMap_[static_cast<uint32_t>(DSchedEventListenerStub::Message::DSCHED_EVENT_CALLBACK)] =
        &DSchedEventListenerStub::DSchedEventNotifyInner;
}

DSchedEventListenerStub::~DSchedEventListenerStub()
{}

int32_t DSchedEventListenerStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    HILOGI("DSchedEventListenerStub OnRemoteRequest code: %u", code);
    std::u16string desc = DSchedEventListenerStub::GetDescriptor();
    std::u16string remoteDesc = data.ReadInterfaceToken();
    if (desc != remoteDesc) {
        HILOGE("remoteDesc is invalid!");
        return GET_REMOTE_DMS_FAIL;
    }
    auto itFunc = memberFuncMap_.find(code);
    if (itFunc == memberFuncMap_.end()) {
        HILOGE("memberFuncMap_ not found");
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    auto memberFunc = itFunc->second;
    if (!memberFunc) {
        HILOGE("memberFunc is null for code %u", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }
    (this->*memberFunc)(data, reply);
    return 0;
}

void DSchedEventListenerStub::DSchedEventNotifyInner(MessageParcel &data, MessageParcel &reply)
{
    HILOGI("DSchedEventListenerStub DSchedEventNotifyInner");
    int32_t ret = 0;
    do {
        EventNotify eventNotify;
        eventNotify.eventResult_ = data.ReadInt32();
        eventNotify.srcNetworkId_ = data.ReadString();
        eventNotify.dstNetworkId_ = data.ReadString();
        eventNotify.srcBundleName_ = data.ReadString();
        eventNotify.srcModuleName_ = data.ReadString();
        eventNotify.srcAbilityName_ = data.ReadString();
        eventNotify.destBundleName_ = data.ReadString();
        eventNotify.destModuleName_ = data.ReadString();
        eventNotify.destAbilityName_ = data.ReadString();
        eventNotify.developerId_ = data.ReadString();
        eventNotify.dSchedEventType_ = static_cast<DSchedEventType>(data.ReadInt32());
        eventNotify.state_ = static_cast<DSchedEventState>(data.ReadInt32());
        DSchedEventNotify(eventNotify);
    } while (0);
    if (!reply.WriteInt32(ret)) {
        HILOGE("DSchedEventNotifyInner write ret failed, ret = %{public}d", ret);
    }
}
}  // namespace DistributedSchedule
}  // namespace OHOS