/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "distributed_extension_stub.h"

#include "dtbschedmgr_log.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DExtensionStub";
using namespace std;

DExtensionStub::DExtensionStub()
{
    opToInterfaceMap_[static_cast<uint32_t>(IDExtensionInterfaceCode::CMD_ON_CREATE)] =
        &DExtensionStub::TriggerOnCreateInner;
    opToInterfaceMap_[static_cast<uint32_t>(IDExtensionInterfaceCode::CMD_ON_DESTORY)] =
        &DExtensionStub::TriggerOnDestroyInner;
    opToInterfaceMap_[static_cast<uint32_t>(IDExtensionInterfaceCode::CMD_ON_COLLAB_REQUEST)] =
        &DExtensionStub::TriggerOnCollaborateInner;
}

int32_t DExtensionStub::OnRemoteRequest(uint32_t code,
                                        MessageParcel &data,
                                        MessageParcel &reply,
                                        MessageOption &option)
{
    const std::u16string descriptor = DExtensionStub::GetDescriptor();
    const std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        return ERR_FLATTEN_OBJECT;
    }

    HILOGI("Begin to call procedure indexed %{public}u", code);
    auto interfaceIndex = opToInterfaceMap_.find(code);
    if (interfaceIndex == opToInterfaceMap_.end() || !interfaceIndex->second) {
        HILOGE("Cannot response request %{public}d : unknown procedure", code);
        return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
    }

    (this->*(interfaceIndex->second))(data, reply);
    return ERR_NONE;
}

int32_t DExtensionStub::TriggerOnCreateInner(MessageParcel &data, MessageParcel &reply)
{
    HILOGI("DExtensionStub::TriggerOnCreateInner");
    std::shared_ptr<AAFwk::Want> want(data.ReadParcelable<AAFwk::Want>());
    if (want == nullptr) {
        HILOGE("want readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int ret = TriggerOnCreate(*want);
    if (!reply.WriteInt32(ret)) {
        HILOGE("TriggerOnCreateInner write reply failed %{public}d", ret);
        return ERR_FLATTEN_OBJECT;
    }

    return ERR_NONE;
}

int32_t DExtensionStub::TriggerOnDestroyInner(MessageParcel &data, MessageParcel &reply)
{
    HILOGI("DExtensionStub::TriggerOnDestroy");
    int ret = TriggerOnDestroy();
    if (!reply.WriteInt32(ret)) {
        HILOGE("TriggerOnDestroy write reply failed %{public}d", ret);
        return ERR_FLATTEN_OBJECT;
    }
    return ERR_NONE;
}

int32_t DExtensionStub::TriggerOnCollaborateInner(MessageParcel &data, MessageParcel &reply)
{
    HILOGI("DExtensionStub::CmdTriggerOnCollaborate");
    std::shared_ptr<AAFwk::WantParams> wantParams(data.ReadParcelable<AAFwk::WantParams>());
    if (wantParams == nullptr) {
        HILOGE("wantParams readParcelable failed!");
        return ERR_NULL_OBJECT;
    }
    int ret = TriggerOnCollaborate(*wantParams);
    if (!reply.WriteInt32(ret)) {
        HILOGE("CmdTriggerOnCollaborate write reply failed %{public}d", ret);
        return ERR_FLATTEN_OBJECT;
    }

    return ERR_NONE;
}
}
}
