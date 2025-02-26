/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_APPMGMT_DISTRIBUTED_EXTENSION_STUB_H
#define OHOS_APPMGMT_DISTRIBUTED_EXTENSION_STUB_H

#include <map>

#include "i_distributed_extension.h"
#include "iremote_stub.h"

namespace OHOS {
namespace DistributedSchedule {
class DExtensionStub : public IRemoteStub<IDExtension> {
public:
    int OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

public:
    DExtensionStub();
    ~DExtensionStub() = default;

private:
    int32_t TriggerOnCreateInner(MessageParcel &data, MessageParcel &reply);
    int32_t TriggerOnDestroyInner(MessageParcel &data, MessageParcel &reply);
    int32_t TriggerOnCollaborateInner(MessageParcel &data, MessageParcel &reply);

private:
    using DExtensionInterfaceCode = int32_t (DExtensionStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, DExtensionInterfaceCode> opToInterfaceMap_;
};
}
}

#endif // OHOS_APPMGMT_DISTRIBUTED_EXTENSION_STUB_H
