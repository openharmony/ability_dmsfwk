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

#ifndef OHOS_DISTRIBUTED_ABILITY_CONNECTION_MANAGER_STUB_H
#define OHOS_DISTRIBUTED_ABILITY_CONNECTION_MANAGER_STUB_H

#include <functional>
#include <map>

#include "ability_connection_manager_interface.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "refbase.h"

namespace OHOS {
namespace DistributedCollab {
class AbilityConnectionManagerStub : public IRemoteStub<IAbilityConnectionManager> {
public:
    AbilityConnectionManagerStub();
    virtual ~AbilityConnectionManagerStub();
    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data,
        MessageParcel& reply, MessageOption& option) override;

private:
    int32_t NotifyCollabResultInner(MessageParcel& data, MessageParcel& reply);
    int32_t NotifyDisconnectInner(MessageParcel& data, MessageParcel& reply);
    int32_t NotifyWifiOpenInner(MessageParcel& data, MessageParcel& reply);

    using Func = int32_t(AbilityConnectionManagerStub::*)(MessageParcel& data, MessageParcel& reply);
    std::map<uint32_t, Func> funcsMap_;
};
} // namespace DistributedCollab
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_ABILITY_MANAGER_STUB_H