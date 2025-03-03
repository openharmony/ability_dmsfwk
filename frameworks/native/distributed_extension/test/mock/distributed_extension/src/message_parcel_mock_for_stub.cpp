/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#include "iremote_broker.h"
#include "message_parcel_mock_for_stub.h"

namespace OHOS {
using namespace OHOS::DistributedSchedule;

sptr<IRemoteBroker> BrokerRegistration::NewInstance(const std::u16string &descriptor,
    const sptr<IRemoteObject> &object)
{
    return DistributedIfaceCast::cast->iface_cast(object);
}

std::u16string MessageParcel::ReadInterfaceToken()
{
    return DistributedMessageParcelForStub::messageParcel->ReadInterfaceToken();
}
} // namespace OHOS
