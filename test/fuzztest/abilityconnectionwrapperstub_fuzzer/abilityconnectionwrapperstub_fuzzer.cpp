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

#include "abilityconnectionwrapperstub_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "ability_connection_wrapper_stub.h"
#include "mock_distributed_sched.h"
#include "mock_fuzz_util.h"
#include "parcel_helper.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace AAFwk;

bool OnAbilityConnectDoneFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return false;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    std::shared_ptr<AbilityConnectionWrapperStub> abilityConnection =
        std::make_shared<AbilityConnectionWrapperStub>();
    sptr<IRemoteObject> connection(new MockDistributedSched());
    std::string localDeviceId = fdp.ConsumeRandomLengthString();
    std::shared_ptr<AbilityConnectionWrapperStub> abilityConnection_ =
        std::make_shared<AbilityConnectionWrapperStub>(connection, localDeviceId);
    uint32_t code = IAbilityConnection::ON_ABILITY_CONNECT_DONE;
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    abilityConnection_->OnRemoteRequest(code, dataParcel, reply, option);

    std::u16string descriptor = IAbilityConnection::GetDescriptor();
    dataParcel.WriteInterfaceToken(descriptor);
    abilityConnection_->OnRemoteRequest(code, dataParcel, reply, option);
    
    std::string str1 = fdp.ConsumeRandomLengthString();
    std::string str2 = fdp.ConsumeRandomLengthString();
    std::string str3 = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element(str1, str2, str3);
    dataParcel.WriteParcelable(&element);
    abilityConnection_->OnRemoteRequest(code, dataParcel, reply, option);
    
    dataParcel.WriteRemoteObject(connection);
    dataParcel.WriteInt32(resultCode);
    abilityConnection_->OnRemoteRequest(code, dataParcel, reply, option);
    abilityConnection_->OnAbilityConnectDone(element, connection, resultCode);
    return true;
}

bool OnAbilityDisconnectDoneFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return false;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteObject> connection(new MockDistributedSched());
    std::shared_ptr<AbilityConnectionWrapperStub> abilityConnection_ =
        std::make_shared<AbilityConnectionWrapperStub>(connection);
    uint32_t code = IAbilityConnection::ON_ABILITY_DISCONNECT_DONE;
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string str1 = fdp.ConsumeRandomLengthString();
    std::string str2 = fdp.ConsumeRandomLengthString();
    std::string str3 = fdp.ConsumeRandomLengthString();
    std::u16string descriptor = IAbilityConnection::GetDescriptor();
    dataParcel.WriteInterfaceToken(descriptor);
    AppExecFwk::ElementName element(str1, str2, str3);
    dataParcel.WriteParcelable(&element);
    dataParcel.WriteRemoteObject(connection);
    dataParcel.WriteInt32(resultCode);
    abilityConnection_->OnRemoteRequest(code, dataParcel, reply, option);
    abilityConnection_->OnAbilityDisconnectDone(element, resultCode);
    return true;
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::OnAbilityConnectDoneFuzzTest(data, size);
    OHOS::DistributedSchedule::OnAbilityDisconnectDoneFuzzTest(data, size);
    return 0;
}