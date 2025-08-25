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

#include "distributedschedstubseven_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <singleton.h>

#include "distributed_sched_interface.h"
#include "distributed_sched_service.h"
#include "distributed_sched_stub.h"
#include "distributedWant/distributed_want.h"
#include "mock_fuzz_util.h"
#include "mock_distributed_sched.h"
#include "parcel_helper.h"
#include "dms_continue_time_dumper.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedSchedFuzzTest";

void ConnectAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    std::string str = fdp.ConsumeRandomLengthString();
    std::vector<std::string> strVector = {str};
    DistributedWant dstbWant;
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    
    dstbWant.SetDeviceId(dstDeviceId);
    dstbWant.SetElementName(bundleName, abilityName);
    const sptr<IRemoteObject> connect(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &compatibleAbilityInfo);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().ConnectAbilityFromRemoteInner(dataParcel, reply);
}

void DisconnectAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    std::string str = fdp.ConsumeRandomLengthString();

    sptr<IRemoteObject> connect(new MockDistributedSched());
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().DisconnectAbilityFromRemoteInner(dataParcel, reply);
    DistributedSchedService::GetInstance().ProcessCallerDied(connect, int32Data);
    DistributedSchedService::GetInstance().ProcessCalleeDied(connect);
}

void NotifyProcessDiedFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    std::string str = fdp.ConsumeRandomLengthString();

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().NotifyProcessDiedFromRemoteInner(dataParcel, reply);
}

void GetContinueInfoInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().GetContinueInfoInner(dataParcel, reply);
}

void StopAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    std::string str = fdp.ConsumeRandomLengthString();
    std::vector<std::string> strVector = {str};
    DistributedWant dstbWant;
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    
    dstbWant.SetDeviceId(dstDeviceId);
    dstbWant.SetElementName(bundleName, abilityName);

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().StopAbilityFromRemoteInner(dataParcel, reply);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::ConnectAbilityFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::DisconnectAbilityFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyProcessDiedFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::GetContinueInfoInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StopAbilityFromRemoteInnerFuzzTest(data, size);
    return 0;
}
