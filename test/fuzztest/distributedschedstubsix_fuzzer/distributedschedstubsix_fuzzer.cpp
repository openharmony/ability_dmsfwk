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

#include "distributedschedstubsix_fuzzer.h"

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

void StartAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    DistributedWant dstbWant;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    std::string str = fdp.ConsumeRandomLengthString();
    std::vector<std::string> strVector = {str};
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    
    dstbWant.SetDeviceId(dstDeviceId);
    dstbWant.SetElementName(bundleName, abilityName);

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &compatibleAbilityInfo);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().StartAbilityFromRemoteInner(dataParcel, reply);
}

void SendResultFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
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

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().SendResultFromRemoteInner(dataParcel, reply);
}

void NotifyDSchedEventResultFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().NotifyDSchedEventResultFromRemoteInner(dataParcel, reply);
}

void NotifyContinuationResultFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    DmsContinueTime::GetInstance().Init();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    FuzzedDataProvider fdp(data, size);
    bool boolData = fdp.ConsumeBool();
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    std::string str = fdp.ConsumeRandomLengthString();

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Bool, boolData);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().NotifyContinuationResultFromRemoteInner(dataParcel, reply);
}

void StopExtensionAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
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
    DistributedSchedService::GetInstance().StopExtensionAbilityFromRemoteInner(dataParcel, reply);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::StartAbilityFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::SendResultFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyDSchedEventResultFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyContinuationResultFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StopExtensionAbilityFromRemoteInnerFuzzTest(data, size);
    return 0;
}
