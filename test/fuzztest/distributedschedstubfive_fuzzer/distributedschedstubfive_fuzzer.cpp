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

#include "distributedschedstubfive_fuzzer.h"

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

void RegisterOffListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string str = fdp.ConsumeRandomLengthString();
    sptr<IRemoteObject> obj(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().RegisterOffListenerInner(dataParcel, reply);
}

void RegisterDSchedEventListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    uint8_t uint8Data = *(reinterpret_cast<const uint8_t*>(data));
    sptr<IRemoteObject> obj(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint8, uint8Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().RegisterDSchedEventListenerInner(dataParcel, reply);
}

void UnRegisterDSchedEventListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    uint8_t uint8Data = *(reinterpret_cast<const uint8_t*>(data));
    sptr<IRemoteObject> obj(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint8, uint8Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().UnRegisterDSchedEventListenerInner(dataParcel, reply);
}

void SetMissionContinueStateInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    int32_t state = fdp.ConsumeIntegral<int32_t>();
    int32_t timeout = fdp.ConsumeIntegral<int32_t>();

    dataParcel.WriteInt32(missionId);
    dataParcel.WriteInt32(state);
    DistributedSchedService::GetInstance().SetMissionContinueStateInner(dataParcel, reply);
    DistributedSchedService::GetInstance().RemoveContinuationTimeout(missionId);
    DistributedSchedService::GetInstance().SetContinuationTimeout(missionId, timeout);
    DistributedSchedService::GetInstance().GetContinuaitonDevice(missionId);
}

void StartShareFormFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    std::string str(reinterpret_cast<const char*>(data), size);
    DistributedWant dstbWant;
    FuzzedDataProvider fdp(data, size);
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    
    dstbWant.SetDeviceId(dstDeviceId);
    dstbWant.SetElementName(bundleName, abilityName);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    DistributedSchedService::GetInstance().StartShareFormFromRemoteInner(dataParcel, reply);
}

}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::RegisterOffListenerInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::RegisterDSchedEventListenerInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::UnRegisterDSchedEventListenerInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::SetMissionContinueStateInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartShareFormFromRemoteInnerFuzzTest(data, size);
    return 0;
}
