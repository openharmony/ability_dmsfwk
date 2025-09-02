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

#include "distributedschedstubthree_fuzzer.h"

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
namespace {
const uint32_t ONE = 1;
}

void GetRemoteMissionSnapshotInfoInnerFuzzTest(const uint8_t* data, size_t size)
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
    std::string networkId = fdp.ConsumeRandomLengthString();

    dataParcel.WriteString(networkId);
    dataParcel.WriteInt32(missionId);
    DistributedSchedService::GetInstance().GetRemoteMissionSnapshotInfoInner(dataParcel, reply);
    DistributedSchedService::GetInstance().DurationStart(networkId, networkId);
}

void StartRemoteAbilityByCallInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    Want want;
    sptr<IRemoteObject> obj(new MockDistributedSched());
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    uint32_t uint32Data = fdp.ConsumeIntegral<uint32_t>();
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    
    want.SetDeviceId(dstDeviceId);

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &want);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, uint32Data);
    DistributedSchedService::GetInstance().StartRemoteAbilityByCallInner(dataParcel, reply);
    DistributedSchedService::GetInstance().SetWantForContinuation(want, int32Data);
}

void ReleaseRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    AppExecFwk::ElementName element;
    CallerInfo callerInfo;
    std::string deviceId(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &element);
    DistributedSchedService::GetInstance().ReleaseRemoteAbilityInner(dataParcel, reply);
    callerInfo.uid = ONE;
    DistributedSchedService::GetInstance().CheckDistributedConnectLocked(callerInfo);
    DistributedSchedService::GetInstance().DecreaseConnectLocked(ONE);
    DistributedSchedService::GetInstance().RemoteConnectAbilityMappingLocked(connect, deviceId,
        deviceId, element, callerInfo, TargetComponent::HARMONY_COMPONENT);
    DistributedSchedService::GetInstance().NotifyProcessDied(deviceId, callerInfo, TargetComponent::HARMONY_COMPONENT);
    DistributedSchedService::GetInstance().ProcessDeviceOffline(deviceId);
}

int32_t GetDistributedComponentListInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return INVALID_PARAMETERS_ERR;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    std::vector<std::string> distributedComponents;
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    std::string str = fdp.ConsumeRandomLengthString();
    distributedComponents.push_back(str);
    PARCEL_WRITE_HELPER(reply, Int32, int32Data);
    PARCEL_WRITE_HELPER(reply, StringVector, distributedComponents);

    DistributedSchedService::GetInstance().GetDistributedComponentListInner(dataParcel, reply);
    return ERR_OK;
}

void StartSyncMissionsFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
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
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().StartSyncMissionsFromRemoteInner(dataParcel, reply);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::GetRemoteMissionSnapshotInfoInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartRemoteAbilityByCallInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ReleaseRemoteAbilityInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::GetDistributedComponentListInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartSyncMissionsFromRemoteInnerFuzzTest(data, size);
    return 0;
}
