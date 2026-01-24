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

#include "distributedschedstubone_fuzzer.h"

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

void NotifyCompleteContinuationInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    bool isSuccess = fdp.ConsumeBool();
    int32_t sessionId = fdp.ConsumeIntegral<int32_t>();
    std::string devId = fdp.ConsumeRandomLengthString();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;

    dataParcel.WriteString16(Str8ToStr16(devId));
    dataParcel.WriteInt32(sessionId);
    dataParcel.WriteBool(isSuccess);
    DistributedSchedService::GetInstance().NotifyCompleteContinuationInner(dataParcel, reply);
}

void ContinueMissionInnerFuzzTest(const uint8_t* data, size_t size)
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
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    sptr<IRemoteObject> callback(new MockDistributedSched());
    WantParams wantParams;

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, callback);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &wantParams);
    DistributedSchedService::GetInstance().ContinueMissionInner(dataParcel, reply);
    DistributedSchedService::GetInstance().ContinueLocalMission(deviceId, int32Data, callback, wantParams);
    DistributedSchedService::GetInstance().ContinueRemoteMission(deviceId, deviceId, int32Data, callback, wantParams);
    DistributedSchedService::GetInstance().ContinueMission(deviceId, deviceId, int32Data, callback, wantParams);
}

void ContinueMissionOfBundleNameInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    std::string str = fdp.ConsumeRandomLengthString();
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    sptr<IRemoteObject> callback(new MockDistributedSched());
    WantParams wantParams;

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, callback);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &wantParams);
    DistributedSchedService::GetInstance().ContinueMissionOfBundleNameInner(dataParcel, reply);
    DistributedSchedService::GetInstance().ContinueRemoteMission(deviceId, deviceId, bundleName,
        callback, wantParams);
    DistributedSchedService::GetInstance().ProcessContinueLocalMission(deviceId, deviceId, bundleName,
        callback, wantParams);
    DistributedSchedService::GetInstance().ProcessContinueRemoteMission(deviceId, deviceId, bundleName,
        callback, wantParams);
}

void GetMissionInfosInnerFuzzTest(const uint8_t* data, size_t size)
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

    PARCEL_WRITE_HELPER_NORET(dataParcel, String16, Str8ToStr16(str));
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().GetMissionInfosInner(dataParcel, reply);
}

void GetDSchedEventInfoInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>() % DMS_ALL;

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().GetDSchedEventInfoInner(dataParcel, reply);
}

void ConnectDExtensionFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    DExtConnectInfo info;

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &info);
    DistributedSchedService::GetInstance().ConnectDExtensionFromRemoteInner(dataParcel, reply);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::NotifyCompleteContinuationInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ContinueMissionInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ContinueMissionOfBundleNameInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::GetMissionInfosInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::GetDSchedEventInfoInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ConnectDExtensionFromRemoteInnerFuzzTest(data, size);
    return 0;
}
