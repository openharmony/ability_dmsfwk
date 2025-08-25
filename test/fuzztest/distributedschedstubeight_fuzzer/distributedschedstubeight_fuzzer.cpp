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

#include "distributedschedstubeight_fuzzer.h"

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
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
}

uint32_t GetU32Data(const uint8_t* ptr, size_t size)
{
    if (size > FOO_MAX_LEN || size < U32_AT_SIZE) {
        return 0;
    }
    char *ch = static_cast<char *>(malloc(size + 1));
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }
    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, ptr, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }
    uint32_t data = (ch[0] << 24) | (ch[1] << 16) | (ch[2] << 8) | ch[3];
    free(ch);
    ch = nullptr;
    return data;
}

void NotifyMissionsChangedFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
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
    std::vector<DstbMissionInfo> missionInfos;
    CallerInfo callerInfo;
    DistributedWant dstbWant;
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    
    dstbWant.SetDeviceId(dstDeviceId);
    dstbWant.SetElementName(bundleName, abilityName);

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    if (!DstbMissionInfo::WriteDstbMissionInfosToParcel(dataParcel, missionInfos)) {
        return;
    }
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().NotifyMissionsChangedFromRemoteInner(dataParcel, reply);
}

void ReleaseAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
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
    Want want;
    const CallerInfo callerInfo;
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    std::string str = fdp.ConsumeRandomLengthString();
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    
    want.SetDeviceId(dstDeviceId);
    want.SetElementName(bundleName, abilityName);

    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &element);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().ReleaseAbilityFromRemoteInner(dataParcel, reply);
    DistributedSchedService::GetInstance().TryStartRemoteAbilityByCall(want, connect, callerInfo);
    DistributedSchedService::GetInstance().SaveCallerComponent(want, connect, callerInfo);
    DistributedSchedService::GetInstance().SaveConnectToken(want, connect);
    DistributedSchedService::GetInstance().NotifyStateChanged(int32Data, element, connect);
    DistributedSchedService::GetInstance().SetCleanMissionFlag(want, int32Data);
}

void NotifyStateChangedFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    const AppExecFwk::ElementName element;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    std::string str = fdp.ConsumeRandomLengthString();

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &element);
    DistributedSchedService::GetInstance().NotifyStateChangedFromRemoteInner(dataParcel, reply);
    DistributedSchedService::GetInstance().NotifyApp(connect, element, int32Data);
}

void StartFreeInstallFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
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
    int64_t int64Data = static_cast<int64_t>(GetU32Data(data, size));
    std::vector<std::string> strVector = {str};
    DistributedWant dstbWant;
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    
    dstbWant.SetDeviceId(dstDeviceId);
    dstbWant.SetElementName(bundleName, abilityName);

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int64, int64Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().StartFreeInstallFromRemoteInner(dataParcel, reply);
}

void CollabMissionInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    FuzzedDataProvider fdp(data, size);
    CollabMessage massage;
    ConnectOpt opt;
    int32_t collabSessionId = fdp.ConsumeIntegral<int32_t>();
    std::string srcSocketName = fdp.ConsumeRandomLengthString();
    std::string collabToken = fdp.ConsumeRandomLengthString();
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, collabSessionId);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, srcSocketName);
    dataParcel.WriteParcelable(&massage);
    dataParcel.WriteParcelable(&massage);
    dataParcel.WriteParcelable(&opt);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, collabToken);
    DistributedSchedService::GetInstance().CollabMissionInner(dataParcel, reply);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::NotifyMissionsChangedFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ReleaseAbilityFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyStateChangedFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartFreeInstallFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::CollabMissionInnerFuzzTest(data, size);
    return 0;
}
