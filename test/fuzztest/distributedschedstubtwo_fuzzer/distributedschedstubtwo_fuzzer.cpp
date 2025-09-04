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

#include "distributedschedstubtwo_fuzzer.h"

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

void RegisterMissionListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    Want want;
    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    uint32_t uint32Data = fdp.ConsumeIntegral<uint32_t>();
    std::string str = fdp.ConsumeRandomLengthString();
    sptr<IRemoteObject> obj(new MockDistributedSched());
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    
    want.SetDeviceId(dstDeviceId);

    PARCEL_WRITE_HELPER_NORET(dataParcel, String16, Str8ToStr16(str));
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().RegisterMissionListenerInner(dataParcel, reply);
    DistributedSchedService::GetInstance().ContinueLocalMissionDealFreeInstall(want, missionId, str, obj);
    DistributedSchedService::GetInstance().ContinueAbilityWithTimeout(str, missionId, obj, uint32Data);
}

void UnRegisterMissionListenerInnerFuzzTest(const uint8_t* data, size_t size)
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
    sptr<IRemoteObject> obj(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, String16, Str8ToStr16(str));
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().UnRegisterMissionListenerInner(dataParcel, reply);
}

void StartSyncRemoteMissionsInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    bool boolData = fdp.ConsumeBool();
    std::string str = fdp.ConsumeRandomLengthString();
    int64_t int64Data = static_cast<int64_t>(GetU32Data(data, size));

    PARCEL_WRITE_HELPER_NORET(dataParcel, String16, Str8ToStr16(str));
    PARCEL_WRITE_HELPER_NORET(dataParcel, Bool, boolData);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int64, int64Data);
    DistributedSchedService::GetInstance().StartSyncRemoteMissionsInner(dataParcel, reply);
}

void StopSyncRemoteMissionsInnerFuzzTest(const uint8_t* data, size_t size)
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

    PARCEL_WRITE_HELPER_NORET(dataParcel, String16, Str8ToStr16(str));
    DistributedSchedService::GetInstance().StopSyncRemoteMissionsInner(dataParcel, reply);

    Want want;
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    
    want.SetDeviceId(dstDeviceId);
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t flag = *(reinterpret_cast<const int32_t*>(data));
    DistributedSchedService::GetInstance().CheckTargetPermission(want, callerInfo, accountInfo, flag, true);
}

void StartAbilityByCallFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
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
    sptr<IRemoteObject> connect(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    DistributedSchedService::GetInstance().StartAbilityByCallFromRemoteInner(dataParcel, reply);
    DistributedSchedService::GetInstance().ProcessConnectDied(connect);
    DistributedSchedService::GetInstance().DisconnectEachRemoteAbilityLocked(str, str, connect);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::RegisterMissionListenerInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::UnRegisterMissionListenerInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartSyncRemoteMissionsInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StopSyncRemoteMissionsInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartAbilityByCallFromRemoteInnerFuzzTest(data, size);
    return 0;
}
