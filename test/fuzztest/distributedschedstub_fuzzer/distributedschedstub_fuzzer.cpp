/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "distributedschedstub_fuzzer.h"

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

bool StartRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return false;
    }
    MessageParcel dataParcel;
    MessageParcel reply;
    Want want;
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    uint32_t uint32Data = fdp.ConsumeIntegral<uint32_t>();
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    
    want.SetDeviceId(dstDeviceId);
    want.SetElementName(bundleName, abilityName);

    PARCEL_WRITE_HELPER(dataParcel, Parcelable, &want);
    PARCEL_WRITE_HELPER(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER(dataParcel, Uint32, uint32Data);
    DistributedSchedService::GetInstance().StartRemoteAbilityInner(dataParcel, reply);
    FuzzUtil::MockPermission();
    DistributedSchedService::GetInstance().StartRemoteAbilityInner(dataParcel, reply);
    return true;
}

void ConnectRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    Want want;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    uint32_t uint32Data = fdp.ConsumeIntegral<uint32_t>();
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    
    want.SetDeviceId(dstDeviceId);
    want.SetElementName(bundleName, abilityName);

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &want);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, uint32Data);
    DistributedSchedService::GetInstance().ConnectRemoteAbilityInner(dataParcel, reply);
    std::string devId = fdp.ConsumeRandomLengthString();
    DistributedSchedService::GetInstance().ProcessFreeInstallOffline(devId);
    DistributedSchedService::GetInstance().ProcessCalleeOffline(devId);
}

void DisconnectRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    FuzzedDataProvider fdp(data, size);
    int32_t int32Data = fdp.ConsumeIntegral<int32_t>();
    uint32_t uint32Data = fdp.ConsumeIntegral<uint32_t>();

    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, uint32Data);
    DistributedSchedService::GetInstance().DisconnectRemoteAbilityInner(dataParcel, reply);
    
    std::string networkId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    DistributedSchedService::GetInstance().IsRemoteInstall(networkId, bundleName);
    DistributedSchedService::GetInstance().GetContinueInfo(networkId, networkId);
}

void StartContinuationInnerFuzzTest(const uint8_t* data, size_t size)
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
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    
    want.SetDeviceId(dstDeviceId);
    want.SetElementName(bundleName, abilityName);

    dataParcel.WriteParcelable(&want);
    dataParcel.WriteInt32(missionId);
    dataParcel.WriteInt32(callerUid);
    dataParcel.WriteInt32(status);
    dataParcel.WriteUint32(accessToken);
    DistributedSchedService::GetInstance().StartContinuationInner(dataParcel, reply);
    DistributedSchedService::GetInstance().StartAbility(want, callerUid);
}

void NotifyCompleteFreeInstallFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
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
    int64_t int64Data = static_cast<int64_t>(GetU32Data(data, size));

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int64, int64Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().NotifyCompleteFreeInstallFromRemoteInner(dataParcel, reply);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::StartRemoteAbilityInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ConnectRemoteAbilityInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::DisconnectRemoteAbilityInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartContinuationInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyCompleteFreeInstallFromRemoteInnerFuzzTest(data, size);
    return 0;
}
