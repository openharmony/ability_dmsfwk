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

#include "distributedschedservicesix_fuzzer.h"

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

std::string GetDExtensionName(std::string bundleName, int32_t userId);
std::string GetDExtensionProcess(std::string bundleName, int32_t userId);

void DurationStartFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string srcDeviceId = fdp.ConsumeRandomLengthString();
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    DistributedSchedService::GetInstance().DurationStart(srcDeviceId, dstDeviceId);
}

void GetCallerInfoFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string localDeviceId = fdp.ConsumeRandomLengthString();
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();
    CallerInfo callerInfo;
    DistributedSchedService::GetInstance().GetCallerInfo(localDeviceId, callerUid, accessToken, callerInfo);
}

void StartRemoteAbilityFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();
    int32_t requestCode = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
}

void StartAbilityFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();
    AccountInfo accountInfo;
    int32_t requestCode = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().StartAbilityFromRemote(
        want, abilityInfo, requestCode, callerInfo, accountInfo);
}

void SendResultFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element(deviceId, bundleName, abilityName);
    want.SetElement(element);
    want.SetParam("dmsSrcNetworkId", deviceId);
    want.SetParam("dmsMissionId", fdp.ConsumeIntegral<int32_t>());

    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();

    AccountInfo accountInfo;
    int32_t requestCode = fdp.ConsumeIntegral<int32_t>();
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().SendResultFromRemote(want, requestCode, callerInfo, accountInfo, resultCode);
}
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::DurationStartFuzzTest(data, size);
    OHOS::DistributedSchedule::GetCallerInfoFuzzTest(data, size);
    OHOS::DistributedSchedule::StartRemoteAbilityFuzzTest(data, size);
    OHOS::DistributedSchedule::StartAbilityFromRemoteFuzzTest(data, size);
    OHOS::DistributedSchedule::SendResultFromRemoteFuzzTest(data, size);
    return 0;
}
