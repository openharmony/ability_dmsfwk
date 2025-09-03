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

#include "distributedschedserviceseven_fuzzer.h"

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

void RemoveContinuationTimeoutFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().RemoveContinuationTimeout(missionId);
}

void SetContinuationTimeoutFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    int32_t timeout = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().SetContinuationTimeout(missionId, timeout);
}

void GetContinuationDeviceFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    std::string result = DistributedSchedService::GetInstance().GetContinuaitonDevice(missionId);
}

void SetWantForContinuationFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    AAFwk::Want newWant;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element(deviceId, bundleName, abilityName);
    newWant.SetElement(element);
    newWant.SetParam("ohos.extra.param.key.supportContinuePageStack", fdp.ConsumeBool());
    newWant.SetParam("ohos.extra.param.key.supportContinueModuleNameUpdate", fdp.ConsumeRandomLengthString());
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().SetWantForContinuation(newWant, missionId);
}

void DealDSchedEventResultFuzzTest(const uint8_t* data, size_t size)
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
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().DealDSchedEventResult(want, status);
}
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::RemoveContinuationTimeoutFuzzTest(data, size);
    OHOS::DistributedSchedule::SetContinuationTimeoutFuzzTest(data, size);
    OHOS::DistributedSchedule::GetContinuationDeviceFuzzTest(data, size);
    OHOS::DistributedSchedule::SetWantForContinuationFuzzTest(data, size);
    OHOS::DistributedSchedule::DealDSchedEventResultFuzzTest(data, size);
    return 0;
}
