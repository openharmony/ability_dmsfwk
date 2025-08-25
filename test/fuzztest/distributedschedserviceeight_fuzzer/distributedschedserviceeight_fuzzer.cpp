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

#include "distributedschedserviceeight_fuzzer.h"

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

void GetIsFreeInstallFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().GetIsFreeInstall(missionId);
}

void StartContinuationFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t) + sizeof(uint32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element(deviceId, bundleName, abilityName);
    want.SetElement(element);
    want.SetFlags(fdp.ConsumeIntegral<uint32_t>());
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();

    DistributedSchedService::GetInstance().StartContinuation(want, missionId, callerUid, status, accessToken);
}

void NotifyContinuationResultFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t sessionId = fdp.ConsumeIntegralInRange<int32_t>(1, INT32_MAX);
    std::string dstInfo = fdp.ConsumeRandomLengthString();
    bool isSuccess = fdp.ConsumeBool();
    DistributedSchedService::GetInstance().NotifyContinuationResultFromRemote(sessionId, isSuccess, dstInfo);
}

void NotifyDSchedEventResultFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string type = fdp.ConsumeRandomLengthString();
    int32_t dSchedEventResult = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().NotifyDSchedEventResultFromRemote(type, dSchedEventResult);
}

void NotifyDSchedEventCallbackResultFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();
    EventNotify event;
    event.eventResult_ = fdp.ConsumeIntegral<int32_t>();
    event.srcNetworkId_ = fdp.ConsumeRandomLengthString();
    event.dstNetworkId_ = fdp.ConsumeRandomLengthString();
    event.srcBundleName_ = fdp.ConsumeRandomLengthString();
    event.srcModuleName_ = fdp.ConsumeRandomLengthString();
    event.srcAbilityName_ = fdp.ConsumeRandomLengthString();
    event.destBundleName_ = fdp.ConsumeRandomLengthString();
    event.destModuleName_ = fdp.ConsumeRandomLengthString();
    event.destAbilityName_ = fdp.ConsumeRandomLengthString();
    event.dSchedEventType_ = static_cast<DSchedEventType>(fdp.ConsumeIntegral<int32_t>());
    event.state_ = static_cast<DSchedEventState>(fdp.ConsumeIntegral<int32_t>());

    DistributedSchedService::GetInstance().NotifyDSchedEventCallbackResult(resultCode, event);
}
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::GetIsFreeInstallFuzzTest(data, size);
    OHOS::DistributedSchedule::StartContinuationFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyContinuationResultFromRemoteFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyDSchedEventResultFromRemoteFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyDSchedEventCallbackResultFuzzTest(data, size);
    return 0;
}
