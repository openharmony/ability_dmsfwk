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

#include "distributedschedservicefive_fuzzer.h"

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
constexpr int SESSION_COUNT_MAX = 10;

std::string GetDExtensionName(std::string bundleName, int32_t userId);
std::string GetDExtensionProcess(std::string bundleName, int32_t userId);

void StartLocalAbilityFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t)) + (size < sizeof(int64_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    DistributedSchedService::FreeInstallInfo info;
    int64_t taskId = fdp.ConsumeIntegral<int64_t>();
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().StartLocalAbility(info, taskId, resultCode);
}

void SetMissionContinueStateFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t)) + (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    AAFwk::ContinueState state = static_cast<AAFwk::ContinueState>(fdp.ConsumeIntegral<int32_t>());
    int32_t callingUid = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().SetMissionContinueState(missionId, state, callingUid);
}

void TryConnectRemoteAbilityFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    sptr<IRemoteObject> connect = nullptr;
    CallerInfo callerInfo;
    DistributedSchedService::GetInstance().TryConnectRemoteAbility(want, connect, callerInfo);
}

void NotifyContinuateEventResultFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();
    EventNotify eventNotify;
    DistributedSchedService::GetInstance().NotifyContinuateEventResult(resultCode, eventNotify);
}

void GetUidLockedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::list<ConnectAbilitySession> sessionsList;
    int sessionCount = fdp.ConsumeIntegralInRange<int>(0, SESSION_COUNT_MAX);
    for (int i = 0; i < sessionCount; ++i) {
        CallerInfo callerInfo;
        callerInfo.uid = fdp.ConsumeIntegral<int32_t>();
        callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();

        AppExecFwk::ElementName element(
            fdp.ConsumeRandomLengthString(),
            fdp.ConsumeRandomLengthString(),
            fdp.ConsumeRandomLengthString()
        );

        ConnectAbilitySession session(callerInfo.sourceDeviceId, fdp.ConsumeRandomLengthString(), callerInfo);
        session.AddElement(element);
        sessionsList.emplace_back(session);
    }
    DistributedSchedService::GetInstance().GetUidLocked(sessionsList);
}
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::StartLocalAbilityFuzzTest(data, size);
    OHOS::DistributedSchedule::SetMissionContinueStateFuzzTest(data, size);
    OHOS::DistributedSchedule::TryConnectRemoteAbilityFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyContinuateEventResultFuzzTest(data, size);
    OHOS::DistributedSchedule::GetUidLockedFuzzTest(data, size);
    return 0;
}