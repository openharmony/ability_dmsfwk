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

#include "distributedschedservicenine_fuzzer.h"

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

void NotifyCollaborateEventWithSessionsFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    std::list<ConnectAbilitySession> sessionsList;
    int sessionCount = fdp.ConsumeIntegralInRange<int>(1, SESSION_COUNT_MAX);
    for (int i = 0; i < sessionCount; ++i) {
        CallerInfo callerInfo;
        callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
        callerInfo.uid = fdp.ConsumeIntegral<int32_t>();

        AppExecFwk::ElementName element(
            fdp.ConsumeRandomLengthString(),
            fdp.ConsumeRandomLengthString(),
            fdp.ConsumeRandomLengthString()
        );
        ConnectAbilitySession session(callerInfo.sourceDeviceId, fdp.ConsumeRandomLengthString(), callerInfo);
        session.AddElement(element);
        sessionsList.emplace_back(session);
    }
    DSchedEventState state = static_cast<DSchedEventState>(fdp.ConsumeIntegral<int32_t>());
    int32_t ret = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().NotifyCollaborateEventWithSessions(sessionsList, state, ret);
}

void GetCurSrcCollaborateEventFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    CallerInfo callerInfo;
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();

    AppExecFwk::ElementName element(
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString()
    );
    element.SetModuleName(fdp.ConsumeRandomLengthString());
    DSchedEventState state = static_cast<DSchedEventState>(fdp.ConsumeIntegral<int32_t>());
    int32_t ret = fdp.ConsumeIntegral<int32_t>();
    EventNotify event;

    DistributedSchedService::GetInstance().GetCurSrcCollaborateEvent(callerInfo, element, state, ret, event);
}

void GetCurDestCollaborateEventFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    CallerInfo callerInfo;
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    callerInfo.extraInfoJson["dmsCallerUidBundleName"] = fdp.ConsumeRandomLengthString();

    AppExecFwk::ElementName element(
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString()
    );
    element.SetModuleName(fdp.ConsumeRandomLengthString());
    DSchedEventState state = static_cast<DSchedEventState>(fdp.ConsumeIntegral<int32_t>());
    int32_t ret = fdp.ConsumeIntegral<int32_t>();
    EventNotify event;
    DistributedSchedService::GetInstance().GetCurDestCollaborateEvent(callerInfo, element, state, ret, event);
}

void CheckDistributedConnectLockedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    CallerInfo callerInfo;
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    DistributedSchedService::GetInstance().CheckDistributedConnectLocked(callerInfo);
}

void DecreaseConnectLockedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().DecreaseConnectLocked(uid);
}
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::NotifyCollaborateEventWithSessionsFuzzTest(data, size);
    OHOS::DistributedSchedule::GetCurSrcCollaborateEventFuzzTest(data, size);
    OHOS::DistributedSchedule::GetCurDestCollaborateEventFuzzTest(data, size);
    OHOS::DistributedSchedule::CheckDistributedConnectLockedFuzzTest(data, size);
    OHOS::DistributedSchedule::DecreaseConnectLockedFuzzTest(data, size);
    return 0;
}
