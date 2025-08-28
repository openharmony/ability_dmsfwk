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

#include "distributedschedstubten_fuzzer.h"

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

void GetWifiStatusInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;

    FuzzedDataProvider fdp(data, size);
    bool isSuccess = fdp.ConsumeBool();
    int32_t sessionId = fdp.ConsumeIntegral<int32_t>();
    std::string devId = fdp.ConsumeRandomLengthString();
    dataParcel.WriteString16(Str8ToStr16(devId));
    dataParcel.WriteInt32(sessionId);
    dataParcel.WriteBool(isSuccess);
    DistributedSchedService::GetInstance().GetWifiStatusInner(dataParcel, reply);
}

void IsNewCollabVersionFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    std::string remoteDeviceId = fdp.ConsumeRandomLengthString();
    DistributedSchedService::GetInstance().IsNewCollabVersion(remoteDeviceId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::IsNewCollabVersionFuzzTest(data, size);
    OHOS::DistributedSchedule::GetWifiStatusInnerFuzzTest(data, size);
    return 0;
}
