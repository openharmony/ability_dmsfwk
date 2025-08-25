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

#include "distributedschedservicetwo_fuzzer.h"

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
constexpr int32_t GET_DEXTENSION_PROCESS_PARAM_COUNT = 6;
constexpr int32_t ON_DEMAND_REASON_ID_COUNT_FOUR = 4;

std::string GetDExtensionName(std::string bundleName, int32_t userId);
std::string GetDExtensionProcess(std::string bundleName, int32_t userId);

void InitBluetoothStateListenerFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    DistributedSchedService::GetInstance().InitBluetoothStateListener();
}

void InitDeviceCfgFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    DistributedSchedService::GetInstance().InitDeviceCfg();
}

void GetDExtensionNameFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    OHOS::DistributedSchedule::GetDExtensionName(bundleName, userId);
}

void GetDExtensionProcessFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < GET_DEXTENSION_PROCESS_PARAM_COUNT * sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    OHOS::DistributedSchedule::GetDExtensionProcess(bundleName, userId);
}

void ConnectDExtensionFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < ON_DEMAND_REASON_ID_COUNT_FOUR * sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    DExtSourceInfo sourceInfo;
    sourceInfo.deviceId = fdp.ConsumeRandomLengthString();
    sourceInfo.networkId = fdp.ConsumeRandomLengthString();
    sourceInfo.bundleName = fdp.ConsumeRandomLengthString();
    sourceInfo.moduleName = fdp.ConsumeRandomLengthString();
    sourceInfo.abilityName = fdp.ConsumeRandomLengthString();

    DExtSinkInfo sinkInfo;
    sinkInfo.userId = fdp.ConsumeIntegral<int32_t>();
    sinkInfo.pid = fdp.ConsumeIntegral<int32_t>();
    sinkInfo.bundleName = fdp.ConsumeRandomLengthString();
    sinkInfo.moduleName = fdp.ConsumeRandomLengthString();
    sinkInfo.abilityName = fdp.ConsumeRandomLengthString();
    sinkInfo.serviceName = fdp.ConsumeRandomLengthString();
    std::string tokenId = fdp.ConsumeRandomLengthString();
    std::string delegatee = fdp.ConsumeRandomLengthString();
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, tokenId, delegatee);

    int32_t resultEnum = fdp.ConsumeIntegralInRange<int32_t>(0, static_cast<int32_t>(DExtConnectResult::FAILED));
    DExtConnectResult result = static_cast<DExtConnectResult>(resultEnum);
    int32_t errCode = fdp.ConsumeIntegral<int32_t>();
    DExtConnectResultInfo resultInfo(connectInfo, result, errCode);
    DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
}
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::InitBluetoothStateListenerFuzzTest(data, size);
    OHOS::DistributedSchedule::InitDeviceCfgFuzzTest(data, size);
    OHOS::DistributedSchedule::GetDExtensionNameFuzzTest(data, size);
    OHOS::DistributedSchedule::GetDExtensionProcessFuzzTest(data, size);
    OHOS::DistributedSchedule::ConnectDExtensionFromRemoteFuzzTest(data, size);
    return 0;
}
