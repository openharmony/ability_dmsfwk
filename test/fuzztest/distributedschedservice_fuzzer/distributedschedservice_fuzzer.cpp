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

#include "distributedschedservice_fuzzer.h"

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
void OnStopFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string reasonName = fdp.ConsumeRandomLengthString();
    std::string reasonValue = fdp.ConsumeRandomLengthString();
    int enumIdx = fdp.ConsumeIntegral<int>() % 7;
    OnDemandReasonId reasonId = static_cast<OnDemandReasonId>(enumIdx);
    int32_t extraDataId = fdp.ConsumeIntegral<int32_t>();
    SystemAbilityOnDemandReason reason(reasonId, reasonName, reasonValue, extraDataId);

    DistributedSchedService service;
    service.OnStop(reason);
}

void OnActiveFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string reasonName = fdp.ConsumeRandomLengthString();
    std::string reasonValue = fdp.ConsumeRandomLengthString();

    int enumIdx = fdp.ConsumeIntegral<int>() % 7;
    OnDemandReasonId reasonId = static_cast<OnDemandReasonId>(enumIdx);

    int32_t extraDataId = fdp.ConsumeIntegral<int32_t>();

    SystemAbilityOnDemandReason reason(reasonId, reasonName, reasonValue, extraDataId);

    DistributedSchedService service;
    service.OnActive(reason);
}

void HandleBootStartFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string reasonName = fdp.ConsumeRandomLengthString();
    std::string reasonValue = fdp.ConsumeRandomLengthString();

    int enumIdx = fdp.ConsumeIntegral<int>() % 7;
    OnDemandReasonId reasonId = static_cast<OnDemandReasonId>(enumIdx);

    int32_t extraDataId = fdp.ConsumeIntegral<int32_t>();

    SystemAbilityOnDemandReason reason(reasonId, reasonName, reasonValue, extraDataId);

    DistributedSchedService service;
    service.HandleBootStart(reason);
}

void DoStartFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    DistributedSchedService service;
    service.DoStart();
}

void DeviceOnlineNotifyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string networkId(reinterpret_cast<const char*>(data), size / 2);

    DistributedSchedService service;
    service.DeviceOnlineNotify(networkId);
}

void DeviceOfflineNotifyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string networkId(reinterpret_cast<const char*>(data), size / 2);

    DistributedSchedService service;
    service.DeviceOfflineNotify(networkId);
}

void DeviceOfflineNotifyAfterDeleteFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string networkId(reinterpret_cast<const char*>(data), size / 2);

    DistributedSchedService service;
    service.DeviceOfflineNotifyAfterDelete(networkId);
}

void InitFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    DistributedSchedService service;
    service.Init();
}

void InitMissionManagerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    DistributedSchedService service;
    service.InitMissionManager();
}

void InitWifiStateListenerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    DistributedSchedService service;
    service.InitWifiStateListener();
}

void InitBluetoothStateListenerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    DistributedSchedService service;
    service.InitBluetoothStateListener();
}

void InitDeviceCfgFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    DistributedSchedService service;
    service.InitDeviceCfg();
}
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::OnStopFuzzTest(data, size);
    OHOS::DistributedSchedule::OnActiveFuzzTest(data, size);
    OHOS::DistributedSchedule::HandleBootStartFuzzTest(data, size);
    OHOS::DistributedSchedule::DoStartFuzzTest(data, size);
    OHOS::DistributedSchedule::DeviceOnlineNotifyFuzzTest(data, size);
    OHOS::DistributedSchedule::DeviceOfflineNotifyFuzzTest(data, size);
    OHOS::DistributedSchedule::DeviceOfflineNotifyAfterDeleteFuzzTest(data, size);
    OHOS::DistributedSchedule::InitFuzzTest(data, size);
    OHOS::DistributedSchedule::InitMissionManagerFuzzTest(data, size);
    OHOS::DistributedSchedule::InitWifiStateListenerFuzzTest(data, size);
    OHOS::DistributedSchedule::InitBluetoothStateListenerFuzzTest(data, size);
    OHOS::DistributedSchedule::InitDeviceCfgFuzzTest(data, size);
    return 0;
}