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

#include "mission/bluetooth_state_adapter.h"
#include "mission/dms_continue_condition_manager.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string TAG = "BluetoothStateAdapter";
}

IMPLEMENT_SINGLE_INSTANCE(BluetoothStateAdapter);

bool BluetoothStateAdapter::IsBluetoothActive()
{
    HILOGI("current BT state cache is: %{public}s; BLE state cache is: %{public}s", isBTActive_ ? "true" : "false",
           isBLEActive_ ? "true" : "false");
    return isBTActive_.load() || isBLEActive_.load();
}

void BluetoothStateAdapter::UpdateBTState(bool isBTActive)
{
    HILOGI("update BT state: %{public}s", isBTActive ? "true" : "false");
    isBTActive_.store(isBTActive);
    DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_BLUETOOTH,
        isBTActive_.load() || isBLEActive_.load());
}

void BluetoothStateAdapter::UpdateBLEState(bool isBLEActive)
{
    HILOGI("update BLE state: %{public}s", isBLEActive ? "true" : "false");
    isBLEActive_.store(isBLEActive);
    DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_BLUETOOTH,
        isBTActive_.load() || isBLEActive_.load());
}


} // namespace DistributedSchedule
} // namespace OHOS
