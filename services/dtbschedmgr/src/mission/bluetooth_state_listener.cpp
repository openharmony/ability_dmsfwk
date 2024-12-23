/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include "mission/bluetooth_state_listener.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string TAG = "BluetoothStateListener";
}

void BluetoothStateListener::InitBluetoothState()
{
    Bluetooth::BluetoothState bluetoothState = Bluetooth::BluetoothHost::GetDefaultHost().GetBluetoothState();
    HILOGI("query bluetooth state is: %{public}d", static_cast<int>(bluetoothState));
    if (bluetoothState == Bluetooth::BluetoothState::STATE_ON) {
        BluetoothStateAdapter::GetInstance().UpdateBTState(true);
        BluetoothStateAdapter::GetInstance().UpdateBLEState(true);
    } else if (bluetoothState == Bluetooth::BluetoothState::STATE_BLE_ON) {
        BluetoothStateAdapter::GetInstance().UpdateBTState(false);
        BluetoothStateAdapter::GetInstance().UpdateBLEState(true);
    }
}

void BluetoothStateListener::OnStateChanged(const int transport, const int status)
{
    HILOGI("Bluetooth state changed, transport: %{public}d, state: %{public}d", transport, status);
    if (transport == static_cast<int>(Bluetooth::BTTransport::ADAPTER_BREDR)) {
        BluetoothStateAdapter::GetInstance().UpdateBTState(status == Bluetooth::BTStateID::STATE_TURN_ON);
    }

    if (transport == static_cast<int>(Bluetooth::BTTransport::ADAPTER_BLE)) {
        BluetoothStateAdapter::GetInstance().UpdateBLEState(status == Bluetooth::BTStateID::STATE_TURN_ON);
    }
}

} // namespace DistributedSchedule
} // namespace OHOS
