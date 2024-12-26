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

#ifndef ABILITY_DMSFWK_1_BLUETOOTH_STATE_LISTENER_H
#define ABILITY_DMSFWK_1_BLUETOOTH_STATE_LISTENER_H

#include "bluetooth_host.h"

namespace OHOS {
namespace DistributedSchedule {
class BluetoothStateListener : public Bluetooth::BluetoothHostObserver {

public:
    BluetoothStateListener() = default;

    virtual ~BluetoothStateListener() = default;

    static std::shared_ptr<BluetoothStateListener> &GetInstance()
    {
        static std::shared_ptr<BluetoothStateListener> instance = std::make_shared<BluetoothStateListener>();
        return instance;
    }

    void InitBluetoothState();

    bool CheckBluetoothStateIsActived();

    void OnStateChanged(const int transport, const int status) override;

    void OnDiscoveryStateChanged(int status) override {};

    void OnDiscoveryResult(const Bluetooth::BluetoothRemoteDevice &device,
                           int rssi, const std::string deviceName, int deviceClass) override {};

    void OnPairRequested(const Bluetooth::BluetoothRemoteDevice &device) override {};

    void OnPairConfirmed(const Bluetooth::BluetoothRemoteDevice &device, int reqType, int number) override {};

    void OnScanModeChanged(int mode) override {};

    void OnDeviceNameChanged(const std::string &deviceName) override {};

    void OnDeviceAddrChanged(const std::string &address) override {};
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif //ABILITY_DMSFWK_1_BLUETOOTH_STATE_LISTENER_H
