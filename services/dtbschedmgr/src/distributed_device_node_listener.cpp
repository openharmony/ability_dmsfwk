/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "distributed_device_node_listener.h"

#include <memory>
#include <string>

#include "deviceManager/dms_device_info.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedDeviceNodeListener";
}
void DistributedDeviceNodeListener::OnDeviceOnline(const DistributedHardware::DmDeviceInfo& deviceInfo)
{
    auto dmsDeviceInfo = std::make_shared<DmsDeviceInfo>(
        deviceInfo.deviceName, deviceInfo.deviceTypeId, deviceInfo.deviceId);
    DtbschedmgrDeviceInfoStorage::GetInstance().DeviceOnlineNotify(dmsDeviceInfo);
}

void DistributedDeviceNodeListener::OnDeviceOffline(const DistributedHardware::DmDeviceInfo& deviceInfo)
{
    DtbschedmgrDeviceInfoStorage::GetInstance().DeviceOfflineNotify(deviceInfo.deviceId);
}

void DistributedDeviceNodeListener::OnDeviceInfoChanged(const DistributedHardware::DmDeviceInfo& deviceInfo)
{
    DtbschedmgrDeviceInfoStorage::GetInstance().OnDeviceInfoChanged(deviceInfo.deviceId);
}
} // namespace DistributedSchedule
} // namespace OHOS
