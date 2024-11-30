/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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
#include "distributed_sched_service.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "mission/notification/dms_continue_send_manager.h"
#include "multi_user_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedDeviceNodeListener";
}
void DistributedDeviceNodeListener::OnDeviceOnline(const DistributedHardware::DmDeviceInfo& deviceInfo)
{
    int32_t osType = Constants::OH_OS_TYPE;
    std::string osVersion = "";
    if (!GetOsInfoFromDM(deviceInfo.extraData, osType, osVersion)) {
        HILOGE("Get Os info from DM device info fail, extraData %{public}s.", deviceInfo.extraData.c_str());
    }

    auto dmsDeviceInfo = std::make_shared<DmsDeviceInfo>(deviceInfo.deviceName, deviceInfo.deviceTypeId,
        deviceInfo.networkId, ONLINE, osType, osVersion);
    DtbschedmgrDeviceInfoStorage::GetInstance().DeviceOnlineNotify(dmsDeviceInfo);
#ifdef DMSFWK_INTERACTIVE_ADAPTER
    DistributedSchedService::GetInstance().OnDeviceOnlineEx(deviceInfo);
#endif
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    if (sendMgr == nullptr) {
        HILOGI("GetSendMgr failed.");
        return;
    }
    sendMgr->OnDeviceOnline();
}

void DistributedDeviceNodeListener::OnDeviceOffline(const DistributedHardware::DmDeviceInfo& deviceInfo)
{
    DtbschedmgrDeviceInfoStorage::GetInstance().DeviceOfflineNotify(deviceInfo.networkId);
#ifdef DMSFWK_INTERACTIVE_ADAPTER
    DistributedSchedService::GetInstance().OnDeviceOfflineEx(deviceInfo);
#endif
}

void DistributedDeviceNodeListener::OnDeviceInfoChanged(const DistributedHardware::DmDeviceInfo& deviceInfo)
{
    DtbschedmgrDeviceInfoStorage::GetInstance().OnDeviceInfoChanged(deviceInfo.networkId);
#ifdef DMSFWK_INTERACTIVE_ADAPTER
    DistributedSchedService::GetInstance().OnDeviceInfoChangedEx(deviceInfo);
#endif
}
} // namespace DistributedSchedule
} // namespace OHOS
