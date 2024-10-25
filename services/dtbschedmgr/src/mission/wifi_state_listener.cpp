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
#include <system_ability_definition.h>

#include "mission/wifi_state_listener.h"

#include "dtbschedmgr_log.h"
#include "mission/dms_continue_recv_manager.h"
#include "mission/wifi_state_adapter.h"
#include "wifi_device.h"
#include "wifi_msg.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "WifiStateListener";
}

void WifiStateListener::OnReceiveEvent(const EventFwk::CommonEventData &data)
{
    HILOGI("receive event code = %{public}d", data.GetCode());
    switch (data.GetCode()) {
        case int32_t(OHOS::Wifi::WifiState::DISABLED): {
            HILOGI("on wifi disabled");
            if (CheckWifiStateIsActived()) {
                WifiStateAdapter::GetInstance().UpdateWifiState(true);
                HILOGI("WifiState is STATE_SEMIACTIVE");
                return;
            }
            WifiStateAdapter::GetInstance().UpdateWifiState(false);
            DMSContinueRecvMgr::GetInstance().OnContinueSwitchOff();
            break;
        }

        case int32_t(Wifi::WifiDetailState::STATE_SEMI_ACTIVE): {
            HILOGI("on wifi SEMI_ACTIVE");
            WifiStateAdapter::GetInstance().UpdateWifiState(true);
            break;
        }

        case int32_t(OHOS::Wifi::WifiState::ENABLED): {
            HILOGI("on wifi enabled");
            WifiStateAdapter::GetInstance().UpdateWifiState(true);
            break;
        }

        default: {
            HILOGI("unhandled code");
            break;
        }
    }
}

bool WifiStateListener::CheckWifiStateIsActived()
{
    std::shared_ptr<Wifi::WifiDevice> wifiDevicePtr = Wifi::WifiDevice::GetInstance(WIFI_DEVICE_SYS_ABILITY_ID);
    if (wifiDevicePtr == nullptr) {
        HILOGE("wifiDevice is nullptr");
        return false;
    }
    Wifi::WifiDetailState wifiDetailState;
    auto ret = wifiDevicePtr->GetWifiDetailState(wifiDetailState);
    if (ret != Wifi::WIFI_OPT_SUCCESS) {
        HILOGE("GetWifiDetailState failed, ret %{public}d", ret);
        return false;
    }
    
    HILOGI("get wifi detail state is %{public}d", wifiDetailState);
    return (wifiDetailState == Wifi::WifiDetailState::STATE_SEMI_ACTIVE) ||
        (wifiDetailState == Wifi::WifiDetailState::STATE_ACTIVATED);
}

void WifiStateListener::InitWifiState()
{
    bool isWifiActive = CheckWifiStateIsActived();
    WifiStateAdapter::GetInstance().UpdateWifiState(isWifiActive);
    HILOGI("init wifiActive, State=%{public}d", isWifiActive);
}
} // namespace DistributedSchedule
} // namespace OHOS