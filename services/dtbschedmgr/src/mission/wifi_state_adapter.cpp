/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "mission/dms_continue_condition_manager.h"
#include "mission/wifi_state_adapter.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "WifiStateAdapter";
}

IMPLEMENT_SINGLE_INSTANCE(WifiStateAdapter);

bool WifiStateAdapter::IsWifiActive()
{
    return isWifiActive_;
}

void WifiStateAdapter::UpdateWifiState(bool isWifiActive)
{
    isWifiActive_ = isWifiActive;
    DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_WIFI, isWifiActive_);
}
} // namespace DistributedSchedule
} // namespace OHOS
