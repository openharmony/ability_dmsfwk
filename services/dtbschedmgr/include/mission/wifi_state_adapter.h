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

#ifndef OHOS_DTBSCHEDMGR_WIFI_STATE_ADAPTER_H
#define OHOS_DTBSCHEDMGR_WIFI_STATE_ADAPTER_H

#include <string>

#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
class WifiStateAdapter {
public:
    DECLARE_SINGLE_INSTANCE_BASE(WifiStateAdapter);
public:
    bool IsWifiActive();
    void UpdateWifiState(bool isWifiActive);

private:
    WifiStateAdapter() {}
    bool isWifiActive_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif /* OHOS_DTBSCHEDMGR_WIFI_STATE_ADAPTER_H */