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

#ifndef DMS_SWITCH_STATUS_DEPENDENCY_H
#define DMS_SWITCH_STATUS_DEPENDENCY_H

#include <string>
#include <mutex>
#include <vector>
#include "json/json.h"
#include "datashare_helper.h"

namespace OHOS {
namespace DistributedSchedule {

class SwitchStatusDependency {
public:
    static SwitchStatusDependency &GetInstance();
    bool IsContinueSwitchOn();

private:
    std::string GetSwitchStatus(const std::string &key, const std::string &defaultValue);
    std::shared_ptr<DataShare::DataShareHelper> GetDataShareHelper();
    std::mutex dataShareMutex_;
    const std::string SETTINGS_DATA_URI_PREFIX =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
    const std::string SETTINGS_USER_SECURE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE";
    const std::string SETTINGS_DATA_FIELD_KEY = "KEYWORD";
    const std::string SETTINGS_DATA_FIELD_VAL = "VALUE";
    const std::string CONTINUE_SWITCH_STATUS_KEY = "Continue_Switch_Status";
    const std::string CONTINUE_SWITCH_OFF = "0";
    const std::string CONTINUE_SWITCH_ON = "1";
    std::string switchStatus_;
};
} // namespace DistributedSchedule
} // namespace OHOS

#endif // DMS_SWITCH_STATUS_DEPENDENCY_H