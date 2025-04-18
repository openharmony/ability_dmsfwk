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

#include "switch_status_dependency.h"

#include <fstream>
#include <iostream>
#include "datashare_manager.h"
#include "dtbschedmgr_log.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "uri.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DMSSwitchStatusDep";
}
const std::string SwitchStatusDependency::SETTINGS_USER_SECURE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE";
const std::string SwitchStatusDependency::SETTINGS_DATA_FIELD_KEY = "KEYWORD";
const std::string SwitchStatusDependency::SETTINGS_DATA_FIELD_VAL = "VALUE";
const std::string SwitchStatusDependency::CONTINUE_SWITCH_STATUS_KEY = "Continue_Switch_Status";
const std::string SwitchStatusDependency::CONTINUE_SWITCH_OFF = "0";
const std::string SwitchStatusDependency::CONTINUE_SWITCH_ON = "1";

SwitchStatusDependency &SwitchStatusDependency::GetInstance()
{
    static SwitchStatusDependency instance;
    return instance;
}

bool SwitchStatusDependency::IsContinueSwitchOn()
{
    HILOGD("IsContinueSwitchOn start");
    std::lock_guard<std::mutex> lock(dataShareMutex_);
    HILOGD("start query switch status from dataShare");
    switchStatus_ = GetSwitchStatus(CONTINUE_SWITCH_STATUS_KEY, CONTINUE_SWITCH_ON);
    return switchStatus_ != CONTINUE_SWITCH_OFF;
}

std::string SwitchStatusDependency::GetSwitchStatus(const std::string &key, const std::string &defaultValue)
{
    HILOGD("GetSwitchStatus start, key is %{public}s", key.c_str());
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = GetDataShareHelper();
    if (dataShareHelper == nullptr) {
        HILOGE("dataShareHelper is null, key is %{public}s", key.c_str());
        return defaultValue;
    }
    int32_t userId = DataShareManager::GetInstance().GetLocalAccountId();
    Uri uri(DataShareManager::GetInstance().AssembleUserSecureUri(userId, key));
    DataShare::DataSharePredicates dataSharePredicates;
    std::vector<std::string> columns;
    dataSharePredicates.EqualTo(SETTINGS_DATA_FIELD_KEY, key);
    columns.emplace_back(SETTINGS_DATA_FIELD_VAL);
    auto resultSet = dataShareHelper->Query(uri, dataSharePredicates, columns);
    if (resultSet == nullptr) {
        HILOGE("get switch status, resultSet is nullptr with key is %{public}s", key.c_str());
        dataShareHelper->Release();
        return defaultValue;
    }
    int32_t numRows = 0;
    resultSet->GetRowCount(numRows);
    if (numRows == 0) {
        HILOGW("get switch status, numRows is zero with key is %{public}s", key.c_str());
        resultSet->Close();
        dataShareHelper->Release();
        return defaultValue;
    }
    int32_t columnIndex = 0;
    int32_t rowNumber = 0;
    resultSet->GoToRow(rowNumber);
    std::string valueResult;
    int32_t ret = resultSet->GetString(columnIndex, valueResult);
    if (ret != 0) {
        HILOGE("get switch status, resultSet->GetString not ok with key is %{public}s", key.c_str());
        resultSet->Close();
        dataShareHelper->Release();
        return defaultValue;
    }
    resultSet->Close();
    dataShareHelper->Release();
    HILOGI("GetStringValue, setting value is %{public}s with key is %{public}s", valueResult.c_str(), key.c_str());
    return valueResult;
}

std::shared_ptr<DataShare::DataShareHelper> SwitchStatusDependency::GetDataShareHelper()
{
    HILOGD("create DataShareHelper instance");
    DataShare::CreateOptions options;
    options.isProxy_ = true;
    return DataShare::DataShareHelper::Creator(SETTINGS_USER_SECURE_URI, options);
}
} // namespace DistributedSchedule
} // namespace OHOS