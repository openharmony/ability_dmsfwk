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

#include "datashare_manager.h"
#include "dtbschedmgr_log.h"
#include "switch_status_dependency.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DMSDataShareManager";
}

DataShareManager DataShareManager::instance_;
DataShareManager &DataShareManager::GetInstance()
{
    return instance_;
}

std::shared_ptr<DataShare::DataShareHelper> DataShareManager::CreateDataShareHelper()
{
    HILOGI("create DataShareHelper instance");
    DataShare::CreateOptions options;
    options.isProxy_ = true;
    datashareUri_ = SETTINGS_DATA_URI;
    helper_ = DataShare::DataShareHelper::Creator(datashareUri_, options);
    return helper_;
}

bool DataShareManager::IsCreateDataShareHelper(const std::string &datashareUri)
{
    HILOGI("DataShareManager IsCreateDataShareHelper start");
    if (CreateDataShareHelper() == nullptr) {
        HILOGE("create helper failed for uri:%{public}s", datashareUri.c_str());
        return false;
    } else {
        HILOGI("create new helper success for uri:%{public}s", datashareUri.c_str());
        return true;
    }
}

void DataShareManager::RegisterObserver(const std::string &datashareUri)
{
    HILOGI("DataShareManager RegisterObserver start");
    if (IsCreateDataShareHelper(datashareUri)) {
        Uri uri(SETTINGS_DATA_URI);
        std::shared_ptr<DataShareRegisterObserver> dataObserver = std::make_shared<DataShareRegisterObserver>();
        helper_->RegisterObserverExt(uri, dataObserver, true);
        HILOGI("DataShareManager RegisterObserver uri:%{public}s success", datashareUri.c_str());
    }
    HILOGI("DataShareManager RegisterObserver done");
}

void DataShareRegisterObserver::OnChange(const ChangeInfo &changeInfo)
{
    HILOGI("DataShareRegisterObserver OnChange start");
    bool IsContinueSwitchOn = SwitchStatusDependency::GetInstance().IsContinueSwitchOn();
    HILOGI("IsContinueSwitchOn : %{public}d", IsContinueSwitchOn);
    HILOGI("DataShareRegisterObserver OnChange done");
}
} // namespace DistributedSchedule
} // namespace OHOS