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

#include "distributed_sched_utils.h"
#include "dtbschedmgr_log.h"
#include "mission/dms_continue_recv_manager.h"
#include "mission/dms_continue_send_manager.h"
#include "switch_status_dependency.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DMSDataShareManager";
const std::string SETTINGS_DATA_URI_PREFIX =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true";
}
SettingObserver::SettingObserver() = default;
SettingObserver::~SettingObserver() = default;

void SettingObserver::OnChange()
{
    HILOGI("DataShareRegisterObserver OnChange start");
    if (observerCallback_ != nullptr) {
        observerCallback_();
    }
    HILOGI("DataShareRegisterObserver OnChange done");
}

void SettingObserver::SetObserverCallback(ObserverCallback &observerCallback)
{
    observerCallback_ = observerCallback;
}

sptr<SettingObserver> DataShareManager::GetSettingObserver(const std::string &key)
{
    HILOGI("GetSettingObserver with key is %{public}s", key.c_str());
    std::lock_guard<std::mutex> lockGuard(observerMapMutex_);
    if (settingObserverMap_.find(key) != settingObserverMap_.end()) {
        return settingObserverMap_.find(key)->second;
    }
    return nullptr;
}

Uri DataShareManager::AssembleUri(const std::string &key)
{
    return Uri(SETTINGS_DATA_URI_PREFIX + "&key=" + key);
}

std::shared_ptr<DataShare::DataShareHelper> DataShareManager::CreateDataShareHelper()
{
    HILOGI("DataShareManager CreateDataShareHelper start");
    DataShare::CreateOptions options;
    options.isProxy_ = true;
    return DataShare::DataShareHelper::Creator(SETTINGS_DATA_URI_PREFIX, options);
}

void DataShareManager::RegisterObserver(const std::string &key, SettingObserver::ObserverCallback &observerCallback)
{
    HILOGI("DataShareManager RegisterObserver start");
    sptr<SettingObserver> observer = GetSettingObserver(key);
    if (observer != nullptr) {
        HILOGI("Observer is already registered with key is %{public}s", key.c_str());
        UnregisterObserver(key);
    }
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper();
    if (dataShareHelper == nullptr) {
        HILOGE("Register observer failed, dataShareHelper is null");
        return;
    }
    Uri uri = AssembleUri(key);
    observer = new SettingObserver();
    if (observer == nullptr) {
        HILOGE("Register observer failed, observer is null");
        return;
    }
    observer->SetObserverCallback(observerCallback);
    dataShareHelper->RegisterObserver(uri, observer);
    dataShareHelper->Release();
    
    std::lock_guard<std::mutex> lockGuard(observerMapMutex_);
    settingObserverMap_[key] = observer;
    HILOGI("DataShareManager RegisterObserver success with key is %{public}s", key.c_str());
}

void DataShareManager::UnregisterObserver(const std::string &key)
{
    HILOGI("DataShareManager UnregisterObserver start");
    sptr<SettingObserver> observer = GetSettingObserver(key);
    if (observer == nullptr) {
        HILOGI("UnregisterObserver, observer is nullptr with key is %{public}s", key.c_str());
        return;
    }
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper();
    if (dataShareHelper == nullptr) {
        HILOGE("Unregister observer failed with key is %{public}s", key.c_str());
        return;
    }
    Uri uri = AssembleUri(key);
    dataShareHelper->UnregisterObserver(uri, observer);
    dataShareHelper->Release();

    std::lock_guard<std::mutex> lockGuard(observerMapMutex_);
    settingObserverMap_.erase(key);
    HILOGI("DataShareManager UnregisterObserver success with key is %{public}s", key.c_str());
}
} // namespace DistributedSchedule
} // namespace OHOS