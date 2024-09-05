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

#include "dfx/distributed_ue.h"
#include "distributed_sched_utils.h"
#include "dsched_continue_manager.h"
#include "dtbschedmgr_log.h"
#include "mission/dms_continue_recv_manager.h"
#include "mission/dms_continue_send_manager.h"
#include "os_account_manager.h"
#include "switch_status_dependency.h"

namespace OHOS {
namespace DistributedSchedule {
IMPLEMENT_SINGLE_INSTANCE(DataShareManager);
namespace {
const std::string TAG = "DMSDataShareManager";
const std::string SETTINGS_DATA_FIELD_KEY = "KEYWORD";
const std::string SETTINGS_DATA_FIELD_VAL = "VALUE";
constexpr static int32_t INVALID_ACCOUNT_ID = -1;
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

std::shared_ptr<DataShare::DataShareHelper> DataShareManager::CreateDataShareHelper()
{
    HILOGI("DataShareManager CreateDataShareHelper start");
    DataShare::CreateOptions options;
    options.isProxy_ = true;
    return DataShare::DataShareHelper::Creator(SETTINGS_USER_SECURE_URI, options);
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
    int32_t userId = GetLocalAccountId();
    Uri uri(AssembleUserSecureUri(userId, key));
    sptr<SettingObserver> newObserver(new SettingObserver());
    observer = newObserver;
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
    int32_t userId = GetLocalAccountId();
    Uri uri(AssembleUserSecureUri(userId, key));
    dataShareHelper->UnregisterObserver(uri, observer);
    dataShareHelper->Release();
    if (observer != nullptr) {
        HILOGI("UnregisterObserver delete observer");
        delete observer;
    }
    std::lock_guard<std::mutex> lockGuard(observerMapMutex_);
    settingObserverMap_.erase(key);
    HILOGI("DataShareManager UnregisterObserver success with key is %{public}s", key.c_str());
}

Uri DataShareManager::AssembleUserSecureUri(int userId, const std::string &key)
{
    Uri uri(SETTING_USER_SECURE_URI + "_" + std::to_string(userId) + "?Proxy=true&key=" + key);
    return uri;
}

int32_t DataShareManager::GetLocalAccountId()
{
    int32_t id = INVALID_ACCOUNT_ID;
    ErrCode err = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(id);
    if (err != ERR_OK || id == INVALID_ACCOUNT_ID) {
        HILOGE("GetLocalAccountId passing param invalid or return error!, err : %{public}d", err);
        return INVALID_PARAMETERS_ERR;
    }
    return id;
}

void DataShareManager::UpdateSwitchStatus(const std::string &key, const std::string &value)
{
    HILOGI("Start UpdateSwitchStatus");
    std::shared_ptr<DataShare::DataShareHelper> dataShareHelper = CreateDataShareHelper();
    if (dataShareHelper == nullptr) {
        HILOGE("dataShareHelper is null, key is %{public}s", key.c_str());
        return;
    }

    HILOGD("UpdateSwitchStatus key = %{public}s", key.c_str());
    int32_t userId = GetLocalAccountId();
    Uri uri(AssembleUserSecureUri(userId, key));
    DataShare::DataSharePredicates predicates;
    predicates.EqualTo(SETTINGS_DATA_FIELD_KEY, key);

    DataShare::DataShareValuesBucket bucket;
    bucket.Put(SETTINGS_DATA_FIELD_KEY, key);
    bucket.Put(SETTINGS_DATA_FIELD_VAL, value);

    auto result = dataShareHelper->UpdateEx(uri, predicates, bucket);
    dataShareHelper->Release();
    if (result.first != ERR_OK) {
        HILOGE("Update status failed: %{public}d", result.first);
    }
    HILOGI("Finish UpdateSwitchStatus, Updata status success: %{public}d", result.first);
    return;
}

bool DataShareManager::IsCurrentContinueSwitchOn()
{
    HILOGD(IsCurrentContinueSwitchOn start);
    return isCurrentContinueSwitchOn_.load();
}

void DataShareManager::SetCurrentContinueSwitch(bool status)
{
    HILOGD(SetCurrentContinueSwitch start);
    isCurrentContinueSwitchOn_.store(status);
}
} // namespace DistributedSchedule
} // namespace OHOS