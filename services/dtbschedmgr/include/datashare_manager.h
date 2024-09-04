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

#ifndef DMS_DATASHARE_MANAGER_H
#define DMS_DATASHARE_MANAGER_H

#include <map>

#include "datashare_helper.h"
#include "data_ability_observer_stub.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string SETTINGS_DATA_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=Continue_Switch_Status";
const std::string SETTINGS_USER_SECURE_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/USER_SETTINGSDATA_SECURE";
    
class SettingObserver : public AAFwk::DataAbilityObserverStub {
public:
    SettingObserver();
    ~SettingObserver() override;
    void OnChange() override;

    using ObserverCallback = std::function<void()>;
    void SetObserverCallback(ObserverCallback &observerCallback);
private:
    ObserverCallback observerCallback_  = nullptr;
};

class DataShareManager {
public:
    void RegisterObserver(const std::string &key, SettingObserver::ObserverCallback &observerCallback);
    void UnregisterObserver(const std::string &key);

    using ObserverCallback = std::function<void()>;

    int32_t GetLocalAccountId();
    Uri AssembleUserSecureUri(int userId, const std::string& key);
    void UpdateSwitchStatus(const std::string &key, const std::string &value);
    std::atomic<bool> isContinueSwitchOn_ = false;
    
private:
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    Uri AssembleUri(const std::string &key);
    sptr<SettingObserver> GetSettingObserver(const std::string &key);

private:
    std::map<std::string, sptr<SettingObserver>> settingObserverMap_;
    std::mutex observerMapMutex_;
    std::mutex datashareMutex_;
};
} // namespace DistributedSchedule
} // namespace OHOS

#endif // DMS_DATASHARE_MANAGER_H