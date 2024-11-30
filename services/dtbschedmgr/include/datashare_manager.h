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

#ifndef DMS_DATASHARE_MANAGER_H
#define DMS_DATASHARE_MANAGER_H

#include <map>

#include "datashare_helper.h"
#include "data_ability_observer_stub.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

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
    DECLARE_SINGLE_INSTANCE(DataShareManager);

public:
    void RegisterObserver(const std::string &key, SettingObserver::ObserverCallback &observerCallback);
    void UnregisterObserver(const std::string &key);
    void UnInit();

    using ObserverCallback = std::function<void()>;

    int32_t GetLocalAccountId();
    Uri AssembleUserSecureUri(int userId, const std::string& key);
    void UpdateSwitchStatus(const std::string &key, const std::string &value);
    std::atomic<bool> isCurrentContinueSwitchOn_ = true;
    bool IsCurrentContinueSwitchOn();
    void SetCurrentContinueSwitch(bool status);

private:
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    void RegisterObserver(SettingObserver::ObserverCallback &observerCallback);

private:
    sptr<SettingObserver> observer_;
    std::mutex observerMutex_;
    std::mutex datashareMutex_;
};
} // namespace DistributedSchedule
} // namespace OHOS

#endif // DMS_DATASHARE_MANAGER_H
