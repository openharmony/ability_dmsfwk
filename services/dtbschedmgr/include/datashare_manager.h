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

#include <shared_mutex>
#include "datashare_helper.h"

namespace OHOS {
namespace DistributedSchedule {
using ChangeInfo = DataShare::DataShareObserver::ChangeInfo;
const std::string SETTINGS_DATA_URI =
    "datashare:///com.ohos.settingsdata/entry/settingsdata/SETTINGSDATA?Proxy=true&key=Continue_Switch_Status";

class DataShareManager {
public:
    static DataShareManager &GetInstance();
    std::shared_ptr<DataShare::DataShareHelper> CreateDataShareHelper();
    bool IsCreateDataShareHelper(const std::string &datashareUri);
    void RegisterObserver(const std::string &datashareUri);

private:
    DataShareManager() = default;
    ~DataShareManager() = default;
    DISALLOW_COPY_AND_MOVE(DataShareManager);

    static DataShareManager instance_;
    std::shared_ptr<DataShare::DataShareHelper> helper_;
    std::string datashareUri_;
};

class DataShareRegisterObserver : public DataShare::DataShareObserver {
public:
    DataShareRegisterObserver() {}
    ~DataShareRegisterObserver() {}
    void OnChange(const ChangeInfo &changeInfo) override;
};
} // namespace DistributedSchedule
} // namespace OHOS

#endif // DMS_DATASHARE_MANAGER_H