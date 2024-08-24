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

#include "mission/dsched_sync_e2e.h"

#include <parameter.h>

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsKvSyncE2E";
const std::string BMS_KV_BASE_DIR = "/data/service/el1/public/database/DistributedSchedule";
const int32_t SLEEP_INTERVAL = 100 * 1000;  // 100ms
const int32_t EL1 = 1;
const int32_t MAX_TIMES = 600;              // 1min
const char DETERMINE_DEVICE_TYPE_KEY[] = "persist.distributed_scene.sys_settings_data_sync";
}  // namespace

std::shared_ptr<DmsKvSyncE2E> DmsKvSyncE2E::instance_ = nullptr;
std::mutex DmsKvSyncE2E::mutex_;

DmsKvSyncE2E::DmsKvSyncE2E()
{
    HILOGD("called.");
    TryTwice([this] { return GetKvStore(); });
    HILOGD("end.");
}

DmsKvSyncE2E::~DmsKvSyncE2E()
{
    HILOGD("called.");
    dataManager_.CloseKvStore(appId_, storeId_);
    HILOGD("end.");
}

std::shared_ptr<DmsKvSyncE2E> DmsKvSyncE2E::GetInstance()
{
    HILOGD("called.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (instance_ == nullptr) {
        instance_ = std::make_shared<DmsKvSyncE2E>();
    }
    HILOGD("end.");
    return instance_;
}

void DmsKvSyncE2E::SetDeviceCfg()
{
    HILOGI("called.");
    const char *syncType = "1";
    const int bufferLen = 10;
    char paramOutBuf[bufferLen] = {0};
    int ret = GetParameter(DETERMINE_DEVICE_TYPE_KEY, "", paramOutBuf, bufferLen);
    HILOGI("paramOutBuf: %{public}s, ret: %{public}d", paramOutBuf, ret);
    if (ret > 0 && strncmp(paramOutBuf, syncType, strlen(syncType)) == 0) {
        HILOGI("Determining the e2e device succeeded.");
        isCfgDevices_ = true;
    }
}

bool DmsKvSyncE2E::CheckDeviceCfg()
{
    HILOGI("called.");
    return isCfgDevices_;
}

bool DmsKvSyncE2E::PushAndPullData()
{
    HILOGI("called.");
    std::vector<std::string> networkIdList = DtbschedmgrDeviceInfoStorage::GetInstance().GetNetworkIdList();
    if (networkIdList.empty()) {
        HILOGE("GetNetworkIdList failed");
        return false;
    }
    if (!CheckKvStore()) {
        HILOGE("kvStore is nullptr");
        return false;
    }
    DistributedKv::DataQuery dataQuery;
    std::shared_ptr<DmsKvSyncCB> syncCallback = std::make_shared<DmsKvSyncCB>();
    Status status = kvStorePtr_->Sync(networkIdList, DistributedKv::SyncMode::PUSH_PULL, dataQuery, syncCallback);
    if (status != Status::SUCCESS) {
        HILOGE("sync error: %{public}d", status);
        return false;
    }
    HILOGI("Synchronizing");
    return true;
}

bool DmsKvSyncE2E::PushAndPullData(const std::string &networkId)
{
    HILOGI("called.");
    if (!CheckDeviceCfg() && IsSynchronized(networkId)) {
        HILOGW("The normal device been synchronized : %{public}s", GetAnonymStr(networkId).c_str());
        return false;
    }
    std::vector<std::string> networkIdList = {networkId};
    if (!CheckKvStore()) {
        HILOGE("kvStore is nullptr");
        return false;
    }

    SetSyncRecord(networkId);
    DistributedKv::DataQuery dataQuery;
    std::shared_ptr<DmsKvSyncCB> syncCallback = std::make_shared<DmsKvSyncCB>();
    Status status = kvStorePtr_->Sync(networkIdList, DistributedKv::SyncMode::PUSH_PULL, dataQuery, syncCallback);
    if (status != Status::SUCCESS) {
        HILOGE("sync error: %{public}d", status);
        return false;
    }
    HILOGI("Synchronizing");
    return true;
}

void DmsKvSyncE2E::SetSyncRecord(const std::string &networkId)
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    deviceSyncRecord_.insert(std::make_pair(networkId, true));
}

void DmsKvSyncE2E::ClearSyncRecord(const std::string &networkId)
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    auto it = deviceSyncRecord_.find(networkId);
    if (it != deviceSyncRecord_.end()) {
        deviceSyncRecord_.erase(it);
        HILOGI("Successfully cleared synchronization records for: %{public}s", GetAnonymStr(networkId).c_str());
    } else {
        HILOGI("No need to clean up for: %{public}s", GetAnonymStr(networkId).c_str());
    }
}

bool DmsKvSyncE2E::IsSynchronized(const std::string &networkId)
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (deviceSyncRecord_.find(networkId) != deviceSyncRecord_.end() && deviceSyncRecord_[networkId]) {
        return true;
    }
    return false;
}

bool DmsKvSyncE2E::CheckKvStore()
{
    HILOGD("called.");
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (kvStorePtr_ != nullptr) {
        return true;
    }
    int32_t tryTimes = MAX_TIMES;
    while (tryTimes > 0) {
        Status status = GetKvStore();
        if (status == Status::SUCCESS && kvStorePtr_ != nullptr) {
            return true;
        }
        HILOGW("CheckKvStore, Times: %{public}d", tryTimes);
        usleep(SLEEP_INTERVAL);
        tryTimes--;
    }
    HILOGD("end.");
    return kvStorePtr_ != nullptr;
}

Status DmsKvSyncE2E::GetKvStore()
{
    HILOGI("called.");
    Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .isPublic = true,
        .securityLevel = SecurityLevel::S1,
        .area = EL1,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
        .baseDir = BMS_KV_BASE_DIR,
        .dataType = DataType::TYPE_DYNAMICAL,
        .cloudConfig = {
            .enableCloud = true,
            .autoSync = true
        },
    };
    Status status = dataManager_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    if (status == Status::SUCCESS) {
        HILOGI("get kvStore success");
    } else if (status == DistributedKv::Status::STORE_META_CHANGED) {
        HILOGE("This db meta changed, remove and rebuild it");
        dataManager_.DeleteKvStore(appId_, storeId_, BMS_KV_BASE_DIR + appId_.appId);
    }
    HILOGI("end.");
    return status;
}

void DmsKvSyncE2E::TryTwice(const std::function<Status()> &func) const
{
    HILOGD("called.");
    Status status = func();
    if (status != Status::SUCCESS) {
        status = func();
        HILOGW("error and try to call again, result = %{public}d", status);
    }
    HILOGD("end.");
}

DmsKvSyncCB::DmsKvSyncCB()
{
    HILOGD("create");
}

DmsKvSyncCB::~DmsKvSyncCB()
{
    HILOGD("destroy");
}

void DmsKvSyncCB::SyncCompleted(const std::map<std::string, DistributedKv::Status> &result)
{
    HILOGI("kvstore sync completed.");
    for (auto ele : result) {
        HILOGI("uuid: %{public}s , result: %{public}d", GetAnonymStr(ele.first).c_str(), ele.second);
    }
}
}  // namespace DistributedSchedule
}  // namespace OHOS
