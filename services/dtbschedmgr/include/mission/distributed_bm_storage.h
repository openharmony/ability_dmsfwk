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

#ifndef DISTRIBUTED_BM_STORAGE_H
#define DISTRIBUTED_BM_STORAGE_H

#include <future>
#include <map>
#include <mutex>
#include <shared_mutex>

#include "bundle_info.h"
#include "bundle_mgr_interface.h"
#include "distributed_kv_data_manager.h"
#include "deviceManager/dms_device_info.h"
#include "distributed_data_change_listener.h"
#include "distributed_kv_data_manager.h"
#include "distributed_sched_continuation.h"
#include "mission/distributed_bundle_info.h"
#include "kvstore_death_recipient.h"
#include "os_account_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
// distributed bm
static std::string DMS_BM_APP_ID = "DistributedSchedule";
static std::string DISTRIBUTE_BM_STORE_ID = "dms_bundle_datas";
const uint16_t MAX_BUNDLEID = 65535; // size of uint16_t
const uint8_t MAX_CONTINUETYPEID = 255; // size of uint8_t
}
struct ContinueEventInfo {
    std::string networkId;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string developerId;
};

class DmsBmStorage {
public:
    DmsBmStorage();
    ~DmsBmStorage();
    static std::shared_ptr<DmsBmStorage> GetInstance();
    OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> GetBundleMgr();
    bool SaveStorageDistributeInfo(const std::string &bundleName, bool isPackageChange = false);
    bool DeleteStorageDistributeInfo(const std::string &bundleName);
    bool GetStorageDistributeInfo(const std::string &networkId, const std::string &bundleName,
        DmsBundleInfo &info);
    bool GetDistributedBundleName(const std::string &networkId,  const uint16_t& bundleNameId,
        std::string& bundleName);
    bool GetDistributedBundleInfo(const std::string &networkId, const uint16_t &bundleNameId,
        DmsBundleInfo &distributeBundleInfo);
    bool GetBundleNameId(const std::string& bundleName, uint16_t &bundleNameId);
    std::string GetContinueType(const std::string &networkId, std::string &bundleName, uint8_t continueTypeId);
    std::string GetAbilityName(const std::string &networkId, std::string &bundleName, std::string &continueType);
    bool GetContinueTypeId(const std::string &bundleName, const std::string &abilityName, uint8_t &continueTypeId);
    bool GetContinueEventInfo(const std::string &networkId, const std::string &bundleName,
        const std::string& continueType, ContinueEventInfo &continueEventInfo);
    void UpdateDistributedData();
    int32_t CloudSync();
    void FindProvishionInfo(OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> bundleMgr,
        AppExecFwk::AppProvisionInfo appProvisionInfo, std::vector<AccountSA::OsAccountInfo> accounts,
        int32_t result, const std::string& bundleName);
    void DmsPutBatch(const std::vector<DmsBundleInfo> &dmsBundleInfos);
    bool UpdatePublicRecords(const std::string &localUdid);

private:
    std::string DeviceAndNameToKey(const std::string &udid, const std::string &bundleName) const;
    void TryTwice(const std::function<DistributedKv::Status()> &func) const;
    bool CheckKvStore();
    DistributedKv::Status GetKvStore();
    bool DealGetBundleName(const std::string &networkId, const uint16_t& bundleNameId, std::string &bundleName);
    uint16_t CreateBundleNameId(const std::string &bundleName, bool isPackageChange = false);
    void AddBundleNameId(const uint16_t &bundleNameId, const std::string &bundleName);
    void DelBundleNameId(const std::string &bundleName);
    DmsBundleInfo ConvertToDistributedBundleInfo(const AppExecFwk::BundleInfo &bundleInfo,
        AppExecFwk::AppProvisionInfo appProvisionInfo,
        bool isPackageChange = false);
    bool InnerSaveStorageDistributeInfo(const DmsBundleInfo &distributedBundleInfo, const std::string &localUdid);
    std::map<std::string, DmsBundleInfo> GetAllOldDistributionBundleInfo(
        const std::vector<std::string> &bundleNames);
    void GetEntries(const std::string &networkId, const OHOS::DistributedKv::Key &allEntryKeyPrefix,
        std::promise<OHOS::DistributedKv::Status> &resultStatusSignal,
        std::vector<OHOS::DistributedKv::Entry> &allEntries);
    OHOS::DistributedKv::Status GetResultSatus(std::promise<OHOS::DistributedKv::Status> &resultStatusSignal);
    bool DelReduData(const std::string &networkId, const std::vector<OHOS::DistributedKv::Entry> &reduRiskEntries);
    bool CheckSyncData(const std::string &networkId);
    bool RebuildLocalData();
    bool GetLastBundleNameId(uint16_t &bundleNameId);

private:
    static std::mutex mutex_;
    static std::shared_ptr<DmsBmStorage> instance_;
    const DistributedKv::AppId appId_ {DMS_BM_APP_ID};
    const DistributedKv::StoreId storeId_ {DISTRIBUTE_BM_STORE_ID};
    DistributedKv::DistributedKvDataManager dataManager_;
    std::shared_ptr<DistributedKv::SingleKvStore> kvStorePtr_;
    mutable std::mutex kvStorePtrMutex_;
    OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> bundleMgr_;
    std::map<uint16_t, std::string> bundleNameIdTables_;
    int32_t waittingTime_ = 180; // 3 s
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // DISTRIBUTED_BM_STORAGE_H