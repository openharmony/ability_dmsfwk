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


#include "mission/distributed_bm_storage.h"

#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "iservice_registry.h"
#include "mission/distributed_sched_mission_manager.h"
#include "system_ability_definition.h"
#include "os_account_manager.h"

using namespace OHOS::DistributedKv;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsBmDataStorage";
const std::string BMS_KV_BASE_DIR = "/data/service/el1/public/database/DistributedSchedule";
const int32_t EL1 = 1;
const int32_t MAX_TIMES = 600;              // 1min
const int32_t SLEEP_INTERVAL = 100 * 1000;  // 100ms
const int32_t FLAGS = AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES |
                      AppExecFwk::ApplicationFlag::GET_APPLICATION_INFO_WITH_DISABLE |
                      AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_DISABLE;
}  // namespace

std::shared_ptr<DmsBmStorage> DmsBmStorage::instance_ = nullptr;
std::mutex DmsBmStorage::mutex_;

DmsBmStorage::DmsBmStorage()
{
    HILOGD("called.");
    TryTwice([this] { return GetKvStore(); });
    HILOGD("end.");
}

DmsBmStorage::~DmsBmStorage()
{
    HILOGD("called.");
    dataManager_.CloseKvStore(appId_, storeId_);
    HILOGD("end.");
}

std::shared_ptr<DmsBmStorage> DmsBmStorage::GetInstance()
{
    HILOGD("called.");
    std::lock_guard<std::mutex> lock_l(mutex_);
    if (instance_ == nullptr) {
        instance_ = std::make_shared<DmsBmStorage>();
    }
    HILOGD("end.");
    return instance_;
}

bool DmsBmStorage::SaveStorageDistributeInfo(const std::string &bundleName)
{
    HILOGD("called.");
    {
        if (!CheckKvStore()) {
            HILOGE("kvStore is nullptr");
            return false;
        }
    }
    auto bundleMgr = DmsBmStorage::GetInstance()->GetBundleMgr();
    if (bundleMgr == nullptr) {
        HILOGE("Get bundleMgr shared_ptr nullptr");
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    bool ret = bundleMgr->GetBundleInfo(bundleName, FLAGS, bundleInfo, AppExecFwk::Constants::ALL_USERID);
    if (!ret) {
        HILOGW("GetBundleInfo of %{public}s failed", bundleName.c_str());
        DeleteStorageDistributeInfo(bundleName);
        return false;
    }
    ret = InnerSaveStorageDistributeInfo(ConvertToDistributedBundleInfo(bundleInfo));
    if (!ret) {
        HILOGW("InnerSaveStorageDistributeInfo:%{public}s  failed", bundleName.c_str());
        return false;
    }
    return true;
    HILOGD("end.");
}

bool DmsBmStorage::InnerSaveStorageDistributeInfo(const DmsBundleInfo &distributedBundleInfo)
{
    std::string udid;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalUdid(udid);
    if (udid == "") {
        HILOGE("GetLocalUdid failed");
        return false;
    }
    std::string keyOfData = DeviceAndNameToKey(udid, distributedBundleInfo.bundleName);
    Key key(keyOfData);
    Value value(distributedBundleInfo.ToString());
    Status status = kvStorePtr_->Put(key, value);
    if (status == Status::IPC_ERROR) {
        status = kvStorePtr_->Put(key, value);
        HILOGW("distribute database ipc error and try to call again, result = %{public}d", status);
    }
    if (status != Status::SUCCESS) {
        HILOGE("put to kvStore error: %{public}d", status);
        return false;
    }
    return true;
}

bool DmsBmStorage::DeleteStorageDistributeInfo(const std::string &bundleName)
{
    HILOGD("called.");
    {
        if (!CheckKvStore()) {
            HILOGE("kvStore is nullptr");
            return false;
        }
    }
    std::string udid;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalUdid(udid);
    if (udid == "") {
        HILOGE("GetLocalUdid failed");
        return false;
    }

    auto bundleMgr = DmsBmStorage::GetInstance()->GetBundleMgr();
    if (bundleMgr == nullptr) {
        HILOGE("Get bundleMgr shared_ptr nullptr");
        return false;
    }
    AppExecFwk::BundleInfo bundleInfo;
    bool ret = bundleMgr->GetBundleInfo(bundleName, FLAGS, bundleInfo, AppExecFwk::Constants::ALL_USERID);
    if (ret) {
        HILOGW("The bundleInfo exists and does not need to be deleted.");
        return true;
    }
    uint16_t accessTokenId = 0;
    GetBundleNameId(bundleName, accessTokenId);
    if (bundleNameIdTables_.size() > accessTokenId) {
        bundleNameIdTables_[accessTokenId] = false;
    }
    std::string keyOfData = DeviceAndNameToKey(udid, bundleName);
    Key key(keyOfData);
    Status status = kvStorePtr_->Delete(key);
    if (status == Status::IPC_ERROR) {
        status = kvStorePtr_->Delete(key);
        HILOGW("distribute database ipc error and try to call again, result = %{public}d", status);
    }
    if (status != Status::SUCCESS) {
        HILOGE("delete key error: %{public}d", status);
        return false;
    }
    return true;
    HILOGD("delete value to kvStore success");
}

bool DmsBmStorage::GetStorageDistributeInfo(const std::string &networkId,
    const std::string &bundleName, DmsBundleInfo &info)
{
    HILOGD("called.");
    {
        if (!CheckKvStore()) {
            HILOGE("kvStore is nullptr");
            return false;
        }
    }
    std::string udid = DtbschedmgrDeviceInfoStorage::GetInstance().GetUdidByNetworkId(networkId);
    if (udid == "") {
        HILOGE("can not get udid by networkId");
        return false;
    }
    std::string keyOfData = DeviceAndNameToKey(udid, bundleName);
    Key key(keyOfData);
    Value value;
    Status status = kvStorePtr_->Get(key, value);
    if (status == Status::IPC_ERROR) {
        status = kvStorePtr_->Get(key, value);
        HILOGW("distribute database ipc error and try to call again, result = %{public}d", status);
    }
    if (status == Status::SUCCESS) {
        info.FromJsonString(value.ToString());
        return true;
    }
    HILOGD("end.");
    return false;
}

bool DmsBmStorage::DealGetBundleName(const std::string &networkId, uint16_t accessTokenId,
    std::string &bundleName)
{
    HILOGD("networkId: %{public}s  accessTokenId: %{public}d",
        DnetworkAdapter::AnonymizeNetworkId(networkId).c_str(), accessTokenId);
    {
        if (!CheckKvStore()) {
            HILOGE("kvStore is nullptr");
            return false;
        }
    }
    std::string udid = DtbschedmgrDeviceInfoStorage::GetInstance().GetUdidByNetworkId(networkId);
    if (udid == "") {
        HILOGE("can not get udid by networkId");
        return false;
    }
    Key allEntryKeyPrefix("");
    std::vector<Entry> allEntries;
    Status status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
    if (status != Status::SUCCESS) {
        HILOGE("GetEntries error: %{public}d", status);
        return false;
    }
    for (auto entry : allEntries) {
        std::string key = entry.key.ToString();
        std::string value =  entry.value.ToString();
        if (key.find(udid) == std::string::npos) {
            continue;
        }
        DmsBundleInfo distributedBundleInfo;
        if (distributedBundleInfo.FromJsonString(value) && distributedBundleInfo.accessTokenId == accessTokenId) {
            bundleName = distributedBundleInfo.bundleName;
            HILOGD("end.");
            return true;
        }
    }
    HILOGE("get bundleName failed");
    return false;
}

bool DmsBmStorage::GetDistributedBundleName(const std::string &networkId, uint16_t accessTokenId,
    std::string &bundleName)
{
    HILOGD("networkId: %{public}s  accessTokenId: %{public}d",
        DnetworkAdapter::AnonymizeNetworkId(networkId).c_str(), accessTokenId);
    bool ret = DealGetBundleName(networkId, accessTokenId, bundleName);
    if (!ret) {
        HILOGW("GetDistributedBundleName error and try to call again");
        PullOtherDistributedData();
        ret = DealGetBundleName(networkId, accessTokenId, bundleName);
    }
    if (bundleName == "") {
        HILOGE("GetBundleNameId fail");
        return false;
    }
    HILOGD("end.");
    return true;
}

bool DmsBmStorage::GetBundleNameId(std::string bundleName, uint16_t &accessTokenId)
{
    HILOGD("called.");
    {
        if (!CheckKvStore()) {
            HILOGE("kvStore is nullptr");
            return false;
        }
    }
    std::string udid;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalUdid(udid);
    if (udid == "") {
        HILOGE("can not get udid by networkId");
        return false;
    }
    Key allEntryKeyPrefix("");
    std::vector<Entry> allEntries;
    Status status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
    if (status != Status::SUCCESS) {
        HILOGE("GetEntries error: %{public}d", status);
        return false;
    }
    for (auto entry : allEntries) {
        std::string key = entry.key.ToString();
        std::string value =  entry.value.ToString();
        if (key.find(udid) == std::string::npos) {
            continue;
        }
        DmsBundleInfo distributedBundleInfo;
        if (distributedBundleInfo.FromJsonString(value) && distributedBundleInfo.bundleName == bundleName) {
            accessTokenId = distributedBundleInfo.accessTokenId;
            HILOGD("end.");
            return true;
        }
    }
    HILOGE("get distributed bundleName no matching data: %{public}s %{public}d", udid.c_str(), accessTokenId);
    return false;
}

std::string DmsBmStorage::DeviceAndNameToKey(const std::string &udid, const std::string &bundleName) const
{
    std::string key = udid + AppExecFwk::Constants::FILE_UNDERLINE + bundleName;
    return key;
}

bool DmsBmStorage::CheckKvStore()
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

Status DmsBmStorage::GetKvStore()
{
    HILOGD("called.");
    Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .securityLevel = SecurityLevel::S1,
        .area = EL1,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
        .baseDir = BMS_KV_BASE_DIR
    };
    Status status = dataManager_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    if (status != Status::SUCCESS) {
        HILOGE("return error: %{public}d", status);
    } else {
        HILOGD("get kvStore success");
    }
    HILOGD("end.");
    return status;
}

void DmsBmStorage::TryTwice(const std::function<Status()> &func) const
{
    HILOGD("called.");
    Status status = func();
    if (status == Status::IPC_ERROR) {
        status = func();
        HILOGW("distribute database ipc error and try to call again, result = %{public}d", status);
    }
    HILOGD("end.");
}

uint16_t DmsBmStorage::CreateBundleNameId()
{
    uint16_t len = bundleNameIdTables_.size();
    if (bundleNameIdTables_.size() < MAX_BUNDLEID) {
        bundleNameIdTables_.push_back(true);
        return len + 1;
    } else {
        for (uint16_t i = 0; i < len; ++i) {
            if (!bundleNameIdTables_[i]) {
                bundleNameIdTables_[i] = true;
                return i;
            }
        }
    }
    HILOGE("CreateBundleNameId failed");
    return MAX_BUNDLEID;
}

DmsBundleInfo DmsBmStorage::ConvertToDistributedBundleInfo(const AppExecFwk::BundleInfo &bundleInfo)
{
    DmsBundleInfo distributedBundleInfo;
    distributedBundleInfo.bundleName = bundleInfo.name;
    distributedBundleInfo.versionCode = bundleInfo.versionCode;
    distributedBundleInfo.compatibleVersionCode = bundleInfo.compatibleVersion;
    distributedBundleInfo.versionName = bundleInfo.versionName;
    distributedBundleInfo.minCompatibleVersion = bundleInfo.minCompatibleVersionCode;
    distributedBundleInfo.targetVersionCode = bundleInfo.targetVersion;
    distributedBundleInfo.appId = bundleInfo.appId;
    distributedBundleInfo.enabled = bundleInfo.applicationInfo.enabled;
    distributedBundleInfo.accessTokenId = CreateBundleNameId();
    distributedBundleInfo.updateTime = bundleInfo.updateTime;
    uint8_t pos = 0;
    for (const auto &abilityInfo : bundleInfo.abilityInfos) {
        DmsAbilityInfo dmsAbilityInfo;
        dmsAbilityInfo.abilityName = abilityInfo.name;
        for (const auto &continueType : abilityInfo.continueType) {
            dmsAbilityInfo.continueType.push_back(continueType);
            dmsAbilityInfo.continueTypeId.push_back(pos++);
        }
        distributedBundleInfo.dmsAbilityInfos.push_back(dmsAbilityInfo);
    }
    return distributedBundleInfo;
}

OHOS::sptr<OHOS::AppExecFwk::IBundleMgr> DmsBmStorage::GetBundleMgr()
{
    HILOGD("called.");
    if (bundleMgr_ == nullptr) {
        if (bundleMgr_ == nullptr) {
            auto systemAbilityManager = OHOS::SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
            if (systemAbilityManager == nullptr) {
                HILOGE("GetBundleMgr GetSystemAbilityManager is null");
                return nullptr;
            }
            auto bundleMgrSa = systemAbilityManager->GetSystemAbility(OHOS::BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
            if (bundleMgrSa == nullptr) {
                HILOGE("GetBundleMgr GetSystemAbility is null");
                return nullptr;
            }
            bundleMgr_ = OHOS::iface_cast<AppExecFwk::IBundleMgr>(bundleMgrSa);
        }
    }
    HILOGD("end.");
    return bundleMgr_;
}

int32_t DmsBmStorage::PullOtherDistributedData()
{
    HILOGD("called.");
    std::vector<std::string> networkIdList = DtbschedmgrDeviceInfoStorage::GetInstance().GetNetworkIdList();
    if (networkIdList.empty()) {
        HILOGE("GetNetworkIdList failed");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    Status status = kvStorePtr_->Sync(networkIdList, DistributedKv::SyncMode::PULL);
    if (status != Status::SUCCESS) {
        HILOGE("sync failed, error = %{public}d", status);
    } else {
        HILOGI("sync ok");
    }
    HILOGD("end.");
    return static_cast<int32_t>(status);
}

int32_t DmsBmStorage::PushOtherDistributedData()
{
    HILOGD("called.");
    std::vector<std::string> networkIdList = DtbschedmgrDeviceInfoStorage::GetInstance().GetNetworkIdList();
    if (networkIdList.empty()) {
        HILOGE("GetNetworkIdList failed");
        return INVALID_REMOTE_PARAMETERS_ERR;
    }
    Status status = kvStorePtr_->Sync(networkIdList, DistributedKv::SyncMode::PUSH);
    if (status != Status::SUCCESS) {
        HILOGE("sync failed, error = %{public}d", status);
    } else {
        HILOGI("sync ok");
    }
    HILOGD("end.");
    return static_cast<int32_t>(status);
}

bool IsContinuable(AppExecFwk::BundleInfo bundleInfo)
{
    for (auto abilityInfo : bundleInfo.abilityInfos) {
        if (abilityInfo.continuable == false) {
            HILOGD("is not continuable");
            return false;
        }
    }
    return true;
}

void DmsBmStorage::UpdateDistributedData()
{
    HILOGD("called.");
    auto bundleMgr = DmsBmStorage::GetInstance()->GetBundleMgr();
    if (bundleMgr == nullptr) {
        HILOGE("Get bundleMgr shared_ptr nullptr");
        return;
    }
    std::vector<AppExecFwk::BundleInfo> bundleInfos;
    if (!bundleMgr->GetBundleInfos(FLAGS, bundleInfos, AppExecFwk::Constants::ALL_USERID)) {
        HILOGE("get bundleInfos failed");
        return;
    }
    std::vector<std::string> bundleNames;
    for (const auto &bundleInfo : bundleInfos) {
        if (IsContinuable(bundleInfo)) {
            HILOGD("need push");
            bundleNames.push_back(bundleInfo.name);
        }
    }
    std::map<std::string, DmsBundleInfo> oldDistributedBundleInfos =
        GetAllOldDistributionBundleInfo(bundleNames);

    for (const auto &bundleInfo : bundleInfos) {
        if (bundleInfo.singleton) {
            continue;
        }
        if (oldDistributedBundleInfos.find(bundleInfo.name) != oldDistributedBundleInfos.end()) {
            int32_t updateTime = oldDistributedBundleInfos[bundleInfo.name].updateTime;
            if (updateTime == bundleInfo.updateTime) {
                continue;
            }
        }
        if (!InnerSaveStorageDistributeInfo(ConvertToDistributedBundleInfo(bundleInfo))) {
            HILOGW("UpdateDistributedData SaveStorageDistributeInfo:%{public}s failed", bundleInfo.name.c_str());
        }
    }
    PushOtherDistributedData();
    HILOGD("end.");
}

std::map<std::string, DmsBundleInfo> DmsBmStorage::GetAllOldDistributionBundleInfo(
    const std::vector<std::string> &bundleNames)
{
    HILOGD("called.");
    std::map<std::string, DmsBundleInfo> oldDistributedBundleInfos;
    if (kvStorePtr_ == nullptr) {
        HILOGE("kvStorePtr_ is null");
        return oldDistributedBundleInfos;
    }
    std::string udid;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalUdid(udid);
    if (udid == "") {
        HILOGE("GetLocalUdid failed");
        return oldDistributedBundleInfos;
    }
    Key allEntryKeyPrefix("");
    std::vector<Entry> allEntries;
    Status status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
    if (status != Status::SUCCESS) {
        HILOGE("GetEntries error: %{public}d", status);
        return oldDistributedBundleInfos;
    }
    for (const auto &entry : allEntries) {
        std::string key = entry.key.ToString();
        if (key.find(udid) == std::string::npos) {
            continue;
        }
        std::string value = entry.value.ToString();
        DmsBundleInfo distributedBundleInfo;
        if (distributedBundleInfo.FromJsonString(value)) {
            if (std::find(bundleNames.begin(), bundleNames.end(), distributedBundleInfo.bundleName) ==
                bundleNames.end()) {
                kvStorePtr_->Delete(entry.key);
                continue;
            }
            oldDistributedBundleInfos.emplace(distributedBundleInfo.bundleName, distributedBundleInfo);
        } else {
            HILOGE("DistributionInfo FromJsonString key:%{public}s failed", key.c_str());
        }
    }
    HILOGD("end.");
    return oldDistributedBundleInfos;
}

std::string FindContinueType(const DmsBundleInfo& distributedBundleInfo, uint8_t continueTypeId)
{
    uint32_t pos = 0;
    for (auto dmsAbilityInfo : distributedBundleInfo.dmsAbilityInfos) {
        for (auto continueType : dmsAbilityInfo.continueType) {
            if (pos == continueTypeId) {
                HILOGD("end.");
                return continueType;
            }
            ++pos;
        }
    }
    return "";
}

std::string DmsBmStorage::GetContinueType(const std::string &networkId, std::string &bundleName,
    uint8_t continueTypeId)
{
    HILOGD("networkId: %{public}s,  bundleName: %{public}s,  continueTypeId: %{public}d",
        DnetworkAdapter::AnonymizeNetworkId(networkId).c_str(), bundleName.c_str(), continueTypeId);
    {
        if (!CheckKvStore()) {
            HILOGE("kvStore is nullptr");
            return "";
        }
    }
    std::string udid = DtbschedmgrDeviceInfoStorage::GetInstance().GetUdidByNetworkId(networkId);
    if (udid == "") {
        HILOGE("can not get udid by networkId");
        return "";
    }
    Key allEntryKeyPrefix("");
    std::vector<Entry> allEntries;
    Status status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
    if (status != Status::SUCCESS) {
        HILOGE("GetEntries error: %{public}d", status);
        return "";
    }
    for (auto entry : allEntries) {
        std::string key = entry.key.ToString();
        std::string value =  entry.value.ToString();
        if (key.find(udid) == std::string::npos) {
            continue;
        }
        DmsBundleInfo distributedBundleInfo;
        if (distributedBundleInfo.FromJsonString(value) && distributedBundleInfo.bundleName == bundleName) {
            std::string continueType = FindContinueType(distributedBundleInfo, continueTypeId);
            if (continueType != "") {
                return continueType;
            }
        }
    }
    HILOGW("Can't find continueType");
    return "";
}

std::string FindAbilityName(const DmsBundleInfo& distributedBundleInfo, std::string continueType)
{
    for (auto dmsAbilityInfo : distributedBundleInfo.dmsAbilityInfos) {
        for (auto ele : dmsAbilityInfo.continueType) {
            if (ele == continueType) {
                return dmsAbilityInfo.abilityName;
            }
        }
    }
    return "";
}

std::string DmsBmStorage::GetAbilityName(const std::string &networkId, std::string &bundleName,
    std::string &continueType)
{
    HILOGD("networkId: %{public}s,  bundleName: %{public}s,  continueTypeId: %{public}s",
        DnetworkAdapter::AnonymizeNetworkId(networkId).c_str(), bundleName.c_str(), continueType.c_str());
    {
        if (!CheckKvStore()) {
            HILOGE("kvStore is nullptr");
            return "";
        }
    }
    std::string udid = DtbschedmgrDeviceInfoStorage::GetInstance().GetUdidByNetworkId(networkId);
    if (udid == "") {
        HILOGE("can not get udid by networkId");
        return "";
    }
    Key allEntryKeyPrefix("");
    std::vector<Entry> allEntries;
    Status status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
    if (status != Status::SUCCESS) {
        HILOGE("GetEntries error: %{public}d", status);
        return "";
    }
    for (auto entry : allEntries) {
        std::string key = entry.key.ToString();
        std::string value =  entry.value.ToString();
        if (key.find(udid) == std::string::npos) {
            continue;
        }
        DmsBundleInfo distributedBundleInfo;
        if (distributedBundleInfo.FromJsonString(value) && distributedBundleInfo.bundleName == bundleName) {
            std::string abilityName = FindAbilityName(distributedBundleInfo, continueType);
            if (abilityName != "") {
                return abilityName;
            }
        }
    }
    HILOGW("Can't find abilityName");
    return "";
}

uint8_t FindContinueTypeId(const DmsBundleInfo& distributedBundleInfo, std::string abilityName)
{
    HILOGD("called.");
    uint8_t pos = 0;
    for (auto dmsAbilityInfo : distributedBundleInfo.dmsAbilityInfos) {
        if (dmsAbilityInfo.abilityName == abilityName) {
            return pos;
        }
        ++pos;
    }
    return MAX_CONTINUETYPEID;
}

bool DmsBmStorage::GetContinueTypeId(const std::string bundleName, const std::string &abilityName,
    uint8_t &continueTypeId)
{
    HILOGD("called.");
    {
        if (!CheckKvStore()) {
            HILOGE("kvStore is nullptr");
            return false;
        }
    }
    std::string udid;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalUdid(udid);
    if (udid == "") {
        HILOGE("can not get udid by networkId");
        return false;
    }
    Key allEntryKeyPrefix("");
    std::vector<Entry> allEntries;
    Status status = kvStorePtr_->GetEntries(allEntryKeyPrefix, allEntries);
    if (status != Status::SUCCESS) {
        HILOGE("GetEntries error: %{public}d", status);
        return false;
    }
    for (auto entry : allEntries) {
        std::string key = entry.key.ToString();
        std::string value =  entry.value.ToString();
        if (key.find(udid) == std::string::npos) {
            continue;
        }
        DmsBundleInfo distributedBundleInfo;
        if (distributedBundleInfo.FromJsonString(value) && distributedBundleInfo.bundleName == bundleName) {
            continueTypeId = FindContinueTypeId(distributedBundleInfo, abilityName);
            if (continueTypeId != MAX_CONTINUETYPEID) {
                HILOGD("end.");
                return true;
            }
        }
    }
    HILOGW("Can't find continueTypeId");
    return false;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
