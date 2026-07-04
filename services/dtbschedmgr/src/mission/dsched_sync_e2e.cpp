/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include <iostream>
#include <parameter.h>

#ifdef DMS_CHECK_EDM
#include "application_manager_proxy.h"
#endif
#include "bundle/bundle_manager_internal.h"
#include "dtbschedmgr_log.h"
#include "config_policy_utils.h"
#ifdef DMS_CHECK_EDM
#include "edm_constants.h"
#endif
#include "ipc_skeleton.h"
#include "message_parcel.h"
#include "parameters.h"
#include "securec.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsKvSyncE2E";
const std::string BMS_KV_BASE_DIR = "/data/service/el1/public/database/DistributedSchedule";
const int32_t SLEEP_INTERVAL = 100 * 1000;  // 100ms
const int32_t EL1 = 1;
const int32_t MAX_TIMES = 600;              // 1min
const char DETERMINE_DEVICE_TYPE_KEY[] = "persist.distributed_scene.sys_settings_data_sync";
static const int32_t FORBID_SEND_FORBID_RECV = 0;
static const int32_t ALLOW_SEND_ALLOW_RECV = 1;
const std::string PARAM_DISTRIBUTED_DATAFILES_TRANS_CTRL = "persist.distributed_scene.datafiles_trans_ctrl";
const std::string CONSTRAINT = "constraint.distributed.transmission.outgoing";
constexpr const char *TRANSMISSION_OUTGOING = "constraint.distributed.transmission.outgoing";
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
    HILOGD("called.");
    const char *syncType = "1";
    const int bufferLen = 10;
    char paramOutBuf[bufferLen] = {0};
    int ret = GetParameter(DETERMINE_DEVICE_TYPE_KEY, "", paramOutBuf, bufferLen);
    HILOGD("paramOutBuf: %{public}s, ret: %{public}d", paramOutBuf, ret);
    if (ret > 0 && strncmp(paramOutBuf, syncType, strlen(syncType)) == 0) {
        HILOGI("Determining the e2e device succeeded.");
        isCfgDevices_ = true;
    }

    auto contralType = OHOS::system::GetIntParameter(PARAM_DISTRIBUTED_DATAFILES_TRANS_CTRL,
        ALLOW_SEND_ALLOW_RECV);
    HILOGI("contralType=%{public}d", contralType);
    if (contralType == FORBID_SEND_FORBID_RECV) {
        isForbidSendAndRecv_ = true;
    }
}

bool DmsKvSyncE2E::CheckDeviceCfg()
{
    HILOGD("called.");
    return isCfgDevices_;
}

bool DmsKvSyncE2E::CheckMDMCtrlRule(const std::string &bundleName)
{
    HILOGD("called.");
    return isMDMControl_.load();
}

bool DmsKvSyncE2E::CheckCtrlRule()
{
    HILOGD("called.");
    if (isCfgDevices_ && isForbidSendAndRecv_) {
        HILOGE("The device is a special device and checkCtrlRule fail");
        return false;
    }
    return true;
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
    std::vector<std::string> networkIdList = {networkId};
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
    HILOGD("called.");
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
        HILOGD("get kvStore success");
    } else if (status == DistributedKv::Status::STORE_META_CHANGED) {
        HILOGE("This db meta changed, remove and rebuild it");
        dataManager_.DeleteKvStore(appId_, storeId_, BMS_KV_BASE_DIR + appId_.appId);
    }
    HILOGD("end.");
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

bool DmsKvSyncE2E::QueryMDMControl()
{
#ifdef OS_ACCOUNT_PART
    HILOGI("QueryMDMControl called, isMDMControl: %{public}d", isMDMControl_.load());
    int32_t activeAccountId = 0;
    std::vector<int32_t> ids;
    ErrCode err = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (err != ERR_OK || ids.empty()) {
        HILOGE("QueryActiveOsAccountIds passing param invalid or return error!, err : %{public}d", err);
        return false;
    }
    activeAccountId = ids[0];
    bool isMDMControl = false;
    err = AccountSA::OsAccountManager::CheckOsAccountConstraintEnabled(activeAccountId,  CONSTRAINT, isMDMControl);
    if (err != ERR_OK || ids.empty()) {
        HILOGE("QueryActiveOsAccountIds passing param invalid or return error!, err : %{public}d", err);
        return false;
    }
    isMDMControl_.store(isMDMControl);
#endif
    HILOGI("QueryMDMControl end, isMDMControl: %{public}d.", isMDMControl_.load());
    return isMDMControl_.load();
}

bool DmsKvSyncE2E::IsMDMControl()
{
    HILOGI("isMDMControl: %{public}d.", isMDMControl_.load());
    return isMDMControl_.load();
}

int32_t DmsKvSyncE2E::GetActiveAccountId()
{
#ifdef OS_ACCOUNT_PART
    std::vector<int32_t> ids;
    ErrCode err = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (err == ERR_OK && !ids.empty()) {
        return ids[0];
    }
#endif
    return 0;
}

bool DmsKvSyncE2E::IsMDMControlWithExemption(const std::string &bundleName, int32_t serviceType, int32_t accountId)
{
#ifndef DMS_CHECK_EDM
    HILOGI("DMS_CHECK_EDM not defined, allow all operations");
    return false;
#else
#ifdef OS_ACCOUNT_PART
    HILOGI("IsMDMControlWithExemption called, bundleName: %{public}s, serviceType: %{public}d, accountId: %{public}d",
        GetAnonymStr(bundleName).c_str(), serviceType, accountId);

    std::string appId;
    std::string appIdentifier;
    if (!BundleManagerInternal::GetAppIdAndAppIdentifierFromBms(bundleName, appId, appIdentifier)) {
        HILOGE("GetAppIdAndAppIdentifierFromBms failed for bundleName: %{public}s",
            GetAnonymStr(bundleName).c_str());
        return true;
    }
    HILOGI("Get appId: %{public}s, appIdentifier: %{public}s for bundleName: %{public}s",
        GetAnonymStr(appId).c_str(), GetAnonymStr(appIdentifier).c_str(), GetAnonymStr(bundleName).c_str());

    std::vector<std::string> allowedList = GetAllowedDistributeAbilityConnBundlesStub(serviceType, accountId);
    if (!appIdentifier.empty()) {
        auto idIt = std::find(allowedList.begin(), allowedList.end(), appIdentifier);
        if (idIt != allowedList.end()) {
            HILOGI("AppIdentifier %{public}s is in exemption list, allow access",
                GetAnonymStr(appIdentifier).c_str());
            return false;
        }
    }
    HILOGI("Neither AppId %{public}s nor AppIdentifier %{public}s is in exemption list, block access",
        GetAnonymStr(appId).c_str(), GetAnonymStr(appIdentifier).c_str());
    return true;
#else
    return false;
#endif
#endif
}

void DmsKvSyncE2E::SetMdmControl(bool isMdmControl)
{
    isMDMControl_.store(isMdmControl);
}

void DmsKvSyncE2E::SubscriptionAccount()
{
    const std::set<std::string> constraintSet = { TRANSMISSION_OUTGOING };
    osAccountConstraintSubscriber_ = std::make_shared<AccountConstraintSubscriber>(constraintSet);
    ErrCode constraintsErrCode = OHOS::AccountSA::OsAccountManager
        ::SubscribeOsAccountConstraints(osAccountConstraintSubscriber_);
    HILOGI("osAccountConstraintSubscriber os accouunt done errCode = %{public}d", constraintsErrCode);
}

void DmsKvSyncE2E::UnsubscriptionAccount()
{
    ErrCode constraintsErrCode = OHOS::AccountSA::OsAccountManager
        ::UnsubscribeOsAccountConstraints(osAccountConstraintSubscriber_);
    HILOGI("osAccountConstraintSubscriber os accouunt done errCode = %{public}d", constraintsErrCode);
}

void AccountConstraintSubscriber::OnConstraintChanged(
    const OHOS::AccountSA::OsAccountConstraintStateData &constraintData)
{
    HILOGI("localId: %{private}d, constraint: %{public}s, isEnabled: %{public}d",
        constraintData.localId, constraintData.constraint.c_str(), constraintData.isEnabled);
    DmsKvSyncE2E::GetInstance()->SetMdmControl(constraintData.isEnabled);
}

std::vector<std::string> DmsKvSyncE2E::GetAllowedDistributeAbilityConnBundlesStub(
    int32_t serviceType, int32_t accountId)
{
#ifdef DMS_CHECK_EDM
    HILOGI("GetAllowedDistributeAbilityConnBundlesStub called, serviceType: %{public}d, accountId: %{public}d",
        serviceType, accountId);
    HILOGI("Strict control mode: return empty list, all apps will be blocked");
    if (serviceType != COLLABORATION_SERVICE) {
        HILOGI("ServiceType %{public}d is not COLLABORATION_SERVICE, return empty list", serviceType);
        return {};
    }
#ifdef OS_ACCOUNT_PART

    auto proxy = EDM::ApplicationManagerProxy::GetApplicationManagerProxy();
    if (proxy == nullptr) {
        HILOGE("Failed to get ApplicationManagerProxy");
        return {};
    }
    std::vector<std::string> appIdentifiers;
    int32_t ret = proxy->GetAllowedDistributeAbilityConnBundles(serviceType, accountId, appIdentifiers);
    if (ret != ERR_OK) {
        HILOGE("GetAllowedDistributeAbilityConnBundles failed, ret: %{public}d", ret);
        return {};
    }
    HILOGI("GetAllowedDistributeAbilityConnBundles success, got %{public}zu items", appIdentifiers.size());
    for (const auto& appId : appIdentifiers) {
        HILOGI("Allowed appId: %{public}s", GetAnonymStr(appId).c_str());
    }
    return appIdentifiers;
#else
    HILOGI("OS_ACCOUNT_PART not defined, return empty list");
    return {};
#endif
#else
    HILOGI("DMS_CHECK_EDM not defined, return empty list");
    return {};
#endif
}
}  // namespace DistributedSchedule
}  // namespace OHOS
