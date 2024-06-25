/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "adapter/dnetwork_adapter.h"
#include "bundle/bundle_manager_internal.h"
#include "bundle/bundle_manager_callback_stub.h"
#include "distributed_sched_adapter.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_log.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace AccountSA;
namespace {
const std::string TAG = "BundleManagerInternal";
}
IMPLEMENT_SINGLE_INSTANCE(BundleManagerInternal);
bool BundleManagerInternal::GetCallerAppIdFromBms(int32_t callingUid, std::string& appId)
{
    std::vector<std::string> bundleNameList;
    if (!GetBundleNameListFromBms(callingUid, bundleNameList)) {
        HILOGE("GetBundleNameListFromBms failed");
        return false;
    }
    if (bundleNameList.empty()) {
        HILOGE("bundleNameList empty");
        return false;
    }
    // getting an arbitrary bundlename for they sharing a same appId, here we get the first one
    return GetCallerAppIdFromBms(bundleNameList.front(), appId);
}

bool BundleManagerInternal::GetCallerAppIdFromBms(const std::string& bundleName, std::string& appId)
{
    auto bundleMgr = GetBundleManager();
    if (bundleMgr == nullptr) {
        HILOGE("failed to get bms");
        return false;
    }
    int32_t activeAccountId = 0;
    ErrCode err = QueryOsAccount(activeAccountId);
    if (err != ERR_OK) {
        return false;
    }
    appId = bundleMgr->GetAppIdByBundleName(bundleName, activeAccountId);
    HILOGD("appId:%s", GetAnonymStr(appId).c_str());
    return true;
}

bool BundleManagerInternal::GetSpecifyBundleNameFromBms(int32_t callingUid, std::string& bundleName)
{
    auto bundleMgr = GetBundleManager();
    if (bundleMgr == nullptr) {
        HILOGE("failed to get bms");
        return false;
    }
    bool result = bundleMgr->GetBundleNameForUid(callingUid, bundleName);
    if (!result) {
        HILOGE("Get specify bundle name for uid failed, result: %{public}d", result);
        return false;
    }
    return result;
}

bool BundleManagerInternal::GetBundleNameListFromBms(int32_t callingUid, std::vector<std::string>& bundleNameList)
{
    auto bundleMgr = GetBundleManager();
    if (bundleMgr == nullptr) {
        HILOGE("failed to get bms");
        return false;
    }
    bool result = bundleMgr->GetBundlesForUid(callingUid, bundleNameList);
    if (!result) {
        HILOGE("Get bundle name list for userId which the uid belongs failed, result: %{public}d", result);
        return false;
    }
    return result;
}

bool BundleManagerInternal::GetBundleNameListFromBms(int32_t callingUid,
    std::vector<std::u16string>& u16BundleNameList)
{
    std::vector<std::string> bundleNameList;
    if (!GetBundleNameListFromBms(callingUid, bundleNameList)) {
        HILOGE("Get bundle name list for userId which the uid belongs failed.");
        return false;
    }
    for (const std::string& bundleName : bundleNameList) {
        u16BundleNameList.emplace_back(Str8ToStr16(bundleName));
    }
    return true;
}

bool BundleManagerInternal::QueryAbilityInfo(const AAFwk::Want& want, AppExecFwk::AbilityInfo& abilityInfo)
{
    int32_t activeAccountId = 0;
    ErrCode err = QueryOsAccount(activeAccountId);
    if (err != ERR_OK) {
        return false;
    }
    auto bundleMgr = GetBundleManager();
    if (bundleMgr == nullptr) {
        HILOGE("failed to get bms");
        return false;
    }
    bool result = bundleMgr->QueryAbilityInfo(want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT
        | AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION, activeAccountId, abilityInfo);
    if (!result) {
        HILOGW("QueryAbilityInfo failed");
        return false;
    }
    return true;
}

bool BundleManagerInternal::QueryExtensionAbilityInfo(const AAFwk::Want& want,
    AppExecFwk::ExtensionAbilityInfo& extensionInfo)
{
    int32_t activeAccountId = 0;
    ErrCode err = QueryOsAccount(activeAccountId);
    if (err != ERR_OK) {
        return false;
    }
    auto bundleMgr = GetBundleManager();
    if (bundleMgr == nullptr) {
        HILOGE("failed to get bms");
        return false;
    }
    std::vector<AppExecFwk::ExtensionAbilityInfo> extensionInfos;
    bundleMgr->QueryExtensionAbilityInfos(want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT
        | AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION, activeAccountId, extensionInfos);
    if (extensionInfos.empty()) {
        HILOGE("QueryExtensionAbilityInfo failed.");
        return false;
    }
    extensionInfo = extensionInfos.front();
    if (extensionInfo.bundleName.empty() || extensionInfo.name.empty()) {
        HILOGE("ExtensionAbilityInfo is empty.");
        return false;
    }
    HILOGD("ExtensionAbilityInfo found, name=%{public}s.", extensionInfo.name.c_str());
    return true;
}

void BundleManagerInternal::InitAbilityInfoFromExtension(const AppExecFwk::ExtensionAbilityInfo &extensionAbilityInfo,
    AppExecFwk::AbilityInfo &abilityInfo)
{
    abilityInfo.bundleName = extensionAbilityInfo.bundleName;
    abilityInfo.name = extensionAbilityInfo.name;
    abilityInfo.permissions = extensionAbilityInfo.permissions;
    abilityInfo.visible = extensionAbilityInfo.visible;
}

bool BundleManagerInternal::IsSameAppId(const std::string& callerAppId, const std::string& targetBundleName)
{
    if (targetBundleName.empty() || callerAppId.empty()) {
        HILOGE("targetBundleName:%{public}s or callerAppId:%s is empty",
            targetBundleName.c_str(), GetAnonymStr(callerAppId).c_str());
        return false;
    }
    HILOGD("callerAppId:%s", GetAnonymStr(callerAppId).c_str());
    std::string calleeAppId;
    if (!GetCallerAppIdFromBms(targetBundleName, calleeAppId)) {
        HILOGE("GetCallerAppIdFromBms failed");
        return false;
    }
    HILOGD("calleeAppId:%s", GetAnonymStr(calleeAppId).c_str());
    return callerAppId == calleeAppId;
}

int32_t BundleManagerInternal::GetLocalBundleInfo(const std::string& bundleName,
    AppExecFwk::BundleInfo &localBundleInfo)
{
    auto bms = GetBundleManager();
    if (bms == nullptr) {
        HILOGE("get bundle manager failed");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t activeAccountId = 0;
    ErrCode err = QueryOsAccount(activeAccountId);
    if (err != ERR_OK) {
        return err;
    }
    if (!bms->GetBundleInfo(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_WITH_ABILITIES,
        localBundleInfo, activeAccountId)) {
        HILOGE("get local bundle info failed");
        return INVALID_PARAMETERS_ERR;
    }
    return ERR_OK;
}

int32_t BundleManagerInternal::GetLocalBundleInfoV9(const std::string& bundleName,
    AppExecFwk::BundleInfo &bundleInfo)
{
    auto bms = GetBundleManager();
    if (bms == nullptr) {
        HILOGE("get bundle manager failed");
        return INVALID_PARAMETERS_ERR;
    }

    int32_t activeAccountId = 0;
    ErrCode ret = QueryOsAccount(activeAccountId);
    if (ret != ERR_OK) {
        return ret;
    }
    ret = bms->GetBundleInfoV9(bundleName,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_APPLICATION),
        bundleInfo, activeAccountId);
    if (ret != ERR_OK) {
        HILOGE("get local bundle info failed, ret: %{public}d", ret);
    }
    return ret;
}

int32_t BundleManagerInternal::CheckRemoteBundleInfoForContinuation(const std::string& dstDeviceId,
    const std::string& bundleName, AppExecFwk::DistributedBundleInfo& remoteBundleInfo)
{
    if (bundleName.empty()) {
        HILOGE("bundle name empty");
        return INVALID_PARAMETERS_ERR;
    }
    HILOGI("bundleName: %{public}s", bundleName.c_str());

    auto bms = GetBundleManager();
    if (bms == nullptr) {
        HILOGE("get bundle manager failed");
        return INVALID_PARAMETERS_ERR;
    }

    bool isInstalled = bms->GetDistributedBundleInfo(dstDeviceId, bundleName, remoteBundleInfo);
    if (isInstalled) {
        return ERR_OK;
    }

    AppExecFwk::BundleInfo localBundleInfo;
    if (GetLocalBundleInfo(bundleName, localBundleInfo) != ERR_OK) {
        HILOGE("get local bundle info failed");
        return INVALID_PARAMETERS_ERR;
    }
    if (localBundleInfo.entryInstallationFree) {
        return CONTINUE_REMOTE_UNINSTALLED_SUPPORT_FREEINSTALL;
    }
    return CONTINUE_REMOTE_UNINSTALLED_UNSUPPORT_FREEINSTALL;
}

bool BundleManagerInternal::CheckIfRemoteCanInstall(const AAFwk::Want& want, int32_t missionId)
{
    std::string bundleName = want.GetElement().GetBundleName();
    std::string moduleName = want.GetElement().GetModuleName();
    std::string abilityName = want.GetElement().GetAbilityName();
    std::string deviceId = want.GetElement().GetDeviceID();
    std::string udid = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(deviceId);
    HILOGD("bundleName = %{public}s, moduleName = %{public}s, abilityName = %{public}s, udid = %{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str(), GetAnonymStr(udid).c_str());

    if (bundleName.empty() || moduleName.empty() || abilityName.empty() || udid.empty()) {
        HILOGE("udid or bundle or module or ability name is empty");
        return false;
    }
    auto bms = GetBundleManager();
    if (bms == nullptr) {
        HILOGE("get bundle manager failed");
        return false;
    }

    AAFwk::Want newWant;
    newWant.SetElementName(udid, bundleName, abilityName, moduleName);
    int32_t activeAccountId = 0;
    ErrCode err = QueryOsAccount(activeAccountId);
    if (err != ERR_OK) {
        return false;
    }
    bool ret = bms->CheckAbilityEnableInstall(newWant, missionId, activeAccountId, new DmsBundleManagerCallbackStub());
    if (ret != true) {
        HILOGE("CheckAbilityEnableInstall from bms failed");
    }
    return ret;
}

sptr<AppExecFwk::IBundleMgr> BundleManagerInternal::GetBundleManager()
{
    sptr<ISystemAbilityManager> samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        return nullptr;
    }
    sptr<IRemoteObject> bmsProxy = samgrProxy->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (bmsProxy == nullptr) {
        HILOGE("failed to get bms from samgr");
        return nullptr;
    }
    return iface_cast<AppExecFwk::IBundleMgr>(bmsProxy);
}

sptr<AppExecFwk::IDistributedBms> BundleManagerInternal::GetDistributedBundleManager()
{
    sptr<ISystemAbilityManager> samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("failed to get samgrProxy from dbms");
        return nullptr;
    }
    sptr<IRemoteObject> dbmsProxy = samgrProxy->GetSystemAbility(DISTRIBUTED_BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (dbmsProxy == nullptr) {
        HILOGE("failed to get dbmsProxy from dbms");
        return nullptr;
    }
    return iface_cast<AppExecFwk::IDistributedBms>(dbmsProxy);
}

int32_t BundleManagerInternal::GetUidFromBms(const std::string& bundleName)
{
    auto bundleMgr = GetBundleManager();
    if (bundleMgr == nullptr) {
        HILOGE("failed to get bms");
        return -1;
    }
    int32_t activeAccountId = 0;
    ErrCode err = QueryOsAccount(activeAccountId);
    if (err != ERR_OK) {
        return err;
    }
    return bundleMgr->GetUidByBundleName(bundleName, activeAccountId);
}

int32_t BundleManagerInternal::GetBundleNameId(const std::string& bundleName, uint16_t& bundleNameId)
{
    HILOGD("called.");
    bool ret = DmsBmStorage::GetInstance()->GetBundleNameId(bundleName, bundleNameId);
    HILOGI("bundleNameId: %{public}d end.", bundleNameId);
    if (!ret) {
        HILOGE("can not get bundleNameId by bundleName");
        return CAN_NOT_FOUND_ABILITY_ERR;
    }
    HILOGD("end.");
    return ERR_OK;
}

std::string BundleManagerInternal::GetContinueType(const std::string &networkId,
    std::string &bundleName, uint8_t continueTypeId)
{
    HILOGD("called.");
    std::string continueType = DmsBmStorage::GetInstance()->GetContinueType(networkId, bundleName, continueTypeId);
    HILOGI("continueType: %{public}s end.", continueType.c_str());
    if (continueType == "") {
        HILOGE("can not get continueType!");
    }
    HILOGD("end.");
    return continueType;
}

int32_t BundleManagerInternal::GetContinueTypeId(const std::string &bundleName,
    const std::string &abilityName, uint8_t &continueTypeId)
{
    HILOGD("called.");
    bool ret = DmsBmStorage::GetInstance()->GetContinueTypeId(bundleName, abilityName, continueTypeId);
    HILOGI("ContinueTypeId: %{public}d ", continueTypeId);
    if (!ret) {
        HILOGE("can not get ContinueTypeId!");
        return CAN_NOT_FOUND_ABILITY_ERR;
    }
    HILOGD("end.");
    return ERR_OK;
}

std::string BundleManagerInternal::GetAbilityName(const std::string &networkId,
    std::string &bundleName, std::string &continueType)
{
    HILOGD("called.");
    HILOGI("continueType: %{public}s ", continueType.c_str());
    std::string abilityName = DmsBmStorage::GetInstance()->GetAbilityName(networkId, bundleName, continueType);
    if (abilityName == "") {
        HILOGE("can not get abilityName!");
    }
    HILOGD("end.");
    return abilityName;
}

int32_t BundleManagerInternal::GetBundleNameById(const std::string& networkId,
    const uint16_t& bundleNameId, std::string& bundleName)
{
    HILOGD("called.");
    bool result = DmsBmStorage::GetInstance()->GetDistributedBundleName(networkId, bundleNameId, bundleName);
    if (!result) {
        HILOGE("failed to get bundleName by bundleNameId");
        return CAN_NOT_FOUND_ABILITY_ERR;
    }
    HILOGD("end.");
    return ERR_OK;
}

int32_t BundleManagerInternal::GetApplicationInfoFromBms(const std::string& bundleName,
    const AppExecFwk::BundleFlag flag, const int32_t userId, AppExecFwk::ApplicationInfo &appInfo)
{
    auto bundleMgr = GetBundleManager();
    if (bundleMgr == nullptr) {
        HILOGE("failed to get bms");
        return INVALID_PARAMETERS_ERR;
    }
    std::string identity = IPCSkeleton::ResetCallingIdentity();
    bundleMgr->GetApplicationInfo(bundleName, flag, userId, appInfo);
    IPCSkeleton::SetCallingIdentity(identity);
    return ERR_OK;
}

ErrCode BundleManagerInternal::QueryOsAccount(int32_t& activeAccountId)
{
#ifdef OS_ACCOUNT_PART
    std::vector<int32_t> ids;
    ErrCode err = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (err != ERR_OK || ids.empty()) {
        HILOGE("QueryActiveOsAccountIds passing param invalid or return error!, err : %{public}d", err);
        return INVALID_PARAMETERS_ERR;
    }
    activeAccountId = ids[0];
#endif
    return ERR_OK;
}
} // namespace DistributedSchedule
} // namespace OHOS
