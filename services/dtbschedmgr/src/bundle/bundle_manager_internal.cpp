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

#include "bundle/bundle_manager_internal.h"
#include "bundle/bundle_manager_callback_stub.h"
#include "distributed_sched_adapter.h"
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
    std::vector<int32_t> ids;
    ErrCode result = OsAccountManager::QueryActiveOsAccountIds(ids);
    if (result != ERR_OK || ids.empty()) {
        return false;
    }
    int32_t activeAccountId = ids[0];
    appId = bundleMgr->GetAppIdByBundleName(bundleName, activeAccountId);
    HILOGD("appId:%s", appId.c_str());
    return true;
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
        HILOGE("GetBundlesForUid failed, result: %{public}d", result);
        return false;
    }
    return result;
}

bool BundleManagerInternal::GetBundleNameListFromBms(int32_t callingUid,
    std::vector<std::u16string>& u16BundleNameList)
{
    std::vector<std::string> bundleNameList;
    if (!GetBundleNameListFromBms(callingUid, bundleNameList)) {
        HILOGE("GetBundleNameListFromBms failed");
        return false;
    }
    for (const std::string& bundleName : bundleNameList) {
        u16BundleNameList.emplace_back(Str8ToStr16(bundleName));
    }
    return true;
}

bool BundleManagerInternal::QueryAbilityInfo(const AAFwk::Want& want, AppExecFwk::AbilityInfo& abilityInfo)
{
    std::vector<int32_t> ids;
    int32_t ret = OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != ERR_OK || ids.empty()) {
        return false;
    }
    int32_t activeAccountId = ids[0];
    auto bundleMgr = GetBundleManager();
    if (bundleMgr == nullptr) {
        HILOGE("failed to get bms");
        return false;
    }
    bool result = bundleMgr->QueryAbilityInfo(want, AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_DEFAULT
        | AppExecFwk::AbilityInfoFlag::GET_ABILITY_INFO_WITH_PERMISSION, activeAccountId, abilityInfo);
    if (!result) {
        HILOGE("QueryAbilityInfo failed");
        return false;
    }
    return true;
}

bool BundleManagerInternal::QueryExtensionAbilityInfo(const AAFwk::Want& want,
    AppExecFwk::ExtensionAbilityInfo& extensionInfo)
{
    std::vector<int32_t> ids;
    int32_t ret = OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != ERR_OK || ids.empty()) {
        return false;
    }
    int32_t activeAccountId = ids[0];
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
            targetBundleName.c_str(), callerAppId.c_str());
        return false;
    }
    HILOGD("callerAppId:%s", callerAppId.c_str());
    std::string calleeAppId;
    if (!GetCallerAppIdFromBms(targetBundleName, calleeAppId)) {
        HILOGE("GetCallerAppIdFromBms failed");
        return false;
    }
    HILOGD("calleeAppId:%s", calleeAppId.c_str());
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

    std::vector<int32_t> ids;
    ErrCode ret = OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != ERR_OK || ids.empty()) {
        HILOGE("QueryActiveOsAccountIds failed");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t activeAccountId = ids[0];
    if (!bms->GetBundleInfo(bundleName, AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT,
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

    std::vector<int32_t> ids;
    ErrCode ret = OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != ERR_OK || ids.empty()) {
        HILOGE("QueryActiveOsAccountIds failed");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t activeAccountId = ids[0];
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
    HILOGD("bundleName = %{public}s, moduleName = %{public}s, abilityName = %{public}s, deviceId = %{public}s",
        bundleName.c_str(), moduleName.c_str(), abilityName.c_str(), deviceId.c_str());

    if (bundleName.empty() || moduleName.empty() || abilityName.empty() || deviceId.empty()) {
        HILOGE("deviceId or bundle or module or ability name is empty");
        return false;
    }
    auto bms = GetBundleManager();
    if (bms == nullptr) {
        HILOGE("get bundle manager failed");
        return false;
    }

    AAFwk::Want newWant;
    newWant.SetElementName(deviceId, bundleName, abilityName, moduleName);
    std::vector<int32_t> ids;
    ErrCode result = OsAccountManager::QueryActiveOsAccountIds(ids);
    if (result != ERR_OK || ids.empty()) {
        return false;
    }
    int32_t activeAccountId = ids[0];
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
    std::vector<int32_t> ids;
    ErrCode result = OsAccountManager::QueryActiveOsAccountIds(ids);
    if (result != ERR_OK || ids.empty()) {
        return -1;
    }
    int32_t activeAccountId = ids[0];
    return bundleMgr->GetUidByBundleName(bundleName, activeAccountId);
}

int32_t BundleManagerInternal::GetBundleIdFromBms(const std::string& bundleName, uint32_t& accessTokenId)
{
    auto bundleMgr = GetBundleManager();
    if (bundleMgr == nullptr) {
        HILOGE("failed to get bms");
        return INVALID_PARAMETERS_ERR;
    }
    std::vector<int32_t> ids;
    ErrCode result = OsAccountManager::QueryActiveOsAccountIds(ids);
    if (result != ERR_OK || ids.empty()) {
        HILOGE("fild to get userId");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t activeAccountId = ids[0];
    AppExecFwk::ApplicationInfo appInfo;
    int32_t flag = static_cast<int32_t>(AppExecFwk::GetApplicationFlag::GET_APPLICATION_INFO_DEFAULT);
    result = bundleMgr->GetApplicationInfoV9(bundleName, flag, activeAccountId, appInfo);
    if (result != ERR_OK) {
        HILOGE("failed to get appInfo from bms");
        return CAN_NOT_FOUND_ABILITY_ERR;
    }
    accessTokenId = appInfo.accessTokenId;
    return ERR_OK;
}

int32_t BundleManagerInternal::GetBundleNameFromDbms(const std::string& networkId,
    const uint32_t accessTokenId, std::string& bundleName)
{
    auto bundleMgr = GetDistributedBundleManager();
    if (bundleMgr == nullptr) {
        HILOGE("failed to get dbms");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t result = bundleMgr->GetDistributedBundleName(networkId, accessTokenId, bundleName);
    if (result != ERR_OK) {
        HILOGE("failed to get bundleName from dbms");
        return CAN_NOT_FOUND_ABILITY_ERR;
    }
    return ERR_OK;
}
} // namespace DistributedSchedule
} // namespace OHOS
