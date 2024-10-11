/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "distributed_sched_permission.h"

#include "accesstoken_kit.h"
#include "datetime_ex.h"
#include "device_auth_defines.h"
#include "device_manager.h"
#include "device_security_defines.h"
#include "device_security_info.h"
#include "ipc_skeleton.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "string_wrapper.h"

#include "adapter/dnetwork_adapter.h"
#include "bundle/bundle_manager_internal.h"
#include "caller_info.h"
#include "distributed_sched_adapter.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "json_util.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace OHOS::Security;
using namespace AAFwk;
using namespace DistributedHardware;
namespace {
const std::string FOUNDATION_PROCESS_NAME = "foundation";
const std::string DMS_API_VERSION = "dmsApiVersion";
const std::string DMS_IS_CALLER_BACKGROUND = "dmsIsCallerBackGround";
const std::string DMS_MISSION_ID = "dmsMissionId";
const std::string DMS_VERSION_ID = "dmsVersion";
const std::string PARAMS_URI = "ability.verify.uri";
const std::string PARAMS_STREAM = "ability.params.stream";
const std::string PERMISSION_START_ABILIIES_FROM_BACKGROUND = "ohos.permission.START_ABILIIES_FROM_BACKGROUND";
const std::string PERMISSION_START_ABILITIES_FROM_BACKGROUND = "ohos.permission.START_ABILITIES_FROM_BACKGROUND";
const std::string PERMISSION_START_INVISIBLE_ABILITY = "ohos.permission.START_INVISIBLE_ABILITY";
const std::string DISTRIBUTED_FILES_PATH = "/data/storage/el2/distributedfiles/";
const std::string BUNDLE_NAME_SCENEBOARD = "com.ohos.sceneboard";
constexpr int32_t DEFAULT_DMS_API_VERSION = 9;
const int DEFAULT_DMS_MISSION_ID = -1;
const int FA_MODULE_ALLOW_MIN_API_VERSION = 8;
const int DEFAULT_DEVICE_SECURITY_LEVEL = -1;
}

IMPLEMENT_SINGLE_INSTANCE(DistributedSchedPermission);

void from_json(const nlohmann::json& jsonObject, GroupInfo& groupInfo)
{
    const auto &jsonObjectEnd = jsonObject.end();
    int32_t parseResult = ERR_OK;
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        FIELD_GROUP_NAME,
        groupInfo.groupName,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        FIELD_GROUP_ID,
        groupInfo.groupId,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<std::string>(jsonObject,
        jsonObjectEnd,
        FIELD_GROUP_OWNER,
        groupInfo.groupOwner,
        JsonType::STRING,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        FIELD_GROUP_TYPE,
        groupInfo.groupType,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
    GetValueIfFindKey<int32_t>(jsonObject,
        jsonObjectEnd,
        FIELD_GROUP_VISIBILITY,
        groupInfo.groupVisibility,
        JsonType::NUMBER,
        false,
        parseResult,
        ArrayType::NOT_ARRAY);
}

int32_t DistributedSchedPermission::CheckSendResultPermission(const AAFwk::Want& want, const CallerInfo& callerInfo,
    const AccountInfo& accountInfo, AppExecFwk::AbilityInfo& targetAbility)
{
    // 1.check account access permission in no account networking environment.
    int32_t ret = CheckAccountAccessPermission(callerInfo, accountInfo, targetAbility.bundleName);
    if (ret != ERR_OK) {
        HILOGE("CheckAccountAccessPermission denied or failed!");
        return ret;
    }
    // 2.check component access permission, when the ability is not visible.
    if (!CheckComponentAccessPermission(targetAbility, callerInfo, accountInfo, want)) {
        HILOGE("CheckComponentAccessPermission denied or failed! the callee component do not have permission");
        return DMS_COMPONENT_ACCESS_PERMISSION_DENIED;
    }
    HILOGI("CheckSendResultPermission success!!");
    return ERR_OK;
}

int32_t DistributedSchedPermission::CheckStartPermission(const AAFwk::Want& want, const CallerInfo& callerInfo,
    const AccountInfo& accountInfo, AppExecFwk::AbilityInfo& targetAbility, bool isSameBundle)
{
    // 1.check account access permission in no account networking environment.
    int32_t ret = CheckAccountAccessPermission(callerInfo, accountInfo, targetAbility.bundleName);
    if (ret != ERR_OK) {
        HILOGE("CheckAccountAccessPermission denied or failed!");
        return ret;
    }
    // 2.check start control permissions.
    if (!CheckStartControlPermission(targetAbility, callerInfo, want, isSameBundle)) {
        HILOGE("CheckStartControlPermission denied or failed! the callee component do not have permission");
        return DMS_START_CONTROL_PERMISSION_DENIED;
    }
    HILOGI("CheckDistributedPermission success!");
    return ERR_OK;
}

int32_t DistributedSchedPermission::GetAccountInfo(const std::string& remoteNetworkId,
    const CallerInfo& callerInfo, AccountInfo& accountInfo)
{
    if (remoteNetworkId.empty()) {
        HILOGE("remoteNetworkId is empty");
        return ERR_NULL_OBJECT;
    }
    std::string udid = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(remoteNetworkId);
    if (udid.empty()) {
        HILOGE("udid is empty");
        return ERR_NULL_OBJECT;
    }
    if (!GetOsAccountData(accountInfo)) {
        HILOGE("Get Os accountId and userId fail.");
        return INVALID_PARAMETERS_ERR;
    }

#ifdef DMSFWK_SAME_ACCOUNT
    if (CheckDstSameAccount(remoteNetworkId, accountInfo, callerInfo)) {
        return ERR_OK;
    }
    HILOGI("check same account by DM fail, will try check access Group by hichain");
#endif // DMSFWK_SAME_ACCOUNT

    if (GetRelatedGroups(udid, callerInfo.bundleNames, accountInfo)) {
        return ERR_OK;
    }

    HILOGI("Check access Group by hichain fail, will try check different account ACL by DM.");
    if (CheckAclList(remoteNetworkId, accountInfo, callerInfo)) {
        return ERR_OK;
    }
    HILOGE("Check different account ACL by DM fail.");
    return  INVALID_PARAMETERS_ERR;
}

bool DistributedSchedPermission::GetOsAccountData(AccountInfo& dmsAccountInfo)
{
#ifdef OS_ACCOUNT_PART
    std::vector<int32_t> ids;
    ErrCode ret = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (ret != ERR_OK || ids.empty()) {
        HILOGE("Get userId from active Os AccountIds fail, ret : %{public}d", ret);
        return false;
    }
    dmsAccountInfo.userId = ids[0];

    AccountSA::OhosAccountInfo osAccountInfo;
    ret = AccountSA::OhosAccountKits::GetInstance().GetOhosAccountInfo(osAccountInfo);
    if (ret != 0 || osAccountInfo.uid_ == "") {
        HILOGE("Get accountId from Ohos account info fail, ret: %{public}d.", ret);
        return false;
    }
    dmsAccountInfo.activeAccountId = osAccountInfo.uid_;
    HILOGI("Get caller dmsAccountInfo OK, accountId %{public}s, userId %{public}s.",
        GetAnonymStr(dmsAccountInfo.activeAccountId).c_str(), GetAnonymInt32(dmsAccountInfo.userId).c_str());
#endif
    return true;
}

bool DistributedSchedPermission::CheckDstSameAccount(const std::string& dstNetworkId,
    const AccountInfo& dmsAccountInfo, const CallerInfo& callerInfo)
{
#ifdef DMSFWK_SAME_ACCOUNT
    DmAccessCaller dmSrcCaller = {
        .accountId = dmsAccountInfo.activeAccountId,
        .networkId = callerInfo.sourceDeviceId,
        .userId = dmsAccountInfo.userId,
        .tokenId = callerInfo.accessToken,
    };
    DmAccessCallee dmDstCallee = {
        .networkId = dstNetworkId,
        .peerId = "",
    };
    for (const auto& bundleName : callerInfo.bundleNames) {
        dmSrcCaller.pkgName = bundleName;
        HILOGI("dmSrcCaller networkId %{public}s, accountId %{public}s, userId %{public}s, pkgName %{public}s; "
            "dmDstCallee networkId %{public}s.", GetAnonymStr(dmSrcCaller.networkId).c_str(),
            GetAnonymStr(dmSrcCaller.accountId).c_str(), GetAnonymInt32(dmSrcCaller.userId).c_str(),
            dmSrcCaller.pkgName.c_str(), GetAnonymStr(dmDstCallee.networkId).c_str());
        if (!DeviceManager::GetInstance().CheckIsSameAccount(dmSrcCaller, dmDstCallee)) {
            continue;
        }
        return true;
    }
    return false;
#else // DMSFWK_SAME_ACCOUNT
    HILOGI("Not support remote same account check.");
    return false;
#endif // DMSFWK_SAME_ACCOUNT
}

bool DistributedSchedPermission::CheckAclList(const std::string& dstNetworkId,
    const AccountInfo& dmsAccountInfo, const CallerInfo& callerInfo)
{
    DmAccessCaller dmSrcCaller = {
        .accountId = dmsAccountInfo.activeAccountId,
        .networkId = callerInfo.sourceDeviceId,
        .userId = dmsAccountInfo.userId,
        .tokenId = callerInfo.accessToken,
    };
    DmAccessCallee dmDstCallee = {
        .networkId = dstNetworkId,
        .peerId = "",
    };
    for (const auto& bundleName : callerInfo.bundleNames) {
        dmSrcCaller.pkgName = bundleName;
        HILOGI("dmSrcCaller networkId %{public}s, accountId %{public}s, userId %{public}s, pkgName %{public}s; "
            "dmDstCallee networkId %{public}s.", GetAnonymStr(dmSrcCaller.networkId).c_str(),
            GetAnonymStr(dmSrcCaller.accountId).c_str(), GetAnonymInt32(dmSrcCaller.userId).c_str(),
            dmSrcCaller.pkgName.c_str(), GetAnonymStr(dmDstCallee.networkId).c_str());
        if (!DeviceManager::GetInstance().CheckAccessControl(dmSrcCaller, dmDstCallee)) {
            continue;
        }
        return true;
    }
    return false;
}

bool DistributedSchedPermission::GetRelatedGroups(const std::string& udid,
    const std::vector<std::string>& bundleNames, AccountInfo& accountInfo)
{
    for (const auto& bundleName : bundleNames) {
        std::string returnGroups;
        if (!DistributedSchedAdapter::GetInstance().GetRelatedGroups(udid, bundleName, returnGroups)) {
            continue;
        }
        std::vector<GroupInfo> groupInfos;
        if (!ParseGroupInfos(returnGroups, groupInfos)) {
            continue;
        }
        for (const auto& groupInfo : groupInfos) {
            // check group type is whether (same count or point to point) or not
            if (groupInfo.groupType != GroupType::IDENTICAL_ACCOUNT_GROUP
                && groupInfo.groupType != GroupType::PEER_TO_PEER_GROUP) {
                continue;
            }
            accountInfo.groupIdList.push_back(groupInfo.groupId);
            if (groupInfo.groupType == GroupType::IDENTICAL_ACCOUNT_GROUP
                && accountInfo.accountType != IDistributedSched::SAME_ACCOUNT_TYPE) {
                accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
            }
        }
    }
    if (accountInfo.groupIdList.empty()) {
        HILOGE("groupIdList is empty");
        return false;
    }
    return true;
}

bool DistributedSchedPermission::ParseGroupInfos(const std::string& returnGroupStr, std::vector<GroupInfo>& groupInfos)
{
    nlohmann::json groupInfoJson = nlohmann::json::parse(returnGroupStr, nullptr, false);
    if (groupInfoJson.is_discarded()) {
        HILOGE("returnGroupStr parse failed");
        return false;
    }
    HILOGD("groupInfoJson:%{public}s", groupInfoJson.dump().c_str());
    groupInfos = groupInfoJson.get<std::vector<GroupInfo>>();
    if (groupInfos.empty()) {
        HILOGE("groupInfos is empty");
        return false;
    }
    return true;
}

bool DistributedSchedPermission::GetTargetAbility(const AAFwk::Want& want,
    AppExecFwk::AbilityInfo& targetAbility, bool needQueryExtension) const
{
    if (BundleManagerInternal::QueryAbilityInfo(want, targetAbility)) {
        if (want.GetIntParam(DMS_MISSION_ID, DEFAULT_DMS_MISSION_ID) != DEFAULT_DMS_MISSION_ID &&
            (targetAbility.type == AppExecFwk::AbilityType::SERVICE ||
            targetAbility.type == AppExecFwk::AbilityType::EXTENSION)) {
            HILOGE("StartAbilityForResult can not start service and extension ability");
            return false;
        }
        return true;
    }
    if (needQueryExtension) {
        HILOGI("QueryAbilityInfo failed, try to QueryExtensionAbilityInfo");
        // try to find extension
        AppExecFwk::ExtensionAbilityInfo extensionAbility;
        if (BundleManagerInternal::QueryExtensionAbilityInfo(want, extensionAbility)) {
            // extensionAbilityInfo translates to abilityInfo
            BundleManagerInternal::InitAbilityInfoFromExtension(extensionAbility, targetAbility);
            return true;
        }
    }
    HILOGE("QueryAbilityInfo failed, want bundle name=%{public}s, ability name=%{public}s.",
        want.GetElement().GetBundleName().c_str(), want.GetElement().GetAbilityName().c_str());
    return false;
}

int32_t DistributedSchedPermission::CheckGetCallerPermission(const AAFwk::Want& want, const CallerInfo& callerInfo,
    const AccountInfo& accountInfo, AppExecFwk::AbilityInfo& targetAbility)
{
    // 1.check account access permission in no account networking environment.
    int32_t ret = CheckAccountAccessPermission(callerInfo, accountInfo, targetAbility.bundleName);
    if (ret != ERR_OK) {
        HILOGE("CheckAccountAccessPermission denied or failed!");
        return ret;
    }
    // 2. check call with same appid
    if (!BundleManagerInternal::IsSameAppId(callerInfo.callerAppId, targetAbility.bundleName)) {
        HILOGE("the appId is different, check permission denied!");
        return CALL_PERMISSION_DENIED;
    }
    // 3. check background permission
    if (!CheckBackgroundPermission(targetAbility, callerInfo, want, false)) {
        HILOGE("Check background permission failed!");
        return DMS_BACKGROUND_PERMISSION_DENIED;
    }
    // 4. check device security level
    if (!targetAbility.visible &&
        !CheckDeviceSecurityLevel(callerInfo.sourceDeviceId, want.GetElement().GetDeviceID())) {
        HILOGE("check device security level failed!");
        return CALL_PERMISSION_DENIED;
    }
    HILOGI("CheckGetCallerPermission success!!");
    return ERR_OK;
}

bool DistributedSchedPermission::IsFoundationCall() const
{
    uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
    AccessToken::NativeTokenInfo nativeTokenInfo;
    int32_t result = AccessToken::AccessTokenKit::GetNativeTokenInfo(accessToken, nativeTokenInfo);
    if (result == ERR_OK && nativeTokenInfo.processName == FOUNDATION_PROCESS_NAME) {
        return true;
    }
    HILOGE("not foundation called, processName:%{private}s", nativeTokenInfo.processName.c_str());
    return false;
}

bool DistributedSchedPermission::IsSceneBoardCall() const
{
    int32_t activeAccountId = 0;
#ifdef OS_ACCOUNT_PART
    std::vector<int32_t> ids;
    int32_t errCode = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
    if (errCode != ERR_OK || ids.empty()) {
        HILOGE("QueryActiveOsAccountIds failed.");
        return false;
    }
    activeAccountId = ids[0];
#endif
    AppExecFwk::ApplicationInfo appInfo;
    if (BundleManagerInternal::GetApplicationInfoFromBms(BUNDLE_NAME_SCENEBOARD,
        AppExecFwk::BundleFlag::GET_BUNDLE_DEFAULT, activeAccountId, appInfo) != ERR_OK) {
        HILOGE("get applicationInfo failed.");
        return false;
    }
    auto accessTokenId = IPCSkeleton::GetCallingTokenID();
    if (accessTokenId != appInfo.accessTokenId) {
        HILOGE("not sceneBoard called.");
        return false;
    }
    return true;
}

int32_t DistributedSchedPermission::CheckPermission(uint32_t accessToken, const std::string& permissionName) const
{
    HILOGI("CheckPermission called.");
    if (VerifyPermission(accessToken, permissionName)) {
        return ERR_OK;
    }
    return DMS_PERMISSION_DENIED;
}

int32_t DistributedSchedPermission::CheckPermissionAll(uint32_t accessToken, const std::string& permissionName) const
{
    HILOGI("CheckPermissionAll called.");
    if (VerifyPermission(accessToken, permissionName)) {
        return ERR_OK;
    }
    return DMS_PERMISSION_DENIED;
}

void DistributedSchedPermission::MarkUriPermission(OHOS::AAFwk::Want& want, uint32_t accessToken)
{
    if ((want.GetFlags() & (Want::FLAG_AUTH_READ_URI_PERMISSION | Want::FLAG_AUTH_WRITE_URI_PERMISSION)) == 0) {
        return;
    }
    auto bms = BundleManagerInternal::GetBundleManager();
    if (bms == nullptr) {
        HILOGW("Failed to get bms.");
        return;
    }
    std::vector<std::string> uriVec = want.GetStringArrayParam(PARAMS_STREAM);
    std::string uriStr = want.GetUri().ToString();
    uriVec.emplace_back(uriStr);
    std::vector<std::string> uriVecPermission;
    HILOGI("GrantUriPermission uriVec size: %{public}zu", uriVec.size());
    for (std::string str : uriVec) {
        Uri uri(str);
        if (!IsDistributedFile(uri.GetPath())) {
            continue;
        }
        std::string authority = uri.GetAuthority();
        HILOGI("uri authority is %{public}s.", authority.c_str());
        AppExecFwk::BundleInfo bundleInfo;
        int32_t activeAccountId = 0;
#ifdef OS_ACCOUNT_PART
        std::vector<int32_t> ids;
        int32_t errCode = AccountSA::OsAccountManager::QueryActiveOsAccountIds(ids);
        if (errCode != ERR_OK || ids.empty()) {
            return;
        }
        activeAccountId = ids[0];
#endif
        if (!bms->GetBundleInfo(authority,
            AppExecFwk::BundleFlag::GET_BUNDLE_WITH_EXTENSION_INFO, bundleInfo, activeAccountId)) {
            HILOGW("To fail to get bundle info according to uri.");
            continue;
        }
        if (bundleInfo.applicationInfo.accessTokenId == accessToken) {
            HILOGI("uri token is true.");
            uriVecPermission.emplace_back(str);
        }
    }
    want.SetParam(PARAMS_URI, uriVecPermission);
}

bool DistributedSchedPermission::IsDistributedFile(const std::string& path) const
{
    if (path.compare(0, DISTRIBUTED_FILES_PATH.size(), DISTRIBUTED_FILES_PATH) == 0) {
        return true;
    }
    HILOGE("uri path is false.");
    return false;
}

bool DistributedSchedPermission::VerifyPermission(uint32_t accessToken, const std::string& permissionName) const
{
    int32_t result = AccessToken::AccessTokenKit::VerifyAccessToken(accessToken, permissionName);
    if (result == AccessToken::PermissionState::PERMISSION_DENIED) {
        HILOGE("permission denied, permissionName:%{public}s", permissionName.c_str());
        return false;
    }
    HILOGD("permission matched.");
    return true;
}

int32_t DistributedSchedPermission::CheckAccountAccessPermission(const CallerInfo& callerInfo,
    const AccountInfo& accountInfo, const std::string& targetBundleName)
{
    std::string udid = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(callerInfo.sourceDeviceId);
    std::string dstNetworkId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(dstNetworkId)) {
        HILOGE("GetLocalDeviceId failed");
        return GET_LOCAL_DEVICE_ERR;
    }
    DmAccessCaller dmSrcCaller = {
        .accountId = accountInfo.activeAccountId,
        .pkgName = targetBundleName,
        .networkId = callerInfo.sourceDeviceId,
        .userId = accountInfo.userId,
        .tokenId = callerInfo.accessToken,
    };
    DmAccessCallee dmDstCallee = {
        .networkId = dstNetworkId,
        .peerId = "",
    };
    HILOGI("dmSrcCaller netWorkId %{public}s, accountId %{public}s, userId %{public}s, pkgName %{public}s; "
        "dmDstCallee networkId %{public}s.", GetAnonymStr(dmSrcCaller.networkId).c_str(),
        GetAnonymStr(dmSrcCaller.accountId).c_str(), GetAnonymInt32(dmSrcCaller.userId).c_str(),
        dmSrcCaller.pkgName.c_str(), GetAnonymStr(dmDstCallee.networkId).c_str());

#ifdef DMSFWK_SAME_ACCOUNT
    if (!DeviceManager::GetInstance().CheckIsSameAccount(dmSrcCaller, dmDstCallee)) {
        HILOGE("Check same account ACL by DM fail.");
        return ACCOUNT_NOT_SAME_BY_DM;
    }
    HILOGI("check same account by DM fail, will try check access Group by hichain");
#endif

    if (!DistributedSchedAdapter::GetInstance().CheckAccessToGroup(udid, targetBundleName)) {
        HILOGE("CheckAccessToGroup by HiChain failed.");
        return CHECK_ACCESS_FAILED_BY_HICHAIN;
    }

    HILOGI("Check access Group by hichain fail, will try check different account ACL by DM.");
    if (!DeviceManager::GetInstance().CheckAccessControl(dmSrcCaller, dmDstCallee)) {
        HILOGE("Check different account ACL by DM failed, CheckAccessControl failed.");
        return CHECK_ACCESS_FAILED_BY_DM;
    }
    return ERR_OK;
}

bool DistributedSchedPermission::CheckComponentAccessPermission(const AppExecFwk::AbilityInfo& targetAbility,
    const CallerInfo& callerInfo, const AccountInfo& accountInfo, const AAFwk::Want& want) const
{
    // reject directly when in no account networking environment and target ability is not visible,
    if (!targetAbility.visible) {
        HILOGE("target ability is not visible, permission denied!");
        return false;
    }
    HILOGD("check component permission success");
    return true;
}

bool DistributedSchedPermission::CheckMigrateStartCtrlPer(const AppExecFwk::AbilityInfo& targetAbility,
    const CallerInfo& callerInfo, const AAFwk::Want& want, bool isSameBundle)
{
    std::string bundleName = want.GetBundle();
    // check if continuation with same appid
    HILOGI("Check migration start control permission with same appid enter.");
    if (!targetAbility.visible &&
        !CheckDeviceSecurityLevel(callerInfo.sourceDeviceId, want.GetElement().GetDeviceID())) {
        HILOGE("check device security level failed!");
        return false;
        }
    if (!isSameBundle) {
        return true;
    }
    if (BundleManagerInternal::IsSameAppId(callerInfo.callerAppId, targetAbility.bundleName)) {
        HILOGD("the appId is the same, check migration start control permission success!");
        return true;
    }
    HILOGE("the appId is different in the migration scenario, permission denied!");
    return false;
}

bool DistributedSchedPermission::CheckCollaborateStartCtrlPer(const AppExecFwk::AbilityInfo& targetAbility,
    const CallerInfo& callerInfo, const AAFwk::Want& want) const
{
    HILOGI("Check collaboration start control permission enter.");
    // 1. check background permission
    if (!CheckBackgroundPermission(targetAbility, callerInfo, want, true)) {
        HILOGE("Check background permission failed!");
        return false;
    }
    // 2. check device security level
    if (!targetAbility.visible &&
        !CheckDeviceSecurityLevel(callerInfo.sourceDeviceId, want.GetElement().GetDeviceID())) {
        HILOGE("check device security level failed!");
        return false;
    }
    // 3. check start or connect ability with same appid
    if (BundleManagerInternal::IsSameAppId(callerInfo.callerAppId, targetAbility.bundleName)) {
        HILOGD("the appId is the same, check permission success!");
        return true;
    }
    // 4. check if target ability is not visible and without PERMISSION_START_INVISIBLE_ABILITY
    if (!CheckTargetAbilityVisible(targetAbility, callerInfo)) {
        HILOGE("target ability is not visible and has no PERMISSION_START_INVISIBLE_ABILITY, permission denied!");
        return false;
    }
    // 5. check if service of fa mode can associatedWakeUp
    if (!targetAbility.isStageBasedModel && targetAbility.type == AppExecFwk::AbilityType::SERVICE &&
        !targetAbility.applicationInfo.associatedWakeUp) {
        HILOGE("target ability is service ability(FA) and associatedWakeUp is false, permission denied!");
        return false;
    }
    HILOGD("Check collaboration start control permission success");
    return true;
}

bool DistributedSchedPermission::CheckStartControlPermission(const AppExecFwk::AbilityInfo& targetAbility,
    const CallerInfo& callerInfo, const AAFwk::Want& want, bool isSameBundle)
{
    HILOGD("Check start control permission enter");
    return ((want.GetFlags() & AAFwk::Want::FLAG_ABILITY_CONTINUATION) != 0) ?
        CheckMigrateStartCtrlPer(targetAbility, callerInfo, want, isSameBundle) :
        CheckCollaborateStartCtrlPer(targetAbility, callerInfo, want);
}

bool DistributedSchedPermission::CheckBackgroundPermission(const AppExecFwk::AbilityInfo& targetAbility,
    const CallerInfo& callerInfo, const AAFwk::Want& want, bool needCheckApiVersion) const
{
    if (callerInfo.extraInfoJson.empty() ||
        callerInfo.extraInfoJson.find(DMS_VERSION_ID) == callerInfo.extraInfoJson.end()) {
        HILOGD("the version is low");
        return true;
    }
    AAFwk::Want* remoteWant = const_cast<Want*>(&want);
    bool isCallerBackGround = remoteWant->GetBoolParam(DMS_IS_CALLER_BACKGROUND, true);
    remoteWant->RemoveParam(DMS_IS_CALLER_BACKGROUND);
    if (!isCallerBackGround) {
        HILOGD("the app is foreground");
        return true;
    }
    int apiVersion = remoteWant->GetIntParam(DMS_API_VERSION, DEFAULT_DMS_API_VERSION);
    remoteWant->RemoveParam(DMS_API_VERSION);
    // service in fa mode(API 8) do not need check
    if (needCheckApiVersion && CheckMinApiVersion(targetAbility, apiVersion)) {
        HILOGD("the app is service ability of fa mode and is under api 8");
        return true;
    }
    uint32_t dAccessToken = AccessToken::AccessTokenKit::AllocLocalTokenID(callerInfo.sourceDeviceId,
        callerInfo.accessToken);
    if (dAccessToken == 0) {
        HILOGE("dAccessTokenID is invalid!");
        return false;
    }
    // check if background's ability has PERMISSION_START_ABILITIES_FROM_BACKGROUND
    if (CheckPermission(dAccessToken, PERMISSION_START_ABILITIES_FROM_BACKGROUND) == ERR_OK ||
        CheckPermission(dAccessToken, PERMISSION_START_ABILIIES_FROM_BACKGROUND) == ERR_OK) {
        HILOGD("the app has PERMISSION_START_ABILITIES_FROM_BACKGROUND");
        return true;
    }
    HILOGE("CheckBackgroundPermission failed!");
    return false;
}

bool DistributedSchedPermission::CheckMinApiVersion(const AppExecFwk::AbilityInfo& targetAbility,
    int32_t apiVersion) const
{
    if (!targetAbility.isStageBasedModel && targetAbility.type == AppExecFwk::AbilityType::SERVICE &&
        apiVersion <= FA_MODULE_ALLOW_MIN_API_VERSION) {
        HILOGD("CheckMinApiVersion pass");
        return true;
    }
    return false;
}

bool DistributedSchedPermission::CheckDeviceSecurityLevel(const std::string& srcDeviceId,
    const std::string& dstDeviceId) const
{
    std::string srcUdid = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(srcDeviceId);
    if (srcUdid.empty()) {
        HILOGE("src udid is empty");
        return false;
    }
    std::string dstUdid = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(dstDeviceId);
    if (dstUdid.empty()) {
        HILOGE("dst udid is empty");
        return false;
    }
    int32_t srcDeviceSecurityLevel = GetDeviceSecurityLevel(srcUdid);
    int32_t dstDeviceSecurityLevel = GetDeviceSecurityLevel(dstUdid);
    if (srcDeviceSecurityLevel == DEFAULT_DEVICE_SECURITY_LEVEL ||
        srcDeviceSecurityLevel < dstDeviceSecurityLevel) {
        HILOGE("the device security of source device is lower");
        return false;
    }
    return true;
}

int32_t DistributedSchedPermission::GetDeviceSecurityLevel(const std::string& udid) const
{
    DeviceIdentify devIdentify;
    devIdentify.length = DEVICE_ID_MAX_LEN;
    int32_t ret = memcpy_s(devIdentify.identity, DEVICE_ID_MAX_LEN, udid.c_str(), udid.length());
    if (ret != 0) {
        HILOGE("str copy failed %{public}d", ret);
        return DEFAULT_DEVICE_SECURITY_LEVEL;
    }
    DeviceSecurityInfo *info = nullptr;
    ret = RequestDeviceSecurityInfo(&devIdentify, nullptr, &info);
    if (ret != SUCCESS) {
        HILOGE("request device security info failed %{public}d", ret);
        FreeDeviceSecurityInfo(info);
        info = nullptr;
        return DEFAULT_DEVICE_SECURITY_LEVEL;
    }
    int32_t level = 0;
    ret = GetDeviceSecurityLevelValue(info, &level);
    HILOGD("get device security level, level is %{public}d", level);
    FreeDeviceSecurityInfo(info);
    info = nullptr;
    if (ret != SUCCESS) {
        HILOGE("get device security level failed %{public}d", ret);
        return DEFAULT_DEVICE_SECURITY_LEVEL;
    }
    return level;
}

bool DistributedSchedPermission::CheckTargetAbilityVisible(const AppExecFwk::AbilityInfo& targetAbility,
    const CallerInfo& callerInfo) const
{
    if (targetAbility.visible) {
        HILOGD("Target ability is visible.");
        return true;
    }
    uint32_t dAccessToken = AccessToken::AccessTokenKit::AllocLocalTokenID(callerInfo.sourceDeviceId,
        callerInfo.accessToken);
    if (dAccessToken == 0) {
        HILOGE("dAccessTokenID is invalid!");
        return false;
    }
    if (CheckPermissionAll(dAccessToken, PERMISSION_START_INVISIBLE_ABILITY) != ERR_OK) {
        HILOGE("CheckTargetAbilityVisible failed.");
        return false;
    }
    HILOGD("CheckTargetAbilityVisible passed.");
    return true;
}

void DistributedSchedPermission::RemoveRemoteObjectFromWant(std::shared_ptr<AAFwk::Want> want) const
{
    if (want == nullptr) {
        return;
    }
    WantParams wantParams = want->GetParams();
    std::map<std::string, sptr<IInterface>> params = wantParams.GetParams();
    for (auto param : params) {
        sptr<IInterface> object = param.second;
        IWantParams *wp = IWantParams::Query(object);
        if (wp == nullptr) {
            continue;
        }
        WantParams value = WantParamWrapper::Unbox(wp);
        auto type = value.GetParam(TYPE_PROPERTY);
        AAFwk::IString *typeP = AAFwk::IString::Query(type);
        if (typeP == nullptr) {
            continue;
        }
        std::string typeValue = AAFwk::String::Unbox(typeP);
        if (typeValue == REMOTE_OBJECT) {
            wantParams.Remove(param.first);
        }
    }
    want->SetParams(wantParams);
}
}
}
