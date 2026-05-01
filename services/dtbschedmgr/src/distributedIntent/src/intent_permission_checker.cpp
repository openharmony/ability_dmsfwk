/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "intent_permission_checker.h"

#include <vector>
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "distributed_sched_utils.h"
#include "distributed_sched_permission.h"
#include "distributed_intent_error_code.h"
#include "access_token.h"
#include "accesstoken_kit.h"
#include "bundle/bundle_manager_internal.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "dms_constant.h"
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
#include "mission/dsched_sync_e2e.h"
#include "distributed_sched_service.h"
#endif

#include "remote_intent_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "IntentPermissionChecker";
const std::string DMS_INTENT_VERSION_ID = "dmsIntentVersion";
constexpr int32_t DMS_INTENT_VERSION = 7;
const std::string PERMISSION_EXECUTE_INSIGHT_INTENT = "ohos.permission.EXECUTE_INSIGHT_INTENT";
const std::string PERMISSION_EXECUTE_DISTRIBUTED_INTENT = "ohos.permission.EXECUTE_DISTRIBUTED_INTENT";
const std::string PERMISSION_START_ABILITIES_FROM_BACKGROUND = "ohos.permission.START_ABILITIES_FROM_BACKGROUND";
const std::string INSIGHT_INTENT_EXECUTE_PARAM_MODE = "ohos.insightIntent.executeParam.mode";
constexpr int32_t EXECUTE_MODE_UI_ABILITY_BACKGROUND = 1;

#ifdef DMSFWK_SAME_ACCOUNT
bool CheckIsSameAccountByBundle(DistributedHardware::DmAccessCaller& dmSrcCaller,
    const DistributedHardware::DmAccessCallee& dmDstCallee, const CallerInfo& callerInfo, bool isSink)
{
    for (const auto& bundleName : callerInfo.bundleNames) {
        dmSrcCaller.pkgName = bundleName;
        HILOGI("dmSrcCaller networkId %{public}s, accountId %{public}s, userId %{public}s, pkgName %{public}s; "
            "dmDstCallee networkId %{public}s.", GetAnonymStr(dmSrcCaller.networkId).c_str(),
            GetAnonymStr(dmSrcCaller.accountId).c_str(), GetAnonymInt32(dmSrcCaller.userId).c_str(),
            dmSrcCaller.pkgName.c_str(), GetAnonymStr(dmDstCallee.networkId).c_str());
        bool isSameAccount = false;
        if (isSink) {
            isSameAccount = DistributedHardware::DeviceManager::GetInstance()
                .CheckSinkIsSameAccount(dmSrcCaller, dmDstCallee);
        } else {
            isSameAccount = DistributedHardware::DeviceManager::GetInstance()
                .CheckSrcIsSameAccount(dmSrcCaller, dmDstCallee);
        }
        if (isSameAccount) {
            return true;
        }
    }
    return false;
}
#endif
}

IMPLEMENT_SINGLE_INSTANCE(IntentPermissionChecker);

IntentPermissionChecker::IntentPermissionChecker()
{
    HILOGI("IntentPermissionChecker construct");
}

int32_t IntentPermissionChecker::GetCallerInfo(const std::string& localDeviceId, int32_t callerUid,
    uint32_t accessToken, CallerInfo& callerInfo)
{
    callerInfo.sourceDeviceId = localDeviceId;
    callerInfo.uid = callerUid;
    callerInfo.accessToken = accessToken;
    if (!BundleManagerInternal::GetCallerAppIdFromBms(callerInfo.uid, callerInfo.callerAppId)) {
        HILOGE("GetCallerAppIdFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    if (!BundleManagerInternal::GetBundleNameListFromBms(callerInfo.uid, callerInfo.bundleNames)) {
        HILOGE("GetBundleNameListFromBms failed");
        return INVALID_PARAMETERS_ERR;
    }
    callerInfo.extraInfoJson[DMS_INTENT_VERSION_ID] = DMS_INTENT_VERSION;
    return ERR_OK;
}

void IntentPermissionChecker::SetCallerExtraInfo(CallerInfo& callerInfo,
    const IntentCallerInfo& intentCallerInfo)
{
    HILOGI("called");
    uint32_t accessToken = intentCallerInfo.accessToken;
    if (intentCallerInfo.specifyTokenId != 0) {
        accessToken = intentCallerInfo.specifyTokenId;
        callerInfo.accessToken = intentCallerInfo.specifyTokenId;
    }
    callerInfo.extraInfoJson[Constants::IS_CALLER_SYSAPP] = false;
    auto tokenType = Security::AccessToken::AccessTokenKit::GetTokenTypeFlag(accessToken);
    if (tokenType == Security::AccessToken::ATokenTypeEnum::TOKEN_HAP) {
        Security::AccessToken::HapTokenInfo hapInfo;
        auto ret = Security::AccessToken::AccessTokenKit::GetHapTokenInfo(accessToken, hapInfo);
        if (ret != Security::AccessToken::AccessTokenKitRet::RET_SUCCESS) {
            HILOGI("get hap tokenInfo failed, ret: %{public}d", ret);
            return;
        }
        callerInfo.bundleNames.clear();
        callerInfo.bundleNames.push_back(hapInfo.bundleName);
        uint64_t fullTokenId = (static_cast<uint64_t>(hapInfo.tokenAttr) << Constants::TOKEN_ID_BIT_SIZE) + accessToken;
        bool isSysApp = Security::AccessToken::AccessTokenKit::IsSystemAppByFullTokenID(fullTokenId);
        callerInfo.extraInfoJson[Constants::IS_CALLER_SYSAPP] = isSysApp;
        HILOGI("bundleName: %{public}s, isSysApp: %{public}d", hapInfo.bundleName.c_str(), isSysApp);
    }
}

bool IntentPermissionChecker::GetOsAccountData(IDistributedSched::AccountInfo& dmsAccountInfo)
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
        HILOGE("Get accountId from Ohos account info fail, ret: %{public}d", ret);
        return false;
    }
    dmsAccountInfo.activeAccountId = osAccountInfo.uid_;
    HILOGI("Get caller dmsAccountInfo OK, accountId %{public}s, userId %{public}s.",
        GetAnonymStr(dmsAccountInfo.activeAccountId).c_str(), GetAnonymInt32(dmsAccountInfo.userId).c_str());
#endif
    return true;
}

bool IntentPermissionChecker::CheckDstSameAccount(const std::string& dstNetworkId,
    const IDistributedSched::AccountInfo& dmsAccountInfo, const CallerInfo& callerInfo, bool isSrc)
{
#ifdef DMSFWK_SAME_ACCOUNT
    HILOGI("called");
    DistributedHardware::DmAccessCaller dmSrcCaller = {
        .accountId = dmsAccountInfo.activeAccountId,
        .networkId = callerInfo.sourceDeviceId,
        .userId = dmsAccountInfo.userId,
        .tokenId = callerInfo.accessToken,
    };
    DistributedHardware::DmAccessCallee dmDstCallee = {
        .networkId = dstNetworkId,
        .peerId = "",
    };
#ifdef OS_ACCOUNT_PART
    if (!isSrc) {
        IDistributedSched::AccountInfo dstAccountInfo;
        if (!GetOsAccountData(dstAccountInfo)) {
            HILOGE("Get Os accountId and userId fail.");
            return false;
        }
        dmDstCallee.accountId = dstAccountInfo.activeAccountId;
        dmDstCallee.userId = dstAccountInfo.userId;
        HILOGI("calleeAccountId: %{public}s, callerUserId: %{public}d",
            GetAnonymStr(dmDstCallee.accountId).c_str(), dmDstCallee.userId);
        return CheckIsSameAccountByBundle(dmSrcCaller, dmDstCallee, callerInfo, true);
    }
#endif
    return CheckIsSameAccountByBundle(dmSrcCaller, dmDstCallee, callerInfo, !isSrc);
#else // DMSFWK_SAME_ACCOUNT
    HILOGI("Not support remote same account check.");
    return false;
#endif // DMSFWK_SAME_ACCOUNT
}

int32_t IntentPermissionChecker::GetAccountInfo(const std::string& remoteNetworkId,
    const CallerInfo& callerInfo, IDistributedSched::AccountInfo& accountInfo)
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
        return ERR_DI_INVALID_PARAMETER;
    }

    if (!CheckDstSameAccount(remoteNetworkId, accountInfo, callerInfo, true)) {
        HILOGE("CheckDstSameAccount fail");
        return ERR_DI_INVALID_PARAMETER;
    }
    return ERR_OK;
}

int32_t IntentPermissionChecker::CheckCallerPermission(const AAFwk::Want& want, uint64_t accessToken)
{
    if (DistributedSchedPermission::GetInstance().CheckPermission(
        accessToken, PERMISSION_EXECUTE_DISTRIBUTED_INTENT) != ERR_DI_OK) {
        HILOGE("CheckPermission EXECUTE_DISTRIBUTED_INTENT failed");
        return ERR_DI_PERMISSION_DENIED;
    }
    if (DistributedSchedPermission::GetInstance().CheckPermission(
        accessToken, PERMISSION_EXECUTE_INSIGHT_INTENT) != ERR_DI_OK) {
        HILOGE("CheckPermission EXECUTE_INSIGHT_INTENT failed");
        return ERR_DI_PERMISSION_DENIED;
    }
    int32_t executeMode = want.GetIntParam(INSIGHT_INTENT_EXECUTE_PARAM_MODE, -1);
    if (executeMode == EXECUTE_MODE_UI_ABILITY_BACKGROUND) {
        if (DistributedSchedPermission::GetInstance().CheckPermission(
            accessToken, PERMISSION_START_ABILITIES_FROM_BACKGROUND) != ERR_DI_OK) {
            HILOGE("CheckPermission START_ABILITIES_FROM_BACKGROUND failed");
            return ERR_DI_PERMISSION_DENIED;
        }
    }
    HILOGI("CheckCallerPermission success");
    return ERR_DI_OK;
}

bool IntentPermissionChecker::CheckComponentPermission(
    const AppExecFwk::AbilityInfo& targetAbility) const
{
    if (!targetAbility.visible) {
        HILOGE("target ability is not visible, permission denied");
        return false;
    }
    return true;
}

bool IntentPermissionChecker::CheckCustomPermission(
    const AppExecFwk::AbilityInfo& targetAbility, const uint64_t& dAccessToken) const
{
    const auto& permissions = targetAbility.permissions;
    if (permissions.empty()) {
        HILOGI("no need any permission, so granted!");
        return true;
    }
    for (const auto& permission : permissions) {
        if (permission.empty()) {
            continue;
        }
        int32_t result = Security::AccessToken::AccessTokenKit::VerifyAccessToken(dAccessToken, permission);
        if (result == Security::AccessToken::PermissionState::PERMISSION_DENIED) {
            HILOGI("permission:%{public}s denied!", permission.c_str());
            return false;
        }
        HILOGI("permission:%{public}s matched!", permission.c_str());
    }
    return true;
}

int32_t IntentPermissionChecker::CheckStartPermission(const std::string& localDeviceId,
    const AAFwk::Want& want, const CallerInfo& callerInfo,
    const IDistributedSched::AccountInfo& accountInfo, uint64_t& dAccessToken)
{
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    CHECK_MDM_CONTROL_BY_TOKEN(callerInfo.accessToken, 0, COLLABORATION_SERVICE);
#endif
    if (!CheckDstSameAccount(localDeviceId, accountInfo, callerInfo, false)) {
        HILOGE("CheckDstSameAccount fail");
        return ERR_DI_PERMISSION_DENIED;
    }
    dAccessToken = Security::AccessToken::AccessTokenKit::AllocLocalTokenID(callerInfo.sourceDeviceId,
        callerInfo.accessToken);
    if (dAccessToken == 0) {
        HILOGE("AllocLocalTokenId failed, sourceDeviceId=%{public}s, accessToken=%{private}s",
            GetAnonymStr(callerInfo.sourceDeviceId).c_str(),
            GetAnonymStr(std::to_string(callerInfo.accessToken)).c_str());
        return ERR_DI_PERMISSION_DENIED;
    }
    HILOGI("AllocLocalTokenID success, dAccessToken=%{private}s", GetAnonymStr(std::to_string(dAccessToken)).c_str());
    int32_t ret = CheckCallerPermission(want, dAccessToken);
    if (ret != ERR_DI_OK) {
        return ERR_DI_PERMISSION_DENIED;
    }
    DistributedSchedPermission& permissionInstance = DistributedSchedPermission::GetInstance();
    AppExecFwk::AbilityInfo targetAbility;
    bool result = permissionInstance.GetTargetAbility(want, targetAbility);
    if (!result) {
        HILOGE("can not find the target ability, check by ability manager");
        return ERR_DI_OK;
    }
    HILOGD("target ability info bundleName:%{public}s abilityName:%{public}s visible:%{public}d",
        targetAbility.bundleName.c_str(), targetAbility.name.c_str(), targetAbility.visible);
    if (!targetAbility.visible &&
        !DistributedSchedPermission::GetInstance().CheckDeviceSecurityLevel(callerInfo.sourceDeviceId,
            want.GetElement().GetDeviceID())) {
        HILOGE("check device security level failed!");
        return ERR_DI_PERMISSION_DENIED;
    }
    if (!DistributedSchedPermission::GetInstance().CheckTargetAbilityVisible(targetAbility, callerInfo)) {
        HILOGE("target ability is not visible and has no PERMISSION_START_INVISIBLE_ABILITY, permission denied");
        return ERR_DI_PERMISSION_DENIED;
    }
    if (!CheckCustomPermission(targetAbility, dAccessToken)) {
        HILOGE("CheckCustomPermission denied");
        return ERR_DI_PERMISSION_DENIED;
    }
    HILOGI("CheckStartPermission success");
    return ERR_DI_OK;
}

int32_t IntentPermissionChecker::CheckBusinessResultPermission(const std::string& srcDeviceId,
    const OHOS::AAFwk::Want& want, const IntentContext& ctx)
{
    if (srcDeviceId != ctx.callerInfo.sourceDeviceId) {
        HILOGE("Device ID mismatch: session=%{public}s, payload=%{public}s",
            GetAnonymStr(srcDeviceId).c_str(), GetAnonymStr(ctx.callerInfo.sourceDeviceId).c_str());
        return ERR_DI_PERMISSION_DENIED;
    }

#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    CHECK_MDM_CONTROL_BY_TOKEN(ctx.callerInfo.accessToken, 0, COLLABORATION_SERVICE);
#endif

    std::string localDeviceId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId)) {
        HILOGE("GetLocalDeviceId failed");
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    std::string targetDeviceId = want.GetElement().GetDeviceID();
    if (targetDeviceId.empty() || targetDeviceId != localDeviceId) {
        HILOGE("Target device is not local device");
        return ERR_DI_PERMISSION_DENIED;
    }

    if (!CheckDstSameAccount(localDeviceId, ctx.accountInfo, ctx.callerInfo, false)) {
        HILOGE("CheckDstSameAccount fail");
        return ERR_DI_PERMISSION_DENIED;
    }

    HILOGI("CheckBusinessResultPermission success");
    return ERR_DI_OK;
}

} // namespace DistributedSchedule
} // namespace OHOS
