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

#include "intent_permission_checker_mock.h"
#include "intent_permission_checker.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

IMPLEMENT_SINGLE_INSTANCE(IntentPermissionChecker);

IntentPermissionChecker::IntentPermissionChecker() {}

int32_t IntentPermissionChecker::GetCallerInfo(const std::string& localDeviceId, int32_t callerUid,
    uint32_t accessToken, CallerInfo& callerInfo)
{
    if (IIntentPermissionChecker::permCheckerMock == nullptr) {
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    return IIntentPermissionChecker::permCheckerMock->GetCallerInfo(localDeviceId, callerUid, accessToken, callerInfo);
}

void IntentPermissionChecker::SetCallerExtraInfo(CallerInfo& callerInfo, const IntentCallerInfo& intentCallerInfo)
{
    if (IIntentPermissionChecker::permCheckerMock != nullptr) {
        IIntentPermissionChecker::permCheckerMock->SetCallerExtraInfo(callerInfo, intentCallerInfo);
    }
}

int32_t IntentPermissionChecker::GetAccountInfo(const std::string& remoteNetworkId,
    const CallerInfo& callerInfo, IDistributedSched::AccountInfo& accountInfo)
{
    if (IIntentPermissionChecker::permCheckerMock == nullptr) {
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    return IIntentPermissionChecker::permCheckerMock->GetAccountInfo(remoteNetworkId, callerInfo, accountInfo);
}

int32_t IntentPermissionChecker::CheckStartPermission(const std::string& localDeviceId,
    const AAFwk::Want& want, const CallerInfo& callerInfo,
    const IDistributedSched::AccountInfo& accountInfo, uint64_t& dAccessToken)
{
    if (IIntentPermissionChecker::permCheckerMock == nullptr) {
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    return IIntentPermissionChecker::permCheckerMock->CheckStartPermission(localDeviceId, want, callerInfo,
        accountInfo, dAccessToken);
}

int32_t IntentPermissionChecker::CheckTargetAbilityPermission(const AAFwk::Want& want,
    const CallerInfo& callerInfo, uint64_t dAccessToken)
{
    if (IIntentPermissionChecker::permCheckerMock == nullptr) {
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    return IIntentPermissionChecker::permCheckerMock->CheckTargetAbilityPermission(want, callerInfo, dAccessToken);
}

int32_t IntentPermissionChecker::CheckBusinessResultPermission(const std::string& srcDeviceId,
    const AAFwk::Want& want, const IntentContext& ctx)
{
    if (IIntentPermissionChecker::permCheckerMock == nullptr) {
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    return IIntentPermissionChecker::permCheckerMock->CheckBusinessResultPermission(srcDeviceId, want, ctx);
}

bool IntentPermissionChecker::CheckComponentPermission(const AppExecFwk::AbilityInfo& targetAbility) const
{
    if (IIntentPermissionChecker::permCheckerMock == nullptr) {
        return false;
    }
    return IIntentPermissionChecker::permCheckerMock->CheckComponentPermission(targetAbility);
}

bool IntentPermissionChecker::CheckCustomPermission(const AppExecFwk::AbilityInfo& targetAbility,
    const uint64_t dAccessToken) const
{
    if (IIntentPermissionChecker::permCheckerMock == nullptr) {
        return false;
    }
    return IIntentPermissionChecker::permCheckerMock->CheckCustomPermission(targetAbility, dAccessToken);
}

} // namespace DistributedSchedule
} // namespace OHOS