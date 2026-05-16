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

#include "distributed_sched_permission_mock.h"
#include "distributed_sched_permission.h"
#include "distributed_intent_error_code.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

int32_t DistributedSchedPermission::CheckPermission(uint64_t accessToken, const std::string& permissionName) const
{
    if (IDistributedSchedPermission::schedPermMock == nullptr) {
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    return IDistributedSchedPermission::schedPermMock->CheckPermission(accessToken, permissionName);
}

bool DistributedSchedPermission::GetTargetAbility(const AAFwk::Want& want,
    AppExecFwk::AbilityInfo& targetAbility, bool needQueryExtension) const
{
    if (IDistributedSchedPermission::schedPermMock == nullptr) {
        return false;
    }
    return IDistributedSchedPermission::schedPermMock->GetTargetAbility(want, targetAbility);
}

bool DistributedSchedPermission::CheckDeviceSecurityLevel(const std::string& srcDeviceId,
    const std::string& dstDeviceId) const
{
    if (IDistributedSchedPermission::schedPermMock == nullptr) {
        return false;
    }
    return IDistributedSchedPermission::schedPermMock->CheckDeviceSecurityLevel(srcDeviceId, dstDeviceId);
}

bool DistributedSchedPermission::CheckTargetAbilityVisible(const AppExecFwk::AbilityInfo& targetAbility,
    const CallerInfo& callerInfo) const
{
    if (IDistributedSchedPermission::schedPermMock == nullptr) {
        return false;
    }
    return IDistributedSchedPermission::schedPermMock->CheckTargetAbilityVisible(targetAbility, callerInfo);
}

} // namespace DistributedSchedule
} // namespace OHOS