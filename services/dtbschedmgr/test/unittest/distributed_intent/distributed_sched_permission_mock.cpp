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
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

int32_t CheckPermission(uint64_t accessToken, const std::string& permission)
{
    if (IDistributedSchedPermission::schedPermMock == nullptr) {
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    return IDistributedSchedPermission::schedPermMock->CheckPermission(accessToken, permission);
}

bool GetTargetAbility(const AAFwk::Want& want, AppExecFwk::AbilityInfo& targetAbility)
{
    if (IDistributedSchedPermission::schedPermMock == nullptr) {
        return false;
    }
    return IDistributedSchedPermission::schedPermMock->GetTargetAbility(want, targetAbility);
}

bool CheckDeviceSecurityLevel(const std::string& srcDeviceId, const std::string& dstDeviceId)
{
    if (IDistributedSchedPermission::schedPermMock == nullptr) {
        return false;
    }
    return IDistributedSchedPermission::schedPermMock->CheckDeviceSecurityLevel(srcDeviceId, dstDeviceId);
}

bool CheckTargetAbilityVisible(const AppExecFwk::AbilityInfo& targetAbility,
    const CallerInfo& callerInfo)
{
    if (IDistributedSchedPermission::schedPermMock == nullptr) {
        return false;
    }
    return IDistributedSchedPermission::schedPermMock->CheckTargetAbilityVisible(targetAbility, callerInfo);
}

bool IsFoundationCall()
{
    if (IDistributedSchedPermission::schedPermMock == nullptr) {
        return false;
    }
    return IDistributedSchedPermission::schedPermMock->IsFoundationCall();
}

} // namespace DistributedSchedule
} // namespace OHOS