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

#ifndef OHOS_DISTRIBUTED_INTENT_PERMISSION_CHECKER_H
#define OHOS_DISTRIBUTED_INTENT_PERMISSION_CHECKER_H

#include <string>
#include <vector>

#include "single_instance.h"
#include "distributed_want.h"
#include "distributed_intent_error_code.h"
#include "caller_info.h"
#include "distributed_sched_types.h"
#include "distributed_sched_interface.h"

namespace OHOS {
namespace DistributedSchedule {

struct IntentContext;

class IntentPermissionChecker {
    DECLARE_SINGLE_INSTANCE_BASE(IntentPermissionChecker);
public:
    int32_t GetCallerInfo(const std::string& localDeviceId, int32_t callerUid,
        uint32_t accessToken, CallerInfo& callerInfo);
    void SetCallerExtraInfo(CallerInfo& callerInfo, const IntentCallerInfo& intentCallerInfo);
    int32_t GetAccountInfo(const std::string& remoteNetworkId, const CallerInfo& callerInfo,
        IDistributedSched::AccountInfo& accountInfo);
    int32_t CheckStartPermission(const std::string& localDeviceId, const AAFwk::Want& want,
        const CallerInfo& callerInfo, const IDistributedSched::AccountInfo& accountInfo,
        uint64_t& dAccessToken);
    int32_t CheckBusinessResultPermission(const std::string& srcDeviceId,
        const OHOS::AAFwk::Want& want, const IntentContext& ctx);
    int32_t CheckCallerPermission(const AAFwk::Want& want, uint64_t accessToken);
    bool GetOsAccountData(IDistributedSched::AccountInfo& dmsAccountInfo);

private:
    IntentPermissionChecker();
    ~IntentPermissionChecker() = default;

    bool CheckDstSameAccount(const std::string& dstNetworkId,
        const IDistributedSched::AccountInfo& dmsAccountInfo, const CallerInfo& callerInfo, bool isSrc);
    bool CheckComponentPermission(const AppExecFwk::AbilityInfo& targetAbility) const;
    bool CheckCustomPermission(const AppExecFwk::AbilityInfo& targetAbility,
        const uint64_t& dAccessToken) const;
};

} // namespace DistributedSchedule
} // namespace OHOS

#endif // OHOS_DISTRIBUTED_INTENT_PERMISSION_CHECKER_H
