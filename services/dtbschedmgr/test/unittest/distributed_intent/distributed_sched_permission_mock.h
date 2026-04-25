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

#ifndef DISTRIBUTED_SCHED_PERMISSION_MOCK_H
#define DISTRIBUTED_SCHED_PERMISSION_MOCK_H

#include <gmock/gmock.h>
#include <string>
#include "want.h"
#include "ability_info.h"
#include "caller_info.h"
#include "distributed_intent_error_code.h"

namespace OHOS {
namespace DistributedSchedule {

class IDistributedSchedPermission {
public:
    virtual ~IDistributedSchedPermission() = default;
    virtual int32_t CheckPermission(uint64_t accessToken, const std::string& permission) = 0;
    virtual bool GetTargetAbility(const AAFwk::Want& want, AppExecFwk::AbilityInfo& targetAbility) = 0;
    virtual bool CheckDeviceSecurityLevel(const std::string& srcDeviceId, const std::string& dstDeviceId) = 0;
    virtual bool CheckTargetAbilityVisible(const AppExecFwk::AbilityInfo& targetAbility,
        const CallerInfo& callerInfo) = 0;
    virtual bool IsFoundationCall() const = 0;
public:
    static inline std::shared_ptr<IDistributedSchedPermission> schedPermMock = nullptr;
};

class DistributedSchedPermissionMock : public IDistributedSchedPermission {
public:
    MOCK_METHOD2(CheckPermission, int32_t(uint64_t accessToken, const std::string& permission));
    MOCK_METHOD2(GetTargetAbility, bool(const AAFwk::Want& want, AppExecFwk::AbilityInfo& targetAbility));
    MOCK_METHOD2(CheckDeviceSecurityLevel, bool(const std::string& srcDeviceId, const std::string& dstDeviceId));
    MOCK_METHOD2(CheckTargetAbilityVisible, bool(const AppExecFwk::AbilityInfo& targetAbility,
        const CallerInfo& callerInfo));
    MOCK_CONST_METHOD0(IsFoundationCall, bool());
};

} // namespace DistributedSchedule
} // namespace OHOS
#endif // DISTRIBUTED_SCHED_PERMISSION_MOCK_H