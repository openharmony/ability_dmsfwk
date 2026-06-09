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

#ifndef INTENT_PERMISSION_CHECKER_MOCK_H
#define INTENT_PERMISSION_CHECKER_MOCK_H

#include <gmock/gmock.h>
#include <string>
#include "want.h"
#include "ability_info.h"
#include "caller_info.h"
#include "distributed_sched_types.h"
#include "distributed_sched_interface.h"
#include "distributed_intent_error_code.h"
#include "remote_intent_manager.h"

namespace OHOS {
namespace DistributedSchedule {

class IIntentPermissionChecker {
public:
    virtual ~IIntentPermissionChecker() = default;
    virtual int32_t GetCallerInfo(const std::string& localDeviceId, int32_t callerUid,
        uint32_t accessToken, CallerInfo& callerInfo) = 0;
    virtual void SetCallerExtraInfo(CallerInfo& callerInfo, const IntentCallerInfo& intentCallerInfo) = 0;
    virtual int32_t GetAccountInfo(const std::string& remoteNetworkId, const CallerInfo& callerInfo,
        IDistributedSched::AccountInfo& accountInfo) = 0;
    virtual int32_t CheckStartPermission(const std::string& localDeviceId, const AAFwk::Want& want,
        const CallerInfo& callerInfo, const IDistributedSched::AccountInfo& accountInfo,
        uint64_t& dAccessToken) = 0;
    virtual int32_t CheckTargetAbilityPermission(const AAFwk::Want& want,
        const CallerInfo& callerInfo, uint64_t dAccessToken) = 0;
    virtual int32_t CheckBusinessResultPermission(const std::string& srcDeviceId,
        const AAFwk::Want& want, const IntentContext& ctx) = 0;
    virtual int32_t CheckCallerPermission(const AAFwk::Want& want, uint64_t accessToken) = 0;
    virtual bool GetOsAccountData(IDistributedSched::AccountInfo& dmsAccountInfo) = 0;
    virtual bool CheckComponentPermission(const AppExecFwk::AbilityInfo& targetAbility) const = 0;
    virtual bool CheckCustomPermission(const AppExecFwk::AbilityInfo& targetAbility,
        const uint64_t dAccessToken) const = 0;
public:
    static inline std::shared_ptr<IIntentPermissionChecker> permCheckerMock = nullptr;
};

class IntentPermissionCheckerMock : public IIntentPermissionChecker {
public:
    MOCK_METHOD4(GetCallerInfo, int32_t(const std::string& localDeviceId, int32_t callerUid,
        uint32_t accessToken, CallerInfo& callerInfo));
    MOCK_METHOD2(SetCallerExtraInfo, void(CallerInfo& callerInfo, const IntentCallerInfo& intentCallerInfo));
    MOCK_METHOD3(GetAccountInfo, int32_t(const std::string& remoteNetworkId, const CallerInfo& callerInfo,
        IDistributedSched::AccountInfo& accountInfo));
    MOCK_METHOD5(CheckStartPermission, int32_t(const std::string& localDeviceId, const AAFwk::Want& want,
        const CallerInfo& callerInfo, const IDistributedSched::AccountInfo& accountInfo,
        uint64_t& dAccessToken));
    MOCK_METHOD3(CheckTargetAbilityPermission, int32_t(const AAFwk::Want& want,
        const CallerInfo& callerInfo, uint64_t dAccessToken));
    MOCK_METHOD3(CheckBusinessResultPermission, int32_t(const std::string& srcDeviceId,
        const AAFwk::Want& want, const IntentContext& ctx));
    MOCK_METHOD2(CheckCallerPermission, int32_t(const AAFwk::Want& want, uint64_t accessToken));
    MOCK_METHOD1(GetOsAccountData, bool(IDistributedSched::AccountInfo& dmsAccountInfo));
    MOCK_CONST_METHOD1(CheckComponentPermission, bool(const AppExecFwk::AbilityInfo& targetAbility));
    MOCK_CONST_METHOD2(CheckCustomPermission, bool(const AppExecFwk::AbilityInfo& targetAbility,
        const uint64_t dAccessToken));
};

} // namespace DistributedSchedule
} // namespace OHOS
#endif // INTENT_PERMISSION_CHECKER_MOCK_H