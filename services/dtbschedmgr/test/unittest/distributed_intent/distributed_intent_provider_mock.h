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

#ifndef OHOS_DISTRIBUTED_INTENT_PROVIDER_MOCK_H
#define OHOS_DISTRIBUTED_INTENT_PROVIDER_MOCK_H

#include <gmock/gmock.h>
#include "distributed_intent_provider.h"

namespace OHOS {
namespace DistributedSchedule {

class MockIntentProvider : public IIntentProvider {
public:
    MOCK_METHOD1(GetLocalDeviceId, bool(std::string& networkId));
    MOCK_METHOD0(IsFoundationCall, bool());
    MOCK_METHOD2(CheckPermission, int32_t(uint64_t accessToken, const std::string& permissionName));
    MOCK_METHOD3(GetTargetAbility, bool(const AAFwk::Want& want, AppExecFwk::AbilityInfo& targetAbility,
        bool needQueryExtension));
    MOCK_METHOD2(CheckDeviceSecurityLevel, bool(const std::string& srcDeviceId, const std::string& dstDeviceId));
    MOCK_METHOD2(CheckTargetAbilityVisible, bool(const AppExecFwk::AbilityInfo& targetAbility,
        const CallerInfo& callerInfo));
    MOCK_METHOD1(RemoveRemoteObjectFromWant, void(std::shared_ptr<AAFwk::Want> want));
    MOCK_METHOD2(MarkUriPermission, void(AAFwk::Want& want, uint32_t accessToken));
    MOCK_METHOD2(GetCallerAppIdFromBms, bool(int32_t callingUid, std::string& appId));
    MOCK_METHOD2(GetBundleNameListFromBms, bool(int32_t callingUid, std::vector<std::string>& bundleNameList));
    MOCK_METHOD1(GetUdidByNetworkId, std::string(const std::string& networkId));
    MOCK_METHOD0(IsMDMControl, bool());
    MOCK_METHOD2(GetBundleNameFromToken, std::string(uint32_t accessToken, uint32_t specifyTokenId));
    MOCK_METHOD0(GetActiveAccountId, int32_t());
    MOCK_METHOD3(IsMDMControlWithExemption, bool(const std::string& bundleName,
        int32_t serviceType, int32_t accountId));
    MOCK_METHOD1(EncodeWantToBase64, std::string(const AAFwk::Want& want));
    MOCK_METHOD1(DecodeWantFromBase64, std::shared_ptr<AAFwk::Want>(const std::string& base64Str));
    MOCK_METHOD0(IsWifiActive, bool());
    MOCK_METHOD4(SerializeIntentData, int32_t(const AAFwk::Want& want,
        const IntentContext& ctx, std::string& data, const std::string& resultMsg));
    MOCK_METHOD4(DeserializeIntentData, int32_t(const std::string& data,
        AAFwk::Want& want, IntentContext& ctx, std::string& resultMsg));
    MOCK_METHOD4(SerializeResultData, int32_t(int32_t resultCode,
        const std::string& resultMsg, uint64_t requestCode, std::string& data));
    MOCK_METHOD3(ParseDisconnectData, void(const std::string& data,
        int32_t& resultCode, std::string& resultMsg));
    MOCK_METHOD4(ParseResultData, bool(const std::string& data,
        uint64_t& requestCode, int32_t& resultCode, std::string& resultMsg));
    MOCK_METHOD3(ParseIntentVersionProfile, bool(const std::string& profileData,
        int32_t& supportFlag, int32_t& intentVersionId));
};

} // namespace DistributedSchedule
} // namespace OHOS

#endif // OHOS_DISTRIBUTED_INTENT_PROVIDER_MOCK_H
