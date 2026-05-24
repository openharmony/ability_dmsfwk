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

#ifndef OHOS_DISTRIBUTED_INTENT_PROVIDER_IMPL_H
#define OHOS_DISTRIBUTED_INTENT_PROVIDER_IMPL_H

#include "distributed_intent_provider.h"

namespace OHOS {
namespace DistributedSchedule {

class DmsIntentProviderImpl : public IIntentProvider {
public:
    bool GetLocalDeviceId(std::string& networkId) override;
    bool IsFoundationCall() override;
    int32_t CheckPermission(uint64_t accessToken, const std::string& permissionName) override;
    bool GetTargetAbility(const AAFwk::Want& want, AppExecFwk::AbilityInfo& targetAbility,
        bool needQueryExtension = false) override;
    bool CheckDeviceSecurityLevel(const std::string& srcDeviceId, const std::string& dstDeviceId) override;
    bool CheckTargetAbilityVisible(const AppExecFwk::AbilityInfo& targetAbility,
        const CallerInfo& callerInfo) override;
    void RemoveRemoteObjectFromWant(std::shared_ptr<AAFwk::Want> want) override;
    void MarkUriPermission(AAFwk::Want& want, uint32_t accessToken) override;
    bool GetCallerAppIdFromBms(int32_t callingUid, std::string& appId) override;
    bool GetBundleNameListFromBms(int32_t callingUid, std::vector<std::string>& bundleNameList) override;
    std::string GetUdidByNetworkId(const std::string& networkId) override;
    bool IsMDMControl() override;
    std::string GetBundleNameFromToken(uint32_t accessToken, uint32_t specifyTokenId) override;
    int32_t GetActiveAccountId() override;
    bool IsMDMControlWithExemption(const std::string& bundleName,
        int32_t serviceType, int32_t accountId) override;
    std::string EncodeWantToBase64(const AAFwk::Want& want) override;
    std::shared_ptr<AAFwk::Want> DecodeWantFromBase64(const std::string& base64Str) override;
    bool IsWifiActive() override;
    int32_t SerializeIntentData(const AAFwk::Want& want,
        const IntentContext& ctx, std::string& data, const std::string& resultMsg) override;
    int32_t DeserializeIntentData(const std::string& data,
        AAFwk::Want& want, IntentContext& ctx, std::string& resultMsg) override;
    int32_t SerializeResultData(int32_t resultCode,
        const std::string& resultMsg, uint64_t requestCode, std::string& data) override;
    void ParseDisconnectData(const std::string& data,
        int32_t& resultCode, std::string& resultMsg) override;
    bool ParseResultData(const std::string& data,
        uint64_t& requestCode, int32_t& resultCode, std::string& resultMsg) override;
    bool ParseIntentVersionProfile(const std::string& profileData,
        int32_t& supportFlag, int32_t& intentVersionId) override;
};

} // namespace DistributedSchedule
} // namespace OHOS

#endif // OHOS_DISTRIBUTED_INTENT_PROVIDER_IMPL_H
