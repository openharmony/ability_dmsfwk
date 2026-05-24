/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_DISTRIBUTED_INTENT_PROVIDER_H
#define OHOS_DISTRIBUTED_INTENT_PROVIDER_H

#include <string>
#include <vector>
#include <memory>
#include "want.h"
#include "ability_info.h"
#include "caller_info.h"
#include "distributed_sched_types.h"
#include "distributed_sched_interface.h"
#include "parcel.h"

struct IntentContext;

namespace OHOS {
namespace DistributedSchedule {

struct IntentContext;

class IIntentProvider {
public:
    virtual ~IIntentProvider() = default;

    // DtbschedmgrDeviceInfoStorage
    virtual bool GetLocalDeviceId(std::string& networkId) = 0;

    // DistributedSchedPermission
    virtual bool IsFoundationCall() = 0;
    virtual int32_t CheckPermission(uint64_t accessToken, const std::string& permissionName) = 0;
    virtual bool GetTargetAbility(const AAFwk::Want& want, AppExecFwk::AbilityInfo& targetAbility,
        bool needQueryExtension = false) = 0;
    virtual bool CheckDeviceSecurityLevel(const std::string& srcDeviceId, const std::string& dstDeviceId) = 0;
    virtual bool CheckTargetAbilityVisible(const AppExecFwk::AbilityInfo& targetAbility,
        const CallerInfo& callerInfo) = 0;
    virtual void RemoveRemoteObjectFromWant(std::shared_ptr<AAFwk::Want> want) = 0;
    virtual void MarkUriPermission(AAFwk::Want& want, uint32_t accessToken) = 0;

    // BundleManagerInternal
    virtual bool GetCallerAppIdFromBms(int32_t callingUid, std::string& appId) = 0;
    virtual bool GetBundleNameListFromBms(int32_t callingUid, std::vector<std::string>& bundleNameList) = 0;

    // DnetworkAdapter
    virtual std::string GetUdidByNetworkId(const std::string& networkId) = 0;

    // MDM (DmsKvSyncE2E + DistributedSchedService)
    virtual bool IsMDMControl() = 0;
    virtual std::string GetBundleNameFromToken(uint32_t accessToken, uint32_t specifyTokenId) = 0;
    virtual int32_t GetActiveAccountId() = 0;
    virtual bool IsMDMControlWithExemption(const std::string& bundleName,
        int32_t serviceType, int32_t accountId) = 0;

    // DistributedWantV2 (序列化留在主SO)
    virtual std::string EncodeWantToBase64(const AAFwk::Want& want) = 0;
    virtual std::shared_ptr<AAFwk::Want> DecodeWantFromBase64(const std::string& base64Str) = 0;

    // WifiStateAdapter
    virtual bool IsWifiActive() = 0;

    // Serialization (nlohmann/json in main SO)
    virtual int32_t SerializeIntentData(const AAFwk::Want& want,
        const IntentContext& ctx, std::string& data, const std::string& resultMsg = "") = 0;
    virtual int32_t DeserializeIntentData(const std::string& data,
        AAFwk::Want& want, IntentContext& ctx, std::string& resultMsg) = 0;
    virtual int32_t SerializeResultData(int32_t resultCode,
        const std::string& resultMsg, uint64_t requestCode, std::string& data) = 0;
    virtual void ParseDisconnectData(const std::string& data,
        int32_t& resultCode, std::string& resultMsg) = 0;
    virtual bool ParseResultData(const std::string& data,
        uint64_t& requestCode, int32_t& resultCode, std::string& resultMsg) = 0;
    virtual bool ParseIntentVersionProfile(const std::string& profileData,
        int32_t& supportFlag, int32_t& intentVersionId) = 0;
};

} // namespace DistributedSchedule
} // namespace OHOS

#endif // OHOS_DISTRIBUTED_INTENT_PROVIDER_H
