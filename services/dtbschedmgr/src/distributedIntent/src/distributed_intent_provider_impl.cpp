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

#include "distributedIntent/distributed_intent_provider_impl.h"

#include "adapter/dnetwork_adapter.h"
#include "bundle/bundle_manager_internal.h"
#include "distributed_intent_error_code.h"
#include "distributed_sched_permission.h"
#include "distributed_sched_service.h"
#include "distributed_sched_utils.h"
#include "distributed_want_v2.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "nlohmann/json.hpp"
#include "remote_intent_manager.h"
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
#include "mission/dsched_sync_e2e.h"
#include "mission/wifi_state_adapter.h"
#endif

namespace OHOS {
namespace DistributedSchedule {

bool DmsIntentProviderImpl::GetLocalDeviceId(std::string& networkId)
{
    return DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(networkId);
}

bool DmsIntentProviderImpl::IsFoundationCall()
{
    return DistributedSchedPermission::GetInstance().IsFoundationCall();
}

int32_t DmsIntentProviderImpl::CheckPermission(uint64_t accessToken, const std::string& permissionName)
{
    return DistributedSchedPermission::GetInstance().CheckPermission(accessToken, permissionName);
}

bool DmsIntentProviderImpl::GetTargetAbility(const AAFwk::Want& want, AppExecFwk::AbilityInfo& targetAbility,
    bool needQueryExtension)
{
    return DistributedSchedPermission::GetInstance().GetTargetAbility(want, targetAbility, needQueryExtension);
}

bool DmsIntentProviderImpl::CheckDeviceSecurityLevel(const std::string& srcDeviceId, const std::string& dstDeviceId)
{
    return DistributedSchedPermission::GetInstance().CheckDeviceSecurityLevel(srcDeviceId, dstDeviceId);
}

bool DmsIntentProviderImpl::CheckTargetAbilityVisible(const AppExecFwk::AbilityInfo& targetAbility,
    const CallerInfo& callerInfo)
{
    return DistributedSchedPermission::GetInstance().CheckTargetAbilityVisible(targetAbility, callerInfo);
}

void DmsIntentProviderImpl::RemoveRemoteObjectFromWant(std::shared_ptr<AAFwk::Want> want)
{
    DistributedSchedPermission::GetInstance().RemoveRemoteObjectFromWant(want);
}

void DmsIntentProviderImpl::MarkUriPermission(AAFwk::Want& want, uint32_t accessToken)
{
    DistributedSchedPermission::GetInstance().MarkUriPermission(want, accessToken);
}

bool DmsIntentProviderImpl::GetCallerAppIdFromBms(int32_t callingUid, std::string& appId)
{
    return BundleManagerInternal::GetCallerAppIdFromBms(callingUid, appId);
}

bool DmsIntentProviderImpl::GetBundleNameListFromBms(int32_t callingUid, std::vector<std::string>& bundleNameList)
{
    return BundleManagerInternal::GetBundleNameListFromBms(callingUid, bundleNameList);
}

std::string DmsIntentProviderImpl::GetUdidByNetworkId(const std::string& networkId)
{
    return DnetworkAdapter::GetInstance()->GetUdidByNetworkId(networkId);
}

bool DmsIntentProviderImpl::IsMDMControl()
{
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    return DmsKvSyncE2E::GetInstance()->IsMDMControl();
#else
    return false;
#endif
}

std::string DmsIntentProviderImpl::GetBundleNameFromToken(uint32_t accessToken, uint32_t specifyTokenId)
{
    return DistributedSchedService::GetInstance().GetBundleNameFromToken(accessToken, specifyTokenId);
}

int32_t DmsIntentProviderImpl::GetActiveAccountId()
{
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    return DmsKvSyncE2E::GetInstance()->GetActiveAccountId();
#else
    return -1;
#endif
}

bool DmsIntentProviderImpl::IsMDMControlWithExemption(const std::string& bundleName,
    int32_t serviceType, int32_t accountId)
{
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    return DmsKvSyncE2E::GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
#else
    return false;
#endif
}

std::string DmsIntentProviderImpl::EncodeWantToBase64(const AAFwk::Want& want)
{
    DistributedWantV2 distributedWant(want);
    OHOS::Parcel parcel;
    if (!distributedWant.Marshalling(parcel)) {
        return "";
    }
    return ParcelToBase64Str(parcel);
}

std::shared_ptr<AAFwk::Want> DmsIntentProviderImpl::DecodeWantFromBase64(const std::string& base64Str)
{
    std::string decodedData = Base64Decode(base64Str);
    if (decodedData.empty()) {
        return nullptr;
    }
    OHOS::Parcel parcel;
    parcel.WriteBuffer(decodedData.data(), decodedData.size());
    DistributedWantV2* distributedWant = DistributedWantV2::Unmarshalling(parcel);
    if (distributedWant == nullptr) {
        return nullptr;
    }
    auto aafwkWant = distributedWant->ToWant();
    delete distributedWant;
    return aafwkWant;
}

bool DmsIntentProviderImpl::IsWifiActive()
{
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    return WifiStateAdapter::GetInstance().IsWifiActive();
#else
    return false;
#endif
}

int32_t DmsIntentProviderImpl::SerializeIntentData(const AAFwk::Want& want,
    const IntentContext& ctx, std::string& data, const std::string& resultMsg)
{
    std::string wantBase64 = EncodeWantToBase64(want);
    nlohmann::json root;
    root["wantData"] = wantBase64;
    root["requestCode"] = ctx.requestCode;
    root["uid"] = ctx.callerInfo.uid;
    root["pid"] = ctx.callerInfo.pid;
    root["callerType"] = ctx.callerInfo.callerType;
    root["sourceDeviceId"] = ctx.callerInfo.sourceDeviceId;
    root["duid"] = ctx.callerInfo.duid;
    root["callerAppId"] = ctx.callerInfo.callerAppId;
    root["bundleNames"] = ctx.callerInfo.bundleNames;
    root["dmsVersion"] = ctx.callerInfo.dmsVersion;
    root["accessToken"] = ctx.callerInfo.accessToken;
    root["extraInfoJson"] = ctx.callerInfo.extraInfoJson;
    root["accountUserId"] = ctx.accountInfo.userId;
    root["accountActiveAccountId"] = ctx.accountInfo.activeAccountId;
    if (!resultMsg.empty()) {
        root["resultMsg"] = resultMsg;
    }
    data = root.dump();
    return ERR_DI_OK;
}

int32_t DmsIntentProviderImpl::DeserializeIntentData(const std::string& data,
    AAFwk::Want& want, IntentContext& ctx, std::string& resultMsg)
{
    nlohmann::json root = nlohmann::json::parse(data, nullptr, false);
    if (!root.is_object()) {
        return ERR_DI_INVALID_PARAMETER;
    }
    if (!root.contains("requestCode") || !root["requestCode"].is_number()) {
        return ERR_DI_INVALID_PARAMETER;
    }
    ctx.requestCode = root.value("requestCode", (uint64_t)0);
    if (!root.contains("wantData") || !root["wantData"].is_string()) {
        return ERR_DI_INVALID_PARAMETER;
    }
    std::string wantData = root["wantData"].get<std::string>();
    auto aafwkWant = DecodeWantFromBase64(wantData);
    if (aafwkWant == nullptr) {
        return ERR_DI_INVALID_PARAMETER;
    }
    want = *aafwkWant;
    ctx.callerInfo.uid = root.value("uid", -1);
    ctx.callerInfo.pid = root.value("pid", -1);
    ctx.callerInfo.callerType = root.value("callerType", 0);
    ctx.callerInfo.sourceDeviceId = root.value("sourceDeviceId", "");
    ctx.callerInfo.duid = root.value("duid", -1);
    ctx.callerInfo.callerAppId = root.value("callerAppId", "");
    if (root.contains("bundleNames") && root["bundleNames"].is_array()) {
        root["bundleNames"].get_to<std::vector<std::string>>(ctx.callerInfo.bundleNames);
    }
    ctx.callerInfo.dmsVersion = root.value("dmsVersion", -1);
    ctx.callerInfo.accessToken = root.value("accessToken", 0u);
    if (root.contains("extraInfoJson") && root["extraInfoJson"].is_object()) {
        ctx.callerInfo.extraInfoJson = root["extraInfoJson"];
    }
    ctx.accountInfo.userId = root.value("accountUserId", -1);
    ctx.accountInfo.activeAccountId = root.value("accountActiveAccountId", "");
    if (root.contains("resultMsg") && root["resultMsg"].is_string()) {
        resultMsg = root.value("resultMsg", "");
    }
    return ERR_DI_OK;
}

int32_t DmsIntentProviderImpl::SerializeResultData(int32_t resultCode,
    const std::string& resultMsg, uint64_t requestCode, std::string& data)
{
    nlohmann::json root;
    root["requestCode"] = requestCode;
    root["result"] = resultCode;
    root["resultMsg"] = resultMsg;
    data = root.dump();
    return ERR_DI_OK;
}

void DmsIntentProviderImpl::ParseDisconnectData(const std::string& data,
    int32_t& resultCode, std::string& resultMsg)
{
    nlohmann::json root = nlohmann::json::parse(data, nullptr, false);
    if (!root.is_object()) {
        return;
    }
    resultCode = root.value("result", resultCode);
    resultMsg = root.value("resultMsg", "");
}

bool DmsIntentProviderImpl::ParseResultData(const std::string& data,
    uint64_t& requestCode, int32_t& resultCode, std::string& resultMsg)
{
    nlohmann::json root = nlohmann::json::parse(data, nullptr, false);
    if (!root.is_object()) {
        return false;
    }
    requestCode = root.value("requestCode", (uint64_t)0);
    resultCode = root.value("result", 0);
    resultMsg = root.value("resultMsg", "");
    return true;
}

bool DmsIntentProviderImpl::ParseIntentVersionProfile(const std::string& profileData,
    int32_t& supportFlag, int32_t& intentVersionId)
{
    nlohmann::json root = nlohmann::json::parse(profileData, nullptr, false);
    if (root.is_discarded() || !root.is_object()) {
        return false;
    }
    if (root.find("supportDistributedIntent") == root.end() ||
        !root.at("supportDistributedIntent").is_number()) {
        return false;
    }
    supportFlag = root.at("supportDistributedIntent").get<int32_t>();
    intentVersionId = root.value("IntentVersionId", 0);
    return true;
}

} // namespace DistributedSchedule
} // namespace OHOS
