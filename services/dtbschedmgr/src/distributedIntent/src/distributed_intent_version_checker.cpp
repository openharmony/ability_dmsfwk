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

#include "distributed_intent_version_checker.h"

#include "distributed_device_profile_client.h"
#include "distributed_intent_error_code.h"
#include "distributed_intent_provider.h"
#include "dtbschedmgr_log.h"
#include "intent_permission_checker.h"

namespace OHOS {
namespace DistributedSchedule {

namespace {
const std::string TAG = "DistributedIntentVersionChecker";
const std::string INTENT_SERVICE_ID = "distributedIntent";
const std::string INTENT_CHAR_ID = "static_capability";
const std::string SUPPORT_DISTRIBUTED_INTENT = "supportDistributedIntent";
const std::string INTENT_VERSION_ID = "IntentVersionId";
constexpr int32_t MIN_INTENT_VERSION_ID = 1;
}

int32_t DistributedIntentVersionChecker::CheckRemoteDistributedIntentSupport(
    const std::string& remoteDeviceId)
{
    if (remoteDeviceId.empty()) {
        HILOGE("remoteDeviceId is empty");
        return ERR_DI_INVALID_PARAMETER;
    }
    auto* provider = IntentPermissionChecker::GetInstance().GetProvider();
    if (provider == nullptr) {
        HILOGE("provider is null");
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    std::string udid = provider->GetUdidByNetworkId(remoteDeviceId);
    if (udid.empty()) {
        HILOGE("GetUdidByNetworkId failed");
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    std::string profileData;
    int32_t ret = GetIntentProfileFromDP(udid, profileData);
    if (ret != ERR_OK) {
        HILOGE("GetIntentProfileFromDP failed, ret=%{public}d", ret);
        return ERR_DI_VERSION_NOT_COMPATIBLE;
    }
    int32_t intentVersionId = 0;
    if (!ParseIntentSupportInfo(profileData, intentVersionId)) {
        HILOGE("ParseIntentSupportInfo failed");
        return ERR_DI_VERSION_NOT_COMPATIBLE;
    }
    if (intentVersionId < MIN_INTENT_VERSION_ID) {
        HILOGE("remote intentVersionId too low, intentVersionId=%{public}d, required=%{public}d",
            intentVersionId, MIN_INTENT_VERSION_ID);
        return ERR_DI_VERSION_NOT_COMPATIBLE;
    }
    HILOGI("remote device supports distributed intent, intentVersionId=%{public}d", intentVersionId);
    return ERR_DI_OK;
}

int32_t DistributedIntentVersionChecker::GetIntentProfileFromDP(
    const std::string& udid, std::string& profileData)
{
    DistributedDeviceProfile::CharacteristicProfile profile;
    int32_t result = DistributedDeviceProfile::DistributedDeviceProfileClient::GetInstance()
        .GetCharacteristicProfile(udid, INTENT_SERVICE_ID, INTENT_CHAR_ID, profile);
    if (result != ERR_OK) {
        HILOGE("GetCharacteristicProfile failed, result=%{public}d", result);
        return result;
    }
    profileData = profile.GetCharacteristicValue();
    if (profileData.empty()) {
        HILOGE("profileData is empty");
        return ERR_DI_VERSION_NOT_COMPATIBLE;
    }
    return ERR_OK;
}

bool DistributedIntentVersionChecker::ParseIntentSupportInfo(
    const std::string& profileData, int32_t& intentVersionId)
{
    auto* provider = IntentPermissionChecker::GetInstance().GetProvider();
    if (provider == nullptr) {
        HILOGE("provider is null");
        return false;
    }
    int32_t supportFlag = 0;
    if (!provider->ParseIntentVersionProfile(profileData, supportFlag, intentVersionId)) {
        HILOGE("ParseIntentVersionProfile failed");
        return false;
    }
    if (supportFlag != 1) {
        HILOGE("distributed intent not supported, supportFlag=%{public}d", supportFlag);
        return false;
    }
    return true;
}

} // namespace DistributedSchedule
} // namespace OHOS
