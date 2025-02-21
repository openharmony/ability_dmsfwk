/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_DISTRIBUTED_BUNDLE_MANANGER_INTERNAL_H
#define OHOS_DISTRIBUTED_BUNDLE_MANANGER_INTERNAL_H

#include <string>
#include <vector>

#include "bundlemgr/bundle_mgr_interface.h"
#include "bundlemgr/bundle_mgr_proxy.h"
#include "distributed_bms_interface.h"
#include "distributed_bms_proxy.h"
#include "mission/distributed_bm_storage.h"
#include "mission/distributed_bundle_info.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
class BundleManagerInternal {
    DECLARE_SINGLE_INSTANCE(BundleManagerInternal);

public:
    static bool GetCallerAppIdFromBms(int32_t callingUid, std::string& appId);
    static bool GetCallerAppIdFromBms(const std::string& bundleName, std::string& appId);
    static bool GetSpecifyBundleNameFromBms(int32_t callingUid, std::string& bundleName);
    static bool GetBundleNameListFromBms(int32_t callingUid, std::vector<std::string>& bundleNameList);
    static bool GetBundleNameListFromBms(int32_t callingUid, std::vector<std::u16string>& u16BundleNameList);
    static bool QueryAbilityInfo(const AAFwk::Want& want, AppExecFwk::AbilityInfo& abilityInfo);
    static bool QueryExtensionAbilityInfo(const AAFwk::Want& want, AppExecFwk::ExtensionAbilityInfo& extensionInfo);
    static void InitAbilityInfoFromExtension(const AppExecFwk::ExtensionAbilityInfo &extensionAbilityInfo,
        AppExecFwk::AbilityInfo &abilityInfo);
    static bool IsSameAppId(const std::string& callerAppId, const std::string& targetBundleName);
    static bool IsSameDeveloperId(const std::string &bundleNameInCurrentSide,
        const std::string &developerId4OtherSide);
    static int32_t GetLocalBundleInfo(const std::string& bundleName, AppExecFwk::BundleInfo &localBundleInfo);
    static int32_t GetLocalBundleInfoV9(const std::string& bundleName, AppExecFwk::BundleInfo &bundleInfo);
    static int32_t GetLocalAbilityInfo(const std::string& bundleName,
        const std::string& moduleName, const std::string& abilityName, AppExecFwk::AbilityInfo &abilityInfo);
    static bool GetContinueBundle4Src(const std::string& srcBundleName,
        std::vector<std::string>& bundleNameList);
    static bool GetAppProvisionInfo4CurrentUser(const std::string& bundleName,
        AppExecFwk::AppProvisionInfo& appProvisionInfo);
    static int32_t CheckRemoteBundleInfoForContinuation(const std::string& dstDeviceId,
        const std::string& bundleName, AppExecFwk::DistributedBundleInfo& remoteBundleInfo);
    static sptr<AppExecFwk::IBundleMgr> GetBundleManager();
    static sptr<AppExecFwk::IDistributedBms> GetDistributedBundleManager();
    static int32_t GetUidFromBms(const std::string& bundleName);
    static bool CheckIfRemoteCanInstall(const AAFwk::Want& want, int32_t missionId);
    static int32_t GetBundleNameId(const std::string& bundleName, uint16_t& bundleNameId);
    static std::string GetContinueType(const std::string &networkId,
        std::string &bundleName, uint8_t continueTypeId);
    static int32_t GetContinueTypeId(const std::string &bundleName,
        const std::string &abilityName, uint8_t &continueTypeId);
    static std::string GetAbilityName(const std::string &networkId, std::string &bundleName, std::string &continueType);
    static int32_t GetBundleNameById(const std::string& networkId,
        const uint16_t& bundleNameId, std::string& bundleName);
    static int32_t GetApplicationInfoFromBms(const std::string& bundleName, const AppExecFwk::BundleFlag flag,
        const int32_t userId, AppExecFwk::ApplicationInfo &appInfo);
    static ErrCode QueryOsAccount(int32_t& activeAccountId);
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif /* OHOS_DISTRIBUTED_BUNDLE_MANANGER_INTERNAL_H */
