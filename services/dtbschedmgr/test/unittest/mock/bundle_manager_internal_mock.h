/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_DISTRIBUTED_BUNDLE_MANANGER_INTERNAL_MOCK_H
#define OHOS_DISTRIBUTED_BUNDLE_MANANGER_INTERNAL_MOCK_H

#include <gmock/gmock.h>

#include "bundle/bundle_manager_internal.h"

namespace OHOS {
namespace DistributedSchedule {
class IBundleManagerInternal {
public:
    virtual ~IBundleManagerInternal() = default;
    virtual bool GetCallerAppIdFromBms(int32_t callingUid, std::string& appId) = 0;
    virtual bool GetCallerAppIdFromBms(const std::string& bundleName, std::string& appId);
    virtual bool GetSpecifyBundleNameFromBms(int32_t callingUid, std::string& bundleName) = 0;
    virtual bool GetBundleNameListFromBms(int32_t callingUid, std::vector<std::string>& bundleNameList) = 0;
    virtual bool GetBundleNameListFromBms(int32_t callingUid, std::vector<std::u16string>& u16BundleNameList) = 0;
    virtual bool QueryAbilityInfo(const AAFwk::Want& want, AppExecFwk::AbilityInfo& abilityInfo) = 0;
    virtual bool QueryExtensionAbilityInfo(const AAFwk::Want& want,
        AppExecFwk::ExtensionAbilityInfo& extensionInfo) = 0;
    virtual void InitAbilityInfoFromExtension(const AppExecFwk::ExtensionAbilityInfo &extensionAbilityInfo,
        AppExecFwk::AbilityInfo &abilityInfo) = 0;
    virtual bool IsSameAppId(const std::string& callerAppId, const std::string& targetBundleName) = 0;
    virtual bool IsSameDeveloperId(const std::string &bundleNameInCurrentSide,
        const std::string &developerId4OtherSide) = 0;
    virtual int32_t GetLocalBundleInfo(const std::string& bundleName, AppExecFwk::BundleInfo &localBundleInfo) = 0;
    virtual int32_t GetLocalBundleInfoV9(const std::string& bundleName, AppExecFwk::BundleInfo &bundleInfo) = 0;
    virtual int32_t GetLocalAbilityInfo(const std::string& bundleName,
        const std::string& moduleName, const std::string& abilityName, AppExecFwk::AbilityInfo &abilityInfo) = 0;
    virtual bool GetContinueBundle4Src(const std::string& srcBundleName,
        std::vector<std::string>& bundleNameList) = 0;
    virtual bool GetAppProvisionInfo4CurrentUser(const std::string& bundleName,
        AppExecFwk::AppProvisionInfo& appProvisionInfo) = 0;
    virtual int32_t CheckRemoteBundleInfoForContinuation(const std::string& dstDeviceId,
        const std::string& bundleName, AppExecFwk::DistributedBundleInfo& remoteBundleInfo) = 0;
    virtual sptr<AppExecFwk::IBundleMgr> GetBundleManager() = 0;
    virtual sptr<AppExecFwk::IDistributedBms> GetDistributedBundleManager() = 0;
    virtual int32_t GetUidFromBms(const std::string& bundleName) = 0;
    virtual bool CheckIfRemoteCanInstall(const AAFwk::Want& want, int32_t missionId) = 0;
    virtual int32_t GetBundleNameId(const std::string& bundleName, uint16_t& bundleNameId) = 0;
    virtual std::string GetContinueType(const std::string &networkId,
        std::string &bundleName, uint8_t continueTypeId) = 0;
    virtual int32_t GetContinueTypeId(const std::string &bundleName,
        const std::string &abilityName, uint8_t &continueTypeId) = 0;
    virtual std::string GetAbilityName(const std::string &, std::string &, std::string &) = 0;
    virtual int32_t GetBundleNameById(const std::string& networkId,
        const uint16_t& bundleNameId, std::string& bundleName) = 0;
    virtual int32_t GetApplicationInfoFromBms(const std::string& bundleName, const AppExecFwk::BundleFlag flag,
        const int32_t userId, AppExecFwk::ApplicationInfo &appInfo) = 0;
    virtual ErrCode QueryOsAccount(int32_t& activeAccountId) = 0;
public:
    static inline std::shared_ptr<IBundleManagerInternal> bundleMgrMock = nullptr;
};

class BundleManagerInternalMock : public IBundleManagerInternal {
public:
    MOCK_METHOD2(GetCallerAppIdFromBms, bool(int32_t callingUid, std::string& appId));
    MOCK_METHOD2(GetCallerAppIdFromBms, bool(const std::string& bundleName, std::string& appId));
    MOCK_METHOD2(GetSpecifyBundleNameFromBms, bool(int32_t callingUid, std::string& bundleName));
    MOCK_METHOD2(GetBundleNameListFromBms, bool(int32_t callingUid, std::vector<std::string>& bundleNameList));
    MOCK_METHOD2(GetBundleNameListFromBms, bool(int32_t callingUid, std::vector<std::u16string>& u16BundleNameList));
    MOCK_METHOD2(QueryAbilityInfo, bool(const AAFwk::Want& want, AppExecFwk::AbilityInfo& abilityInfo));
    MOCK_METHOD2(QueryExtensionAbilityInfo, bool(const AAFwk::Want& want,
        AppExecFwk::ExtensionAbilityInfo& extensionInfo));
    MOCK_METHOD2(InitAbilityInfoFromExtension, void(const AppExecFwk::ExtensionAbilityInfo &extensionAbilityInfo,
        AppExecFwk::AbilityInfo &abilityInfo));
    MOCK_METHOD2(IsSameAppId, bool(const std::string& callerAppId, const std::string& targetBundleName));
    MOCK_METHOD2(IsSameDeveloperId, bool(const std::string &bundleNameInCurrentSide,
        const std::string &developerId4OtherSide));
    MOCK_METHOD2(GetLocalBundleInfo, int32_t(const std::string& bundleName, AppExecFwk::BundleInfo &localBundleInfo));
    MOCK_METHOD2(GetLocalBundleInfoV9, int32_t(const std::string& bundleName, AppExecFwk::BundleInfo &bundleInfo));
    MOCK_METHOD4(GetLocalAbilityInfo, int32_t(const std::string& bundleName,
        const std::string& moduleName, const std::string& abilityName, AppExecFwk::AbilityInfo &abilityInfo));
    MOCK_METHOD2(GetContinueBundle4Src, bool(const std::string& srcBundleName,
        std::vector<std::string>& bundleNameList));
    MOCK_METHOD2(GetAppProvisionInfo4CurrentUser, bool(const std::string& bundleName,
        AppExecFwk::AppProvisionInfo& appProvisionInfo));
    MOCK_METHOD3(CheckRemoteBundleInfoForContinuation, int32_t(const std::string& dstDeviceId,
        const std::string& bundleName, AppExecFwk::DistributedBundleInfo& remoteBundleInfo));
    MOCK_METHOD0(GetBundleManager, sptr<AppExecFwk::IBundleMgr>());
    MOCK_METHOD0(GetDistributedBundleManager, sptr<AppExecFwk::IDistributedBms>());
    MOCK_METHOD1(GetUidFromBms, int32_t(const std::string& bundleName));
    MOCK_METHOD2(CheckIfRemoteCanInstall, bool(const AAFwk::Want& want, int32_t missionId));
    MOCK_METHOD2(GetBundleNameId, int32_t(const std::string& bundleName, uint16_t& bundleNameId));
    MOCK_METHOD3(GetContinueType, std::string(const std::string &networkId,
        std::string &bundleName, uint8_t continueTypeId));
    MOCK_METHOD3(GetContinueTypeId, int32_t(const std::string &bundleName,
        const std::string &abilityName, uint8_t &continueTypeId));
    MOCK_METHOD3(GetAbilityName, std::string(const std::string &networkId, std::string &bundleName,
        std::string &continueType));
    MOCK_METHOD3(GetBundleNameById, int32_t(const std::string& networkId,
        const uint16_t& bundleNameId, std::string& bundleName));
    MOCK_METHOD4(GetApplicationInfoFromBms, int32_t(const std::string& bundleName, const AppExecFwk::BundleFlag flag,
        const int32_t userId, AppExecFwk::ApplicationInfo &appInfo));
    MOCK_METHOD1(QueryOsAccount, ErrCode(int32_t& activeAccountId));
};
}
}
#endif