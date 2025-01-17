/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bundle_manager_internal_mock.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::DistributedSchedule;

IMPLEMENT_SINGLE_INSTANCE(BundleManagerInternal);

bool BundleManagerInternal::GetCallerAppIdFromBms(int32_t callingUid, std::string& appId)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMgrMock->GetCallerAppIdFromBms(callingUid, appId);
}

bool BundleManagerInternal::GetCallerAppIdFromBms(const std::string& bundleName, std::string& appId)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMgrMock->GetCallerAppIdFromBms(bundleName, appId);
}

bool BundleManagerInternal::GetSpecifyBundleNameFromBms(int32_t callingUid, std::string& bundleName)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMgrMock->GetSpecifyBundleNameFromBms(callingUid, bundleName);
}

bool BundleManagerInternal::GetBundleNameListFromBms(int32_t callingUid, std::vector<std::string>& bundleNameList)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMgrMock->GetBundleNameListFromBms(callingUid, bundleNameList);
}

bool BundleManagerInternal::GetBundleNameListFromBms(int32_t callingUid,
    std::vector<std::u16string>& u16BundleNameList)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMgrMock->GetBundleNameListFromBms(callingUid, u16BundleNameList);
}

bool BundleManagerInternal::QueryAbilityInfo(const AAFwk::Want& want, AppExecFwk::AbilityInfo& abilityInfo)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMgrMock->QueryAbilityInfo(want, abilityInfo);
}

bool BundleManagerInternal::QueryExtensionAbilityInfo(const AAFwk::Want& want,
    AppExecFwk::ExtensionAbilityInfo& extensionInfo)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMgrMock->QueryExtensionAbilityInfo(want, extensionInfo);
}

void BundleManagerInternal::InitAbilityInfoFromExtension(const AppExecFwk::ExtensionAbilityInfo &extensionAbilityInfo,
    AppExecFwk::AbilityInfo &abilityInfo)
{
    abilityInfo.bundleName = extensionAbilityInfo.bundleName;
    abilityInfo.name = extensionAbilityInfo.name;
    abilityInfo.permissions = extensionAbilityInfo.permissions;
    abilityInfo.visible = extensionAbilityInfo.visible;
}

bool BundleManagerInternal::IsSameAppId(const std::string& callerAppId, const std::string& targetBundleName)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMgrMock->IsSameAppId(callerAppId, targetBundleName);
}

bool BundleManagerInternal::IsSameDeveloperId(const std::string &bundleNameInCurrentSide,
    const std::string &developerId4OtherSide)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMgrMock->IsSameDeveloperId(bundleNameInCurrentSide, developerId4OtherSide);
}

int32_t BundleManagerInternal::GetLocalBundleInfo(const std::string& bundleName,
    AppExecFwk::BundleInfo &localBundleInfo)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return ERR_OK;
    }
    return IBundleManagerInternal::bundleMgrMock->GetLocalBundleInfo(bundleName, localBundleInfo);
}

int32_t BundleManagerInternal::GetLocalBundleInfoV9(const std::string& bundleName,
    AppExecFwk::BundleInfo &bundleInfo)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return ERR_OK;
    }
    return IBundleManagerInternal::bundleMgrMock->GetLocalBundleInfoV9(bundleName, bundleInfo);
}

bool BundleManagerInternal::GetContinueBundle4Src(const std::string &srcBundleName,
    std::vector<std::string> &bundleNameList)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMgrMock->GetContinueBundle4Src(srcBundleName, bundleNameList);
}

bool BundleManagerInternal::GetAppProvisionInfo4CurrentUser(const std::string &bundleName,
    AppExecFwk::AppProvisionInfo &appProvisionInfo)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMgrMock->GetAppProvisionInfo4CurrentUser(bundleName, appProvisionInfo);
}

int32_t BundleManagerInternal::CheckRemoteBundleInfoForContinuation(const std::string& dstDeviceId,
    const std::string& bundleName, AppExecFwk::DistributedBundleInfo& remoteBundleInfo)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return ERR_OK;
    }
    return IBundleManagerInternal::bundleMgrMock->CheckRemoteBundleInfoForContinuation(dstDeviceId, bundleName,
        remoteBundleInfo);
}

sptr<AppExecFwk::IBundleMgr> BundleManagerInternal::GetBundleManager()
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return nullptr;
    }
    return IBundleManagerInternal::bundleMgrMock->GetBundleManager();
}

sptr<AppExecFwk::IDistributedBms> BundleManagerInternal::GetDistributedBundleManager()
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return nullptr;
    }
    return IBundleManagerInternal::bundleMgrMock->GetDistributedBundleManager();
}

int32_t BundleManagerInternal::GetUidFromBms(const std::string& bundleName)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return ERR_OK;
    }
    return IBundleManagerInternal::bundleMgrMock->GetUidFromBms(bundleName);
}

std::string BundleManagerInternal::GetContinueType(const std::string &networkId,
    std::string &bundleName, uint8_t continueTypeId)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return "";
    }
    return IBundleManagerInternal::bundleMgrMock->GetContinueType(networkId, bundleName,
        continueTypeId);
}

int32_t BundleManagerInternal::GetContinueTypeId(const std::string &bundleName,
    const std::string &abilityName, uint8_t &continueTypeId)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return ERR_OK;
    }
    return IBundleManagerInternal::bundleMgrMock->GetContinueTypeId(bundleName, abilityName, continueTypeId);
}

int32_t BundleManagerInternal::GetBundleNameById(const std::string& networkId,
    const uint16_t& bundleNameId, std::string& bundleName)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return ERR_OK;
    }
    return IBundleManagerInternal::bundleMgrMock->GetBundleNameById(networkId, bundleNameId, bundleName);
}

int32_t BundleManagerInternal::GetApplicationInfoFromBms(const std::string& bundleName,
    const AppExecFwk::BundleFlag flag, const int32_t userId, AppExecFwk::ApplicationInfo &appInfo)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return ERR_OK;
    }
    return IBundleManagerInternal::bundleMgrMock->GetApplicationInfoFromBms(bundleName, flag, userId, appInfo);
}

ErrCode BundleManagerInternal::QueryOsAccount(int32_t& activeAccountId)
{
    if (IBundleManagerInternal::bundleMgrMock == nullptr) {
        return ERR_OK;
    }
    return IBundleManagerInternal::bundleMgrMock->QueryOsAccount(activeAccountId);
}
