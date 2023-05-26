/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "dms_version_manager.h"

#include "distributed_device_profile_client.h"
#include "dtbschedmgr_log.h"
#include "string_ex.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsVersionManager";
const std::string DMS_SERVICE_ID = "appInfo";
const std::string DMS_SERVICE_TYPE = "appInfo";
const std::string PACKAGE_NAMES = "packageNames";
const std::string VERSIONS = "versions";
const std::string DMS_NAME = "dmsfwk";
const int32_t DMS_VERSION_LENGTH = 3;
const int32_t DMS_MAJOR_VERSION_INDEX = 0;
const int32_t DMS_MINOR_VERSION_INDEX = 1;
const int32_t DMS_FEATURE_VERSION_INDEX = 2;
}

bool DmsVersionManager::IsRemoteDmsVersionLower(const std::string& remoteDeviceId,
    const DmsVersion& thresholdDmsVersion)
{
    DmsVersion dmsVersion;
    int32_t result = GetRemoteDmsVersion(remoteDeviceId, dmsVersion);
    if (result != ERR_OK) {
        return true;
    }
    return CompareDmsVersion(dmsVersion, thresholdDmsVersion);
}

int32_t DmsVersionManager::GetRemoteDmsVersion(const std::string& deviceId, DmsVersion& dmsVersion)
{
    std::string appInfoJsonData;
    int32_t result = GetAppInfoFromDP(deviceId, appInfoJsonData);
    if (result != ERR_OK) {
        HILOGI("get app info failed, result: %{public}d!", result);
        return result;
    }
    std::string packageNamesData;
    std::string versionsData;
    result = ParseAppInfo(appInfoJsonData, packageNamesData, versionsData);
    if (result != ERR_OK) {
        HILOGI("parse app info failed");
        return result;
    }

    std::string dmsVersionData;
    result = GetDmsVersionDataFromAppInfo(packageNamesData, versionsData, dmsVersionData);
    if (result != ERR_OK) {
        HILOGW("get dms version data failed, result: %{public}d!", result);
        return result;
    }
    if (!ParseDmsVersion(dmsVersionData, dmsVersion)) {
        HILOGE("parse dms version failed");
        return DMS_VERSION_PARSE_EXCEPTION;
    }
    return ERR_OK;
}

int32_t DmsVersionManager::GetAppInfoFromDP(const std::string& deviceId, std::string& appInfoJsonData)
{
    DeviceProfile::ServiceCharacteristicProfile profile;
    int32_t result = DeviceProfile::DistributedDeviceProfileClient::GetInstance().GetDeviceProfile(deviceId,
        DMS_SERVICE_ID, profile);
    if (result != ERR_OK) {
        return result;
    }
    appInfoJsonData = profile.GetCharacteristicProfileJson();
    return ERR_OK;
}

int32_t DmsVersionManager::ParseAppInfo(const std::string& appInfoJsonData, std::string& packageNamesData,
    std::string& versionsData)
{
    if (appInfoJsonData.empty()) {
        return DMS_VERSION_EMPTY;
    }
    nlohmann::json appInfoJson = nlohmann::json::parse(appInfoJsonData.c_str(), nullptr, false);
    if (appInfoJson.is_discarded()) {
        return DMS_VERSION_EMPTY;
    }
    if (appInfoJson.find(PACKAGE_NAMES) == appInfoJson.end() || !appInfoJson.at(PACKAGE_NAMES).is_string()) {
        return DMS_VERSION_EMPTY;
    }
    appInfoJson.at(PACKAGE_NAMES).get_to(packageNamesData);

    if (appInfoJson.find(VERSIONS) == appInfoJson.end() || !appInfoJson.at(VERSIONS).is_string()) {
        return DMS_VERSION_EMPTY;
    }
    appInfoJson.at(VERSIONS).get_to(versionsData);

    return ERR_OK;
}

int32_t DmsVersionManager::GetDmsVersionDataFromAppInfo(const std::string& packageNamesData,
    const std::string& versionsData, std::string& dmsVersionData)
{
    if (packageNamesData.empty() || versionsData.empty()) {
        return DMS_VERSION_EMPTY;
    }
    std::vector<std::string> packageNameList;
    std::vector<std::string> versionsList;
    SplitStr(packageNamesData, ",", packageNameList);
    SplitStr(versionsData, ",", versionsList);
    if (packageNameList.size() != versionsList.size()) {
        return DMS_VERSION_PARSE_EXCEPTION;
    }
    for (std::size_t i = 0; i < packageNameList.size(); i++) {
        if (packageNameList[i] == DMS_NAME) {
            dmsVersionData = versionsList[i];
            return ERR_OK;
        }
    }
    return DMS_VERSION_EMPTY;
}

bool DmsVersionManager::ParseDmsVersion(const std::string& dmsVersionData, DmsVersion& dmsVersion)
{
    std::vector<std::string> versionNumList;
    SplitStr(dmsVersionData, ".", versionNumList);
    if (versionNumList.size() != DMS_VERSION_LENGTH) {
        return false;
    }
    int32_t majorVersionNum = -1;
    if (!OHOS::StrToInt(versionNumList[DMS_MAJOR_VERSION_INDEX], majorVersionNum) || majorVersionNum < 0) {
        return false;
    }
    dmsVersion.majorVersionNum = static_cast<uint32_t>(majorVersionNum);

    int32_t minorVersionNum = -1;
    if (!OHOS::StrToInt(versionNumList[DMS_MINOR_VERSION_INDEX], minorVersionNum) || minorVersionNum < 0) {
        return false;
    }
    dmsVersion.minorVersionNum = static_cast<uint32_t>(minorVersionNum);

    int32_t featureVersionNum = -1;
    if (!OHOS::StrToInt(versionNumList[DMS_FEATURE_VERSION_INDEX], featureVersionNum) || featureVersionNum < 0) {
        return false;
    }
    dmsVersion.featureVersionNum = static_cast<uint32_t>(featureVersionNum);
    return true;
}

bool DmsVersionManager::CompareDmsVersion(const DmsVersion& dmsVersion, const DmsVersion& thresholdDmsVersion)
{
    if (dmsVersion.majorVersionNum < thresholdDmsVersion.majorVersionNum) {
        return true;
    }
    if (dmsVersion.majorVersionNum == thresholdDmsVersion.majorVersionNum &&
        dmsVersion.minorVersionNum < thresholdDmsVersion.minorVersionNum) {
        return true;
    }
    if (dmsVersion.majorVersionNum == thresholdDmsVersion.majorVersionNum &&
        dmsVersion.minorVersionNum == thresholdDmsVersion.minorVersionNum &&
        dmsVersion.featureVersionNum < thresholdDmsVersion.featureVersionNum) {
        return true;
    }
    return false;
}
} // namespace DistributedSchedule
} // namespace OHOS
