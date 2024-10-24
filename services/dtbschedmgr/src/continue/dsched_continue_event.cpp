/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dsched_continue_event.h"

#include "cJSON.h"
#include "parcel.h"

#include "distributed_sched_utils.h"
#include "dms_constant.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedContinueCmd";
const char* EXTRO_INFO_JSON_KEY_ACCESS_TOKEN = "accessTokenID";
const char* DMS_VERSION_ID = "dmsVersion";
}

int32_t DSchedContinueCmdBase::Marshal(std::string &jsonStr)
{
    cJSON *rootValue = cJSON_CreateObject();
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }
    cJSON_AddNumberToObject(rootValue, "Version", version_);
    cJSON_AddNumberToObject(rootValue, "ServiceType", serviceType_);
    cJSON_AddNumberToObject(rootValue, "SubServiceType", subServiceType_);
    cJSON_AddNumberToObject(rootValue, "Command", command_);

    cJSON_AddStringToObject(rootValue, "SrcDeviceId", srcDeviceId_.c_str());
    cJSON_AddStringToObject(rootValue, "SrcBundleName", srcBundleName_.c_str());
    cJSON_AddStringToObject(rootValue, "SrcDeveloperId", srcDeveloperId_.c_str());
    cJSON_AddStringToObject(rootValue, "DstDeviceId", dstDeviceId_.c_str());
    cJSON_AddStringToObject(rootValue, "DstBundleName", dstBundleName_.c_str());
    cJSON_AddStringToObject(rootValue, "DstDeveloperId", dstDeveloperId_.c_str());
    cJSON_AddStringToObject(rootValue, "ContinueType", continueType_.c_str());

    cJSON_AddNumberToObject(rootValue, "ContinueByType", continueByType_);
    cJSON_AddNumberToObject(rootValue, "SourceMissionId", sourceMissionId_);
    cJSON_AddNumberToObject(rootValue, "DmsVersion", dmsVersion_);

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    jsonStr = std::string(data);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    return ERR_OK;
}

int32_t DSchedContinueCmdBase::Unmarshal(const std::string &jsonStr)
{
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        HILOGE("Dms continue cmd base json string parse to cjson fail.");
        return INVALID_PARAMETERS_ERR;
    }

    const char *numKeys[] = { "Version", "ServiceType", "SubServiceType", "ContinueByType", "SourceMissionId",
        "DmsVersion" };
    int32_t *numValues[] = { &version_, &serviceType_, &subServiceType_, &continueByType_, &sourceMissionId_,
        &dmsVersion_ };
    int32_t numLength = sizeof(numKeys) / sizeof(numKeys[0]);
    for (int32_t i = 0; i < numLength; i++) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(rootValue, numKeys[i]);
        if (item == nullptr || !cJSON_IsNumber(item)) {
            cJSON_Delete(rootValue);
            HILOGE("Dms continue cmd base %{public}s term is null or not number.", numKeys[i]);
            return INVALID_PARAMETERS_ERR;
        }
        *numValues[i] = item->valueint;
    }

    const char *strKeys[] = {"SrcDeviceId", "SrcBundleName", "DstDeviceId", "DstBundleName", "ContinueType"};
    std::string *strValues[] = {&srcDeviceId_, &srcBundleName_, &dstDeviceId_, &dstBundleName_, &continueType_};
    int32_t strLength = sizeof(strKeys) / sizeof(strKeys[0]);
    for (int32_t i = 0; i < strLength; i++) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(rootValue, strKeys[i]);
        if (item == nullptr || !cJSON_IsString(item) || (item->valuestring == nullptr)) {
            cJSON_Delete(rootValue);
            HILOGE("Dms continue cmd base %{public}s term is null or not string.", strKeys[i]);
            return INVALID_PARAMETERS_ERR;
        }
        *strValues[i] = item->valuestring;
    }
    const char *strNotRequiredKeys[] = {"SrcDeveloperId", "DstDeveloperId"};
    std::string *strNotRequiredValues[] = { &srcDeveloperId_, &dstDeveloperId_};
    int32_t strNotRequiredLength = sizeof(strNotRequiredKeys) / sizeof(strNotRequiredKeys[0]);
    for (int32_t i = 0; i < strNotRequiredLength; i++) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(rootValue, strNotRequiredKeys[i]);
        if (item == nullptr || !cJSON_IsString(item) || (item->valuestring == nullptr)) {
            *strNotRequiredValues[i] = "";
        } else {
            *strNotRequiredValues[i] = item->valuestring;
        }
    }

    cJSON_Delete(rootValue);
    return ERR_OK;
}

int32_t DSchedContinueStartCmd::Marshal(std::string &jsonStr)
{
    cJSON *rootValue = cJSON_CreateObject();
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }

    std::string baseJsonStr;
    if (DSchedContinueCmdBase::Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());

    cJSON_AddNumberToObject(rootValue, "Direction", direction_);
    cJSON_AddNumberToObject(rootValue, "AppVersion", appVersion_);

    Parcel parcel;
    if (!wantParams_.Marshalling(parcel)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    std::string wantParamsStr = ParcelToBase64Str(parcel);
    cJSON_AddStringToObject(rootValue, "WantParams", wantParamsStr.c_str());

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    jsonStr = std::string(data);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    return ERR_OK;
}

int32_t DSchedContinueStartCmd::Unmarshal(const std::string &jsonStr)
{
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *baseCmd = cJSON_GetObjectItemCaseSensitive(rootValue, "BaseCmd");
    if (baseCmd == nullptr || !cJSON_IsString(baseCmd) || (baseCmd->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    std::string baseCmdStr = baseCmd->valuestring;
    if (DSchedContinueCmdBase::Unmarshal(baseCmdStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *direction = cJSON_GetObjectItemCaseSensitive(rootValue, "Direction");
    if (direction == nullptr || !cJSON_IsNumber(direction)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    direction_ = direction->valueint;

    cJSON *appVersion = cJSON_GetObjectItemCaseSensitive(rootValue, "AppVersion");
    if (appVersion == nullptr || !cJSON_IsNumber(appVersion)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    appVersion_ = appVersion->valueint;

    cJSON *wantParams = cJSON_GetObjectItemCaseSensitive(rootValue, "WantParams");
    if (wantParams == nullptr || !cJSON_IsString(wantParams) || (wantParams->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    Parcel parcel;
    int32_t ret = Base64StrToParcel(wantParams->valuestring, parcel);
    if (ret != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    auto wantParamsPtr = DistributedWantParams::Unmarshalling(parcel);
    if (wantParamsPtr == nullptr) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    wantParams_ = *wantParamsPtr;

    cJSON_Delete(rootValue);
    return ERR_OK;
}

int32_t DSchedContinueDataCmd::Marshal(std::string &jsonStr)
{
    cJSON *rootValue = cJSON_CreateObject();
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }

    std::string baseJsonStr;
    if (DSchedContinueCmdBase::Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }

    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());

    Parcel wantParcel;
    if (!want_.Marshalling(wantParcel)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    std::string wantStr = ParcelToBase64Str(wantParcel);
    cJSON_AddStringToObject(rootValue, "Want", wantStr.c_str());

    Parcel abilityParcel;
    if (!abilityInfo_.Marshalling(abilityParcel)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    std::string abilityInfoStr = ParcelToBase64Str(abilityParcel);
    cJSON_AddStringToObject(rootValue, "AbilityInfo", abilityInfoStr.c_str());

    cJSON_AddNumberToObject(rootValue, "RequestCode", requestCode_);

    std::string callerInfoStr;
    if (MarshalCallerInfo(callerInfoStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    cJSON_AddStringToObject(rootValue, "CallerInfo", callerInfoStr.c_str());

    std::string accountInfoStr;
    if (MarshalAccountInfo(accountInfoStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    cJSON_AddStringToObject(rootValue, "AccountInfo", accountInfoStr.c_str());

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    jsonStr = std::string(data);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    return ERR_OK;
}

int32_t DSchedContinueDataCmd::MarshalCallerInfo(std::string &jsonStr)
{
    cJSON *callerInfoJson = cJSON_CreateObject();
    if (callerInfoJson == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }
    cJSON_AddNumberToObject(callerInfoJson, "Uid", callerInfo_.uid);
    cJSON_AddNumberToObject(callerInfoJson, "Pid", callerInfo_.pid);
    cJSON_AddNumberToObject(callerInfoJson, "CallerType", callerInfo_.callerType);
    cJSON_AddStringToObject(callerInfoJson, "SourceDeviceId", callerInfo_.sourceDeviceId.c_str());
    cJSON_AddNumberToObject(callerInfoJson, "Duid", callerInfo_.duid);
    cJSON_AddStringToObject(callerInfoJson, "CallerAppId", callerInfo_.callerAppId.c_str());

    const auto bundleNamesSize = static_cast<int32_t>(callerInfo_.bundleNames.size());
    cJSON *bundleNames = cJSON_CreateArray();
    if (bundleNames == nullptr) {
        cJSON_Delete(callerInfoJson);
        return INVALID_PARAMETERS_ERR;
    }
    for (auto i = 0; i < bundleNamesSize; i++) {
        cJSON *bundleName = cJSON_CreateString(callerInfo_.bundleNames[i].c_str());
        if (bundleName == nullptr) {
            cJSON_Delete(callerInfoJson);
            cJSON_Delete(bundleNames);
            return INVALID_PARAMETERS_ERR;
        }
        cJSON_AddItemToArray(bundleNames, bundleName);
    }
    cJSON_AddItemToObject(callerInfoJson, "BundleNames", bundleNames);

    std::string extraInfo = callerInfo_.extraInfoJson.dump();
    cJSON_AddStringToObject(callerInfoJson, "ExtraInfo", extraInfo.c_str());

    char *data = cJSON_Print(callerInfoJson);
    if (data == nullptr) {
        cJSON_Delete(callerInfoJson);
        return INVALID_PARAMETERS_ERR;
    }
    jsonStr = std::string(data);
    cJSON_Delete(callerInfoJson);
    cJSON_free(data);
    return ERR_OK;
}

int32_t DSchedContinueDataCmd::MarshalAccountInfo(std::string &jsonStr)
{
    cJSON *accountInfoJson = cJSON_CreateObject();
    if (accountInfoJson == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }

    cJSON_AddNumberToObject(accountInfoJson, "AccountType", accountInfo_.accountType);

    const auto groupIdListSize = static_cast<int32_t>(accountInfo_.groupIdList.size());
    cJSON *groupIdList = cJSON_CreateArray();
    if (groupIdList == nullptr) {
        cJSON_Delete(accountInfoJson);
        return INVALID_PARAMETERS_ERR;
    }
    for (auto i = 0; i < groupIdListSize; i++) {
        cJSON *groupId = cJSON_CreateString(accountInfo_.groupIdList[i].c_str());
        if (groupId == nullptr) {
            cJSON_Delete(accountInfoJson);
            cJSON_Delete(groupIdList);
            return INVALID_PARAMETERS_ERR;
        }
        cJSON_AddItemToArray(groupIdList, groupId);
    }
    cJSON_AddItemToObject(accountInfoJson, "GroupIdList", groupIdList);

    cJSON_AddStringToObject(accountInfoJson, Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID.c_str(),
        accountInfo_.activeAccountId.c_str());
    cJSON_AddNumberToObject(accountInfoJson, Constants::EXTRO_INFO_JSON_KEY_USERID_ID.c_str(), accountInfo_.userId);

    char *data = cJSON_Print(accountInfoJson);
    if (data == nullptr) {
        cJSON_Delete(accountInfoJson);
        return INVALID_PARAMETERS_ERR;
    }
    jsonStr = std::string(data);
    cJSON_Delete(accountInfoJson);
    cJSON_free(data);
    return ERR_OK;
}

int32_t DSchedContinueDataCmd::Unmarshal(const std::string &jsonStr)
{
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *baseCmd = cJSON_GetObjectItemCaseSensitive(rootValue, "BaseCmd");
    if (baseCmd == nullptr || !cJSON_IsString(baseCmd) || (baseCmd->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    std::string baseCmdStr = baseCmd->valuestring;
    if (DSchedContinueCmdBase::Unmarshal(baseCmdStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }

    if (UnmarshalParcel(jsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *requestCode = cJSON_GetObjectItemCaseSensitive(rootValue, "RequestCode");
    if (requestCode == nullptr || !cJSON_IsNumber(requestCode)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    requestCode_ = requestCode->valueint;

    cJSON *callerInfoJson = cJSON_GetObjectItemCaseSensitive(rootValue, "CallerInfo");
    if (callerInfoJson == nullptr || !cJSON_IsString(callerInfoJson) || (callerInfoJson->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    std::string callerInfoStr = callerInfoJson->valuestring;
    if (UnmarshalCallerInfo(callerInfoStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *accountInfoJson = cJSON_GetObjectItemCaseSensitive(rootValue, "AccountInfo");
    if (accountInfoJson == nullptr || !cJSON_IsString(accountInfoJson) || (accountInfoJson->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    std::string accountInfoStr = accountInfoJson->valuestring;
    if (UnmarshalAccountInfo(accountInfoStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }

    cJSON_Delete(rootValue);
    return ERR_OK;
}

int32_t DSchedContinueDataCmd::UnmarshalParcel(const std::string &jsonStr)
{
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        HILOGE("Want and AbilityInfo json string parse to cjson fail.");
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *wantStr = cJSON_GetObjectItemCaseSensitive(rootValue, "Want");
    if (wantStr == nullptr || !cJSON_IsString(wantStr) || (wantStr->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        HILOGE("Want term is null or not string.");
        return INVALID_PARAMETERS_ERR;
    }
    Parcel wantParcel;
    int32_t ret = Base64StrToParcel(wantStr->valuestring, wantParcel);
    if (ret != ERR_OK) {
        cJSON_Delete(rootValue);
        HILOGE("Want parcel Base64Str unmarshal fail, ret %{public}d.", ret);
        return INVALID_PARAMETERS_ERR;
    }
    auto wantPtr = AAFwk::Want::Unmarshalling(wantParcel);
    if (wantPtr == nullptr) {
        cJSON_Delete(rootValue);
        HILOGE("AAFwk Want unmarshalling fail, check return null.");
        return INVALID_PARAMETERS_ERR;
    }
    want_ = *wantPtr;

    cJSON *abilityInfoStr = cJSON_GetObjectItemCaseSensitive(rootValue, "AbilityInfo");
    if (abilityInfoStr == nullptr || !cJSON_IsString(abilityInfoStr) || (abilityInfoStr->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        HILOGE("AbilityInfo term is null or not string.");
        return INVALID_PARAMETERS_ERR;
    }
    Parcel abilityParcel;
    ret = Base64StrToParcel(abilityInfoStr->valuestring, abilityParcel);
    if (ret != ERR_OK) {
        cJSON_Delete(rootValue);
        HILOGE("AbilityInfo parcel Base64Str unmarshal fail, ret %{public}d.", ret);
        return INVALID_PARAMETERS_ERR;
    }
    auto abilityInfoPtr = AppExecFwk::CompatibleAbilityInfo::Unmarshalling(abilityParcel);
    if (abilityInfoPtr == nullptr) {
        cJSON_Delete(rootValue);
        HILOGE("AppExecFwk CompatibleAbilityInfo unmarshalling fail, check return null.");
        return INVALID_PARAMETERS_ERR;
    }
    abilityInfo_ = *abilityInfoPtr;

    cJSON_Delete(rootValue);
    return ERR_OK;
}

int32_t DSchedContinueDataCmd::UnmarshalCallerInfo(std::string &jsonStr)
{
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        HILOGE("Caller info json string parse to cjson fail.");
        return INVALID_PARAMETERS_ERR;
    }

    const char *strKeys[] = {
        "SourceDeviceId", "CallerAppId"
    };
    std::string *strValues[] = {
        &callerInfo_.sourceDeviceId, &callerInfo_.callerAppId
    };
    int32_t strLength = sizeof(strKeys) / sizeof(strKeys[0]);
    for (int32_t i = 0; i < strLength; i++) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(rootValue, strKeys[i]);
        if (item == nullptr || !cJSON_IsString(item) || (item->valuestring == nullptr)) {
            cJSON_Delete(rootValue);
            HILOGE("Caller info json %{public}s term is null or not string.", strKeys[i]);
            return INVALID_PARAMETERS_ERR;
        }
        *strValues[i] = item->valuestring;
    }

    const char *numKeys[] = {
        "Uid", "Pid", "CallerType", "Duid"
    };
    int32_t *numValues[] = {
        &callerInfo_.uid, &callerInfo_.pid, &callerInfo_.callerType, &callerInfo_.duid
    };
    int32_t numLength = sizeof(numKeys) / sizeof(numKeys[0]);
    for (int32_t i = 0; i < numLength; i++) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(rootValue, numKeys[i]);
        if (item == nullptr || !cJSON_IsNumber(item)) {
            cJSON_Delete(rootValue);
            HILOGE("Caller info json %{public}s term is null or not number.", numKeys[i]);
            return INVALID_PARAMETERS_ERR;
        }
        *numValues[i] = item->valueint;
    }

    if (UnmarshalCallerInfoExtra(jsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        HILOGE("Unmarshal CallerInfoExtra term from caller info json string fail.");
        return INVALID_PARAMETERS_ERR;
    }

    cJSON_Delete(rootValue);
    return ERR_OK;
}

int32_t DSchedContinueDataCmd::UnmarshalCallerInfoExtra(std::string &jsonStr)
{
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        HILOGE("Caller info extra json string parse to cjson fail.");
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *bundleName = nullptr;
    std::vector<std::string> bundleNameList;
    cJSON *bundleNames = cJSON_GetObjectItemCaseSensitive(rootValue, "BundleNames");
    cJSON_ArrayForEach(bundleName, bundleNames) {
        if (bundleName == nullptr || !cJSON_IsString(bundleName) || (bundleName->valuestring == nullptr)) {
            cJSON_Delete(rootValue);
            HILOGE("BundleNames term in CallerInfoExtra json is null or not string.");
            return INVALID_PARAMETERS_ERR;
        }
        bundleNameList.push_back(bundleName->valuestring);
    }
    callerInfo_.bundleNames = bundleNameList;

    cJSON *extraInfo = cJSON_GetObjectItemCaseSensitive(rootValue, "ExtraInfo");
    if (extraInfo == nullptr || !cJSON_IsString(extraInfo) || (extraInfo->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        HILOGE("ExtraInfo term in CallerInfoExtra json is null or not string.");
        return INVALID_PARAMETERS_ERR;
    }
    cJSON *extraInfoValue = cJSON_Parse(extraInfo->valuestring);
    if (extraInfoValue == nullptr) {
        cJSON_Delete(rootValue);
        HILOGE("ExtraInfo term json string parse to cjson fail in CallerInfoExtra json.");
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *accessToken = cJSON_GetObjectItemCaseSensitive(extraInfoValue, EXTRO_INFO_JSON_KEY_ACCESS_TOKEN);
    if (accessToken != nullptr && cJSON_IsNumber(accessToken)) {
        callerInfo_.accessToken = static_cast<unsigned int>(accessToken->valueint);
    }

    cJSON *dmsVersion = cJSON_GetObjectItemCaseSensitive(extraInfoValue, DMS_VERSION_ID);
    if (dmsVersion != nullptr && !cJSON_IsString(dmsVersion) && (dmsVersion->valuestring != nullptr)) {
        callerInfo_.extraInfoJson[DMS_VERSION_ID] = dmsVersion->valuestring;
    }
    cJSON_Delete(extraInfoValue);
    cJSON_Delete(rootValue);
    return ERR_OK;
}

int32_t DSchedContinueDataCmd::UnmarshalAccountInfo(std::string &jsonStr)
{
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        HILOGE("Account info json string parse to cjson fail.");
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *accountType = cJSON_GetObjectItemCaseSensitive(rootValue, "AccountType");
    if (accountType == nullptr || !cJSON_IsNumber(accountType)) {
        cJSON_Delete(rootValue);
        HILOGE("AccountType term in account info json is null or not number.");
        return INVALID_PARAMETERS_ERR;
    }
    accountInfo_.accountType = accountType->valueint;

    cJSON *groupId = nullptr;
    std::vector<std::string> groupIdList;
    cJSON *groupIdListStr = cJSON_GetObjectItemCaseSensitive(rootValue, "groupIdList");
    cJSON_ArrayForEach(groupId, groupIdListStr) {
        if (groupId == nullptr || !cJSON_IsString(groupId) || (groupId->valuestring == nullptr)) {
            cJSON_Delete(rootValue);
            HILOGE("groupId term in account info json is null or not string.");
            return INVALID_PARAMETERS_ERR;
        }
        groupIdList.push_back(groupId->valuestring);
    }
    accountInfo_.groupIdList = groupIdList;

    cJSON *accountId = cJSON_GetObjectItemCaseSensitive(rootValue, Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID.c_str());
    if (accountId == nullptr || !cJSON_IsString(accountId)) {
        HILOGE("accountId term in account info json is null or not string.");
    } else {
        accountInfo_.activeAccountId = accountId->valuestring;
    }
    cJSON *userId = cJSON_GetObjectItemCaseSensitive(rootValue, Constants::EXTRO_INFO_JSON_KEY_USERID_ID.c_str());
    if (userId == nullptr || !cJSON_IsNumber(userId)) {
        HILOGE("userId term in account info json is null or not number.");
    } else {
        accountInfo_.userId = userId->valueint;
    }

    cJSON_Delete(rootValue);
    return ERR_OK;
}

int32_t DSchedContinueReplyCmd::Marshal(std::string &jsonStr)
{
    cJSON *rootValue = cJSON_CreateObject();
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }

    std::string baseJsonStr;
    if (DSchedContinueCmdBase::Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());

    cJSON_AddNumberToObject(rootValue, "ReplyCmd", replyCmd_);
    cJSON_AddNumberToObject(rootValue, "AppVersion", appVersion_);
    cJSON_AddNumberToObject(rootValue, "Result", result_);
    cJSON_AddStringToObject(rootValue, "Reason", reason_.c_str());

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    jsonStr = std::string(data);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    return ERR_OK;
}

int32_t DSchedContinueReplyCmd::Unmarshal(const std::string &jsonStr)
{
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *baseCmd = cJSON_GetObjectItemCaseSensitive(rootValue, "BaseCmd");
    if (baseCmd == nullptr || !cJSON_IsString(baseCmd) || (baseCmd->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    std::string baseCmdStr = baseCmd->valuestring;
    if (DSchedContinueCmdBase::Unmarshal(baseCmdStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }

    const char *numKeys[] = {
        "ReplyCmd", "AppVersion", "Result"
    };
    int32_t *numValues[] = {
        &replyCmd_, &appVersion_, &result_
    };
    int32_t numLength = sizeof(numKeys) / sizeof(numKeys[0]);
    for (int32_t i = 0; i < numLength; i++) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(rootValue, numKeys[i]);
        if (item == nullptr || !cJSON_IsNumber(item)) {
            cJSON_Delete(rootValue);
            return INVALID_PARAMETERS_ERR;
        }
        *numValues[i] = item->valueint;
    }

    cJSON *reason = cJSON_GetObjectItemCaseSensitive(rootValue, "Reason");
    if (reason == nullptr || !cJSON_IsString(reason) || (reason->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    reason_ = reason->valuestring;

    cJSON_Delete(rootValue);
    return ERR_OK;
}

int32_t DSchedContinueEndCmd::Marshal(std::string &jsonStr)
{
    cJSON *rootValue = cJSON_CreateObject();
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }

    std::string baseJsonStr;
    if (DSchedContinueCmdBase::Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());

    cJSON_AddNumberToObject(rootValue, "Result", result_);

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    jsonStr = std::string(data);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    return ERR_OK;
}

int32_t DSchedContinueEndCmd::Unmarshal(const std::string &jsonStr)
{
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *baseCmd = cJSON_GetObjectItemCaseSensitive(rootValue, "BaseCmd");
    if (baseCmd == nullptr || !cJSON_IsString(baseCmd) || (baseCmd->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    std::string baseCmdStr = baseCmd->valuestring;
    if (DSchedContinueCmdBase::Unmarshal(baseCmdStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *result = cJSON_GetObjectItemCaseSensitive(rootValue, "Result");
    if (result == nullptr || !cJSON_IsNumber(result)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    result_ = result->valueint;

    cJSON_Delete(rootValue);
    return ERR_OK;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
