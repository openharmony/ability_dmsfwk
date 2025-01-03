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

#include "dsched_collab_event.h"

#include "cJSON.h"
#include "distributed_sched_utils.h"
#include "dms_constant.h"
#include "dtbschedmgr_log.h"
#include "parcel.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedCollabCmd";
const char* EXTRO_INFO_JSON_KEY_ACCESS_TOKEN = "accessTokenID";
const char* DMS_VERSION_ID = "dmsVersion";
}

int32_t BaseCmd::Marshal(std::string &jsonStr)
{
    cJSON *rootValue = cJSON_CreateObject();
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }
    cJSON_AddNumberToObject(rootValue, "Command", command_);
    cJSON_AddNumberToObject(rootValue, "CollabVersion", collabVersion_);
    cJSON_AddNumberToObject(rootValue, "DmsVersion", dmsVersion_);
    cJSON_AddNumberToObject(rootValue, "CollabSessionId", srcCollabSessionId_);
    cJSON_AddStringToObject(rootValue, "CollabToken", collabToken_.c_str());
    cJSON_AddStringToObject(rootValue, "SrcDeviceId", srcDeviceId_.c_str());
    cJSON_AddStringToObject(rootValue, "SrcBundleName", srcBundleName_.c_str());
    cJSON_AddStringToObject(rootValue, "SrcAbilityName", srcAbilityName_.c_str());
    cJSON_AddStringToObject(rootValue, "SrcModuleName", srcModuleName_.c_str());
    cJSON_AddStringToObject(rootValue, "SrcServiceId", srcServerId_.c_str());
    cJSON_AddStringToObject(rootValue, "SinkDeviceId", sinkDeviceId_.c_str());
    cJSON_AddStringToObject(rootValue, "SinkBundleName", sinkBundleName_.c_str());
    cJSON_AddStringToObject(rootValue, "SinkAbilityName", sinkAbilityName_.c_str());
    cJSON_AddStringToObject(rootValue, "SinkModuleName", sinkModuleName_.c_str());
    cJSON_AddStringToObject(rootValue, "SinkServiceId", sinkServerId_.c_str());

    cJSON_AddBoolToObject(rootValue, "NeedSendBigData", needSendBigData_);
    cJSON_AddBoolToObject(rootValue, "NeedSendStream_", needSendStream_);
    cJSON_AddBoolToObject(rootValue, "NeedRecvStream", needRecvStream_);

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        HILOGE("cJSON_Print failed.");
        return INVALID_PARAMETERS_ERR;
    }
    jsonStr = std::string(data);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    return ERR_OK;
}

int32_t BaseCmd::Unmarshal(const std::string &jsonStr)
{
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        HILOGE("Dms collab cmd base json string parse to cjson fail.");
        return INVALID_PARAMETERS_ERR;
    }

    const char *numKeys[] = { "Command", "CollabVersion", "DmsVersion", "CollabSessionId" };
    int32_t *numValues[] = { &command_, &collabVersion_, &dmsVersion_, &srcCollabSessionId_ };
    int32_t numLength = sizeof(numKeys) / sizeof(numKeys[0]);
    for (int32_t i = 0; i < numLength; i++) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(rootValue, numKeys[i]);
        if (item == nullptr || !cJSON_IsNumber(item)) {
            cJSON_Delete(rootValue);
            HILOGE("Dms collab cmd base %{public}s term is null or not number.", numKeys[i]);
            return INVALID_PARAMETERS_ERR;
        }
        *numValues[i] = item->valueint;
    }

    const char *strKeys[] = { "CollabToken", "SrcDeviceId", "SrcBundleName", "SrcAbilityName", "SrcModuleName",
        "SrcServiceId", "SinkDeviceId", "SinkBundleName", "SinkAbilityName", "SinkModuleName", "SinkServiceId" };
    std::string *strValues[] = {&collabToken_, &srcDeviceId_, &srcBundleName_, &srcAbilityName_, &srcModuleName_,
        &srcServerId_, &sinkDeviceId_, &sinkBundleName_, &sinkAbilityName_, &sinkModuleName_, &sinkServerId_ };
    int32_t strLength = sizeof(strKeys) / sizeof(strKeys[0]);
    for (int32_t i = 0; i < strLength; i++) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(rootValue, strKeys[i]);
        if (item == nullptr || !cJSON_IsString(item) || (item->valuestring == nullptr)) {
            cJSON_Delete(rootValue);
            HILOGE("Dms collab cmd base %{public}s term is null or not string.", strKeys[i]);
            return INVALID_PARAMETERS_ERR;
        }
        *strValues[i] = item->valuestring;
    }

    const char *boolKeys[] = { "NeedSendBigData", "NeedSendStream_", "NeedRecvStream" };
    bool *boolValues[] = { &needSendBigData_, &needSendStream_, &needRecvStream_ };
    int32_t boolLength = sizeof(boolKeys) / sizeof(boolKeys[0]);
    for (int32_t i = 0; i < boolLength; i++) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(rootValue, boolKeys[i]);
        if (item == nullptr || !cJSON_IsBool(item)) {
            cJSON_Delete(rootValue);
            HILOGE("Dms collab cmd base %{public}s term is null or not number.", boolKeys[i]);
            return INVALID_PARAMETERS_ERR;
        }
        *boolValues[i] = item->valueint;
    }
    cJSON_Delete(rootValue);
    return ERR_OK;
}

int32_t SinkStartCmd::Marshal(std::string &jsonStr)
{
    cJSON *rootValue = cJSON_CreateObject();
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }
    std::string baseJsonStr;
    if (BaseCmd::Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());
    cJSON_AddNumberToObject(rootValue, "AppVersion", appVersion_);
    cJSON_AddNumberToObject(rootValue, "SrcPid", srcPid_);
    cJSON_AddNumberToObject(rootValue, "SrcUid", srcUid_);
    cJSON_AddNumberToObject(rootValue, "SrcAccessToken", srcAccessToken_);
    Parcel parcel;
    if (!startParams_.Marshalling(parcel)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    std::string startParamsStr = ParcelToBase64Str(parcel);
    cJSON_AddStringToObject(rootValue, "StartParams", startParamsStr.c_str());
    if (!messageParams_.Marshalling(parcel)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    std::string wantParamsStr = ParcelToBase64Str(parcel);
    cJSON_AddStringToObject(rootValue, "WantParams", wantParamsStr.c_str());
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

int32_t SinkStartCmd::Unmarshal(const std::string &jsonStr)
{
    HILOGD("called");
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
    if (BaseCmd::Unmarshal(baseCmdStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    const char *numKeys[] = { "AppVersion", "SrcPid", "SrcUid", "SrcAccessToken" };
    int32_t *numValues[] = { &appVersion_, &srcPid_, &srcUid_, &srcAccessToken_ };
    int32_t numLength = sizeof(numKeys) / sizeof(numKeys[0]);
    for (int32_t i = 0; i < numLength; i++) {
        cJSON *item = cJSON_GetObjectItemCaseSensitive(rootValue, numKeys[i]);
        if (item == nullptr || !cJSON_IsNumber(item)) {
            cJSON_Delete(rootValue);
            HILOGE("%{public}s term is null or not number.", numKeys[i]);
            return INVALID_PARAMETERS_ERR;
        }
        *numValues[i] = item->valueint;
    }

    int32_t ret =  UnmarshalPartParcel(rootValue);
    cJSON_Delete(rootValue);
    return ret;
}

int32_t SinkStartCmd::UnmarshalPartParcel(cJSON *rootValue)
{
    if (UnmarshalOptParams(rootValue) != ERR_OK) {
        HILOGE("get callerInfoJson failed.");
        return INVALID_PARAMETERS_ERR;
    }

    cJSON *callerInfoJson = cJSON_GetObjectItemCaseSensitive(rootValue, "CallerInfo");
    if (callerInfoJson == nullptr || !cJSON_IsString(callerInfoJson) || (callerInfoJson->valuestring == nullptr)) {
        HILOGE("get callerInfoJson failed.");
        return INVALID_PARAMETERS_ERR;
    }
    std::string callerInfoStr = callerInfoJson->valuestring;
    if (UnmarshalCallerInfo(callerInfoStr) != ERR_OK) {
        HILOGE("unmarshal callerInfo failed.");
        return INVALID_PARAMETERS_ERR;
    }
    cJSON *accountInfoJson = cJSON_GetObjectItemCaseSensitive(rootValue, "AccountInfo");
    if (accountInfoJson == nullptr || !cJSON_IsString(accountInfoJson) || (accountInfoJson->valuestring == nullptr)) {
        HILOGE("get accountInfoJson failed.");
        return INVALID_PARAMETERS_ERR;
    }
    std::string accountInfoStr = accountInfoJson->valuestring;
    if (UnmarshalAccountInfo(accountInfoStr) != ERR_OK) {
        HILOGE("unmarshal accountInfo failed.");
        return INVALID_PARAMETERS_ERR;
    }
    return ERR_OK;
}

int32_t SinkStartCmd::UnmarshalOptParams(cJSON *rootValue)
{
    cJSON *startParamsJson = cJSON_GetObjectItemCaseSensitive(rootValue, "StartParams");
    if (startParamsJson == nullptr || !cJSON_IsString(startParamsJson) || (startParamsJson->valuestring == nullptr)) {
        HILOGE("get startParamsJson failed.");
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    Parcel parcel;
    int32_t ret = Base64StrToParcel(startParamsJson->valuestring, parcel);
    if (ret != ERR_OK) {
        cJSON_Delete(rootValue);
        HILOGE("base64StrToParcel failed.");
        return INVALID_PARAMETERS_ERR;
    }
    auto startParamsPtr = AAFwk::WantParams::Unmarshalling(parcel);
    if (startParamsPtr == nullptr) {
        cJSON_Delete(rootValue);
        HILOGE("startParamsJson unmarshalling failed.");
        return INVALID_PARAMETERS_ERR;
    }
    startParams_ = *startParamsPtr;

    cJSON *wantParamsJson = cJSON_GetObjectItemCaseSensitive(rootValue, "WantParams");
    if (wantParamsJson == nullptr || !cJSON_IsString(wantParamsJson) || (wantParamsJson->valuestring == nullptr)) {
        HILOGE("get wantParamsJson failed.");
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    ret = Base64StrToParcel(wantParamsJson->valuestring, parcel);
    if (ret != ERR_OK) {
        cJSON_Delete(rootValue);
        HILOGE("base64StrToParcel failed.");
        return INVALID_PARAMETERS_ERR;
    }
    auto wantParamsPtr = AAFwk::WantParams::Unmarshalling(parcel);
    if (wantParamsPtr == nullptr) {
        cJSON_Delete(rootValue);
        HILOGE("wantParamsJson unmarshalling failed.");
        return INVALID_PARAMETERS_ERR;
    }
    messageParams_ = *wantParamsPtr;
    return ERR_OK;
}

int32_t SinkStartCmd::MarshalCallerInfo(std::string &jsonStr)
{
    HILOGD("called");
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
    HILOGD("end");
    return ERR_OK;
}

int32_t SinkStartCmd::MarshalAccountInfo(std::string &jsonStr)
{
    HILOGD("called");
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
    HILOGD("end");
    return ERR_OK;
}

int32_t SinkStartCmd::UnmarshalCallerInfo(std::string &jsonStr)
{
    HILOGD("called");
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        HILOGE("Caller info json string parse to cjson fail.");
        return INVALID_PARAMETERS_ERR;
    }

    const char *strKeys[] = { "SourceDeviceId", "CallerAppId" };
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

    const char *numKeys[] = { "Uid", "Pid", "CallerType", "Duid" };
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
    HILOGD("end");
    return ERR_OK;
}

int32_t SinkStartCmd::UnmarshalCallerInfoExtra(std::string &jsonStr)
{
    HILOGD("called");
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
    HILOGD("end");
    return ERR_OK;
}

int32_t SinkStartCmd::UnmarshalAccountInfo(std::string &jsonStr)
{
    HILOGD("called");
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
    HILOGD("end");
    return ERR_OK;
}

int32_t NotifyResultCmd::Marshal(std::string &jsonStr)
{
    HILOGD("called");
    cJSON *rootValue = cJSON_CreateObject();
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }

    std::string baseJsonStr;
    if (BaseCmd::Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());
    cJSON_AddNumberToObject(rootValue, "SinkCollabSessionId", sinkCollabSessionId_);
    cJSON_AddNumberToObject(rootValue, "Result", result_);
    cJSON_AddStringToObject(rootValue, "SinkSocketName", sinkSocketName_.c_str());
    cJSON_AddStringToObject(rootValue, "AbilityRejectReason", abilityRejectReason_.c_str());

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    jsonStr = std::string(data);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    HILOGD("end");
    return ERR_OK;
}

int32_t NotifyResultCmd::Unmarshal(const std::string &jsonStr)
{
    HILOGD("called");
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
    if (BaseCmd::Unmarshal(baseCmdStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    cJSON *sinkCollabSessionId = cJSON_GetObjectItemCaseSensitive(rootValue, "SinkCollabSessionId");
    if (sinkCollabSessionId == nullptr || !cJSON_IsNumber(sinkCollabSessionId)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    sinkCollabSessionId_ = sinkCollabSessionId->valueint;
    cJSON *result = cJSON_GetObjectItemCaseSensitive(rootValue, "Result");
    if (result == nullptr || !cJSON_IsNumber(result)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    result_ = result->valueint;
    cJSON *sinkSocketName = cJSON_GetObjectItemCaseSensitive(rootValue, "SinkSocketName");
    if (sinkSocketName == nullptr || !cJSON_IsString(sinkSocketName)) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    sinkSocketName_ = sinkSocketName->valuestring;

    cJSON *abilityRejectReason = cJSON_GetObjectItemCaseSensitive(rootValue, "AbilityRejectReason");
    if (abilityRejectReason != nullptr && cJSON_IsString(abilityRejectReason)) {
        abilityRejectReason_ = abilityRejectReason->valuestring;
    }
    cJSON_Delete(rootValue);
    HILOGD("end");
    return ERR_OK;
}

int32_t DisconnectCmd::Marshal(std::string &jsonStr)
{
    HILOGD("called");
    cJSON *rootValue = cJSON_CreateObject();
    if (rootValue == nullptr) {
        return INVALID_PARAMETERS_ERR;
    }

    std::string baseJsonStr;
    if (BaseCmd::Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }
    jsonStr = std::string(data);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    HILOGD("end");
    return ERR_OK;
}

int32_t DisconnectCmd::Unmarshal(const std::string &jsonStr)
{
    HILOGD("called");
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
    if (BaseCmd::Unmarshal(baseCmdStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        return INVALID_PARAMETERS_ERR;
    }

    cJSON_Delete(rootValue);
    HILOGD("end");
    return ERR_OK;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
