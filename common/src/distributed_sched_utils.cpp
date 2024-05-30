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

#include "distributed_sched_utils.h"

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include "cJSON.h"

#include "ability_manager_client.h"
#include "config_policy_utils.h"

#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedSchedUtils";
const std::string CONTINUE_CONFIG_RELATIVE_PATH = "etc/distributedhardware/dms/continue_config.json";
const std::string ALLOW_APP_LIST_KEY = "allow_applist";
constexpr int32_t MAX_CONFIG_PATH_LEN = 1024;
constexpr size_t INT32_SHORT_ID_LEN = 20;
constexpr size_t INT32_MIN_ID_LEN = 6;
constexpr size_t INT32_PLAINTEXT_LEN = 4;

constexpr uint32_t OFFSET2 = 2;
constexpr uint32_t OFFSET4 = 4;
constexpr uint32_t OFFSET6 = 6;
constexpr uint8_t PARAM_FC = 0xfc;
constexpr uint8_t PARAM_03 = 0x03;
constexpr uint8_t PARAM_F0 = 0xf0;
constexpr uint8_t PARAM_0F = 0x0f;
constexpr uint8_t PARAM_C0 = 0xc0;
constexpr uint8_t PARAM_3F = 0x3f;
constexpr uint32_t INDEX_FIRST = 0;
constexpr uint32_t INDEX_SECOND = 1;
constexpr uint32_t INDEX_THIRD = 2;
constexpr uint32_t INDEX_FORTH = 3;

static std::atomic<bool> g_isMissContinueCfg = false;
static std::string g_continueCfgFullPath = "";
static std::vector<std::string> g_allowAppList;
std::mutex g_allowAppListMtx;

bool IsValidPath(const std::string &inFilePath, std::string &realFilePath)
{
    char path[PATH_MAX + 1] = { 0 };
    if (inFilePath.empty() || inFilePath.length() > PATH_MAX || inFilePath.length() + 1 > MAX_CONFIG_PATH_LEN ||
        realpath(inFilePath.c_str(), path) == nullptr) {
        HILOGE("Get continue config file real path fail, inFilePath %{public}s.", inFilePath.c_str());
        return false;
    }

    realFilePath = std::string(path);
    if (!std::filesystem::exists(realFilePath)) {
        HILOGE("The real file path %{public}s does not exist in the file system.", realFilePath.c_str());
        realFilePath = "";
        return false;
    }
    HILOGI("The real file path %{public}s exist in the file system.", realFilePath.c_str());
    return true;
}

bool UpdateAllowAppList(const std::string &cfgJsonStr)
{
    cJSON *inJson = nullptr;
    cJSON *allowList = nullptr;
    bool isSuccess = false;
    do {
        inJson = cJSON_Parse(cfgJsonStr.c_str());
        if (inJson == nullptr) {
            HILOGE("parse continue config json file stream to json fail.");
            break;
        }

        allowList = cJSON_GetObjectItem(inJson, ALLOW_APP_LIST_KEY.c_str());
        if (allowList == nullptr || !cJSON_IsArray(allowList)) {
            HILOGE("allow app list array is not in continue config json file.");
            break;
        }

        std::lock_guard<std::mutex> lock(g_allowAppListMtx);
        for (int32_t i = 0; i < cJSON_GetArraySize(allowList); i++) {
            cJSON *iAllowAppJson = cJSON_GetArrayItem(allowList, i);
            if (!cJSON_IsString(iAllowAppJson)) {
                HILOGE("allow app list [%{public}d] is not string.", i);
                continue;
            }

            std::string iAllowAppStr = std::string(cJSON_GetStringValue(iAllowAppJson));
            HILOGI("allow app list show [%{public}d] : [%{public}s].", i, iAllowAppStr.c_str());
            g_allowAppList.push_back(iAllowAppStr);
        }
        isSuccess = true;
    } while (false);

    if (inJson != nullptr) {
        cJSON_Delete(inJson);
        inJson = nullptr;
    }
    return isSuccess;
}

int32_t LoadContinueConfig()
{
    HILOGI("Load continue config, isMissContinueCfg %{public}d, ContinueCfgFullPath %{public}s.",
        g_isMissContinueCfg.load(), g_continueCfgFullPath.c_str());
    std::string tempPath = g_continueCfgFullPath;
    if (!g_isMissContinueCfg.load() &&
        (g_continueCfgFullPath.empty() || !IsValidPath(tempPath, g_continueCfgFullPath))) {
        char cfgPathBuf[MAX_CONFIG_PATH_LEN] = { 0 };
        char *filePath  = GetOneCfgFile(CONTINUE_CONFIG_RELATIVE_PATH.c_str(), cfgPathBuf, MAX_CONFIG_PATH_LEN);
        if (filePath == nullptr || filePath != cfgPathBuf) {
            HILOGI("Not find continue config file, relative path %{public}s.", CONTINUE_CONFIG_RELATIVE_PATH.c_str());
            g_isMissContinueCfg.store(true);
            g_continueCfgFullPath = "";
            return ERR_OK;
        }
        g_isMissContinueCfg.store(false);
        g_continueCfgFullPath = std::string(filePath);
        HILOGI("Get Continue config file full path success, cfgFullPath %{public}s.", g_continueCfgFullPath.c_str());
    }

    if (g_isMissContinueCfg.load()) {
        HILOGI("Current device does not carry continue config file.");
        return ERR_OK;
    }

    tempPath = g_continueCfgFullPath;
    if (!IsValidPath(tempPath, g_continueCfgFullPath)) {
        HILOGE("Continue config full path is invalid, cfgFullPath %{public}s.", g_continueCfgFullPath.c_str());
        return DMS_PERMISSION_DENIED;
    }
    std::ifstream in;
    in.open(g_continueCfgFullPath.c_str(), std::ios::binary | std::ios::in);
    if (!in.is_open()) {
        HILOGE("Open continue config json file fail, cfgFullPath %{public}s.", g_continueCfgFullPath.c_str());
        return DMS_PERMISSION_DENIED;
    }

    std::string cfgFileContent;
    in.seekg(0, std::ios::end);
    cfgFileContent.resize(in.tellg());
    in.seekg(0, std::ios::beg);
    in.rdbuf()->sgetn(&cfgFileContent[0], cfgFileContent.size());
    in.close();

    if (!UpdateAllowAppList(cfgFileContent)) {
        HILOGE("Update allow app list fail, cfgFullPath %{public}s.", g_continueCfgFullPath.c_str());
        return DMS_PERMISSION_DENIED;
    }
    HILOGI("Load continue config success, isMissContinueCfg %{public}d, cfgFullPath %{public}s.",
        g_isMissContinueCfg.load(), g_continueCfgFullPath.c_str());
    return ERR_OK;
}

bool CheckBundleContinueConfig(const std::string &bundleName)
{
    if (g_isMissContinueCfg.load()) {
        HILOGI("Current device does not carry continue config file.");
        return true;
    }

    std::lock_guard<std::mutex> lock(g_allowAppListMtx);
    auto it = std::find(g_allowAppList.begin(), g_allowAppList.end(), bundleName);
    if (it == g_allowAppList.end()) {
        HILOGE("Current app is not allow to continue in config file, bundleName %{public}s, cfgPath %{public}s.",
            bundleName.c_str(), g_continueCfgFullPath.c_str());
        return false;
    }

    HILOGI("Current app is allow to continue in config file, bundleName %{public}s, cfgPath %{public}s.",
        bundleName.c_str(), g_continueCfgFullPath.c_str());
    return true;
}

int32_t GetCurrentMissionId()
{
    HILOGI("GetCurrentMission begin");
    sptr<IRemoteObject> token;
    int ret = AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility(token);
    if (ret != ERR_OK || token == nullptr) {
        HILOGE("GetTopAbility failed, ret: %{public}d", ret);
        return INVALID_MISSION_ID;
    }
    int32_t missionId = INVALID_MISSION_ID;
    AAFwk::AbilityManagerClient::GetInstance()->GetMissionIdByToken(token, missionId);
    return missionId;
}

std::string ParcelToBase64Str(const Parcel& parcel)
{
    auto parcelSize = parcel.GetDataSize();
    return Base64Encode(reinterpret_cast<const unsigned char *>(parcel.GetData()), parcelSize);
}

int32_t Base64StrToParcel(const std::string& rawStr, Parcel& parcel)
{
    std::string str = Base64Decode(rawStr);
    auto parcelSize = str.size();
    if (!parcel.SetDataCapacity(parcelSize)) {
        return INVALID_PARAMETERS_ERR;
    }
    auto ret = memcpy_s((void *)parcel.GetData(), parcel.GetMaxCapacity(), &str[0], parcelSize);
    if (ret != ERR_OK || !parcel.SetDataSize(parcelSize)) {
        return INVALID_PARAMETERS_ERR;
    }
    return ERR_OK;
}

std::string Base64Encode(const unsigned char *toEncode, unsigned int len)
{
    std::string ret = "";
    if (len == 0 || toEncode == nullptr) {
        HILOGE("toEncode is null or len is zero.");
        return ret;
    }
    uint32_t length = len;
    uint32_t i = 0;
    unsigned char charArray3[3];
    unsigned char charArray4[4];

    while (length--) {
        charArray3[i++] = *(toEncode++);
        if (i == sizeof(charArray3)) {
            charArray4[INDEX_FIRST] = (charArray3[INDEX_FIRST] & PARAM_FC) >> OFFSET2;
            charArray4[INDEX_SECOND] = ((charArray3[INDEX_FIRST] & PARAM_03) << OFFSET4) +
                ((charArray3[INDEX_SECOND] & PARAM_F0) >> OFFSET4);
            charArray4[INDEX_THIRD] = ((charArray3[INDEX_SECOND] & PARAM_0F) << OFFSET2) +
                ((charArray3[INDEX_THIRD] & PARAM_C0) >> OFFSET6);
            charArray4[INDEX_FORTH] = charArray3[INDEX_THIRD] & PARAM_3F;
            for (i = 0; i < sizeof(charArray4); i++) {
                ret += BASE_64_CHARS[charArray4[i]];
            }
            i = 0;
        }
    }

    if (i > 0) {
        uint32_t j = 0;
        for (j = i; j < sizeof(charArray3); j++) {
            charArray3[j] = '\0';
        }
        charArray4[INDEX_FIRST] = (charArray3[INDEX_FIRST] & PARAM_FC) >> OFFSET2;
        charArray4[INDEX_SECOND] = ((charArray3[INDEX_FIRST] & PARAM_03) << OFFSET4) +
            ((charArray3[INDEX_SECOND] & PARAM_F0) >> OFFSET4);
        charArray4[INDEX_THIRD] = ((charArray3[INDEX_SECOND] & PARAM_0F) << OFFSET2) +
            ((charArray3[INDEX_THIRD] & PARAM_C0) >> OFFSET6);
        charArray4[INDEX_FORTH] = charArray3[INDEX_THIRD] & PARAM_3F;
        for (j = 0; j < i + 1; j++) {
            ret += BASE_64_CHARS[charArray4[j]];
        }
        while (i++ < sizeof(charArray3)) {
            ret += '=';
        }
    }
    return ret;
}

std::string Base64Decode(const std::string& basicString)
{
    std::string ret = "";
    if (basicString.empty()) {
        HILOGE("basicString is empty.");
        return ret;
    }
    uint32_t i = 0;
    int index = 0;
    int len = static_cast<int>(basicString.size());
    unsigned char charArray3[3];
    unsigned char charArray4[4];

    while (len-- && (basicString[index] != '=') && IsBase64(basicString[index])) {
        charArray4[i++] = basicString[index];
        index++;
        if (i == sizeof(charArray4)) {
            for (i = 0; i < sizeof(charArray4); i++) {
                charArray4[i] = BASE_64_CHARS.find(charArray4[i]);
            }
            charArray3[INDEX_FIRST] = (charArray4[INDEX_FIRST] << OFFSET2) +
                ((charArray4[INDEX_SECOND] & 0x30) >> OFFSET4);
            charArray3[INDEX_SECOND] = ((charArray4[INDEX_SECOND] & 0xf) << OFFSET4) +
                ((charArray4[INDEX_THIRD] & 0x3c) >> OFFSET2);
            charArray3[INDEX_THIRD] = ((charArray4[INDEX_THIRD] & 0x3) << OFFSET6) + charArray4[INDEX_FORTH];
            for (i = 0; i < sizeof(charArray3); i++) {
                ret += charArray3[i];
            }
            i = 0;
        }
    }

    if (i > 0) {
        uint32_t j = 0;
        for (j = i; j < sizeof(charArray4); j++) {
            charArray4[j] = 0;
        }
        for (j = 0; j < sizeof(charArray4); j++) {
            charArray4[j] = BASE_64_CHARS.find(charArray4[j]);
        }
        charArray3[INDEX_FIRST] = (charArray4[INDEX_FIRST] << OFFSET2) +
            ((charArray4[INDEX_SECOND] & 0x30) >> OFFSET4);
        charArray3[INDEX_SECOND] = ((charArray4[INDEX_SECOND] & 0xf) << OFFSET4) +
            ((charArray4[INDEX_THIRD] & 0x3c) >> OFFSET2);
        charArray3[INDEX_THIRD] = ((charArray4[INDEX_THIRD] & 0x3) << OFFSET6) + charArray4[INDEX_FORTH];
        for (j = 0; j < i - 1; j++) {
            ret += charArray3[j];
        }
    }
    return ret;
}

bool IsBase64(unsigned char c)
{
    return (isalnum(c) || (c == '+') || (c == '/'));
}

std::string GetAnonymStr(const std::string &value)
{
    std::string res;
    std::string tmpStr("******");
    size_t strLen = value.length();
    if (strLen < INT32_MIN_ID_LEN) {
        return tmpStr;
    }

    if (strLen <= INT32_SHORT_ID_LEN) {
        res += value[0];
        res += tmpStr;
        res += value[strLen - 1];
    } else {
        res.append(value, 0, INT32_PLAINTEXT_LEN);
        res += tmpStr;
        res.append(value, strLen - INT32_PLAINTEXT_LEN, INT32_PLAINTEXT_LEN);
    }

    return res;
}
} // namespace DistributedSchedule
} // namespace OHOS
