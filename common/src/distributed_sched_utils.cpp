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

#include "config_policy_utils.h"

#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedSchedUtils";
const std::string CONTINUE_CONFIG_RELATIVE_PATH = "etc/distributedhardware/dms/continue_config.json";
const std::string ALLOW_APP_LIST_KEY = "allow_applist";
constexpr int32_t MAX_CONFIG_PATH_LEN = 1024;

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

    std::string CfgFileContent;
    in.seekg(0, std::ios::end);
    CfgFileContent.resize(in.tellg());
    in.seekg(0, std::ios::beg);
    in.rdbuf()->sgetn(&CfgFileContent[0], CfgFileContent.size());
    in.close();

    if (!UpdateAllowAppList(CfgFileContent)) {
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
} // namespace DistributedSchedule
} // namespace OHOS
