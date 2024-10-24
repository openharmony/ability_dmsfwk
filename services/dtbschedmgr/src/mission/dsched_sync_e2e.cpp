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

#include "mission/dsched_sync_e2e.h"

#include <filesystem>
#include <fstream>
#include <iostream>
#include <parameter.h>

#include "config_policy_utils.h"
#include "parameters.h"
#include "securec.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsKvSyncE2E";
const std::string BMS_KV_BASE_DIR = "/data/service/el1/public/database/DistributedSchedule";
const int32_t SLEEP_INTERVAL = 100 * 1000;  // 100ms
const int32_t EL1 = 1;
const int32_t MAX_TIMES = 600;              // 1min
const char DETERMINE_DEVICE_TYPE_KEY[] = "persist.distributed_scene.sys_settings_data_sync";
static const int32_t FORBID_SEND_FORBID_RECV = 0;
static const int32_t ALLOW_SEND_ALLOW_RECV = 1;
const std::string PARAM_DISTRIBUTED_DATAFILES_TRANS_CTRL = "persist.distributed_scene.datafiles_trans_ctrl";
const std::string CONTINUE_CONFIG_RELATIVE_PATH = "etc/distributedhardware/dms/continue_config.json";
const std::string ALLOW_APP_LIST_KEY = "allow_applist";
constexpr int32_t MAX_CONFIG_PATH_LEN = 1024;
}  // namespace

std::shared_ptr<DmsKvSyncE2E> DmsKvSyncE2E::instance_ = nullptr;
std::mutex DmsKvSyncE2E::mutex_;

DmsKvSyncE2E::DmsKvSyncE2E()
{
    HILOGD("called.");
    TryTwice([this] { return GetKvStore(); });
    HILOGD("end.");
}

DmsKvSyncE2E::~DmsKvSyncE2E()
{
    HILOGD("called.");
    dataManager_.CloseKvStore(appId_, storeId_);
    HILOGD("end.");
}

std::shared_ptr<DmsKvSyncE2E> DmsKvSyncE2E::GetInstance()
{
    HILOGD("called.");
    std::lock_guard<std::mutex> lock(mutex_);
    if (instance_ == nullptr) {
        instance_ = std::make_shared<DmsKvSyncE2E>();
    }
    HILOGD("end.");
    return instance_;
}

void DmsKvSyncE2E::SetDeviceCfg()
{
    HILOGD("called.");
    const char *syncType = "1";
    const int bufferLen = 10;
    char paramOutBuf[bufferLen] = {0};
    int ret = GetParameter(DETERMINE_DEVICE_TYPE_KEY, "", paramOutBuf, bufferLen);
    HILOGD("paramOutBuf: %{public}s, ret: %{public}d", paramOutBuf, ret);
    if (ret > 0 && strncmp(paramOutBuf, syncType, strlen(syncType)) == 0) {
        HILOGI("Determining the e2e device succeeded.");
        isCfgDevices_ = true;
    }

    auto contralType = OHOS::system::GetIntParameter(PARAM_DISTRIBUTED_DATAFILES_TRANS_CTRL,
        ALLOW_SEND_ALLOW_RECV);
    HILOGI("contralType=%{public}d", contralType);
    if (contralType == FORBID_SEND_FORBID_RECV) {
        isForbidSendAndRecv_ = true;
    }

    int32_t result = LoadContinueConfig();
    if (result != ERR_OK) {
        HILOGE("Load continue config fail, result %{public}d.", result);
    }
}

bool DmsKvSyncE2E::CheckDeviceCfg()
{
    HILOGD("called.");
    return isCfgDevices_;
}

bool DmsKvSyncE2E::CheckCtrlRule()
{
    HILOGD("called.");
    if (isCfgDevices_ && isForbidSendAndRecv_) {
        HILOGE("The device is a special device and checkCtrlRule fail");
        return false;
    }
    return true;
}

bool DmsKvSyncE2E::IsValidPath(const std::string &inFilePath, std::string &realFilePath)
{
    char path[PATH_MAX + 1] = { 0 };
    if (inFilePath.empty() || inFilePath.length() > PATH_MAX || inFilePath.length() + 1 > MAX_CONFIG_PATH_LEN ||
        realpath(inFilePath.c_str(), path) == nullptr) {
        HILOGE("Get continue config file real path fail, inFilePath %{public}s.", GetAnonymStr(inFilePath).c_str());
        return false;
    }

    realFilePath = std::string(path);
    if (realFilePath.empty()) {
        HILOGE("Real file path is empty.");
        return false;
    }
    if (!std::filesystem::exists(realFilePath)) {
        HILOGE("The real file path %{public}s does not exist in the file system.", GetAnonymStr(realFilePath).c_str());
        realFilePath = "";
        return false;
    }
    HILOGD("The real file path %{public}s exist in the file system.", GetAnonymStr(realFilePath).c_str());
    return true;
}

bool DmsKvSyncE2E::UpdateWhiteList(const std::string &cfgJsonStr)
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

        std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
        for (int32_t i = 0; i < cJSON_GetArraySize(allowList); i++) {
            cJSON *iAllowAppJson = cJSON_GetArrayItem(allowList, i);
            if (!cJSON_IsString(iAllowAppJson)) {
                HILOGE("allow app list [%{public}d] is not string.", i);
                continue;
            }

            std::string iAllowAppStr = std::string(cJSON_GetStringValue(iAllowAppJson));
            HILOGI("allow app list show [%{public}d] : [%{public}s].", i, iAllowAppStr.c_str());
            whiteList_.push_back(iAllowAppStr);
        }
        isSuccess = true;
    } while (false);

    if (inJson != nullptr) {
        cJSON_Delete(inJson);
        inJson = nullptr;
    }
    return isSuccess;
}

int32_t DmsKvSyncE2E::LoadContinueConfig()
{
    HILOGD("Load continue config, continueCfgFullPath %{public}s.", GetAnonymStr(continueCfgFullPath_).c_str());
    std::string tempPath = continueCfgFullPath_;
    if ((continueCfgFullPath_.empty() || !IsValidPath(tempPath, continueCfgFullPath_))) {
        char cfgPathBuf[MAX_CONFIG_PATH_LEN] = { 0 };
        char *filePath  = GetOneCfgFile(CONTINUE_CONFIG_RELATIVE_PATH.c_str(), cfgPathBuf, MAX_CONFIG_PATH_LEN);
        if (filePath == nullptr || filePath != cfgPathBuf) {
            HILOGE("Not find continue config file, relative path %{public}s.",
                GetAnonymStr(CONTINUE_CONFIG_RELATIVE_PATH).c_str());
            continueCfgFullPath_ = "";
            return ERR_OK;
        }
        continueCfgFullPath_ = std::string(filePath);
        HILOGD("Get Continue config file full path success, cfgFullPath %{public}s.",
            GetAnonymStr(continueCfgFullPath_).c_str());
    }

    tempPath = continueCfgFullPath_;
    if (!IsValidPath(tempPath, continueCfgFullPath_)) {
        HILOGE("Continue config full path is invalid, cfgFullPath %{public}s.",
            GetAnonymStr(continueCfgFullPath_).c_str());
        return DMS_PERMISSION_DENIED;
    }
    std::ifstream in;
    in.open(continueCfgFullPath_.c_str(), std::ios::binary | std::ios::in);
    if (!in.is_open()) {
        HILOGE("Open continue config json file fail, cfgFullPath %{public}s.",
            GetAnonymStr(continueCfgFullPath_).c_str());
        return DMS_PERMISSION_DENIED;
    }

    std::string cfgFileContent;
    in.seekg(0, std::ios::end);
    cfgFileContent.resize(in.tellg());
    in.seekg(0, std::ios::beg);
    in.rdbuf()->sgetn(&cfgFileContent[0], cfgFileContent.size());
    in.close();

    if (!UpdateWhiteList(cfgFileContent)) {
        HILOGE("Update allow app list fail, cfgFullPath %{public}s.",
            GetAnonymStr(continueCfgFullPath_).c_str());
        return DMS_PERMISSION_DENIED;
    }
    HILOGD("Load continue config success, cfgFullPath %{public}s.", GetAnonymStr(continueCfgFullPath_).c_str());
    return ERR_OK;
}

bool DmsKvSyncE2E::CheckBundleContinueConfig(const std::string &bundleName)
{
    if (!isCfgDevices_) {
        HILOGD("The device is a normal device");
        return true;
    }

    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    auto it = std::find(whiteList_.begin(), whiteList_.end(), bundleName);
    if (it == whiteList_.end()) {
        HILOGE("Current app is not allow to continue in config file, bundleName %{public}s, cfgPath %{public}s.",
            bundleName.c_str(), GetAnonymStr(continueCfgFullPath_).c_str());
        return false;
    }

    HILOGD("Current app is allow to continue in config file, bundleName %{public}s, cfgPath %{public}s.",
        bundleName.c_str(), GetAnonymStr(continueCfgFullPath_).c_str());
    return true;
}

bool DmsKvSyncE2E::PushAndPullData()
{
    HILOGI("called.");
    std::vector<std::string> networkIdList = DtbschedmgrDeviceInfoStorage::GetInstance().GetNetworkIdList();
    if (networkIdList.empty()) {
        HILOGE("GetNetworkIdList failed");
        return false;
    }
    if (!CheckKvStore()) {
        HILOGE("kvStore is nullptr");
        return false;
    }
    DistributedKv::DataQuery dataQuery;
    std::shared_ptr<DmsKvSyncCB> syncCallback = std::make_shared<DmsKvSyncCB>();
    Status status = kvStorePtr_->Sync(networkIdList, DistributedKv::SyncMode::PUSH_PULL, dataQuery, syncCallback);
    if (status != Status::SUCCESS) {
        HILOGE("sync error: %{public}d", status);
        return false;
    }
    HILOGI("Synchronizing");
    return true;
}

bool DmsKvSyncE2E::PushAndPullData(const std::string &networkId)
{
    HILOGI("called.");
    if (!CheckDeviceCfg() && IsSynchronized(networkId)) {
        HILOGW("The normal device been synchronized : %{public}s", GetAnonymStr(networkId).c_str());
        return false;
    }
    std::vector<std::string> networkIdList = {networkId};
    if (!CheckKvStore()) {
        HILOGE("kvStore is nullptr");
        return false;
    }

    SetSyncRecord(networkId);
    DistributedKv::DataQuery dataQuery;
    std::shared_ptr<DmsKvSyncCB> syncCallback = std::make_shared<DmsKvSyncCB>();
    Status status = kvStorePtr_->Sync(networkIdList, DistributedKv::SyncMode::PUSH_PULL, dataQuery, syncCallback);
    if (status != Status::SUCCESS) {
        HILOGE("sync error: %{public}d", status);
        return false;
    }
    HILOGI("Synchronizing");
    return true;
}

void DmsKvSyncE2E::SetSyncRecord(const std::string &networkId)
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    deviceSyncRecord_.insert(std::make_pair(networkId, true));
}

void DmsKvSyncE2E::ClearSyncRecord(const std::string &networkId)
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    auto it = deviceSyncRecord_.find(networkId);
    if (it != deviceSyncRecord_.end()) {
        deviceSyncRecord_.erase(it);
        HILOGI("Successfully cleared synchronization records for: %{public}s", GetAnonymStr(networkId).c_str());
    } else {
        HILOGI("No need to clean up for: %{public}s", GetAnonymStr(networkId).c_str());
    }
}

bool DmsKvSyncE2E::IsSynchronized(const std::string &networkId)
{
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (deviceSyncRecord_.find(networkId) != deviceSyncRecord_.end() && deviceSyncRecord_[networkId]) {
        return true;
    }
    return false;
}

bool DmsKvSyncE2E::CheckKvStore()
{
    HILOGD("called.");
    std::lock_guard<std::mutex> lock(kvStorePtrMutex_);
    if (kvStorePtr_ != nullptr) {
        return true;
    }
    int32_t tryTimes = MAX_TIMES;
    while (tryTimes > 0) {
        Status status = GetKvStore();
        if (status == Status::SUCCESS && kvStorePtr_ != nullptr) {
            return true;
        }
        HILOGW("CheckKvStore, Times: %{public}d", tryTimes);
        usleep(SLEEP_INTERVAL);
        tryTimes--;
    }
    HILOGD("end.");
    return kvStorePtr_ != nullptr;
}

Status DmsKvSyncE2E::GetKvStore()
{
    HILOGD("called.");
    Options options = {
        .createIfMissing = true,
        .encrypt = false,
        .autoSync = false,
        .isPublic = true,
        .securityLevel = SecurityLevel::S1,
        .area = EL1,
        .kvStoreType = KvStoreType::SINGLE_VERSION,
        .baseDir = BMS_KV_BASE_DIR,
        .dataType = DataType::TYPE_DYNAMICAL,
        .cloudConfig = {
            .enableCloud = true,
            .autoSync = true
        },
    };
    Status status = dataManager_.GetSingleKvStore(options, appId_, storeId_, kvStorePtr_);
    if (status == Status::SUCCESS) {
        HILOGD("get kvStore success");
    } else if (status == DistributedKv::Status::STORE_META_CHANGED) {
        HILOGE("This db meta changed, remove and rebuild it");
        dataManager_.DeleteKvStore(appId_, storeId_, BMS_KV_BASE_DIR + appId_.appId);
    }
    HILOGD("end.");
    return status;
}

void DmsKvSyncE2E::TryTwice(const std::function<Status()> &func) const
{
    HILOGD("called.");
    Status status = func();
    if (status != Status::SUCCESS) {
        status = func();
        HILOGW("error and try to call again, result = %{public}d", status);
    }
    HILOGD("end.");
}

DmsKvSyncCB::DmsKvSyncCB()
{
    HILOGD("create");
}

DmsKvSyncCB::~DmsKvSyncCB()
{
    HILOGD("destroy");
}

void DmsKvSyncCB::SyncCompleted(const std::map<std::string, DistributedKv::Status> &result)
{
    HILOGI("kvstore sync completed.");
    for (auto ele : result) {
        HILOGI("uuid: %{public}s , result: %{public}d", GetAnonymStr(ele.first).c_str(), ele.second);
    }
}
}  // namespace DistributedSchedule
}  // namespace OHOS
