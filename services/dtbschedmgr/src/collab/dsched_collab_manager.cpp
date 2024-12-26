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

#include "dsched_collab_manager.h"

#include <chrono>
#include <random>
#include <ctime>
#include <sys/prctl.h>

#include "cJSON.h"

#include "distributed_sched_utils.h"
#include "dsched_transport_softbus_adapter.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "mission/distributed_bm_storage.h"
#include "mission/wifi_state_adapter.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedCollabManager";
const std::string DSCHED_COLLAB_MANAGER = "dsched_collab_manager";
const int32_t RANDOM_MAX = 100;
const int32_t RANDOM_STRING_LENGTH = 20;
const char* RANDOM_SOURCE =
    "abcdefghijklmnopqrsstuvwwxyzABCDDEFGHIJKLMMNOPQRSTUVWXXYZ1234567890!@#$%^&*()_+-={}:<>?[]\\|;\"',./~`";
std::map<int32_t, std::string> CMDDATA = {
    {MIN_CMD, "MIN_CMD"},
    {SINK_START_CMD, "SINK_START_CMD"},
    {NOTIFY_RESULT_CMD, "NOTIFY_RESULT_CMD"},
    {DISCONNECT_CMD, "DISCONNECT_CMD"},
    {MAX_CMD, "MAX_CMD"},
};
}

IMPLEMENT_SINGLE_INSTANCE(DSchedCollabManager);

DSchedCollabManager::DSchedCollabManager()
{
}

DSchedCollabManager::~DSchedCollabManager()
{
    HILOGI("DSchedCollabManager delete");
    UnInit();
}

void DSchedCollabManager::Init()
{
    HILOGI("Init DSchedCollabManager start");
    if (eventHandler_ != nullptr) {
        HILOGI("DSchedCollabManager already inited, end.");
        return;
    }
    DSchedTransportSoftbusAdapter::GetInstance().InitChannel();
    softbusListener_ = std::make_shared<DSchedCollabManager::SoftbusListener>();
    DSchedTransportSoftbusAdapter::GetInstance().RegisterListener(SERVICE_TYPE_COLLAB, softbusListener_);
    eventThread_ = std::thread(&DSchedCollabManager::StartEvent, this);
    std::unique_lock<std::mutex> lock(eventMutex_);
    eventCon_.wait(lock, [this] {
        return eventHandler_ != nullptr;
    });
    HILOGI("Init DSchedCollabManager end");
}

void DSchedCollabManager::StartEvent()
{
    HILOGI("called");
    prctl(PR_SET_NAME, DSCHED_COLLAB_MANAGER.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    if (runner == nullptr) {
        HILOGE("runner is nullptr");
        return;
    }
    runner->Run();
    HILOGI("StartEvent end");
}

void DSchedCollabManager::UnInit()
{
    HILOGI("UnInit start");
    DSchedTransportSoftbusAdapter::GetInstance().UnregisterListener(SERVICE_TYPE_COLLAB, softbusListener_);
    DSchedTransportSoftbusAdapter::GetInstance().ReleaseChannel();
    collabs_.clear();

    if (eventHandler_ != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        eventThread_.join();
        eventHandler_ = nullptr;
    } else {
        HILOGE("eventHandler is nullptr");
    }
    HILOGI("UnInit end");
}

int32_t DSchedCollabManager::CollabMission(DSchedCollabInfo &info)
{
    HILOGI("called, collabInfo is: %{public}s", info.ToString().c_str());
    if (info.srcClientCB_ == nullptr) {
        HILOGE("clientCB is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    if (info.srcInfo_.bundleName_.empty() || info.srcInfo_.bundleName_.empty() ||
        info.srcInfo_.moduleName_.empty() || info.srcInfo_.moduleName_.empty() ||
        info.srcInfo_.abilityName_.empty() || info.srcInfo_.abilityName_.empty()) {
        HILOGE("input parameter validation error!");
        return INVALID_PARAMETERS_ERR;
    }
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(info.srcInfo_.deviceId_)) {
        HILOGE("get local deviceId failed!");
        return FIND_LOCAL_DEVICEID_ERR;
    }
    if (DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(info.sinkInfo_.deviceId_) == nullptr) {
        HILOGE("failed to find sinkDeviceId.");
        return FIND_REMOTE_DEVICEID_ERR;
    }
    if (IsSessionExists(info)) {
        HILOGE("a same collab session is already in progress.");
        return COLLAB_ALREADY_IN_PROGRESS;
    }
    auto func = [this, info]() {
        HandleCollabMission(info);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    eventHandler_->PostTask(func);
    return ERR_OK;
}

bool DSchedCollabManager::IsSessionExists(const DSchedCollabInfo &info)
{
    HILOGI("called");
    for (const auto& pair : collabs_) {
        if (pair.second == nullptr) {
            continue;
        }
        DSchedCollabInfo existCollabInfo = pair.second->GetCollabInfo();
        if (existCollabInfo.srcInfo_.pid_ == info.srcInfo_.pid_ &&
            existCollabInfo.srcCollabSessionId_ == info.srcCollabSessionId_) {
            return true;
        }
    }
    return false;
}

void DSchedCollabManager::HandleCollabMission(const DSchedCollabInfo &info)
{
    HILOGI("called");
    const std::string collabToken = GenerateCollabToken(info.srcInfo_.deviceId_);
    auto newCollab = std::make_shared<DSchedCollab>(collabToken, info);
    newCollab->Init();
    newCollab->UpdateState(SOURCE_START_STATE);
    collabs_.insert(std::make_pair(collabToken, newCollab));
    newCollab->PostSrcStartTask();
    SetTimeOut(collabToken, COLLAB_TIMEOUT);

#ifdef DMSFWK_ALL_CONNECT_MGR
    if (!DSchedTransportSoftbusAdapter::GetInstance().IsNeedAllConnect()) {
        HILOGW("don't need wait all connect decision");
        return;
    }
    const std::string sinkDeviceId = info.sinkInfo_.deviceId_;
    if (peerConnectDecision_.find(sinkDeviceId) != peerConnectDecision_.end()) {
        peerConnectDecision_.erase(sinkDeviceId);
    }
    WaitAllConnectDecision(sinkDeviceId, newCollab);
#endif
    HILOGI("end");
}

std::string DSchedCollabManager::GenerateCollabToken(const std::string &srcDeviceId)
{
    HILOGI("called");
    std::string collabToken;
    std::string randomValue;
    randomValue.resize(RANDOM_STRING_LENGTH);
    bool isUnique = false;
    while (!isUnique) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, RANDOM_MAX);
        for (size_t i = 0; i < RANDOM_STRING_LENGTH; ++i) {
            randomValue[i] = RANDOM_SOURCE[dis(gen)];
        }
        collabToken = srcDeviceId + randomValue;
        if (collabs_.count(collabToken) == 0) {
            isUnique = true;
        }
    }
    HILOGI("end");
    return collabToken;
}

void DSchedCollabManager::SetTimeOut(const std::string &collabToken, int32_t timeout)
{
    HILOGI("called, collabToken: %{public}s", collabToken.c_str());
    auto func = [this, collabToken]() {
        if (collabs_.count(collabToken) == 0) {
            HILOGW("collab not exist.");
            return;
        }
        HILOGE("collab timeout! info: %{public}s", collabToken.c_str());
        auto dCollab = collabs_[collabToken];
        if (dCollab != nullptr) {
            dCollab->PostErrEndTask(COLLAB_ABILITY_TIMEOUT_ERR);
        }
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return;
    }
    timeout > 0 ? eventHandler_->PostTask(func, collabToken, timeout) :
        eventHandler_->PostTask(func);
}

void DSchedCollabManager::RemoveTimeout(const std::string &collabToken)
{
    HILOGI("called, collabToken: %{public}s", collabToken.c_str());
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return;
    }
    eventHandler_->RemoveTask(collabToken);
}

void DSchedCollabManager::WaitAllConnectDecision(const std::string &peerDeviceId,
    const std::shared_ptr<DSchedCollab> &dCollab)
{
#ifdef DMSFWK_ALL_CONNECT_MGR
    {
        HILOGI("called");
        std::unique_lock<std::mutex> decisionLock(connectDecisionMutex_);
        connectDecisionCond_.wait_for(decisionLock, std::chrono::seconds(CONNECT_DECISION_TIME_OUT),
            [this, peerDeviceId]() {
                return peerConnectDecision_.find(peerDeviceId) != peerConnectDecision_.end() &&
                    peerConnectDecision_.at(peerDeviceId).load();
            });

        if (peerConnectDecision_.find(peerDeviceId) == peerConnectDecision_.end()) {
            HILOGE("Not find peerDeviceId %{public}s in peerConnectDecision.", GetAnonymStr(peerDeviceId).c_str());
            if (dCollab != nullptr) {
                dCollab->PostErrEndTask(COLLAB_ABILITY_TIMEOUT_ERR);
            }
            return;
        }
        if (!peerConnectDecision_.at(peerDeviceId).load()) {
            HILOGE("All connect manager refuse bind to PeerDeviceId %{public}s.", GetAnonymStr(peerDeviceId).c_str());
            peerConnectDecision_.erase(peerDeviceId);
            if (dCollab != nullptr) {
                dCollab->PostErrEndTask(COLLAB_ABILITY_TIMEOUT_ERR);
            }
            return;
        }
        peerConnectDecision_.erase(peerDeviceId);
        HILOGI("end");
    }
#endif
}

void DSchedCollabManager::NotifyAllConnectDecision(std::string peerDeviceId, bool isSupport)
{
    HILOGI("Notify all connect decision, peerDeviceId %{public}s, isSupport %{public}d.",
        GetAnonymStr(peerDeviceId).c_str(), isSupport);
#ifdef DMSFWK_ALL_CONNECT_MGR
    std::lock_guard<std::mutex> decisionLock(connectDecisionMutex_);
    peerConnectDecision_[peerDeviceId] = isSupport;
    connectDecisionCond_.notify_all();
#endif
}

int32_t DSchedCollabManager::NotifyStartAbilityResult(const std::string& collabToken, const int32_t &result,
    const int32_t &sinkPid, const int32_t &sinkUid, const int32_t &sinkAccessTokenId)
{
    HILOGI("called, result %{public}d", result);
    auto dCollab = GetDSchedCollabByTokenId(collabToken);
    if (dCollab == nullptr) {
        HILOGE("can't find collab");
        return INVALID_PARAMETERS_ERR;
    }
    if (result != ERR_OK) {
        HILOGE("start ability failed");
        return dCollab->PostErrEndTask(REMOTE_DEVICE_START_ABILITY_ERR);
    }
    dCollab->SaveSinkAbilityData(collabToken, result, sinkPid, sinkUid, sinkAccessTokenId);
    HILOGI("end, info: %{public}s.", dCollab->GetCollabInfo().ToString().c_str());
    return ERR_OK;
}

int32_t DSchedCollabManager::NotifySinkPrepareResult(const std::string &collabToken, const int32_t &result,
    const int32_t &collabSessionId, const std::string &socketName, const sptr<IRemoteObject> &clientCB)
{
    HILOGI("called, collabToken: %{public}s, collabSessionId: %{public}d, result: %{public}d, socketName: %{public}s",
        collabToken.c_str(), collabSessionId, result, socketName.c_str());
    auto func = [this, collabToken, result, collabSessionId, socketName, clientCB]() {
        HandleCollabPrepareResult(collabToken, result, collabSessionId, socketName, clientCB);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    eventHandler_->PostTask(func);
    return ERR_OK;
}

void DSchedCollabManager::HandleCollabPrepareResult(const std::string &collabToken, const int32_t &result,
    const int32_t &collabSessionId, const std::string &socketName, const sptr<IRemoteObject> &clientCB)
{
    HILOGI("called");
    auto dCollab = GetDSchedCollabByTokenId(collabToken);
    if (dCollab == nullptr) {
        HILOGE("not find dCollab");
        return;
    }
    dCollab->PostSinkPrepareResultTask(result, collabSessionId, socketName, clientCB);
    RemoveTimeout(collabToken);
    HILOGI("end, info: %{public}s.", dCollab->GetCollabInfo().ToString().c_str());
    return;
}

std::string DSchedCollabManager::GetSrcSocketName(const std::string& collabToken)
{
    HILOGI("called");
    auto dCollab = GetDSchedCollabByTokenId(collabToken);
    if (dCollab != nullptr) {
        return dCollab->GetCollabInfo().srcInfo_.socketName_;
    }
    HILOGE("not find dCollab");
    return "";
}

int32_t DSchedCollabManager::NotifyAbilityDied(const std::string &bundleName, const int32_t &pid)
{
    HILOGI("called");
    auto func = [this, bundleName, pid]() {
        HandleCloseSessions(bundleName, pid);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    eventHandler_->PostTask(func);
    return ERR_OK;
}

int32_t DSchedCollabManager::HandleCloseSessions(const std::string &bundleName, const int32_t &pid)
{
    HILOGI("called");
    DSchedCollabInfo dSchedCollabInfo;
    for (auto iter = collabs_.begin(); iter != collabs_.end(); iter++) {
        if (iter->second == nullptr) {
            continue;
        }
        dSchedCollabInfo = iter->second->GetCollabInfo();
        if ((bundleName == dSchedCollabInfo.srcInfo_.bundleName_ && pid == dSchedCollabInfo.srcInfo_.pid_) ||
            (bundleName == dSchedCollabInfo.srcInfo_.bundleName_ && pid == dSchedCollabInfo.sinkInfo_.pid_)) {
            HILOGI("find collab, need be clear, collabInfo: %{public}s", dSchedCollabInfo.ToString().c_str());
            return iter->second->PostEndTask();
        }
    }
    return ERR_OK;
}

int32_t DSchedCollabManager::ReleaseAbilityLink(const std::string &bundleName, const int32_t &pid)
{
    HILOGW("called, disconnect the existing link after 5S");
    auto func = [this, bundleName, pid]() {
        HandleReleaseAbilityLink(bundleName, pid);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    const std::string taskName = bundleName + std::to_string(pid);
    eventHandler_->PostTask(func, taskName, BACKGROUND_TIMEOUT);
    return ERR_OK;
}

void DSchedCollabManager::HandleReleaseAbilityLink(const std::string &bundleName, const int32_t &pid)
{
    HILOGI("called");
    DSchedCollabInfo dSchedCollabInfo;
    for (auto iter = collabs_.begin(); iter != collabs_.end(); iter++) {
        if (iter->second == nullptr) {
            continue;
        }
        dSchedCollabInfo = iter->second->GetCollabInfo();
        if (bundleName == dSchedCollabInfo.srcInfo_.bundleName_ && pid == dSchedCollabInfo.srcInfo_.pid_ &&
            CheckBackgroundPermissions() == true) {
            HILOGI("source ability has retired, collabInfo: %{public}s", dSchedCollabInfo.ToString().c_str());
            iter->second->PostEndTask();
        }
        if (bundleName == dSchedCollabInfo.srcInfo_.bundleName_ && pid == dSchedCollabInfo.sinkInfo_.pid_ &&
            CheckBackgroundPermissions() == true) {
            HILOGI("sink ability has retired, collabInfo: %{public}s", dSchedCollabInfo.ToString().c_str());
            iter->second->PostEndTask();
        }
    }
    return;
}

bool DSchedCollabManager::CheckBackgroundPermissions()
{
    return false;
}

int32_t DSchedCollabManager::CancleReleaseAbilityLink(const std::string &bundleName, const int32_t &pid)
{
    HILOGW("called");
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    const std::string taskName = bundleName + std::to_string(pid);
    eventHandler_->RemoveTask(taskName);
    return ERR_OK;
}

int32_t DSchedCollabManager::NotifySessionClose(const std::string &collabToken)
{
    HILOGI("called, collabToken: %{public}s", collabToken.c_str());
    auto dCollab = GetDSchedCollabByTokenId(collabToken);
    if (dCollab == nullptr) {
        HILOGE("can't find collab");
        return INVALID_PARAMETERS_ERR;
    }
    dCollab->PostEndTask();
    HILOGI("end.");
    return ERR_OK;
}

int32_t DSchedCollabManager::CleanUpSession(const std::string &collabToken)
{
    HILOGI("called, collabToken: %{public}s", collabToken.c_str());
    auto dCollab = GetDSchedCollabByTokenId(collabToken);
    if (dCollab == nullptr) {
        HILOGE("can't find collab");
        return INVALID_PARAMETERS_ERR;
    }
    RemoveTimeout(collabToken);
    collabs_.erase(collabToken);
    HILOGI("end.");
    return ERR_OK;
}

std::shared_ptr<DSchedCollab> DSchedCollabManager::GetDSchedCollabByTokenId(const std::string &tokenId)
{
    HILOGI("called, tokenId: %{public}s", tokenId.c_str());
    if (tokenId.empty() || collabs_.count(tokenId) == 0) {
        HILOGE("no such collaboration in progress.");
        return nullptr;
    }
    return collabs_[tokenId];
}

void DSchedCollabManager::OnDataRecv(int32_t softbusSessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    auto func = [this, softbusSessionId, dataBuffer]() {
        HandleDataRecv(softbusSessionId, dataBuffer);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return;
    }
    eventHandler_->PostTask(func);
}

void DSchedCollabManager::HandleDataRecv(const int32_t &softbusSessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    HILOGI("called, softbusSessionId: %{public}d.", softbusSessionId);
    if (dataBuffer == nullptr) {
        HILOGE("dataBuffer is null.");
        return;
    }
    uint8_t *data = dataBuffer->Data();
    std::string jsonStr(reinterpret_cast<const char *>(data), dataBuffer->Capacity());
    cJSON *rootValue = cJSON_Parse(jsonStr.c_str());
    if (rootValue == nullptr) {
        HILOGE("Parse jsonStr error.");
        return;
    }
    cJSON *baseCmd = cJSON_GetObjectItemCaseSensitive(rootValue, "BaseCmd");
    if (baseCmd == nullptr || !cJSON_IsString(baseCmd) || (baseCmd->valuestring == nullptr)) {
        cJSON_Delete(rootValue);
        HILOGE("Parse base cmd error.");
        return;
    }

    cJSON *cmdValue = cJSON_Parse(baseCmd->valuestring);
    cJSON_Delete(rootValue);
    if (cmdValue == nullptr) {
        HILOGE("Parse cmd value error.");
        return;
    }

    cJSON *comvalue = cJSON_GetObjectItemCaseSensitive(cmdValue, "Command");
    if (comvalue == nullptr || !cJSON_IsNumber(comvalue)) {
        cJSON_Delete(cmdValue);
        HILOGE("parse command failed");
        return;
    }
    int32_t command = comvalue->valueint;
    cJSON_Delete(cmdValue);
    NotifyDataRecv(softbusSessionId, command, jsonStr, dataBuffer);
    HILOGI("end");
}

void DSchedCollabManager::NotifyDataRecv(const int32_t &softbusSessionId, int32_t command, const std::string& jsonStr,
    std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    HILOGI("called, parsed cmd %{public}s", CMDDATA[command].c_str());
    for (auto iter = collabs_.begin(); iter != collabs_.end(); iter++) {
        if (iter->second != nullptr && softbusSessionId == iter->second->GetSoftbusSessionId()) {
            HILOGI("softbusSessionId exist.");
            iter->second->OnDataRecv(command, dataBuffer);
            if (command == NOTIFY_RESULT_CMD) {
                RemoveTimeout(iter->first);
            }
            return;
        }
    }
    if (command == SINK_START_CMD) {
        auto startCmd = std::make_shared<SinkStartCmd>();
        int32_t ret = startCmd->Unmarshal(jsonStr);
        if (ret != ERR_OK) {
            HILOGE("Unmarshal start cmd failed, ret: %{public}d", ret);
            return;
        }
        std::string localDevId;
        if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDevId)) {
            HILOGE("get local deviceId failed!");
            return;
        }
        if (startCmd->sinkDeviceId_ != localDevId ||
            DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(startCmd->srcDeviceId_) == nullptr) {
            HILOGE("Irrecognized deviceId! sinkDeviceId: %{public}s, srcDeviceId: %{public}s",
                startCmd->sinkDeviceId_.c_str(), startCmd->srcDeviceId_.c_str());
            return;
        }
        auto newCollab = std::make_shared<DSchedCollab>(startCmd, softbusSessionId);
        newCollab->Init();
        newCollab->UpdateState(SINK_START_STATE);
        collabs_.insert(std::make_pair(startCmd->collabToken_, newCollab));
        newCollab->PostSinkStartTask();
        SetTimeOut(startCmd->collabToken_, COLLAB_TIMEOUT);
        HILOGI("end");
        return;
    }
    HILOGE("No matching session to handle cmd!");
    return;
}

void DSchedCollabManager::OnShutdown(int32_t socket, bool isSelfCalled)
{
    HILOGW("called,softbusSessionId: %{public}d, isSelfCalled: %{public}d", socket, isSelfCalled);
    if (isSelfCalled) {
        HILOGW("called, shutdown by local");
        return;
    }
    auto func = [this, socket]() {
        if (collabs_.empty()) {
            return;
        }
        for (auto iter = collabs_.begin(); iter != collabs_.end(); iter++) {
            if (iter->second != nullptr && socket == iter->second->GetSoftbusSessionId()) {
                HILOGE("collab: %{public}s", iter->second->GetCollabInfo().ToString().c_str());
                iter->second->PostErrEndTask(COLLAB_SESSION_SHUTDOWN);
            }
        }
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler is nullptr");
        return;
    }
    eventHandler_->PostTask(func);
    return;
}

void DSchedCollabManager::SoftbusListener::OnBind(int32_t socket, PeerSocketInfo info)
{
}

void DSchedCollabManager::SoftbusListener::OnShutdown(int32_t socket, bool isSelfCalled)
{
    DSchedCollabManager::GetInstance().OnShutdown(socket, isSelfCalled);
}

void DSchedCollabManager::SoftbusListener::OnDataRecv(int32_t socket, std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    DSchedCollabManager::GetInstance().OnDataRecv(socket, dataBuffer);
}
}  // namespace DistributedSchedule
}  // namespace OHOS
