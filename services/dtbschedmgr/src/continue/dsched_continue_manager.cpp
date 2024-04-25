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

#include "dsched_continue_manager.h"

#include <sys/prctl.h>
#include <map>

#include "adapter/dnetwork_adapter.h"
#include "cJSON.h"
#include "dsched_transport_softbus_adapter.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedContinueManager";
const std::string DSCHED_CONTINUE_MANAGER = "dsched_continue_manager";
const std::string CONTINUE_TIMEOUT_TASK = "continue_timeout_task";

}

IMPLEMENT_SINGLE_INSTANCE(DSchedContinueManager);

DSchedContinueManager::DSchedContinueManager()
{
}

DSchedContinueManager::~DSchedContinueManager()
{
    HILOGI("DSchedContinueManager delete");
    UnInit();
}

void DSchedContinueManager::Init()
{
    HILOGI("Init DSchedContinueManager start");
    DSchedTransportSoftbusAdapter::GetInstance().InitChannel();
    softbusListener_ = std::make_shared<DSchedContinueManager::SoftbusListener>();
    DSchedTransportSoftbusAdapter::GetInstance().RegisterListener(SERVICE_TYPE_CONTINUE, softbusListener_);
    eventThread_ = std::thread(&DSchedContinueManager::StartEvent, this);
    std::unique_lock<std::mutex> lock(eventMutex_);
    eventCon_.wait(lock, [this] {
        return eventHandler_ != nullptr;
    });
}

void DSchedContinueManager::StartEvent()
{
    HILOGI("StartEvent start");
    prctl(PR_SET_NAME, DSCHED_CONTINUE_MANAGER.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    runner->Run();
    HILOGI("StartEvent end");
}

void DSchedContinueManager::UnInit()
{
    HILOGI("UnInit start");
    DSchedTransportSoftbusAdapter::GetInstance().UnregisterListener(SERVICE_TYPE_CONTINUE, softbusListener_);
    DSchedTransportSoftbusAdapter::GetInstance().ReleaseChannel();
    continues_.clear();
    cntSink_ = 0;
    cntSource_ = 0;

    if (eventHandler_ != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        eventThread_.join();
        eventHandler_ = nullptr;
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("UnInit end");
}

int32_t DSchedContinueManager::ContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    int32_t missionId, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    auto func = [this, srcDeviceId, dstDeviceId, missionId, callback, wantParams]() {
        HandleContinueMission(srcDeviceId, dstDeviceId, missionId, callback, wantParams);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    eventHandler_->PostTask(func);
    return ERR_OK;
}

void DSchedContinueManager::HandleContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    int32_t missionId, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    HILOGI("start, srcDeviceId: %s. dstDeviceId: %s. missionId: %d.",
        DnetworkAdapter::AnonymizeNetworkId(srcDeviceId).c_str(),
        DnetworkAdapter::AnonymizeNetworkId(dstDeviceId).c_str(), missionId);

    if (srcDeviceId.empty() || dstDeviceId.empty() || callback == nullptr) {
        HILOGE("srcDeviceId or dstDeviceId or callback is null!");
        return;
    }

    std::string localDevId;
    if (!GetLocalDeviceId(localDevId)) {
        HILOGE("get local deviceId failed!");
        return;
    }
    DSchedContinueInfo info = DSchedContinueInfo(srcDeviceId, dstDeviceId, missionId);

    AAFwk::MissionInfo missionInfo;
    if (AAFwk::AbilityManagerClient::GetInstance()->GetMissionInfo("", missionId, missionInfo) == ERR_OK
        && srcDeviceId == localDevId) {
        info.sourceBundleName_ = missionInfo.want.GetBundle();
        info.sinkBundleName_ = missionInfo.want.GetBundle();
    }

    HandleContinueMissionWithBundleName(info, callback, wantParams);
    return;
}

int32_t DSchedContinueManager::ContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    std::string bundleName, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    auto func = [this, srcDeviceId, dstDeviceId, bundleName, callback, wantParams]() {
        HandleContinueMission(srcDeviceId, dstDeviceId, bundleName, callback, wantParams);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    eventHandler_->PostTask(func);
    return ERR_OK;
}

void DSchedContinueManager::HandleContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
    std::string bundleName, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    HILOGI("start, srcDeviceId: %s. dstDeviceId: %s. bundleName: %s.",
        DnetworkAdapter::AnonymizeNetworkId(srcDeviceId).c_str(),
        DnetworkAdapter::AnonymizeNetworkId(dstDeviceId).c_str(), bundleName.c_str());

    if (srcDeviceId.empty() || dstDeviceId.empty() || callback == nullptr) {
        HILOGE("srcDeviceId or dstDeviceId or callback is null!");
        return;
    }

    DSchedContinueInfo info = DSchedContinueInfo(srcDeviceId, bundleName, dstDeviceId, bundleName, "");
    HandleContinueMissionWithBundleName(info, callback, wantParams);
    return;
}

void DSchedContinueManager::HandleContinueMissionWithBundleName(const DSchedContinueInfo &info,
    const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams)
{
    int32_t direction = CheckContinuationLimit(info.sourceDeviceId_, info.sinkDeviceId_);
    if (direction != CONTINUE_SOURCE && direction != CONTINUE_SINK) {
        HILOGE("CheckContinuationLimit failed, ret: %d", direction);
        return;
    }

    int32_t subType = CONTINUE_PUSH;
    if (direction == CONTINUE_SOURCE) {
        cntSource_++;
    } else {
        cntSink_++;
        subType = CONTINUE_PULL;
    }

    {
        std::lock_guard<std::mutex> continueLock(continueMutex_);
        if (!continues_.empty() && continues_.find(info) != continues_.end()) {
            HILOGE("a same continue task is already in progress.");
            return;
        }
        auto newContinue = std::make_shared<DSchedContinue>(subType, direction, callback, info);
        newContinue->Init();
        continues_.insert(std::make_pair(info, newContinue));
        SetTimeOut(info, CONTINUE_TIMEOUT);
        newContinue->OnContinueMission(wantParams);
    }
    HILOGI("end, subType: %d dirction: %d, continue info: %s", subType, direction, info.toString().c_str());
}

void DSchedContinueManager::SetTimeOut(const DSchedContinueInfo &info, int32_t timeout)
{
    auto func = [this, info]() {
        if (continues_.empty() || continues_.count(info) == 0) {
            HILOGE("continue not exist.");
            return;
        }
        HILOGE("continue timeout! info: %s", info.toString().c_str());
        continues_[info]->OnContinueEnd(CONTINUE_ABILITY_TIMEOUT_ERR);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->PostTask(func, info.ToStringIgnoreMissionId(), timeout);
}

int32_t DSchedContinueManager::StartContinuation(const OHOS::AAFwk::Want& want, int32_t missionId,
    int32_t callerUid, int32_t status, uint32_t accessToken)
{
    auto func = [this, want, missionId, callerUid, status, accessToken]() {
        HandleStartContinuation(want, missionId, callerUid, status, accessToken);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    eventHandler_->PostTask(func);
    return ERR_OK;
}

void DSchedContinueManager::HandleStartContinuation(const OHOS::AAFwk::Want& want, int32_t missionId,
    int32_t callerUid, int32_t status, uint32_t accessToken)
{
    HILOGI("begin");
    std::string srcDeviceId;
    if (!GetLocalDeviceId(srcDeviceId)) {
        HILOGE("get local deviceId failed!");
        return;
    }
    std::string dstDeviceId = want.GetElement().GetDeviceID().c_str();
    std::string bundleName = want.GetElement().GetBundleName().c_str();
    auto info = DSchedContinueInfo(srcDeviceId, bundleName, dstDeviceId, bundleName, "");

    HILOGI("continue info: %s.", info.toString().c_str());
    {
        std::lock_guard<std::mutex> continueLock(continueMutex_);
        if (continues_.empty() || continues_.count(info) == 0) {
            HILOGE("continue info doesn't match an existing continuation.");
            return;
        }
        if (missionId != continues_[info]->GetContinueInfo().missionId_) {
            HILOGE("missionId doesn't match the existing continuation, continueInfo: %s.", info.toString().c_str());
            return;
        }
        continues_[info]->OnStartContinuation(want, callerUid, status, accessToken);
    }
    HILOGI("end");
    return;
}

int32_t DSchedContinueManager::NotifyCompleteContinuation(const std::u16string& devId, int32_t sessionId,
    bool isSuccess)
{
    auto func = [this, devId, sessionId, isSuccess]() {
        HandleNotifyCompleteContinuation(devId, sessionId, isSuccess);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    eventHandler_->PostTask(func);
    return ERR_OK;
}

void DSchedContinueManager::HandleNotifyCompleteContinuation(const std::u16string& devId, int32_t missionId,
    bool isSuccess)
{
    std::string deviceId = Str16ToStr8(devId);
    HILOGI("begin, deviceId %s, missionId %d, isSuccess %d", DnetworkAdapter::AnonymizeNetworkId(deviceId).c_str(),
        missionId, isSuccess);
    {
        std::lock_guard<std::mutex> continueLock(continueMutex_);
        if (continues_.empty()) {
            HILOGE("No continuation in progress.");
            return;
        }
        for (auto iter = continues_.begin(); iter != continues_.end(); iter++) {
            if (iter->second != nullptr && deviceId == iter->second->GetContinueInfo().sourceDeviceId_) {
                iter->second->OnNotifyComplete(missionId, isSuccess);
                HILOGI("end, continue info: %s.", iter->second->GetContinueInfo().toString().c_str());
                return;
            }
        }
    }
    HILOGE("source deviceId doesn't match an existing continuation.");
    return;
}

int32_t DSchedContinueManager::OnContinueEnd(const DSchedContinueInfo& info)
{
    auto func = [this, info]() {
        HandleContinueEnd(info);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    eventHandler_->PostTask(func);
    return ERR_OK;
}

void DSchedContinueManager::HandleContinueEnd(const DSchedContinueInfo& info)
{
    HILOGI("begin, continue info: %s.", info.toString().c_str());
    std::lock_guard<std::mutex> continueLock(continueMutex_);
    if (continues_.empty() || continues_.find(info) == continues_.end()) {
        HILOGE("continue info doesn't match any existing continuation.");
        return;
    }
    RemoveTimeout(info);
    continues_.erase(info);

    std::string localDevId;
    if (!GetLocalDeviceId(localDevId)) {
        HILOGE("get local deviceId failed!");
        return;
    }

    if (info.sinkDeviceId_ == localDevId) {
        cntSink_--;
    } else if (info.sourceDeviceId_ == localDevId) {
        cntSource_--;
    }
    HILOGI("end.");
}

void DSchedContinueManager::RemoveTimeout(const DSchedContinueInfo& info)
{
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->RemoveTask(info.ToStringIgnoreMissionId());
}

void DSchedContinueManager::OnDataRecv(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    auto func = [this, sessionId, dataBuffer]() {
        HandleDataRecv(sessionId, dataBuffer);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->PostTask(func);
}

void DSchedContinueManager::HandleDataRecv(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    HILOGI("start, sessionId: %d.", sessionId);
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
    NotifyContinueDataRecv(sessionId, command, jsonStr, dataBuffer);
    HILOGI("end, sessionId: %d.", sessionId);
}

void DSchedContinueManager::NotifyContinueDataRecv(int32_t sessionId, int32_t command, const std::string& jsonStr,
    std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    HILOGI("start, parsed cmd %d, sessionId: %d.", command, sessionId);
    std::lock_guard<std::mutex> continueLock(continueMutex_);
    for (auto iter = continues_.begin(); iter != continues_.end(); iter++) {
        if (iter->second != nullptr && sessionId == iter->second->GetSessionId()) {
            HILOGI("sessionId %d exist.", sessionId);
            iter->second->OnDataRecv(command, dataBuffer);
            return;
        }
    }
    if (command == DSCHED_CONTINUE_CMD_START) {
        HILOGI("recv start cmd, sessionId: %d.", sessionId);
        auto startCmd = std::make_shared<DSchedContinueStartCmd>();
        int32_t ret = startCmd->Unmarshal(jsonStr);
        if (ret != ERR_OK) {
            HILOGE("Unmarshal start cmd failed, ret: %d", ret);
            return;
        }
        ret = CheckContinuationLimit(startCmd->srcDeviceId_, startCmd->dstDeviceId_);
        if (ret != CONTINUE_SINK && ret != CONTINUE_SOURCE) {
            HILOGE("CheckContinuationSubType failed, ret: %d", ret);
            return;
        }
        auto newContinue = std::make_shared<DSchedContinue>(startCmd, sessionId);
        newContinue->Init();
        continues_.insert(std::make_pair(newContinue->GetContinueInfo(), newContinue));

        newContinue->OnStartCmd(startCmd->appVersion_);
        HILOGI("end, continue info: %s.", newContinue->GetContinueInfo().toString().c_str());
        return;
    }
    HILOGE("No matching session to handle cmd! sessionId: %d, recv cmd %d.", sessionId, command);
    return;
}

int32_t DSchedContinueManager::CheckContinuationLimit(const std::string& srcDeviceId,
    const std::string& dstDeviceId)
{
    std::string localDevId;
    if (!GetLocalDeviceId(localDevId)) {
        HILOGE("get local deviceId failed!");
        return GET_LOCAL_DEVICE_ERR;
    }

    int32_t direction = CONTINUE_SINK;
    if (dstDeviceId == localDevId) {
        if (cntSink_.load() >= MAX_CONCURRENT_SINK) {
            HILOGE("can't deal more than %d pull requests at the same time.", cntSink_.load());
            return CONTINUE_ALREADY_IN_PROGRESS;
        }
        if (DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(srcDeviceId) == nullptr) {
            HILOGE("Irrecognized source device!");
            return INVALID_PARAMETERS_ERR;
        }
    } else if (srcDeviceId == localDevId) {
        if (cntSource_.load() >= MAX_CONCURRENT_SOURCE) {
            HILOGE("can't deal more than %d push requests at the same time.", cntSource_.load());
            return CONTINUE_ALREADY_IN_PROGRESS;
        }
        if (DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(dstDeviceId) == nullptr) {
            HILOGE("Irrecognized destination device!");
            return INVALID_PARAMETERS_ERR;
        }
        direction = CONTINUE_SOURCE;
    } else {
        HILOGE("source or target device must be local!");
        return OPERATION_DEVICE_NOT_INITIATOR_OR_TARGET;
    }
    return direction;
}

bool DSchedContinueManager::GetLocalDeviceId(std::string& localDeviceId)
{
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId)) {
        HILOGE("GetLocalDeviceId failed");
        return false;
    }
    return true;
}

int32_t DSchedContinueManager::GetContinueInfo(std::string &srcDeviceId, std::string &dstDeviceId)
{
    HILOGI("called");
    std::lock_guard<std::mutex> continueLock(continueMutex_);
    if (continues_.empty()) {
        HILOGW("No continuation in progress.");
        return ERR_OK;
    }
    dstDeviceId = continues_.begin()->second->GetContinueInfo().sinkDeviceId_;
    srcDeviceId = continues_.begin()->second->GetContinueInfo().sourceDeviceId_;
    return ERR_OK;
}

void DSchedContinueManager::OnShutdown(int32_t socket, bool isSelfCalled)
{
    if (isSelfCalled) {
        HILOGW("called, shutdown by local, sessionId: %d", socket);
        return;
    }
    HILOGW("called, sessionId: %d, isSelfCalled %d", socket, isSelfCalled);
    auto func = [this, socket]() {
        std::lock_guard<std::mutex> continueLock(continueMutex_);
        if (continues_.empty()) {
            return;
        }
        for (auto iter = continues_.begin(); iter != continues_.end(); iter++) {
            if (iter->second != nullptr && socket == iter->second->GetSessionId()) {
                iter->second->OnContinueEnd(CONTINUE_SESSION_SHUTDOWN);
            }
        }
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->PostTask(func);
    return;
}

void DSchedContinueManager::SoftbusListener::OnBind(int32_t socket, PeerSocketInfo info)
{
}

void DSchedContinueManager::SoftbusListener::OnShutdown(int32_t socket, bool isSelfCalled)
{
    DSchedContinueManager::GetInstance().OnShutdown(socket, isSelfCalled);
}

void DSchedContinueManager::SoftbusListener::OnDataRecv(int32_t socket, std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    DSchedContinueManager::GetInstance().OnDataRecv(socket, dataBuffer);
}
}  // namespace DistributedSchedule
}  // namespace OHOS
