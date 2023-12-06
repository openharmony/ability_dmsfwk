/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "distributed_sched_continuation.h"
#include "dtbschedmgr_log.h"
#include "parcel_helper.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int64_t CONTINUATION_DELAY_TIME = 20000;
const std::string TAG = "DSchedContinuation";
const std::u16string NAPI_MISSION_CENTER_INTERFACE_TOKEN = u"ohos.DistributedSchedule.IMissionCallback";
constexpr int32_t NOTIFY_MISSION_CENTER_RESULT = 4;
const std::u16string DSCHED_EVENT_TOKEN = u"ohos.distributedSchedule.dschedeventlistener";
constexpr int32_t DSCHED_EVENT_CALLBACK = 0;
}

void DSchedContinuation::Init(const FuncContinuationCallback& contCallback)
{
    auto runner = EventRunner::Create("dsched_continuation");
    continuationHandler_ = std::make_shared<ContinuationHandler>(runner, shared_from_this(), contCallback);
}

bool DSchedContinuation::PushAbilityToken(int32_t sessionId, const sptr<IRemoteObject>& abilityToken)
{
    if (abilityToken == nullptr) {
        HILOGE("PushAbilityToken abilityToken null!");
        return false;
    }

    if (sessionId <= 0) {
        HILOGE("PushAbilityToken sessionId invalid!");
        return false;
    }

    if (continuationHandler_ == nullptr) {
        HILOGE("PushAbilityToken not initialized!");
        return false;
    }

    std::lock_guard<std::mutex> autoLock(continuationLock_);
    bool ret = true;
    ret = continuationHandler_->SendEvent(sessionId, 0, CONTINUATION_DELAY_TIME);
    if (!ret) {
        HILOGE("PushAbilityToken SendEvent failed!");
        return false;
    }

    auto iterSession = continuationMap_.find(sessionId);
    if (iterSession != continuationMap_.end()) {
        HILOGE("PushAbilityToken sessionId:%{public}d exist!", sessionId);
        return false;
    }
    (void)continuationMap_.emplace(sessionId, abilityToken);
    return true;
}

sptr<IRemoteObject> DSchedContinuation::PopAbilityToken(int32_t sessionId)
{
    if (sessionId <= 0) {
        HILOGE("PopAbilityToken sessionId invalid");
        return nullptr;
    }

    std::lock_guard<std::mutex> autoLock(continuationLock_);
    auto iter = continuationMap_.find(sessionId);
    if (iter == continuationMap_.end()) {
        HILOGW("PopAbilityToken not found sessionId:%{public}d", sessionId);
        return nullptr;
    }
    sptr<IRemoteObject> abilityToken = iter->second;
    (void)continuationMap_.erase(iter);
    if (continuationHandler_ != nullptr) {
        continuationHandler_->RemoveEvent(sessionId);
    }
    return abilityToken;
}

int32_t DSchedContinuation::GenerateSessionId()
{
    std::lock_guard<std::mutex> autoLock(continuationLock_);
    int32_t currValue = currSessionId_;
    if (++currSessionId_ <= 0) {
        currSessionId_ = 1;
    }
    return currValue;
}

void DSchedContinuation::SetTimeOut(int32_t missionId, int32_t timeout)
{
    if (continuationHandler_ == nullptr) {
        HILOGE("continuationHandler not initialized!");
        return;
    }
    continuationHandler_->SendEvent(missionId, 0, timeout);
}

void DSchedContinuation::RemoveTimeOut(int32_t missionId)
{
    if (continuationHandler_ == nullptr) {
        HILOGE("continuationHandler not initialized!");
        return;
    }
    continuationHandler_->RemoveEvent(missionId);
}

bool DSchedContinuation::IsFreeInstall(int32_t missionId)
{
    std::lock_guard<std::mutex> autoLock(continuationLock_);
    auto iter = freeInstall_.find(missionId);
    if (iter != freeInstall_.end()) {
        HILOGD("continue free install, missionId:%{public}d exist!", missionId);
        return iter->second;
    }
    return false;
}

bool DSchedContinuation::IsInContinuationProgress(int32_t missionId)
{
    std::lock_guard<std::mutex> autoLock(continuationLock_);
    auto iterSession = callbackMap_.find(missionId);
    if (iterSession != callbackMap_.end()) {
        HILOGE("Continuation in progress, missionId:%{public}d exist!", missionId);
        return true;
    }
    return false;
}

std::string DSchedContinuation::GetTargetDevice(int32_t missionId)
{
    std::lock_guard<std::mutex> autoLock(continuationLock_);
    auto iter = continuationDevices_.find(missionId);
    if (iter != continuationDevices_.end()) {
        HILOGD("missionId:%{public}d exist!", missionId);
        return iter->second;
    }
    return "";
}

bool DSchedContinuation::PushCallback(const std::string& type, const sptr<IRemoteObject>& callback)
{
    if (continuationHandler_ == nullptr) {
        HILOGE("not initialized!");
        return false;
    }
    HILOGI("DSchedContinuation PushCallback start!");
    if (callback == nullptr) {
        HILOGE("callback null!");
        return false;
    }
    std::lock_guard<std::mutex> autoLock(continuationLock_);
    std::vector<sptr<IRemoteObject>> vecCallback = continuationCallbackMap_[type];
    for (auto ele = vecCallback.begin(); ele != vecCallback.end(); ++ele) {
        if ((*ele) == callback) {
            HILOGE("type:%{public}s, callback is exists!", type.c_str());
            return false;
        }
    }
    vecCallback.push_back(callback);
    continuationCallbackMap_[type] = vecCallback;
    return true;
}

bool DSchedContinuation::PushCallback(int32_t missionId, const sptr<IRemoteObject>& callback,
    std::string deviceId, bool isFreeInstall)
{
    HILOGI("DSchedContinuation PushCallback start!");
    if (callback == nullptr) {
        HILOGE("callback null!");
        return false;
    }

    if (continuationHandler_ == nullptr) {
        HILOGE("not initialized!");
        return false;
    }

    std::lock_guard<std::mutex> autoLock(continuationLock_);
    auto iterSession = callbackMap_.find(missionId);
    if (iterSession != callbackMap_.end()) {
        HILOGE("missionId:%{public}d exist!", missionId);
        return false;
    }
    (void)callbackMap_.emplace(missionId, callback);
    (void)continuationDevices_.emplace(missionId, deviceId);
    if (isFreeInstall) {
        freeInstall_[missionId] = isFreeInstall;
    }
    return true;
}

std::vector<sptr<IRemoteObject>> DSchedContinuation::GetCallback(const std::string& type)
{
    std::lock_guard<std::mutex> autoLock(continuationLock_);
    return continuationCallbackMap_[type];
}

bool DSchedContinuation::CleanupCallback(const std::string& type, const sptr<IRemoteObject>& callback)
{
    std::lock_guard<std::mutex> autoLock(continuationLock_);
    std::vector<sptr<IRemoteObject>> vecCallback = continuationCallbackMap_[type];
    if (vecCallback.empty()) {
        HILOGE("PopCallback not found, type:%{public}s", type.c_str());
        return false;
    }
    for (auto ele = vecCallback.begin(); ele != vecCallback.end(); ++ele) {
        if ((*ele) == callback) {
            vecCallback.erase(ele);
            continuationCallbackMap_[type] = vecCallback;
            HILOGI("type:%{public}s, callback is exists, cleared successfully.", type.c_str());
            return true;
        }
    }
    HILOGI("type:%{public}s, callback is not exists!", type.c_str());
    return false;
}

sptr<IRemoteObject> DSchedContinuation::PopCallback(int32_t missionId)
{
    std::lock_guard<std::mutex> autoLock(continuationLock_);
    auto iter = callbackMap_.find(missionId);
    if (iter == callbackMap_.end()) {
        HILOGW("PopCallback not found missionId:%{public}d", missionId);
        return nullptr;
    }
    sptr<IRemoteObject> callback = iter->second;

    auto iteration = continuationDevices_.find(missionId);
    if (iteration != continuationDevices_.end()) {
        HILOGD("%{public}d need pop from continuationDevices_", missionId);
        (void)continuationDevices_.erase(iteration);
    }

    auto it = freeInstall_.find(missionId);
    if (it != freeInstall_.end()) {
        HILOGD("%{public}d need pop from freeInstall_", missionId);
        (void)freeInstall_.erase(it);
    }
    (void)cleanMission_.erase(missionId);
    (void)callbackMap_.erase(iter);
    return callback;
}

int32_t DSchedContinuation::NotifyDSchedEventResult(const std::string& type, int32_t resultCode)
{
    HILOGI("GetCallback IDSchedEventListener");
    std::vector<sptr<IRemoteObject>> vecCallback = GetCallback(type);
    if (vecCallback.empty()) {
        HILOGE("NotifyMissionCenterResult IDSchedEventListener is null");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t error = -1;
    for (auto callback = vecCallback.begin(); callback != vecCallback.end(); ++callback) {
        MessageParcel data;
        if (!data.WriteInterfaceToken(DSCHED_EVENT_TOKEN)) {
            HILOGE("NotifyMissionCenterResult write token failed");
            return INVALID_PARAMETERS_ERR;
        }
        PARCEL_WRITE_HELPER_RET(data, Int32, resultCode, false);
        PARCEL_WRITE_HELPER_RET(data, String, continueEvent_.srcNetworkId, false);
        PARCEL_WRITE_HELPER_RET(data, String, continueEvent_.dstNetworkId, false);
        PARCEL_WRITE_HELPER_RET(data, String, continueEvent_.bundleName, false);
        PARCEL_WRITE_HELPER_RET(data, String, continueEvent_.moduleName, false);
        PARCEL_WRITE_HELPER_RET(data, String, continueEvent_.abilityName, false);
        MessageParcel reply;
        MessageOption option;
        error = (*callback)->SendRequest(DSCHED_EVENT_CALLBACK, data, reply, option);
        HILOGI("NotifyDSchedEventListenerResult transact result: %{public}d", error);
    }
    return error;
}

int32_t DSchedContinuation::NotifyMissionCenterResult(int32_t missionId, int32_t resultCode)
{
    sptr<IRemoteObject> callback = PopCallback(missionId);
    RemoveTimeOut(missionId);
    if (callback == nullptr) {
        HILOGE("NotifyMissionCenterResult callback is null");
        return INVALID_PARAMETERS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(NAPI_MISSION_CENTER_INTERFACE_TOKEN)) {
        HILOGE("NotifyMissionCenterResult write token failed");
        return INVALID_PARAMETERS_ERR;
    }
    PARCEL_WRITE_HELPER_RET(data, Int32, resultCode, INVALID_PARAMETERS_ERR);
    MessageParcel reply;
    MessageOption option;
    int32_t error = callback->SendRequest(NOTIFY_MISSION_CENTER_RESULT, data, reply, option);
    HILOGI("NotifyMissionCenterResult transact result: %{public}d", error);
    return error;
}

void DSchedContinuation::ContinuationHandler::ProcessEvent(const InnerEvent::Pointer& event)
{
    if (event == nullptr) {
        HILOGE("ProcessEvent event nullptr!");
        return;
    }

    auto eventId = event->GetInnerEventId();
    int32_t sessionId = static_cast<int32_t>(eventId);
    if (sessionId <= 0) {
        HILOGW("ProcessEvent sessionId invalid!");
        return;
    }

    if (contCallback_ != nullptr) {
        contCallback_(sessionId);
    }
}

void DSchedContinuation::SetCleanMissionFlag(int32_t missionId, bool isCleanMission)
{
    std::lock_guard<std::mutex> autoLock(continuationLock_);
    cleanMission_.emplace(missionId, isCleanMission);
}

bool DSchedContinuation::IsCleanMission(int32_t missionId)
{
    std::lock_guard<std::mutex> autoLock(continuationLock_);
    auto iter = cleanMission_.find(missionId);
    if (iter != cleanMission_.end()) {
        HILOGD("Application need not exit after continue, missionId:%{public}d exist!", missionId);
        return iter->second;
    }
    return true;
}
} // namespace DistributedSchedule
} // namespace OHOS
