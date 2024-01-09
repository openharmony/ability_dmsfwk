/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "mission/distributed_sched_continue_manager.h"

#include "adapter/dnetwork_adapter.h"
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
#include "adapter/mmi_adapter.h"
#endif
#include "datetime_ex.h"
#include "distributed_sched_adapter.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "parcel_helper.h"
#include "softbus_adapter/softbus_adapter.h"
#include <sys/prctl.h>

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t INDEX_2 = 2;
constexpr int32_t INDEX_3 = 3;
constexpr int32_t INDEX_4 = 4;
constexpr int32_t CANCEL_FOCUSED_DELAYED = 60000;
const std::string TAG = "DistributedSchedContinueManager";
const std::string CANCEL_FOCUSED_TASK = "cancel_mission_focused_task";
const std::u16string DESCRIPTOR = u"ohos.aafwk.RemoteOnListener";
}

IMPLEMENT_SINGLE_INSTANCE(DistributedSchedContinueManager);

void DistributedSchedContinueManager::Init()
{
    HILOGI("Init start");
    {
        missionFocusedListener_ = new DistributedMissionFocusedListener();
        int32_t ret = DistributedSchedAdapter::GetInstance().RegisterMissionListener(missionFocusedListener_);
        if (ret != ERR_OK) {
            HILOGE("get RegisterMissionListener failed, ret: %{public}d", ret);
            return;
        }
        missionDiedListener_ = new DistributedMissionDiedListener();
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
        MMIAdapter::GetInstance().Init();
#endif
#ifdef SUPPORT_COMMON_EVENT_SERVICE
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
        EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
        auto applyMonitor = std::make_shared<CommonEventListener>(subscribeInfo);
        EventFwk::CommonEventManager::SubscribeCommonEvent(applyMonitor);
#endif
        eventThread_ = std::thread(&DistributedSchedContinueManager::StartEvent, this);
        std::unique_lock<std::mutex> lock(eventMutex_);
        eventCon_.wait(lock, [this] {
            return eventHandler_ != nullptr;
        });
    }

    int32_t missionId = GetCurrentMissionId();
    if (missionId <= 0) {
        HILOGW("GetCurrentMissionId failed, init end. ret: %{public}d", missionId);
        return;
    }
    NotifyMissionFocused(missionId);
    HILOGI("Init end");
}

void DistributedSchedContinueManager::UnInit()
{
    HILOGI("UnInit start");
    if (eventHandler_ != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        eventThread_.join();
        eventHandler_ = nullptr;
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("UnInit end");
}

int32_t DistributedSchedContinueManager::GetCurrentMissionId()
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

void DistributedSchedContinueManager::AddCancelMissionFocusedTimer(const int32_t missionId, const int32_t delay)
{
    HILOGI("AddCancelMissionFocusedTimer start, missionId: %{public}d", missionId);
    auto cancelfunc = [this, missionId]() {
        DealTimerUnfocusedBussiness(missionId);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(cancelfunc, CANCEL_FOCUSED_TASK, delay);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("AddCancelMissionFocusedTimer end");
}

void DistributedSchedContinueManager::NotifyMissionFocused(const int32_t missionId)
{
    HILOGI("NotifyMissionFocused start, missionId: %{public}d", missionId);
    auto feedfunc = [this, missionId]() {
        DealFocusedBusiness(missionId);
        if (missionId == info_.currentMissionId && info_.currentIsContinuable) {
            AddCancelMissionFocusedTimer(missionId, CANCEL_FOCUSED_DELAYED);
        }
    };

    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
        eventHandler_->PostTask(feedfunc);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("NotifyMissionFocused end");
}

void DistributedSchedContinueManager::NotifyMissionUnfocused(const int32_t missionId)
{
    HILOGI("NotifyMissionUnfocused start, missionId: %{public}d", missionId);
    auto feedfunc = [this, missionId]() {
        DealUnfocusedBusiness(missionId, true);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
        eventHandler_->PostTask(feedfunc);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("NotifyMissionUnfocused end");
}

int32_t DistributedSchedContinueManager::GetMissionId(const std::string& bundleName, int32_t& missionId)
{
    HILOGI("GetMissionId start, bundleName: %{public}s", bundleName.c_str());
    std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
    auto iterItem = focusedMission_.find(bundleName);
    if (iterItem == focusedMission_.end()) {
        HILOGE("get iterItem failed from focusedMission_, bundleName: %{public}s", bundleName.c_str());
        return INVALID_PARAMETERS_ERR;
    }
    missionId = iterItem->second;
    HILOGI("get missionId end, missionId: %{public}d", missionId);
    return ERR_OK;
}

void DistributedSchedContinueManager::StartEvent()
{
    HILOGI("StartEvent start");
    prctl(PR_SET_NAME, CONTINUE_MANAGER.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    runner->Run();
    HILOGI("StartEvent end");
}

int32_t DistributedSchedContinueManager::SendSoftbusEvent(uint32_t accessTokenId, uint8_t type)
{
    HILOGD("SendSoftbusEvent start, accessTokenId: %{public}d", accessTokenId);
    uint8_t data[DMS_SEND_LEN];
    uint8_t len = sizeof(uint32_t);
    data[0] = (type << CONTINUE_SHIFT_04) | len;
    data[1] = (accessTokenId >> CONTINUE_SHIFT_24) & DMS_0XFF;
    data[INDEX_2] = (accessTokenId >> CONTINUE_SHIFT_16) & DMS_0XFF;
    data[INDEX_3] = (accessTokenId >> CONTINUE_SHIFT_08) & DMS_0XFF;
    data[INDEX_4] = accessTokenId & DMS_0XFF;
    int32_t ret = SoftbusAdapter::GetInstance().SendSoftbusEvent(data, DMS_SEND_LEN);
    HILOGD("SendSoftbusEvent end. Result: %{public}d", ret);
    return ret;
}

#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
void DistributedSchedContinueManager::AddMMIListener()
{
    if (mmiMonitorId_ >= 0) {
        HILOGI("MMI listener already exist, monitor id: %{public}d", mmiMonitorId_);
        return;
    }
    mmiMonitorId_ = MMIAdapter::GetInstance().AddMMIListener();
    if (mmiMonitorId_ < 0) {
        HILOGW("Add MMI listener failed, ret: %{public}d", mmiMonitorId_);
        return;
    }
    HILOGI("MMI listener has been added, monitor id: %{public}d", mmiMonitorId_);
}

void DistributedSchedContinueManager::RemoveMMIListener()
{
    std::lock_guard<std::mutex> mmiEventLock(mmiMutex_);
    if (mmiMonitorId_ < 0) {
        HILOGI("No MMI listener to be removed, monitor id: %{public}d", mmiMonitorId_);
        return;
    }
    MMIAdapter::GetInstance().RemoveMMIListener(mmiMonitorId_);
    HILOGI("MMI listener has been removed, monitor id: %{public}d", mmiMonitorId_);

    mmiMonitorId_ = INVALID_MISSION_ID;
    needMMIBroadcast_ = false;
    return;
}
#endif

int32_t DistributedSchedContinueManager::DealFocusedBusiness(const int32_t missionId)
{
    HILOGI("DealFocusedBusiness start, missionId: %{public}d", missionId);
    AAFwk::MissionInfo info;
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->GetMissionInfo("", missionId, info);
    if (ret != ERR_OK) {
        HILOGE("get missionInfo failed, missionId: %{public}d, ret: %{public}d", missionId, ret);
        return ret;
    }
    bool isMissionContinuable = info.continuable;
    {
        std::lock_guard<std::mutex> currentMissionIdLock(eventMutex_);
        info_.currentMissionId = missionId;
        info_.currentIsContinuable = isMissionContinuable;
    }
    if (!isMissionContinuable) {
        HILOGW("Mission is not continuable, task abort, missionId: %{public}d", missionId);
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }
    std::string bundleName = info.want.GetBundle();
    focusedMission_[bundleName] = missionId;

    if (info.continueState != AAFwk::ContinueState::CONTINUESTATE_ACTIVE) {
        HILOGE("Mission continue state set to INACTIVE. Broadcast task abort.");
        return INVALID_PARAMETERS_ERR;
    }
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
    AddMMIListener();
#endif
    uint32_t accessTokenId;
    ret = BundleManagerInternal::GetBundleIdFromBms(bundleName, accessTokenId);
    if (ret != ERR_OK) {
        HILOGE("Get focused accessTokenId failed, accessTokenId: %{public}d, ret: %{public}d", accessTokenId, ret);
        return ret;
    }
    HILOGI("Get focused accessTokenId success, accessTokenId: %{public}d", accessTokenId);

    uint8_t type = DMS_FOCUSED_TYPE;
    ret = SendSoftbusEvent(accessTokenId, type);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent focused failed, ret: %{public}d", ret);
        return ret;
    }
    HILOGI("DealFocusedBusiness end");
    return ERR_OK;
}

int32_t DistributedSchedContinueManager::CheckContinueState(const int32_t missionId)
{
    AAFwk::MissionInfo info;
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->GetMissionInfo("", missionId, info);
    if (ret != ERR_OK) {
        HILOGE("get missionInfo failed, missionId: %{public}d, ret: %{public}d", missionId, ret);
        return ERR_OK;
    }
    if (info.continueState != AAFwk::ContinueState::CONTINUESTATE_ACTIVE) {
        HILOGE("Mission continue state set to INACTIVE. Broadcast task abort.");
        return INVALID_PARAMETERS_ERR;
    }
    return ERR_OK;
}

void DistributedSchedContinueManager::DealTimerUnfocusedBussiness(const int32_t missionId)
{
    HILOGI("DealTimerUnfocusedBussiness start, missionId: %{public}d", missionId);
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
    int64_t interval = GetTickCount() - lastMMIEvent_;
    if (interval < CANCEL_FOCUSED_DELAYED) {
        HILOGD("Last MMI event happened in interval, keep mission focused.");
        auto refocusedTask = [this, missionId, interval]() {
            if (missionId == info_.currentMissionId && info_.currentIsContinuable) {
                AddCancelMissionFocusedTimer(missionId, CANCEL_FOCUSED_DELAYED - static_cast<int32_t>(interval));
            }
            DealFocusedBusiness(missionId);
        };
        if (eventHandler_ != nullptr) {
            eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
            eventHandler_->PostTask(refocusedTask);
        } else {
            HILOGE("eventHandler_ is nullptr");
        }
        return;
    }
    {
        HILOGD("Last MMI event happened out of interval, set mission unfocused.");
        std::lock_guard<std::mutex> mmiEventLock(mmiMutex_);
        needMMIBroadcast_ = true;
        auto unfocusedTask = [this, missionId]() {
            DealUnfocusedBusiness(missionId, false);
        };
        if (eventHandler_ != nullptr) {
            eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
            eventHandler_->PostTask(unfocusedTask);
        } else {
            HILOGE("eventHandler_ is nullptr");
        }
        return;
    }
#else
    auto unfocusedTask = [this, missionId]() {
        DealUnfocusedBusiness(missionId, false);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
        eventHandler_->PostTask(unfocusedTask);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    return;
#endif
}

int32_t DistributedSchedContinueManager::DealUnfocusedBusiness(const int32_t missionId, bool isUnfocused)
{
    HILOGI("DealUnfocusedBusiness start, missionId: %{public}d", missionId);
    std::string bundleName;
    int32_t ret = GetBundleName(missionId, bundleName);
    if (ret != ERR_OK) {
        HILOGW("Get bundleName failed, mission is not continuable, missionId: %{public}d, ret: %{public}d",
            missionId, ret);
        return ret;
    }
    HILOGI("Get bundleName success, mission is continuable, missionId: %{public}d, bundleName: %{public}s",
        missionId, bundleName.c_str());

    if (isUnfocused) {
        bool isContinue = IsContinue(missionId, bundleName);
        if (!isContinue) {
            HILOGE("Not current mission to be continued, missionId: %{public}d", missionId);
            return NO_MISSION_INFO_FOR_MISSION_ID;
        }
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
        RemoveMMIListener();
#endif
    }

    ret = CheckContinueState(missionId);
    if (ret != ERR_OK) {
        HILOGE("Continue state is inactive or can't be obtained, mission id : %{public}d, ret: %{public}d",
            missionId, ret);
        return ret;
    }

    uint32_t accessTokenId;
    ret = BundleManagerInternal::GetBundleIdFromBms(bundleName, accessTokenId);
    if (ret != ERR_OK) {
        HILOGE("Get unfocused accessTokenId failed, accessTokenId: %{public}d, ret: %{public}d", accessTokenId, ret);
        return ret;
    }

    uint8_t type = DMS_UNFOCUSED_TYPE;
    ret = SendSoftbusEvent(accessTokenId, type);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent unfocused failed, ret: %{public}d", ret);
    }

    if (isUnfocused) {
        std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
        focusedMission_.erase(bundleName);
    }
    HILOGI("DealUnfocusedBusiness end");
    return ERR_OK;
}

int32_t DistributedSchedContinueManager::GetBundleName(const int32_t missionId, std::string& bundleName)
{
    for (auto iterItem = focusedMission_.begin(); iterItem != focusedMission_.end(); iterItem++) {
        if (iterItem->second == missionId) {
            bundleName = iterItem->first;
            return ERR_OK;
        }
    }
    return INVALID_PARAMETERS_ERR;
}

bool DistributedSchedContinueManager::IsContinue(const int32_t& missionId, const std::string& bundleName)
{
    if (missionId != info_.currentMissionId && info_.currentIsContinuable) {
        /*missionId and currentMissionId are not equal but currentMission can change,
            continue to not send unfocus broadcast*/
        std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
        focusedMission_.erase(bundleName);
        HILOGI("mission is not continue, missionId: %{public}d, currentMissionId: %{public}d",
            missionId, info_.currentMissionId);
        return false;
    }
    /*missionId and currentMissionId are equal, or missionId and currentMissionId are not equal
        and currentIsContinuable not change, continue to send unfocus broadcast*/
    HILOGI("mission is continue, missionId: %{public}d, currentMissionId: %{public}d",
        missionId, info_.currentMissionId);
    return true;
}

int32_t DistributedSchedContinueManager::SetMissionContinueState(const int32_t missionId,
    const AAFwk::ContinueState &state)
{
    HILOGI("SetMissionContinueState start, missionId: %{public}d, state: %{public}d", missionId, state);
    auto feedfunc = [this, missionId, state]() {
        DealSetMissionContinueStateBusiness(missionId, state);
        if (state == AAFwk::ContinueState::CONTINUESTATE_ACTIVE && missionId == info_.currentMissionId &&
            info_.currentIsContinuable) {
            AddCancelMissionFocusedTimer(missionId, CANCEL_FOCUSED_DELAYED);
        }
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
        eventHandler_->PostTask(feedfunc);
    } else {
        HILOGE("eventHandler_ is nullptr");
        return ERR_NULL_OBJECT;
    }
    HILOGI("SetMissionContinueState end");
    return ERR_OK;
}

int32_t DistributedSchedContinueManager::DealSetMissionContinueStateBusiness(const int32_t missionId,
    const AAFwk::ContinueState &state)
{
    HILOGI("DealSetMissionContinueStateBusiness start, missionId: %{public}d, state: %{public}d", missionId, state);

    if (info_.currentMissionId != missionId) {
        HILOGE("mission is not focused, broadcast task abort, missionId: %{public}d", missionId);
        return INVALID_PARAMETERS_ERR;
    }

    if (!info_.currentIsContinuable) {
        HILOGW("mission is not continuable, broadcast task abort, missionId: %{public}d", missionId);
        return INVALID_PARAMETERS_ERR;
    }

    std::string bundleName;
    int32_t ret = GetBundleName(missionId, bundleName);
    if (ret != ERR_OK) {
        HILOGE("get bundleName failed, broadcast task abort, missionId: %{public}d, ret: %{public}d",
            missionId, ret);
        return ret;
    }
    HILOGI("get bundleName success, missionId: %{public}d, bundleName: %{public}s", missionId, bundleName.c_str());

    uint32_t accessTokenId;
    ret = BundleManagerInternal::GetBundleIdFromBms(bundleName, accessTokenId);
    if (ret != ERR_OK) {
        HILOGE("get setContinueState accessTokenId failed, accessTokenId: %{public}d, ret: %{public}d",
            accessTokenId, ret);
        return ret;
    }

    uint8_t type = DMS_FOCUSED_TYPE;
    if (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE) {
        type = DMS_UNFOCUSED_TYPE;
    }
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
    if (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE) {
        RemoveMMIListener();
    } else {
        AddMMIListener();
    }
#endif

    ret = SendSoftbusEvent(accessTokenId, type);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent setContinueState failed, ret: %{public}d", ret);
        return ret;
    }

    HILOGI("DealSetMissionContinueStateBusiness end. ContinueState set to: %{public}d", state);
    return ERR_OK;
}

void DistributedSchedContinueManager::NotifyDeid(const sptr<IRemoteObject>& obj)
{
    HILOGI("NotifyDeid start");
    if (obj == nullptr) {
        HILOGE("obj is null");
        return;
    }
    for (auto iterItem = registerOnListener_.begin(); iterItem != registerOnListener_.end();) {
        for (auto iter = iterItem->second.begin(); iter != iterItem->second.end();) {
            if (*iter == obj) {
                obj->RemoveDeathRecipient(missionDiedListener_);
                iter = iterItem->second.erase(iter);
            } else {
                iter++;
            }
        }
        if (iterItem->second.empty()) {
            std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
            iterItem = registerOnListener_.erase(iterItem);
        } else {
            iterItem++;
        }
    }
    HILOGI("NotifyDeid end");
}

#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
void DistributedSchedContinueManager::OnMMIEvent()
{
    std::lock_guard<std::mutex> mmiEventLock(mmiMutex_);
    lastMMIEvent_ = GetTickCount();

    if (!needMMIBroadcast_) {
        return;
    }
    HILOGD("Need to resend focus broadcast, missionId = %{public}d", info_.currentMissionId);
    DistributedSchedContinueManager::GetInstance().NotifyMissionFocused(info_.currentMissionId);
    needMMIBroadcast_ = false;
}

void DistributedSchedContinueManager::ResetMMIFlag()
{
    HILOGI("Reset MMI focus flag");
    std::lock_guard<std::mutex> mmiEventLock(mmiMutex_);
    needMMIBroadcast_ = true;
}
#endif
} // namespace DistributedSchedule
} // namespace OHOS
