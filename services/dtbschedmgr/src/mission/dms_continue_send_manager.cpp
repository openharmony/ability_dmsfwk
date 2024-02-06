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

#include "mission/dms_continue_send_manager.h"

#include "adapter/dnetwork_adapter.h"
#include "adapter/mmi_adapter.h"
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
constexpr int32_t SCREEN_OFF_DELAY_TIME = 10000;
constexpr int64_t TIME_DELAYED = 500; // determines whether normal unfocused or lockoff
const std::string TAG = "DMSContinueSendMgr";
const std::string CANCEL_FOCUSED_TASK = "cancel_mission_focused_task";
const std::string SCREEN_OFF_TASK = "screen_off_task";
const std::u16string DESCRIPTOR = u"ohos.aafwk.RemoteOnListener";
}

IMPLEMENT_SINGLE_INSTANCE(DMSContinueSendMgr);

void DMSContinueSendMgr::Init()
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
        MMIAdapter::GetInstance().Init();
#ifdef SUPPORT_COMMON_EVENT_SERVICE
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
        EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
        auto applyMonitor = std::make_shared<CommonEventListener>(subscribeInfo);
        EventFwk::CommonEventManager::SubscribeCommonEvent(applyMonitor);
#endif
        eventThread_ = std::thread(&DMSContinueSendMgr::StartEvent, this);
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
    NotifyMissionFocused(missionId, FocusedReason::INIT);
    HILOGI("Init end");
}

void DMSContinueSendMgr::UnInit()
{
    HILOGI("UnInit start");
    MMIAdapter::GetInstance().UnInit();
    if (eventHandler_ != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        eventThread_.join();
        eventHandler_ = nullptr;
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("UnInit end");
}

int32_t DMSContinueSendMgr::GetCurrentMissionId()
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

void DMSContinueSendMgr::AddCancelMissionFocusedTimer(const int32_t missionId,
    const std::string eventName, const int32_t delay)
{
    HILOGD("AddCancelMissionFocusedTimer start, missionId: %{public}d", missionId);
    auto cancelfunc = [this, missionId, delay]() {
        if (delay == CANCEL_FOCUSED_DELAYED) {
            screenLockInfo_[missionId] = 0;
        }
        DealTimerUnfocusedBussiness(missionId);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(cancelfunc, eventName, delay);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGD("AddCancelMissionFocusedTimer end");
}

void DMSContinueSendMgr::NotifyMissionFocused(const int32_t missionId, FocusedReason focusedReason)
{
    HILOGI("NotifyMissionFocused start, missionId: %{public}d, reason: %{public}d", missionId, focusedReason);
    if (focusedReason <= FocusedReason::MIN || focusedReason >= FocusedReason::MAX) {
        HILOGI("Unknow focusedReason, no need to deal NotifyMissionFocused");
        return;
    }
    auto feedfunc = [this, missionId, focusedReason]() {
        if (focusedReason != FocusedReason::SCREENOFF) {
            screenLockInfo_.clear();
        }
        DealFocusedBusiness(missionId);
        if (missionId == info_.currentMissionId && info_.currentIsContinuable &&
            focusedReason != FocusedReason::SCREENOFF) {
            AddCancelMissionFocusedTimer(missionId, CANCEL_FOCUSED_TASK, CANCEL_FOCUSED_DELAYED);
        }
    };

    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(SCREEN_OFF_TASK);
        eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
        eventHandler_->PostTask(feedfunc);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("NotifyMissionFocused end");
}

void DMSContinueSendMgr::NotifyMissionUnfocused(const int32_t missionId)
{
    HILOGI("NotifyMissionUnfocused start, missionId: %{public}d", missionId);

    auto feedfunc = [this, missionId]() {
        if (screenLockInfo_.empty()) {
            int64_t time = GetTickCount();
            screenLockInfo_[missionId] = time;
        } else {
            HILOGI("Screen lock now, no need to NotifyMissionUnfocused");
            return;
        }
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

void DMSContinueSendMgr::NotifyScreenOff()
{
    HILOGI("NotifyScreenOff start");
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->RemoveAllEvents();
    auto feedfunc = [this]() {
        DealScreenOff();
    };
    eventHandler_->PostTask(feedfunc);

    HILOGI("NotifyScreenOff end");
}

void DMSContinueSendMgr::DealScreenOff()
{
    int32_t missionId = info_.currentMissionId;
    if (screenLockInfo_.count(missionId) != 0 && screenLockInfo_[missionId] == 0) {
        HILOGI("no need to deal screenlock process in case of timed-unfocused");
        return;
    }
    int64_t time = GetTickCount();
    if (screenLockInfo_.size() != 0) {
        auto it = screenLockInfo_.begin();
        if (time - it->second < TIME_DELAYED) {
            NotifyMissionFocused(missionId, FocusedReason::SCREENOFF);
        }
    } else {
        screenLockInfo_[missionId] = time;
    }
    AddCancelMissionFocusedTimer(missionId, SCREEN_OFF_TASK, SCREEN_OFF_DELAY_TIME);
}

int32_t DMSContinueSendMgr::GetMissionId(const std::string& bundleName, int32_t& missionId)
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

void DMSContinueSendMgr::StartEvent()
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

int32_t DMSContinueSendMgr::SendSoftbusEvent(uint32_t accessTokenId, uint8_t type)
{
    HILOGD("SendSoftbusEvent start, accessTokenId: %{public}u", accessTokenId);
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

void DMSContinueSendMgr::AddMMIListener()
{
    if (mmiMonitorId_ >= 0) {
        HILOGD("MMI listener already exist, monitor id: %{public}d", mmiMonitorId_);
        return;
    }
    mmiMonitorId_ = MMIAdapter::GetInstance().AddMMIListener();
    if (mmiMonitorId_ < 0) {
        HILOGW("Add MMI listener failed, ret: %{public}d", mmiMonitorId_);
        return;
    }
    HILOGD("MMI listener has been added, monitor id: %{public}d", mmiMonitorId_);
}

void DMSContinueSendMgr::RemoveMMIListener()
{
    if (mmiMonitorId_ < 0) {
        HILOGI("No MMI listener to be removed, monitor id: %{public}d", mmiMonitorId_);
        return;
    }
    MMIAdapter::GetInstance().RemoveMMIListener(mmiMonitorId_);
    HILOGI("MMI listener has been removed, monitor id: %{public}d", mmiMonitorId_);

    mmiMonitorId_ = INVALID_MISSION_ID;
    return;
}

int32_t DMSContinueSendMgr::DealFocusedBusiness(const int32_t missionId)
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
        HILOGI("Mission is not continuable, task abort, missionId: %{public}d", missionId);
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
        HILOGE("Get focused accessTokenId failed, accessTokenId: %{public}u, ret: %{public}d", accessTokenId, ret);
        return ret;
    }
    HILOGI("Get focused accessTokenId success, accessTokenId: %{public}u", accessTokenId);
    uint8_t type = DMS_FOCUSED_TYPE;
    ret = SendSoftbusEvent(accessTokenId, type);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent focused failed, ret: %{public}d", ret);
        return ret;
    }
    HILOGI("DealFocusedBusiness end");
    return ERR_OK;
}

int32_t DMSContinueSendMgr::CheckContinueState(const int32_t missionId)
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

void DMSContinueSendMgr::DealTimerUnfocusedBussiness(const int32_t missionId)
{
    HILOGD("DealTimerUnfocusedBussiness start, missionId: %{public}d", missionId);
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

int32_t DMSContinueSendMgr::DealUnfocusedBusiness(const int32_t missionId, bool isUnfocused)
{
    HILOGI("DealUnfocusedBusiness start, missionId: %{public}d", missionId);
    std::string bundleName;
    int32_t ret = GetBundleName(missionId, bundleName);
    if (ret != ERR_OK) {
        HILOGI("Get bundleName failed, mission is not continuable, missionId: %{public}d, ret: %{public}d",
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
        HILOGE("Get unfocused accessTokenId failed, accessTokenId: %{public}u, ret: %{public}d", accessTokenId, ret);
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

int32_t DMSContinueSendMgr::GetBundleName(const int32_t missionId, std::string& bundleName)
{
    for (auto iterItem = focusedMission_.begin(); iterItem != focusedMission_.end(); iterItem++) {
        if (iterItem->second == missionId) {
            bundleName = iterItem->first;
            return ERR_OK;
        }
    }
    return INVALID_PARAMETERS_ERR;
}

bool DMSContinueSendMgr::IsContinue(const int32_t& missionId, const std::string& bundleName)
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

int32_t DMSContinueSendMgr::SetMissionContinueState(const int32_t missionId,
    const AAFwk::ContinueState &state)
{
    HILOGI("SetMissionContinueState start, missionId: %{public}d, state: %{public}d", missionId, state);
    auto feedfunc = [this, missionId, state]() {
        DealSetMissionContinueStateBusiness(missionId, state);
        if (state == AAFwk::ContinueState::CONTINUESTATE_ACTIVE && missionId == info_.currentMissionId &&
            info_.currentIsContinuable) {
            AddCancelMissionFocusedTimer(missionId, CANCEL_FOCUSED_TASK, CANCEL_FOCUSED_DELAYED);
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

int32_t DMSContinueSendMgr::DealSetMissionContinueStateBusiness(const int32_t missionId,
    const AAFwk::ContinueState &state)
{
    HILOGI("DealSetMissionContinueStateBusiness start, missionId: %{public}d, state: %{public}d", missionId, state);

    if (info_.currentMissionId != missionId) {
        HILOGE("mission is not focused, broadcast task abort, missionId: %{public}d", missionId);
        return INVALID_PARAMETERS_ERR;
    }

    if (!info_.currentIsContinuable) {
        HILOGI("mission is not continuable, broadcast task abort, missionId: %{public}d", missionId);
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
        HILOGE("get setContinueState accessTokenId failed, accessTokenId: %{public}u, ret: %{public}d",
            accessTokenId, ret);
        return ret;
    }

    uint8_t type = DMS_FOCUSED_TYPE;
    if (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE) {
        type = DMS_UNFOCUSED_TYPE;
        RemoveMMIListener();
    } else {
        AddMMIListener();
    }

    ret = SendSoftbusEvent(accessTokenId, type);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent setContinueState failed, ret: %{public}d", ret);
        return ret;
    }

    HILOGI("DealSetMissionContinueStateBusiness end. ContinueState set to: %{public}d", state);
    return ERR_OK;
}

void DMSContinueSendMgr::NotifyDied(const sptr<IRemoteObject>& obj)
{
    HILOGI("NotifyDied start");
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
    HILOGI("NotifyDied end");
}

void DMSContinueSendMgr::OnMMIEvent()
{
    HILOGD("OnMMIEvent, missionId = %{public}d", info_.currentMissionId);
    DMSContinueSendMgr::GetInstance().NotifyMissionFocused(info_.currentMissionId, FocusedReason::MMI);
}
} // namespace DistributedSchedule
} // namespace OHOS
