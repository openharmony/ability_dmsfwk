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

#include <sys/prctl.h>

#include "adapter/dnetwork_adapter.h"
#include "adapter/mmi_adapter.h"
#include "datetime_ex.h"
#include "datashare_manager.h"
#include "distributed_radar.h"
#include "distributed_sched_adapter.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "parcel_helper.h"
#include "softbus_adapter/softbus_adapter.h"
#include "switch_status_dependency.h"
#include "dsched_continue_manager.h"
#include "mission/dms_continue_recv_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t INDEX_2 = 2;
constexpr int32_t INDEX_3 = 3;
constexpr int32_t CANCEL_FOCUSED_DELAYED = 60000;
constexpr int32_t SCREEN_OFF_DELAY_TIME = 10000;
constexpr int64_t TIME_DELAYED = 250; // determines whether normal unfocused or lockoff
const std::string TAG = "DMSContinueSendMgr";
const std::string TIMEOUT_UNFOCUSED_TASK = "timeout_unfocused_task";
const std::string SCREEN_OFF_UNFOCUSED_TASK = "screen_off_unfocused_task";
static const std::string CONTINUE_SWITCH_STATUS_KEY = "Continue_Switch_Status";
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
        MMIAdapter::GetInstance().Init();
        screenOffHandler_ = std::make_shared<ScreenOffHandler>();

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
    DmsRadar::GetInstance().DmsFocused("Init", INIT);
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

void DMSContinueSendMgr::PostUnfocusedTaskWithDelay(const int32_t missionId, UnfocusedReason reason)
{
    HILOGI("called, missionId: %{public}d, reason: %{public}d", missionId, reason);
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    if (reason == UnfocusedReason::TIMEOUT) {
        auto funcOut = [this, missionId]() {
            DmsRadar::GetInstance().RecordTime("funcOut");
            DealUnfocusedBusiness(missionId, UnfocusedReason::TIMEOUT);
        };
        eventHandler_->RemoveTask(TIMEOUT_UNFOCUSED_TASK);
        eventHandler_->PostTask(funcOut, TIMEOUT_UNFOCUSED_TASK, CANCEL_FOCUSED_DELAYED);
    } else if (reason == UnfocusedReason::SCREENOFF) {
        auto funcOff = [this]() {
            SendScreenOffEvent(DMS_UNFOCUSED_TYPE);
        };
        eventHandler_->RemoveTask(SCREEN_OFF_UNFOCUSED_TASK);
        eventHandler_->PostTask(funcOff, SCREEN_OFF_UNFOCUSED_TASK, SCREEN_OFF_DELAY_TIME);
    }
}

void DMSContinueSendMgr::NotifyMissionFocused(const int32_t missionId, FocusedReason reason)
{
    HILOGI("NotifyMissionFocused called, missionId: %{public}d, reason: %{public}d", missionId, reason);
    if (reason <= FocusedReason::MIN || reason >= FocusedReason::MAX) {
        HILOGI("Unknown focusedReason, no need to deal NotifyMissionFocused");
        return;
    }
    auto feedfunc = [this, missionId, reason]() {
        if (reason == FocusedReason::NORMAL) {
            screenOffHandler_->ClearScreenOffInfo();
        }
        DealFocusedBusiness(missionId);
        if (missionId == info_.currentMissionId && info_.currentIsContinuable) {
            PostUnfocusedTaskWithDelay(missionId, UnfocusedReason::TIMEOUT);
        }
    };

    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->RemoveTask(TIMEOUT_UNFOCUSED_TASK);
    eventHandler_->RemoveTask(SCREEN_OFF_UNFOCUSED_TASK);
    eventHandler_->PostTask(feedfunc);
}

void DMSContinueSendMgr::NotifyMissionUnfocused(const int32_t missionId, UnfocusedReason reason)
{
    HILOGI("NotifyMissionUnfocused start, missionId: %{public}d, reason: %{public}d", missionId, reason);
    DmsRadar::GetInstance().DmsUnfocused("NotifyMissionUnfocused");
    if (reason <= UnfocusedReason::MIN || reason >= UnfocusedReason::MAX) {
        HILOGE("unknown unfocused reason!");
        return;
    }
    auto feedfunc = [this, missionId, reason]() {
        DealUnfocusedBusiness(missionId, reason);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(TIMEOUT_UNFOCUSED_TASK);
        eventHandler_->PostTask(feedfunc);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
}

int32_t DMSContinueSendMgr::GetMissionIdByBundleName(const std::string& bundleName, int32_t& missionId)
{
    HILOGI("start, bundleName: %{public}s", bundleName.c_str());
    std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
    auto iterItem = focusedMission_.find(bundleName);
    if (iterItem != focusedMission_.end()) {
        missionId = iterItem->second;
        HILOGI("get missionId end, missionId: %{public}d", missionId);
        return ERR_OK;
    }
    HILOGW("get iterItem failed from focusedMission_, try screenOffHandler_");
    if (bundleName == screenOffHandler_->GetBundleName()) {
        missionId = screenOffHandler_->GetMissionId();
        HILOGI("get missionId end, missionId: %{public}d", missionId);
        return ERR_OK;
    }
    HILOGE("get bundleName failed from screenOffHandler_");
    return INVALID_PARAMETERS_ERR;
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

int32_t DMSContinueSendMgr::SendSoftbusEvent(uint16_t accessTokenId, uint8_t continueTypeId, uint8_t type)
{
    HILOGD("SendSoftbusEvent start, accessTokenId: %{public}u, continueTypeId: %{public}u",
        accessTokenId, continueTypeId);
    uint8_t data[DMS_SEND_LEN];
    uint8_t len = DMS_DATA_LEN;
    data[0] = (type << CONTINUE_SHIFT_04) | len;
    data[1] = (accessTokenId >> CONTINUE_SHIFT_08) & DMS_0XFF;
    data[INDEX_2] = accessTokenId & DMS_0XFF;
    data[INDEX_3] = continueTypeId & DMS_0XFF;

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
    if (!CheckBundleContinueConfig(bundleName)) {
        HILOGI("App does not allow continue in config file, bundle name %{public}s, missionId: %{public}d",
            bundleName.c_str(), missionId);
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }
    focusedMission_[bundleName] = missionId;
        
    std::string abilityName = info.want.GetElement().GetAbilityName();
    focusedMissionAbility_[missionId] = abilityName;

    if (info.continueState != AAFwk::ContinueState::CONTINUESTATE_ACTIVE) {
        HILOGE("Mission continue state set to INACTIVE. Broadcast task abort.");
        return INVALID_PARAMETERS_ERR;
    }
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
    AddMMIListener();
#endif
    if (!SwitchStatusDependency::GetInstance().IsContinueSwitchOn()) { return DMS_PERMISSION_DENIED;}
    ret = FocusedBusinessSendEvent(bundleName, abilityName);
    HILOGI("DealFocusedBusiness end");
    return ret;
}

int32_t DMSContinueSendMgr::FocusedBusinessSendEvent(std::string bundleName, const std::string& abilityName)
{
    uint16_t bundleNameId = 0;
    int32_t ret = BundleManagerInternal::GetBundleNameId(bundleName, bundleNameId);
    DmsRadar::GetInstance().NormalFocusedGetAccessTokenIdRes("GetBundleNameId", ret);
    if (ret != ERR_OK) {
        HILOGE("Get focused bundleNameId failed, bundleNameId: %{public}u, ret: %{public}d", bundleNameId, ret);
        return ret;
    }

    uint8_t continueTypeId = 0;
    ret = BundleManagerInternal::GetContinueTypeId(bundleName, abilityName, continueTypeId);
    if (ret != ERR_OK) {
        HILOGE("Get focused contineTypeId failed, contineTypeId: %{public}u, ret: %{public}d", continueTypeId, ret);
        return ret;
    }

    ret = SendSoftbusEvent(bundleNameId, continueTypeId, DMS_FOCUSED_TYPE);
    DmsRadar::GetInstance().NormalFocusedSendEventRes("SendSoftbusEvent", ret);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent focused failed, ret: %{public}d", ret);
    }
    return ret;
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

int32_t DMSContinueSendMgr::DealUnfocusedBusiness(const int32_t missionId, UnfocusedReason reason)
{
    HILOGI("DealUnfocusedBusiness start, missionId: %{public}d", missionId);
    std::string bundleName;
    int32_t ret = GetBundleNameByMissionId(missionId, bundleName);
    if (ret != ERR_OK) {
        HILOGI("Get bundleName failed, missionId: %{public}d, ret: %{public}d", missionId, ret);
        return ret;
    }
    HILOGI("Get bundleName success, mission is continuable, missionId: %{public}d, bundleName: %{public}s",
        missionId, bundleName.c_str());
    
    std::string abilityName;
    ret = GetAbilityNameByMissionId(missionId, abilityName);
    if (ret != ERR_OK) {
        HILOGE("get abilityName failed, missionId: %{public}d, ret: %{public}d", missionId, ret);
        return ret;
    }

    if (reason != UnfocusedReason::TIMEOUT) {
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

    uint16_t accessTokenId = 0;
    uint8_t continueTypeId = 0;
    ret = GetAccessTokenIdSendEvent(bundleName, reason, accessTokenId, continueTypeId);
    if (ret != ERR_OK) {
        HILOGE("GetAccessTokenIdSendEvent failed");
        return ret;
    }
    if (reason != UnfocusedReason::TIMEOUT) {
        std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
        focusedMission_.erase(bundleName);
        focusedMissionAbility_.erase(missionId);
    }

    if (reason == UnfocusedReason::NORMAL) {
        screenOffHandler_->SetScreenOffInfo(missionId, bundleName, accessTokenId, abilityName);
    }
    HILOGI("DealUnfocusedBusiness end");
    return ERR_OK;
}

int32_t DMSContinueSendMgr::SendScreenOffEvent(uint8_t type)
{
    int32_t missionId = screenOffHandler_->GetMissionId();
    std::string bundleName = screenOffHandler_->GetBundleName();
    uint32_t accessTokenId = screenOffHandler_->GetAccessTokenId();
    std::string abilityName = screenOffHandler_->GetAbilityName();

    HILOGI("start, type: %{public}d, missionId: %{public}d, bundleName: %{public}s, accessTokenId: %{public}u",
        type, missionId, bundleName.c_str(), accessTokenId);
    if (!CheckBundleContinueConfig(bundleName)) {
        HILOGI("App does not allow continue in config file, bundle name %{public}s, missionId: %{public}d",
            bundleName.c_str(), missionId);
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }

    bool IsContinueSwitchOn = SwitchStatusDependency::GetInstance().IsContinueSwitchOn();
    if (!IsContinueSwitchOn) {
        HILOGE("ContinueSwitch status is off");
        return DMS_PERMISSION_DENIED;
    }

    uint8_t continueTypeId = 0;
    int32_t ret = BundleManagerInternal::GetContinueTypeId(bundleName, abilityName, continueTypeId);
    if (ret != ERR_OK) {
        HILOGE("Get focused contineTypeId failed, abilityName: %{public}s, ret: %{public}d", abilityName.c_str(), ret);
        return ret;
    }
    
    ret = SendSoftbusEvent(accessTokenId, continueTypeId, type);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent unfocused failed, ret: %{public}d", ret);
    }
    HILOGI("end");
    return ERR_OK;
}

int32_t DMSContinueSendMgr::GetBundleNameByMissionId(const int32_t missionId, std::string& bundleName)
{
    for (auto iterItem = focusedMission_.begin(); iterItem != focusedMission_.end(); iterItem++) {
        if (iterItem->second == missionId) {
            bundleName = iterItem->first;
            return ERR_OK;
        }
    }
    return INVALID_PARAMETERS_ERR;
}

int32_t DMSContinueSendMgr::GetAbilityNameByMissionId(const int32_t missionId, std::string& abilityName)
{
    HILOGI("start, missionId: %{public}d", missionId);
    std::lock_guard<std::mutex> focusedMissionAbilityMapLock(eventMutex_);
    auto iterItem = focusedMissionAbility_.find(missionId);
    if (iterItem != focusedMissionAbility_.end()) {
        abilityName = iterItem->second;
        HILOGI("get missionId end, missionId: %{public}d", missionId);
        return ERR_OK;
    }
    HILOGW("get iterItem failed from focusedMissionAbility_, try screenOffHandler_");
    if (missionId == screenOffHandler_->GetMissionId()) {
        abilityName = screenOffHandler_->GetAbilityName();
        HILOGI("get missionId end, abilityName: %{public}s", abilityName.c_str());
        return ERR_OK;
    }
    HILOGE("get abilityName failed from screenOffHandler_");
    return INVALID_PARAMETERS_ERR;
}

bool DMSContinueSendMgr::IsContinue(const int32_t& missionId, const std::string& bundleName)
{
    if (missionId != info_.currentMissionId && info_.currentIsContinuable) {
        /*missionId and currentMissionId are not equal but currentMission can change,
            continue to not send unfocus broadcast*/
        std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
        focusedMission_.erase(bundleName);
        focusedMissionAbility_.erase(missionId);
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
            PostUnfocusedTaskWithDelay(missionId, UnfocusedReason::TIMEOUT);
        }
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(TIMEOUT_UNFOCUSED_TASK);
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
    if (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE) {
        DmsRadar::GetInstance().SetUnfocusedState("DealSetMissionContinueStateBusiness");
    } else {
        DmsRadar::GetInstance().SetFocusedState("DealSetMissionContinueStateBusiness");
    }
    if (info_.currentMissionId != missionId) {
        HILOGE("mission is not focused, broadcast task abort, missionId: %{public}d", missionId);
        return INVALID_PARAMETERS_ERR;
    }

    if (!info_.currentIsContinuable) {
        HILOGI("mission is not continuable, broadcast task abort, missionId: %{public}d", missionId);
        return INVALID_PARAMETERS_ERR;
    }
    
    uint16_t bundleNameId = 0;
    uint8_t continueTypeId = 0;
    int32_t ret = GetBundleNameIdAndContinueTypeId(missionId, state, bundleNameId, continueTypeId);
    if (ret != ERR_OK) {
        HILOGE("Get focused contineTypeId failed, contineTypeId: %{public}u, ret: %{public}d", continueTypeId, ret);
        return ret;
    }

    ret = SetStateSendEvent(bundleNameId, continueTypeId, state);
    if (ret != ERR_OK) {
        HILOGE("SetStateSendEvent failed");
        return ret;
    }
    HILOGI("DealSetMissionContinueStateBusiness end. ContinueState set to: %{public}d", state);
    return ERR_OK;
}

int32_t DMSContinueSendMgr::GetBundleNameIdAndContinueTypeId(const int32_t missionId, const AAFwk::ContinueState& state,
    uint16_t& bundleNameId, uint8_t& continueTypeId)
{
    std::string bundleName;
    int32_t ret = GetBundleNameByMissionId(missionId, bundleName);
    if (ret != ERR_OK) {
        HILOGE("get bundleName failed, missionId: %{public}d, ret: %{public}d", missionId, ret);
        return ret;
    }
    HILOGI("get bundleName success, missionId: %{public}d, bundleName: %{public}s", missionId, bundleName.c_str());
    if (!CheckBundleContinueConfig(bundleName)) {
        HILOGI("App does not allow continue in config file, bundle name %{public}s, missionId: %{public}d",
            bundleName.c_str(), missionId);
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }

    ret = BundleManagerInternal::GetBundleNameId(bundleName, bundleNameId);
    if (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE) {
        DmsRadar::GetInstance().ChangeStateUnfocusedGetAccessTokenIdRes("GetBundleNameId", ret);
    } else {
        DmsRadar::GetInstance().ChangeStateFocusedGetAccessTokenIdRes("GetBundleNameId", ret);
    }
    if (ret != ERR_OK) {
        HILOGE("get bundleNameId failed, bundleNameId: %{public}u, ret: %{public}d", bundleNameId, ret);
        return ret;
    }

    std::string abilityName;
    ret = GetAbilityNameByMissionId(missionId, abilityName);
    if (ret != ERR_OK) {
        HILOGE("get abilityName failed, broadcast task abort, missionId: %{public}d, ret: %{public}d",
            missionId, ret);
        return ret;
    }

    return BundleManagerInternal::GetContinueTypeId(bundleName, abilityName, continueTypeId);
}

void DMSContinueSendMgr::OnMMIEvent()
{
    HILOGD("OnMMIEvent, missionId = %{public}d", info_.currentMissionId);
    DmsRadar::GetInstance().DmsFocused("OnMMIEvent", MULTIMODE);
    DMSContinueSendMgr::GetInstance().NotifyMissionFocused(info_.currentMissionId, FocusedReason::MMI);
}

uint32_t DMSContinueSendMgr::NotifyDeviceOnline()
{
    HILOGD("NotifyDeviceOnline called");
    if (GetCurrentMissionId() <= 0) {
        return INVALID_MISSION_ID;
    }
    DmsRadar::GetInstance().DmsFocused("NotifyDeviceOnline", DEVICEONLINE);
    NotifyMissionFocused(info_.currentMissionId, FocusedReason::ONLINE);
    return ERR_OK;
}

void DMSContinueSendMgr::OnDeviceScreenOff()
{
    HILOGI("OnDeviceScreenOff called");
    if (!info_.currentIsContinuable) {
        HILOGW("current mission is not continuable, ignore");
        return;
    }
    int32_t missionId = info_.currentMissionId;
    auto feedfunc = [this, missionId]() {
        screenOffHandler_->OnDeviceScreenOff(missionId);
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->PostTask(feedfunc);
}

void DMSContinueSendMgr::OnDeviceScreenOn()
{
    HILOGI("OnDeviceScreenOn called");
    auto feedfunc = [this]() {
        screenOffHandler_->OnDeviceScreenOn();
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->PostTask(feedfunc);
}

int32_t DMSContinueSendMgr::ScreenOffHandler::GetMissionId()
{
    return unfoInfo_.missionId;
}

std::string DMSContinueSendMgr::ScreenOffHandler::GetBundleName()
{
    return unfoInfo_.bundleName;
}

std::string DMSContinueSendMgr::ScreenOffHandler::GetAbilityName()
{
    return unfoInfo_.abilityName;
}

uint32_t DMSContinueSendMgr::ScreenOffHandler::GetAccessTokenId()
{
    return unfoInfo_.accessToken;
}

bool DMSContinueSendMgr::ScreenOffHandler::IsDeviceScreenOn()
{
    return isScreenOn_;
}


void DMSContinueSendMgr::ScreenOffHandler::OnDeviceScreenOff(int32_t missionId)
{
    HILOGI("ScreenOffHandler::OnDeviceScreenOff called");
    isScreenOn_ = false;
    if (unfoInfo_.missionId != INVALID_MISSION_ID && (GetTickCount()- unfoInfo_.unfoTime) < TIME_DELAYED) {
        // handle unfocus before screen off
        DMSContinueSendMgr::GetInstance().SendScreenOffEvent(DMS_FOCUSED_TYPE);
    }
    DMSContinueSendMgr::GetInstance().PostUnfocusedTaskWithDelay(missionId, UnfocusedReason::SCREENOFF);
}

void DMSContinueSendMgr::ScreenOffHandler::OnDeviceScreenOn()
{
    HILOGI("ScreenOffHandler::OnDeviceScreenOn called");
    isScreenOn_ = true;
}

void DMSContinueSendMgr::ScreenOffHandler::ClearScreenOffInfo()
{
    HILOGI("clear last unfocused info");
    unfoInfo_.missionId = INVALID_MISSION_ID;
    unfoInfo_.unfoTime = 0;
    unfoInfo_.bundleName = "";
    unfoInfo_.accessToken = 0;
    unfoInfo_.abilityName = "";
}

void DMSContinueSendMgr::ScreenOffHandler::SetScreenOffInfo(int32_t missionId, std::string bundleName,
    uint32_t accessTokenId, std::string abilityName)
{
    HILOGI("set last unfocused info, missionId: %{public}d, bundleName: %{public}s, accessTokenId: %{public}u",
        missionId, bundleName.c_str(), accessTokenId);
    unfoInfo_.missionId = missionId;
    unfoInfo_.unfoTime = GetTickCount();
    unfoInfo_.bundleName = bundleName;
    unfoInfo_.accessToken = accessTokenId;
    unfoInfo_.abilityName = abilityName;
}

int32_t DMSContinueSendMgr::GetAccessTokenIdSendEvent(std::string bundleName,
    UnfocusedReason reason, uint16_t& accessTokenId, uint8_t& continueTypeId)
{
    int32_t ret = BundleManagerInternal::GetBundleNameId(bundleName, accessTokenId);
    bool res = (reason != UnfocusedReason::TIMEOUT)
        ? DmsRadar::GetInstance().NormalUnfocusedGetAccessTokenIdRes("GetBundleNameId", ret)
            : DmsRadar::GetInstance().MultimodeUnfocusedGetAccessTokenIdRes("GetBundleNameId", ret);
    if (!res) {
        HILOGE("%{public}s failed", (reason != UnfocusedReason::TIMEOUT) ? "NormalUnfocusedGetAccessTokenIdRes"
            : "MultimodeUnfocusedGetAccessTokenIdRes");
    }
    if (ret != ERR_OK) {
        HILOGE("Get unfocused accessTokenId failed, accessTokenId: %{public}u, ret: %{public}d", accessTokenId, ret);
        return ret;
    }

    if (screenOffHandler_->IsDeviceScreenOn()) {
        bool IsContinueSwitchOn = SwitchStatusDependency::GetInstance().IsContinueSwitchOn();
        HILOGI("IsContinueSwitchOn : %{public}d", IsContinueSwitchOn);
        if (!IsContinueSwitchOn) {
            HILOGE("ContinueSwitch status is off");
            return DMS_PERMISSION_DENIED;
        }

        ret = SendSoftbusEvent(accessTokenId, continueTypeId, DMS_UNFOCUSED_TYPE);
        bool res = (reason != UnfocusedReason::TIMEOUT)
            ? DmsRadar::GetInstance().NormalUnfocusedSendEventRes("SendSoftbusEvent", ret)
                : DmsRadar::GetInstance().MultimodeUnfocusedSendEventRes("SendSoftbusEvent", ret);
        if (!res) {
            HILOGE("%{public}s failed", (reason != UnfocusedReason::TIMEOUT) ? "NormalUnfocusedSendEventRes"
                : "MultimodeUnfocusedSendEventRes");
        }
        if (ret != ERR_OK) {
            HILOGE("SendSoftbusEvent unfocused failed, ret: %{public}d", ret);
            return ret;
        }
    }
    return ret;
}

int32_t DMSContinueSendMgr::SetStateSendEvent(const uint32_t accessTokenId, const uint8_t& continueTypeId,
    const AAFwk::ContinueState &state)
{
    if (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE) {
        RemoveMMIListener();
    } else {
        AddMMIListener();
    }

    bool IsContinueSwitchOn = SwitchStatusDependency::GetInstance().IsContinueSwitchOn();
    if (!IsContinueSwitchOn) {
        HILOGE("ContinueSwitch status is off");
        return DMS_PERMISSION_DENIED;
    }

    uint8_t type = state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE ? DMS_UNFOCUSED_TYPE : DMS_FOCUSED_TYPE;
    int32_t ret = SendSoftbusEvent(accessTokenId, continueTypeId, type);
    bool res = (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE)
        ? DmsRadar::GetInstance().ChangeStateUnfocusedSendEventRes("SendSoftbusEvent", ret)
            : DmsRadar::GetInstance().ChangeStateFocusedSendEventRes("SendSoftbusEvent", ret);
    if (!res) {
        HILOGE("%{public}s failed", (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE) ?
            "ChangeStateUnfocusedSendEventRes" : "ChangeStateFocusedSendEventRes");
    }
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent setContinueState failed, ret: %{public}d", ret);
        return ret;
    }
    return ret;
}
} // namespace DistributedSchedule
} // namespace OHOS
