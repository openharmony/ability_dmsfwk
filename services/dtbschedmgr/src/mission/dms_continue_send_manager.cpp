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
#include "bluetooth_host.h"
#include "datetime_ex.h"
#include "datashare_manager.h"
#include "dfx/distributed_radar.h"
#include "distributed_sched_adapter.h"
#include "distributed_sched_utils.h"
#include "distributed_sched_service.h"
#include "dsched_data_buffer.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "mission/bluetooth_state_adapter.h"
#include "mission/dms_continue_recv_manager.h"
#include "mission/dsched_sync_e2e.h"
#include "mission/wifi_state_adapter.h"
#include "multi_user_manager.h"
#include "parcel_helper.h"
#include "softbus_adapter/softbus_adapter.h"
#include "switch_status_dependency.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t INDEX_2 = 2;
constexpr int32_t INDEX_3 = 3;
constexpr int32_t CANCEL_FOCUSED_DELAYED = 60000;
constexpr int32_t SCREEN_OFF_DELAY_TIME = 10000;
constexpr int64_t TIME_DELAYED = 500; // determines whether normal unfocused or lockoff
const std::string TAG = "DMSContinueSendMgr";
const std::string TIMEOUT_UNFOCUSED_TASK = "timeout_unfocused_task";
const std::string SCREEN_OFF_UNFOCUSED_TASK = "screen_off_unfocused_task";
}

DMSContinueSendMgr::~DMSContinueSendMgr()
{
    HILOGI("~DMSContinueSendMgr. accountId: %{public}d.", accountId_);
    UnInit();
}

void DMSContinueSendMgr::Init(int32_t accountId)
{
    HILOGI("Init start. accountId: %{public}d.", accountId);
    accountId_ = accountId;
    if (eventHandler_ != nullptr) {
        HILOGI("Already inited, end.");
        return;
    }
    {
        screenOffHandler_ = std::make_shared<ScreenOffHandler>(shared_from_this());

        eventThread_ = std::thread(&DMSContinueSendMgr::StartEvent, this);
        std::unique_lock<std::mutex> lock(eventMutex_);
        eventCon_.wait(lock, [this] {
            return eventHandler_ != nullptr;
        });
    }
    HILOGI("Init end");
}

void DMSContinueSendMgr::UnInit()
{
    HILOGI("UnInit start. accountId: %{public}d.", accountId_);
    if (eventHandler_ != nullptr && eventHandler_->GetEventRunner() != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        if (eventThread_.joinable()) {
            eventThread_.join();
        }
        eventHandler_ = nullptr;
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("UnInit end");
}

void DMSContinueSendMgr::PostUnfocusedTaskWithDelay(const int32_t missionId, UnfocusedReason reason)
{
    HILOGI("called, missionId: %{public}d, reason: %{public}d. accountId: %{public}d.", missionId, reason, accountId_);
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    if (reason == UnfocusedReason::TIMEOUT) {
        auto funcOut = [this, missionId]() {
            DealUnfocusedBusiness(missionId, UnfocusedReason::TIMEOUT);
        };
        std::string timeoutTaskName = TIMEOUT_UNFOCUSED_TASK + std::to_string(missionId);
        eventHandler_->RemoveTask(timeoutTaskName);
        eventHandler_->PostTask(funcOut, timeoutTaskName, CANCEL_FOCUSED_DELAYED);
    } else if (reason == UnfocusedReason::SCREENOFF) {
        auto funcOff = [this]() {
            SendScreenOffEvent(DMS_UNFOCUSED_TYPE);
        };
        std::string scrOffTaskName = SCREEN_OFF_UNFOCUSED_TASK + std::to_string(missionId);
        eventHandler_->RemoveTask(scrOffTaskName);
        eventHandler_->PostTask(funcOff, scrOffTaskName, SCREEN_OFF_DELAY_TIME);
    }
}

void DMSContinueSendMgr::NotifyMissionFocused(const int32_t missionId, FocusedReason reason)
{
    HILOGI("NotifyMissionFocused called, missionId: %{public}d, reason: %{public}d. accountId: %{public}d.",
        missionId, reason, accountId_);
    if (!DmsKvSyncE2E::GetInstance()->CheckCtrlRule()) {
        HILOGE("Forbid sending and receiving");
        return;
    }
    if (reason <= FocusedReason::MIN || reason >= FocusedReason::MAX) {
        HILOGI("Unknown focusedReason, no need to deal NotifyMissionFocused");
        return;
    }

#ifdef DMS_CHECK_WIFI
    if (!WifiStateAdapter::GetInstance().IsWifiActive()) {
        HILOGE("wifi is not activated");
        return;
    }
#endif

#ifdef DMS_CHECK_BLUETOOTH
    if (!BluetoothStateAdapter::GetInstance().IsBluetoothActive()) {
        HILOGE("bluetooth is not activated");
        return;
    }
#endif

    auto feedfunc = [this, missionId, reason]() {
        int32_t newMissionId = missionId;
        if (reason == FocusedReason::MMI) {
            newMissionId = info_.currentMissionId;
        }
        if (reason == FocusedReason::NORMAL && screenOffHandler_ != nullptr) {
            screenOffHandler_->ClearScreenOffInfo();
        }
        DealFocusedBusiness(newMissionId, reason);
        if (newMissionId == info_.currentMissionId && info_.currentIsContinuable) {
            PostUnfocusedTaskWithDelay(newMissionId, UnfocusedReason::TIMEOUT);
        }
    };

    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->RemoveTask(TIMEOUT_UNFOCUSED_TASK + std::to_string(missionId));
    eventHandler_->RemoveTask(SCREEN_OFF_UNFOCUSED_TASK + std::to_string(missionId));
    eventHandler_->PostTask(feedfunc);
}

void DMSContinueSendMgr::NotifyMissionUnfocused(const int32_t missionId, UnfocusedReason reason)
{
    HILOGI("NotifyMissionUnfocused start, missionId: %{public}d, reason: %{public}d. accountId: %{public}d.",
        missionId, reason, accountId_);
    if (reason <= UnfocusedReason::MIN || reason >= UnfocusedReason::MAX) {
        HILOGE("unknown unfocused reason!");
        return;
    }
    auto feedfunc = [this, missionId, reason]() {
        DealUnfocusedBusiness(missionId, reason);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(TIMEOUT_UNFOCUSED_TASK + std::to_string(missionId));
        eventHandler_->PostTask(feedfunc);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
}

int32_t DMSContinueSendMgr::GetMissionIdByBundleName(const std::string& bundleName, int32_t& missionId)
{
    HILOGI("start, bundleName: %{public}s. accountId: %{public}d.", bundleName.c_str(), accountId_);
    std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
    auto iterItem = focusedMission_.find(bundleName);
    if (iterItem != focusedMission_.end()) {
        missionId = iterItem->second;
        HILOGI("get missionId end, missionId: %{public}d", missionId);
        return ERR_OK;
    }
    HILOGW("get iterItem failed from focusedMission_, try screenOffHandler_");
    if (screenOffHandler_ != nullptr && bundleName == screenOffHandler_->GetBundleName()) {
        missionId = screenOffHandler_->GetMissionId();
        HILOGI("get missionId end, missionId: %{public}d", missionId);
        return ERR_OK;
    }
    HILOGW("get bundleName failed from screenOffHandler_");
    if (bundleName == lastFocusedMissionInfo_.bundleName) {
        missionId = lastFocusedMissionInfo_.missionId;
        HILOGI("get missionId end, missionId: %{public}d", missionId);
        return ERR_OK;
    }
    return MISSION_NOT_FOCUSED;
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
    if (runner != nullptr) {
        runner->Run();
    } else {
        HILOGE("runner is null");
    }
    HILOGI("StartEvent end");
}

int32_t DMSContinueSendMgr::SendSoftbusEvent(uint16_t bundleNameId, uint8_t continueTypeId, uint8_t type)
{
    HILOGD("SendSoftbusEvent start, bundleNameId: %{public}u, continueTypeId: %{public}u. accountId: %{public}d.",
        bundleNameId, continueTypeId, accountId_);
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(DMS_SEND_LEN);
    if (buffer->Data() == nullptr || buffer->Size() < DMS_SEND_LEN) {
        HILOGE("Failed to initialize DSchedDataBuffer");
        return INVALID_PARAMETERS_ERR;
    }
    buffer->Data()[0] = (type << CONTINUE_SHIFT_04) | DMS_DATA_LEN;
    buffer->Data()[1] = (bundleNameId >> CONTINUE_SHIFT_08) & DMS_0XFF;
    buffer->Data()[INDEX_2] = bundleNameId & DMS_0XFF;
    buffer->Data()[INDEX_3] = continueTypeId & DMS_0XFF;

    int32_t ret = SoftbusAdapter::GetInstance().SendSoftbusEvent(buffer);
    HILOGD("SendSoftbusEvent end. Result: %{public}d", ret);
    return ret;
}

void DMSContinueSendMgr::AddMMIListener()
{
    HILOGI("accountId: %{public}d.", accountId_);
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
    HILOGI("accountId: %{public}d.", accountId_);
    if (mmiMonitorId_ < 0) {
        HILOGI("No MMI listener to be removed, monitor id: %{public}d", mmiMonitorId_);
        return;
    }
    MMIAdapter::GetInstance().RemoveMMIListener(mmiMonitorId_);
    HILOGI("MMI listener has been removed, monitor id: %{public}d", mmiMonitorId_);

    mmiMonitorId_ = INVALID_MISSION_ID;
    return;
}

void DMSContinueSendMgr::UserSwitchedRemoveMMIListener()
{
    HILOGD("UserSwitched MMI listener remove start.");
    RemoveMMIListener();
    HILOGD("UserSwitched MMI listener remove end.");
}

int32_t DMSContinueSendMgr::DealFocusedBusiness(const int32_t missionId, FocusedReason reason)
{
    HILOGI("DealFocusedBusiness start, missionId: %{public}d. accountId: %{public}d.", missionId, accountId_);
    AAFwk::MissionInfo info;
    auto abilityMgr = AAFwk::AbilityManagerClient::GetInstance();
    if (abilityMgr != nullptr) {
        int32_t ret = abilityMgr->GetMissionInfo("", missionId, info);
        if (ret != ERR_OK) {
            HILOGE("get missionInfo failed, missionId: %{public}d, ret: %{public}d", missionId, ret);
            return ret;
        }
    } else {
        HILOGE("abilityMgr is null");
        return INVALID_PARAMETERS_ERR;
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
    if (!DmsKvSyncE2E::GetInstance()->CheckBundleContinueConfig(bundleName)) {
        HILOGI("App does not allow continue in config file, bundle name %{public}s, missionId: %{public}d",
            bundleName.c_str(), missionId);
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }
    focusedMission_[bundleName] = missionId;

    std::string abilityName = info.want.GetElement().GetAbilityName();
    focusedMissionAbility_[missionId] = abilityName;
    UpdateContinueLaunchMission(info);

    if (info.continueState != AAFwk::ContinueState::CONTINUESTATE_ACTIVE) {
        HILOGE("Mission continue state set to INACTIVE. Broadcast task abort.");
        return INVALID_PARAMETERS_ERR;
    }
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
    if (reason != FocusedReason::MMI) {
        AddMMIListener();
    }
#endif
    if (!SwitchStatusDependency::GetInstance().IsContinueSwitchOn()) { return DMS_PERMISSION_DENIED;}
    int32_t ret = FocusedBusinessSendEvent(bundleName, abilityName);
    HILOGI("DealFocusedBusiness end");
    return ret;
}

int32_t DMSContinueSendMgr::FocusedBusinessSendEvent(std::string bundleName, const std::string& abilityName)
{
    HILOGI("accountId: %{public}d.", accountId_);
    uint16_t bundleNameId = 0;
    int32_t ret = BundleManagerInternal::GetBundleNameId(bundleName, bundleNameId);
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
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent focused failed, ret: %{public}d", ret);
    }
    return ret;
}

int32_t DMSContinueSendMgr::CheckContinueState(const int32_t missionId)
{
    HILOGI("accountId: %{public}d.", accountId_);
    auto abilityMgr = AAFwk::AbilityManagerClient::GetInstance();
    if (abilityMgr == nullptr) {
        HILOGE("abilityMgr is null");
        return INVALID_PARAMETERS_ERR;
    }

    AAFwk::MissionInfo info;
    int32_t ret = abilityMgr->GetMissionInfo("", missionId, info);
    if (ret != ERR_OK) {
        HILOGE("get missionInfo failed, missionId: %{public}d, ret: %{public}d", missionId, ret);
        return INVALID_PARAMETERS_ERR;
    }
    if (info.continueState != AAFwk::ContinueState::CONTINUESTATE_ACTIVE) {
        HILOGE("Mission continue state set to INACTIVE. Broadcast task abort.");
        return INVALID_PARAMETERS_ERR;
    }
    return ERR_OK;
}

int32_t DMSContinueSendMgr::DealUnfocusedBusiness(const int32_t missionId, UnfocusedReason reason)
{
    HILOGI("DealUnfocusedBusiness start, missionId: %{public}d. accountId: %{public}d.", missionId, accountId_);
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
        if (!IsContinue(missionId, bundleName)) {
            HILOGE("Not current mission to be continued, missionId: %{public}d", missionId);
            EraseFocusedMission(bundleName, missionId, reason);
            return NO_MISSION_INFO_FOR_MISSION_ID;
        }
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
        RemoveMMIListener();
#endif
    }
    uint16_t bundleNameId = 0;
    uint8_t continueTypeId = 0;
    ret = BundleManagerInternal::GetContinueTypeId(bundleName, abilityName, continueTypeId);
    if (ret != ERR_OK) {
        HILOGE("Get focused contineTypeId failed, contineTypeId: %{public}u, ret: %{public}d", continueTypeId, ret);
        return ret;
    }
    ret = GetAccessTokenIdSendEvent(bundleName, reason, bundleNameId, continueTypeId);
    if (ret != ERR_OK) {
        HILOGE("GetAccessTokenIdSendEvent failed");
        EraseFocusedMission(bundleName, missionId, reason);
        return ret;
    }
    EraseFocusedMission(bundleName, missionId, reason);
    if (reason == UnfocusedReason::NORMAL && screenOffHandler_ != nullptr) {
        screenOffHandler_->SetScreenOffInfo(missionId, bundleName, bundleNameId, abilityName);
    }
    HILOGI("DealUnfocusedBusiness end");
    return ERR_OK;
}

void DMSContinueSendMgr::EraseFocusedMission(const std::string& bundleName, const int32_t& missionId,
    const UnfocusedReason& reason)
{
    HILOGI("accountId: %{public}d.", accountId_);
    if (reason != UnfocusedReason::TIMEOUT) {
        std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
        focusedMission_.erase(bundleName);
        focusedMissionAbility_.erase(missionId);
        lastFocusedMissionInfo_ = { missionId, bundleName };
    }
}

int32_t DMSContinueSendMgr::SendScreenOffEvent(uint8_t type)
{
    HILOGI("accountId: %{public}d.", accountId_);
    if (screenOffHandler_ == nullptr) {
        HILOGE("screenOffHandler_ is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t missionId = screenOffHandler_->GetMissionId();
    std::string bundleName = screenOffHandler_->GetBundleName();
    uint16_t bundleNameId = screenOffHandler_->GetAccessTokenId();
    std::string abilityName = screenOffHandler_->GetAbilityName();

    HILOGI("start, type: %{public}d, missionId: %{public}d, bundleName: %{public}s, bundleNameId: %{public}u",
        type, missionId, bundleName.c_str(), bundleNameId);
    if (!DmsKvSyncE2E::GetInstance()->CheckBundleContinueConfig(bundleName)) {
        HILOGI("App does not allow continue in config file, bundle name %{public}s, missionId: %{public}d",
            bundleName.c_str(), missionId);
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }

    if (!DataShareManager::GetInstance().IsCurrentContinueSwitchOn()) {
        HILOGE("ContinueSwitch status is off");
        return DMS_PERMISSION_DENIED;
    }

    uint8_t continueTypeId = 0;
    int32_t ret = BundleManagerInternal::GetContinueTypeId(bundleName, abilityName, continueTypeId);
    if (ret != ERR_OK) {
        HILOGE("Get focused contineTypeId failed, abilityName: %{public}s, ret: %{public}d", abilityName.c_str(), ret);
        return ret;
    }

    ret = SendSoftbusEvent(bundleNameId, continueTypeId, type);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent unfocused failed, ret: %{public}d", ret);
    }
    HILOGI("end");
    return ERR_OK;
}

int32_t DMSContinueSendMgr::GetBundleNameByMissionId(const int32_t missionId, std::string& bundleName)
{
    HILOGI("accountId: %{public}d.", accountId_);
    std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
    for (auto iterItem = focusedMission_.begin(); iterItem != focusedMission_.end(); iterItem++) {
        if (iterItem->second == missionId) {
            bundleName = iterItem->first;
            return ERR_OK;
        }
    }
    return INVALID_PARAMETERS_ERR;
}

int32_t DMSContinueSendMgr::GetBundleNameByScreenOffInfo(const int32_t missionId, std::string& bundleName)
{
    HILOGI("accountId: %{public}d.", accountId_);
    if (screenOffHandler_ != nullptr && missionId == screenOffHandler_->GetMissionId()) {
        bundleName = screenOffHandler_->GetBundleName();
        if (bundleName.empty()) {
            HILOGE("get bundleName failed from screenOffHandler");
            return INVALID_PARAMETERS_ERR;
        }
        HILOGI("get missionId end, bundleName: %{public}s", bundleName.c_str());
        return ERR_OK;
    }
    HILOGE("get bundleName failed from screenOffHandler");
    return INVALID_PARAMETERS_ERR;
}

int32_t DMSContinueSendMgr::GetAbilityNameByMissionId(const int32_t missionId, std::string& abilityName)
{
    HILOGI("start, missionId: %{public}d. accountId: %{public}d.", missionId, accountId_);
    std::lock_guard<std::mutex> focusedMissionAbilityMapLock(eventMutex_);
    auto iterItem = focusedMissionAbility_.find(missionId);
    if (iterItem != focusedMissionAbility_.end()) {
        abilityName = iterItem->second;
        HILOGI("get missionId end, missionId: %{public}d", missionId);
        return ERR_OK;
    }
    HILOGW("get iterItem failed from focusedMissionAbility_, try screenOffHandler_");
    if (screenOffHandler_ != nullptr && missionId == screenOffHandler_->GetMissionId()) {
        abilityName = screenOffHandler_->GetAbilityName();
        HILOGI("get missionId end, abilityName: %{public}s", abilityName.c_str());
        return ERR_OK;
    }
    HILOGE("get abilityName failed from screenOffHandler_");
    return INVALID_PARAMETERS_ERR;
}

bool DMSContinueSendMgr::IsContinue(const int32_t& missionId, const std::string& bundleName)
{
    HILOGI("accountId: %{public}d.", accountId_);
    if (missionId != info_.currentMissionId && info_.currentIsContinuable) {
        /*missionId and currentMissionId are not equal but currentMission can change,
            continue to not send unfocus broadcast*/
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
    HILOGI("SetMissionContinueState start, missionId: %{public}d, state: %{public}d. accountId: %{public}d.",
        missionId, state, accountId_);
    auto feedfunc = [this, missionId, state]() {
        DealSetMissionContinueStateBusiness(missionId, state);
        if (state == AAFwk::ContinueState::CONTINUESTATE_ACTIVE && missionId == info_.currentMissionId &&
            info_.currentIsContinuable) {
            PostUnfocusedTaskWithDelay(missionId, UnfocusedReason::TIMEOUT);
        }
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(TIMEOUT_UNFOCUSED_TASK + std::to_string(missionId));
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
    HILOGI("DealSetMissionContinueStateBusiness start,missionId: %{public}d,state: %{public}d.accountId: %{public}d.",
        missionId, state, accountId_);
    if (info_.currentMissionId != missionId) {
        HILOGE("mission is not focused, broadcast task abort, missionId: %{public}d", missionId);
        return INVALID_PARAMETERS_ERR;
    }
    std::string bundleName;
    if (state == AAFwk::ContinueState::CONTINUESTATE_ACTIVE &&
        GetBundleNameByMissionId(missionId, bundleName) != ERR_OK) {
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
    HILOGI("accountId: %{public}d.", accountId_);
    std::string bundleName;
    int32_t ret = GetBundleNameByMissionId(missionId, bundleName);
    if (ret != ERR_OK) {
        HILOGW("get iterItem failed from focusedMission, try screenOffHandler");
        if (GetBundleNameByScreenOffInfo(missionId, bundleName) != ERR_OK) {
            HILOGE("get bundleName failed, missionId: %{public}d, ret: %{public}d", missionId, ret);
            return ret;
        }
    }
    HILOGI("get bundleName success, missionId: %{public}d, bundleName: %{public}s", missionId, bundleName.c_str());
    if (!DmsKvSyncE2E::GetInstance()->CheckBundleContinueConfig(bundleName)) {
        HILOGI("App does not allow continue in config file, bundle name %{public}s, missionId: %{public}d",
            bundleName.c_str(), missionId);
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }

    ret = BundleManagerInternal::GetBundleNameId(bundleName, bundleNameId);
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
    HILOGI("accountId: %{public}d.", accountId_);
    NotifyMissionFocused(INVALID_MISSION_ID, FocusedReason::MMI);
}

int32_t DMSContinueSendMgr::NotifyDeviceOnline()
{
    HILOGD("NotifyDeviceOnline called");
    HILOGI("accountId: %{public}d.", accountId_);
    int32_t missionId = GetCurrentMissionId();
    if (missionId <= 0) {
        HILOGW("GetCurrentMissionId failed, init end. ret: %{public}d", missionId);
        return INVALID_MISSION_ID;
    }
    NotifyMissionFocused(missionId, FocusedReason::ONLINE);
    return ERR_OK;
}

void DMSContinueSendMgr::OnDeviceScreenOff()
{
    HILOGI("OnDeviceScreenOff called. accountId: %{public}d.", accountId_);
    int32_t missionId = info_.currentMissionId;
    if (!info_.currentIsContinuable || CheckContinueState(missionId) != ERR_OK) {
        HILOGW("current mission is not continuable, ignore");
        return;
    }
    auto feedfunc = [this, missionId]() {
        if (screenOffHandler_ != nullptr) {
            screenOffHandler_->OnDeviceScreenOff(missionId);
        }
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->PostTask(feedfunc);
}

void DMSContinueSendMgr::OnDeviceScreenOn()
{
    HILOGI("OnDeviceScreenOn called. accountId: %{public}d.", accountId_);
    auto feedfunc = [this]() {
        if (screenOffHandler_ != nullptr) {
            screenOffHandler_->OnDeviceScreenOn();
        }
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->PostTask(feedfunc);
}

DMSContinueSendMgr::ScreenOffHandler::ScreenOffHandler(const std::shared_ptr<DMSContinueSendMgr>& dmsContinueSendMgr)
    : dmsContinueSendMgr_(dmsContinueSendMgr)
{
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
    std::shared_ptr<DMSContinueSendMgr> sendMgr = dmsContinueSendMgr_.lock();
    if (sendMgr == nullptr) {
        HILOGW("sendMgr is nullptr.");
        return;
    }
    if (unfoInfo_.missionId != INVALID_MISSION_ID && (GetTickCount()- unfoInfo_.unfoTime) < TIME_DELAYED) {
        // handle unfocus before screen off
        sendMgr->SendScreenOffEvent(DMS_FOCUSED_TYPE);
    }
    sendMgr->PostUnfocusedTaskWithDelay(missionId, UnfocusedReason::SCREENOFF);
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
    uint16_t bundleNameId, std::string abilityName)
{
    HILOGI("set last unfocused info, missionId: %{public}d, bundleName: %{public}s, bundleNameId: %{public}u",
        missionId, bundleName.c_str(), bundleNameId);
    unfoInfo_.missionId = missionId;
    unfoInfo_.unfoTime = GetTickCount();
    unfoInfo_.bundleName = bundleName;
    unfoInfo_.accessToken = bundleNameId;
    unfoInfo_.abilityName = abilityName;
}

int32_t DMSContinueSendMgr::GetAccessTokenIdSendEvent(std::string bundleName,
    UnfocusedReason reason, uint16_t& bundleNameId, uint8_t& continueTypeId)
{
    HILOGI("accountId: %{public}d.", accountId_);
    int32_t ret = BundleManagerInternal::GetBundleNameId(bundleName, bundleNameId);
    if (ret != ERR_OK) {
        HILOGE("Get unfocused bundleNameId failed, bundleNameId: %{public}u, ret: %{public}d", bundleNameId, ret);
        return ret;
    }

    if (screenOffHandler_ != nullptr && screenOffHandler_->IsDeviceScreenOn()) {
        ret = SendSoftbusEvent(bundleNameId, continueTypeId, DMS_UNFOCUSED_TYPE);
        if (ret != ERR_OK) {
            HILOGE("SendSoftbusEvent unfocused failed, ret: %{public}d", ret);
            return ret;
        }
    }
    return ret;
}

int32_t DMSContinueSendMgr::SetStateSendEvent(const uint16_t bundleNameId, const uint8_t& continueTypeId,
    const AAFwk::ContinueState &state)
{
    HILOGI("accountId: %{public}d.", accountId_);
    if (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE) {
        RemoveMMIListener();
    } else {
        AddMMIListener();
    }

    if (!DataShareManager::GetInstance().IsCurrentContinueSwitchOn()) {
        HILOGE("ContinueSwitch status is off");
        return DMS_PERMISSION_DENIED;
    }

    uint8_t type = state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE ? DMS_UNFOCUSED_TYPE : DMS_FOCUSED_TYPE;
    int32_t ret = SendSoftbusEvent(bundleNameId, continueTypeId, type);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent setContinueState failed, ret: %{public}d", ret);
        return ret;
    }
    return ret;
}

void DMSContinueSendMgr::DeleteContinueLaunchMissionInfo(const int32_t missionId)
{
    HILOGI("accountId: %{public}d.", accountId_);
    std::lock_guard<std::mutex> continueLaunchMissionMapLock(eventMutex_);
    if (continueLaunchMission_.empty()) {
        return;
    }
    for (auto iter = continueLaunchMission_.begin(); iter != continueLaunchMission_.end(); iter++) {
        if (iter->second == missionId) {
            continueLaunchMission_.erase(iter);
            return;
        }
    }
}

int32_t DMSContinueSendMgr::GetContinueLaunchMissionInfo(const int32_t missionId,
    ContinueLaunchMissionInfo& missionInfo)
{
    HILOGD("start, missionId: %{public}d. accountId: %{public}d.", missionId, accountId_);
    std::lock_guard<std::mutex> continueLaunchMissionMapLock(eventMutex_);
    for (auto iter = continueLaunchMission_.begin(); iter != continueLaunchMission_.end(); iter++) {
        if (iter->second == missionId) {
            missionInfo = iter->first;
            HILOGI("get missionInfo end, missionId: %{public}d", missionId);
            return ERR_OK;
        }
    }
    HILOGW("get missionInfo failed from continueLaunchMission");
    return INVALID_PARAMETERS_ERR;
}

bool DMSContinueSendMgr::UpdateContinueLaunchMission(const AAFwk::MissionInfo& info)
{
    HILOGI("accountId: %{public}d.", accountId_);
    auto flag = info.want.GetFlags();
    if ((flag & AAFwk::Want::FLAG_ABILITY_CONTINUATION) != AAFwk::Want::FLAG_ABILITY_CONTINUATION &&
        (flag & AAFwk::Want::FLAG_ABILITY_PREPARE_CONTINUATION) != AAFwk::Want::FLAG_ABILITY_PREPARE_CONTINUATION) {
        return false;
    }

    std::string bundleName = info.want.GetBundle();
    std::string abilityName = info.want.GetElement().GetAbilityName();
    ContinueLaunchMissionInfo continueLaunchMissionInfo = { bundleName, abilityName };

    std::lock_guard<std::mutex> continueLaunchMissionMapLock(eventMutex_);
    auto iterItem = continueLaunchMission_.find(continueLaunchMissionInfo);
    if (iterItem == continueLaunchMission_.end()) {
        HILOGI("not find continueLaunchMissionInfo");
        continueLaunchMission_[continueLaunchMissionInfo] = info.id;
        return true;
    }
    if (iterItem->second < info.id) {
        HILOGI("old missionId: %{public}d, new missionId: %{public}d", iterItem->second, info.id);
        continueLaunchMission_[continueLaunchMissionInfo] = info.id;
        return true;
    }
    return false;
}
} // namespace DistributedSchedule
} // namespace OHOS
