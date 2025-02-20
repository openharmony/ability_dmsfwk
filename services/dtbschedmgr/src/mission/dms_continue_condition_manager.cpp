/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "mission/dms_continue_condition_manager.h"

#include "ability_manager_client.h"
#include "datashare_manager.h"
#include "dtbschedmgr_log.h"
#include "mission_info.h"
#include "mission/bluetooth_state_adapter.h"
#include "mission/dsched_sync_e2e.h"
#include "mission/wifi_state_adapter.h"
#include "multi_user_manager.h"


namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsContinueConditionMgr";
constexpr int32_t GET_MAX_MISSIONS = 50;
constexpr int32_t CONDITION_INVALID_MISSION_ID = -1;
}

IMPLEMENT_SINGLE_INSTANCE(DmsContinueConditionMgr);

void DmsContinueConditionMgr::Init()
{
    InitConditionFuncs();
    InitSystemCondition();
    InitMissionCondition();
}

void DmsContinueConditionMgr::UnInit()
{
    std::lock_guard<std::mutex> missionlock(missionMutex_);
    missionMap_.clear();
}

void DmsContinueConditionMgr::InitConditionFuncs()
{
    sysFuncMap_[SYS_EVENT_CONTINUE_SWITCH] = &DmsContinueConditionMgr::SetIsContinueSwitchOn;
    sysFuncMap_[SYS_EVENT_WIFI] = &DmsContinueConditionMgr::SetIsWifiActive;
    sysFuncMap_[SYS_EVENT_BLUETOOTH] = &DmsContinueConditionMgr::SetIsBtActive;
    sysFuncMap_[SYS_EVENT_SCREEN_LOCK] = &DmsContinueConditionMgr::SetIsScreenLocked;

    missionFuncMap_[MISSION_EVENT_FOCUSED] = &DmsContinueConditionMgr::OnMissionFocused;
    missionFuncMap_[MISSION_EVENT_UNFOCUSED] = &DmsContinueConditionMgr::OnMissionUnfocused;
    missionFuncMap_[MISSION_EVENT_DESTORYED] = &DmsContinueConditionMgr::OnMissionDestory;
    missionFuncMap_[MISSION_EVENT_ACTIVE] = &DmsContinueConditionMgr::OnMissionActive;
    missionFuncMap_[MISSION_EVENT_INACTIVE] = &DmsContinueConditionMgr::OnMissionInactive;

    conditionFuncMap_[MISSION_EVENT_FOCUSED] = &DmsContinueConditionMgr::CheckSendFocusedCondition;
    conditionFuncMap_[MISSION_EVENT_UNFOCUSED] = &DmsContinueConditionMgr::CheckSendUnfocusedCondition;
    conditionFuncMap_[MISSION_EVENT_DESTORYED] = &DmsContinueConditionMgr::CheckSendUnfocusedCondition;
    conditionFuncMap_[MISSION_EVENT_ACTIVE] = &DmsContinueConditionMgr::CheckSendActiveCondition;
    conditionFuncMap_[MISSION_EVENT_INACTIVE] = &DmsContinueConditionMgr::CheckSendInactiveCondition;
    conditionFuncMap_[MISSION_EVENT_TIMEOUT] = &DmsContinueConditionMgr::CheckSendUnfocusedCondition;
    conditionFuncMap_[MISSION_EVENT_MMI] = &DmsContinueConditionMgr::CheckSendFocusedCondition;
}

void DmsContinueConditionMgr::InitSystemCondition()
{
    isCfgDevice_ = !DmsKvSyncE2E::GetInstance()->CheckCtrlRule();
    isSwitchOn_ = DataShareManager::GetInstance().IsCurrentContinueSwitchOn();
    isWifiActive_ = WifiStateAdapter::GetInstance().IsWifiActive();
    isBtActive_ = BluetoothStateAdapter::GetInstance().IsBluetoothActive();

    HILOGI("end. cfg %{public}d, switch: %{public}d, wifi: %{public}d, bt: %{public}d",
        isCfgDevice_.load(), isSwitchOn_.load(), isWifiActive_.load(), isBtActive_.load());
}

void DmsContinueConditionMgr::InitMissionCondition()
{
    int32_t currentAccountId = MultiUserManager::GetInstance().GetForegroundUser();
    InitMissionStatus(currentAccountId);
}

int32_t DmsContinueConditionMgr::UpdateSystemStatus(SysEventType type, bool value)
{
    auto iterFunc = sysFuncMap_.find(type);
    if (iterFunc == sysFuncMap_.end()) {
        HILOGE("invalid system status %{public}d", type);
        return INVALID_PARAMETERS_ERR;
    }

    auto memberFunc = iterFunc->second;
    int32_t ret = (this->*memberFunc)(value);
    if (ret != ERR_OK) {
        HILOGE("update system status %{public}d failed, ret: %{public}d", type, ret);
    }
    return ret;
}

int32_t DmsContinueConditionMgr::SetIsContinueSwitchOn(bool isSwitchOn)
{
    HILOGI("isSwitchOn changed, before: %{public}d, after: %{public}d", isSwitchOn_.load(), isSwitchOn);
    isSwitchOn_.store(isSwitchOn);
    return ERR_OK;
}

int32_t DmsContinueConditionMgr::SetIsWifiActive(bool isWifiActive)
{
    HILOGI("isWifiActive changed, before: %{public}d, after: %{public}d", isWifiActive_.load(), isWifiActive);
    isWifiActive_.store(isWifiActive);
    return ERR_OK;
}

int32_t DmsContinueConditionMgr::SetIsBtActive(bool isBtActive)
{
    HILOGI("isBtActive changed, before: %{public}d, after: %{public}d", isBtActive_.load(), isBtActive);
    isBtActive_.store(isBtActive);
    return ERR_OK;
}

int32_t DmsContinueConditionMgr::SetIsScreenLocked(bool isScreenLocked)
{
    HILOGI("isScreenLocked changed, before: %{public}d, after: %{public}d", isScreenLocked_.load(), isScreenLocked);
    isScreenLocked_.store(isScreenLocked);
    return ERR_OK;
}

void DmsContinueConditionMgr::OnUserSwitched(int32_t accountId)
{
    HILOGI("OnUserSwitched init mission status for new user: %{public}d", accountId);
    InitMissionStatus(accountId);
    return;
}

void DmsContinueConditionMgr::OnUserRemoved(int32_t accountId)
{
    HILOGI("OnUserRemoved delete mission status for user: %{public}d", accountId);
    std::lock_guard<std::mutex> missionlock(missionMutex_);
    if (missionMap_.empty()) {
        return;
    }
    auto it = missionMap_.find(accountId);
    if (it != missionMap_.end()) {
        missionMap_.erase(it);
    }
    return;
}

int32_t DmsContinueConditionMgr::UpdateMissionStatus(int32_t accountId, int32_t missionId, MissionEventType type)
{
    HILOGI("user %{public}d, missionId %{public}d, type %{public}s", accountId, missionId,
        TypeEnumToString(type).c_str());
    {
        std::lock_guard<std::mutex> missionlock(missionMutex_);
        auto missionList = missionMap_.find(accountId);
        if (missionList == missionMap_.end()) {
            HILOGW("no mission status records for user %{public}d", accountId);
            return INVALID_PARAMETERS_ERR;
        }
    }

    auto iterFunc = missionFuncMap_.find(type);
    if (iterFunc == missionFuncMap_.end()) {
        HILOGE("invalid mission status %{public}d", type);
        return INVALID_PARAMETERS_ERR;
    }

    auto memberFunc = iterFunc->second;
    int32_t ret = (this->*memberFunc)(accountId, missionId);
    if (ret != ERR_OK) {
        HILOGE("update mission status %{public}s failed, accountId %{public}d, missionId %{public}d, ret: %{public}d",
            TypeEnumToString(type).c_str(), accountId, missionId, ret);
    }
    return ret;
}

void DmsContinueConditionMgr::InitMissionStatus(int32_t accountId)
{
    HILOGI("InitMissionStatus for user %{public}d start", accountId);
    std::vector<AAFwk::MissionInfo> missions;
    int32_t ret = GetMissionInfos(missions);
    if (ret != ERR_OK) {
        HILOGE("GetMissionInfos failed, ret %{public}d", ret);
    }

    if (missions.empty()) {
        HILOGW("no running mission under current user");
    }
    HILOGI("GetMissionInfos ret size %{public}zu", missions.size());

    int32_t focusedMissionId = GetCurrentMissionId();
    {
        std::lock_guard<std::mutex> missionlock(missionMutex_);
        if (!missionMap_.empty() && missionMap_.find(accountId) != missionMap_.end()) {
            HILOGI("mission list for user %{public}d has already been inited", accountId);
            return;
        }

        std::map<int32_t, MissionStatus> missionList;
        for (auto mission : missions) {
            MissionStatus status;
            ConvertToMissionStatus(mission, status);
            HILOGD("mission %{public}d status: %{public}s", mission.id, status.ToString().c_str());
            missionList[mission.id] = status;
        }

        if (focusedMissionId > 0 && missionList.count(focusedMissionId) != 0) {
            missionList[focusedMissionId].isFocused = true;
        }
        missionMap_[accountId] = missionList;
    }

    HILOGI("InitMissionStatus for user %{public}d end", accountId);
    return;
}

int32_t DmsContinueConditionMgr::GetMissionInfos(std::vector<AAFwk::MissionInfo>& missions)
{
    auto abilityMgr = AAFwk::AbilityManagerClient::GetInstance();
    if (abilityMgr == nullptr) {
        HILOGE("abilityMgr is null");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t ret = abilityMgr->Connect();
    if (ret != ERR_OK) {
        HILOGE("get ability server failed, ret = %{public}d", ret);
        return ret;
    }
    return abilityMgr->GetMissionInfos("", GET_MAX_MISSIONS, missions);
}

int32_t DmsContinueConditionMgr::OnMissionFocused(int32_t accountId, int32_t missionId)
{
    HILOGI("accountId %{public}d, missionId %{public}d", accountId, missionId);

    AAFwk::MissionInfo info;
    int32_t ret = GetMissionInfo(missionId, info);
    {
        std::lock_guard<std::mutex> missionlock(missionMutex_);
        if (IsMissionStatusExistLocked(accountId, missionId)) {
            HILOGI("found mission %{public}d, update status: isFocused", missionId);
            CleanLastFocusedFlagLocked(accountId, missionId);
            missionMap_[accountId][missionId].isFocused = true;
            return ERR_OK;
        }

        if (ret != ERR_OK) {
            HILOGE("GetMissionInfo failed, missionId %{public}d, ret %{public}d", missionId, ret);
            return ret;
        }

        HILOGI("new mission %{public}d focused, add record", missionId);
        MissionStatus status;
        ConvertToMissionStatus(info, status);
        CleanLastFocusedFlagLocked(accountId, missionId);
        status.isFocused = true;

        HILOGD("mission %{public}d status: %{public}s", missionId, status.ToString().c_str());
        missionMap_[accountId][missionId] = status;
    }
    return ERR_OK;
}

int32_t DmsContinueConditionMgr::GetMissionInfo(int32_t missionId, AAFwk::MissionInfo& info)
{
    auto abilityMgr = AAFwk::AbilityManagerClient::GetInstance();
    if (abilityMgr == nullptr) {
        HILOGE("abilityMgr is null");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t ret = abilityMgr->Connect();
    if (ret != ERR_OK) {
        HILOGE("get ability server failed, ret = %{public}d", ret);
        return ret;
    }
    return abilityMgr->GetMissionInfo("", missionId, info);
}

void DmsContinueConditionMgr::ConvertToMissionStatus(const AAFwk::MissionInfo& missionInfo,
    MissionStatus& status)
{
    status.missionId = missionInfo.id;
    status.bundleName = missionInfo.want.GetElement().GetBundleName();
    status.moduleName = missionInfo.want.GetElement().GetModuleName();
    status.abilityName = missionInfo.want.GetElement().GetAbilityName();
    status.isContinuable = missionInfo.continuable;
    status.launchFlag = missionInfo.want.GetFlags();
    status.continueState = missionInfo.continueState;
    return;
}

void DmsContinueConditionMgr::CleanLastFocusedFlagLocked(int32_t accountId, int32_t missionId)
{
    for (auto& record : missionMap_[accountId]) {
        if (record.first != missionId && record.second.isFocused) {
            HILOGI("new mission %{public}d focused, mission %{public}d lose focus", missionId, record.first);
            record.second.isFocused = false;
        }
    }
    return;
}

int32_t DmsContinueConditionMgr::OnMissionUnfocused(int32_t accountId, int32_t missionId)
{
    HILOGI("accountId %{public}d, missionId %{public}d", accountId, missionId);

    std::lock_guard<std::mutex> missionlock(missionMutex_);
    if (!IsMissionStatusExistLocked(accountId, missionId)) {
        HILOGW("mission %{public}d under user %{public}d not exist", missionId, accountId);
        return CONDITION_INVALID_MISSION_ID;
    }
    missionMap_[accountId][missionId].isFocused = false;
    lastFocusMission_.first = accountId;
    lastFocusMission_.second = missionMap_[accountId][missionId];
    HILOGI("missionMap update finished! status: %{public}s", missionMap_[accountId][missionId].ToString().c_str());
    return ERR_OK;
}

int32_t DmsContinueConditionMgr::OnMissionDestory(int32_t accountId, int32_t missionId)
{
    HILOGI("accountId %{public}d, missionId %{public}d", accountId, missionId);

    std::lock_guard<std::mutex> missionlock(missionMutex_);
    if (!IsMissionStatusExistLocked(accountId, missionId)) {
        HILOGW("mission %{public}d under user %{public}d not exist", missionId, accountId);
        return ERR_OK;
    }
    missionMap_[accountId].erase(missionId);
    HILOGI("missionMap update finished!");
    return ERR_OK;
}

int32_t DmsContinueConditionMgr::OnMissionActive(int32_t accountId, int32_t missionId)
{
    HILOGI("accountId %{public}d, missionId %{public}d", accountId, missionId);

    std::lock_guard<std::mutex> missionlock(missionMutex_);
    if (!IsMissionStatusExistLocked(accountId, missionId)) {
        HILOGW("mission %{public}d under user %{public}d not exist", missionId, accountId);
        return ERR_OK;
    }
    missionMap_[accountId][missionId].continueState = AAFwk::ContinueState::CONTINUESTATE_ACTIVE;
    HILOGI("missionMap update finished! status: %{public}s", missionMap_[accountId][missionId].ToString().c_str());
    return ERR_OK;
}

int32_t DmsContinueConditionMgr::OnMissionInactive(int32_t accountId, int32_t missionId)
{
    HILOGI("accountId %{public}d, missionId %{public}d", accountId, missionId);

    std::lock_guard<std::mutex> missionlock(missionMutex_);
    if (!IsMissionStatusExistLocked(accountId, missionId)) {
        HILOGW("mission %{public}d under user %{public}d not exist", missionId, accountId);
        return ERR_OK;
    }
    missionMap_[accountId][missionId].continueState = AAFwk::ContinueState::CONTINUESTATE_INACTIVE;
    HILOGI("missionMap update finished! status: %{public}s", missionMap_[accountId][missionId].ToString().c_str());
    return ERR_OK;
}

bool DmsContinueConditionMgr::CheckSystemSendCondition()
{
    HILOGI("CheckSystemSendCondition start. cfg %{public}d, switch: %{public}d, wifi: %{public}d, bt: %{public}d",
        isCfgDevice_.load(), isSwitchOn_.load(), isWifiActive_.load(), isBtActive_.load());

    std::string reason = "";
    do {
        if (isCfgDevice_) {
            reason = "CFG_DEVICE";
            break;
        }
        if (!isSwitchOn_) {
            reason = "CONTINUE_SWITCH_OFF";
            break;
        }
#ifdef DMS_CHECK_WIFI
        if (!isWifiActive_) {
            reason = "WIFI_INACTIVE";
            break;
        }
#endif
#ifdef DMS_CHECK_BLUETOOTH
        if (!isBtActive_) {
            reason = "BLUETOOTH_INACTIVE";
            break;
        }
#endif
        HILOGI("PASS");
        return true;
    } while (0);

    HILOGE("FAILED, Reason: %{public}s", reason.c_str());
    return false;
}

bool DmsContinueConditionMgr::CheckMissionSendCondition(const MissionStatus& status, MissionEventType type)
{
    HILOGI("missionId %{public}d, type %{public}s", status.missionId, TypeEnumToString(type).c_str());

    auto iterFunc = conditionFuncMap_.find(type);
    if (iterFunc == conditionFuncMap_.end()) {
        HILOGE("invalid system status %{public}d", type);
        return false;
    }

    auto memberFunc = iterFunc->second;
    return (this->*memberFunc)(status);
}

bool DmsContinueConditionMgr::CheckSendFocusedCondition(const MissionStatus& status)
{
    HILOGI("missionId %{public}d", status.missionId);

    std::string reason = "";
    do {
        if (!status.isContinuable) {
            reason = "NOT_CONTINUABLE";
            break;
        }
        if (status.continueState != AAFwk::ContinueState::CONTINUESTATE_ACTIVE) {
            reason = "CONTINUE_STATE_INACTIVE";
            break;
        }
        if (!DmsKvSyncE2E::GetInstance()->CheckBundleContinueConfig(status.bundleName)) {
            reason = "BUNDLE_NOT_ALLOWED_IN_CFG";
            break;
        }
        HILOGI("PASS");
        return true;
    } while (0);

    HILOGE("FAILED, Reason: %{public}s", reason.c_str());
    return false;
}

bool DmsContinueConditionMgr::CheckSendUnfocusedCondition(const MissionStatus& status)
{
    HILOGI("missionId %{public}d", status.missionId);

    std::string reason = "";
    do {
        if (!status.isFocused) {
            reason = "NOT_FOCUSED";
            break;
        }
        if (!status.isContinuable) {
            reason = "NOT_CONTINUABLE";
            break;
        }
        if (status.continueState != AAFwk::ContinueState::CONTINUESTATE_ACTIVE) {
            reason = "CONTINUE_STATE_INACTIVE";
            break;
        }
        if (!DmsKvSyncE2E::GetInstance()->CheckBundleContinueConfig(status.bundleName)) {
            reason = "BUNDLE_NOT_ALLOWED_IN_CFG";
            break;
        }
        HILOGI("PASS");
        return true;
    } while (0);

    HILOGE("FAILED, Reason: %{public}s", reason.c_str());
    return false;
}

bool DmsContinueConditionMgr::CheckSendActiveCondition(const MissionStatus& status)
{
    HILOGI("missionId %{public}d", status.missionId);

    std::string reason = "";
    do {
        if (!status.isFocused) {
            reason = "NOT_FOCUSED";
            break;
        }
        if (!status.isContinuable) {
            reason = "NOT_CONTINUABLE";
            break;
        }
        if (!DmsKvSyncE2E::GetInstance()->CheckBundleContinueConfig(status.bundleName)) {
            reason = "BUNDLE_NOT_ALLOWED_IN_CFG";
            break;
        }
        HILOGI("PASS");
        return true;
    } while (0);

    HILOGE("FAILED, Reason: %{public}s", reason.c_str());
    return false;
}

bool DmsContinueConditionMgr::CheckSendInactiveCondition(const MissionStatus& status)
{
    HILOGI("missionId %{public}d", status.missionId);

    std::string reason = "";
    do {
        if (!status.isContinuable) {
            reason = "NOT_CONTINUABLE";
            break;
        }
        if (!DmsKvSyncE2E::GetInstance()->CheckBundleContinueConfig(status.bundleName)) {
            reason = "BUNDLE_NOT_ALLOWED_IN_CFG";
            break;
        }
        HILOGI("PASS");
        return true;
    } while (0);

    HILOGE("FAILED, Reason: %{public}s", reason.c_str());
    return false;
}

int32_t DmsContinueConditionMgr::GetMissionStatus(int32_t accountId, int32_t missionId, MissionStatus& status)
{
    std::lock_guard<std::mutex> missionlock(missionMutex_);
    if (!IsMissionStatusExistLocked(accountId, missionId)) {
        HILOGE("mission %{public}d under user %{public}d not exist", missionId, accountId);
        return INVALID_PARAMETERS_ERR;
    }

    status = missionMap_[accountId][missionId];
    return ERR_OK;
}

bool DmsContinueConditionMgr::IsMissionStatusExistLocked(int32_t accountId, int32_t missionId)
{
    if (missionMap_.count(accountId) == 0 || missionMap_[accountId].count(missionId) == 0) {
        return false;
    }
    return true;
}

bool DmsContinueConditionMgr::IsScreenLocked()
{
    return isScreenLocked_.load();
}

int32_t DmsContinueConditionMgr::GetMissionIdByBundleName(
    int32_t accountId, const std::string& bundleName, int32_t& missionId)
{
    std::lock_guard<std::mutex> missionlock(missionMutex_);
    if (missionMap_.count(accountId) == 0) {
        HILOGE("user %{public}d not exist!", accountId);
        return MISSION_NOT_FOCUSED;
    }

    missionId = GetCurrentFocusedMission(accountId);
    MissionStatus missionStatus = missionMap_[accountId][missionId];
    if (missionStatus.bundleName == bundleName && missionStatus.isContinuable) {
        return ERR_OK;
    }

    if (lastFocusMission_.second.bundleName == bundleName && lastFocusMission_.second.isContinuable) {
        missionId = lastFocusMission_.second.missionId;
        return ERR_OK;
    }
    return MISSION_NOT_FOCUSED;
}

int32_t DmsContinueConditionMgr::GetCurrentFocusedMission(int32_t accountId)
{
    int32_t missionId = CONDITION_INVALID_MISSION_ID;
    {
        std::lock_guard<std::mutex> missionlock(missionMutex_);
        if (missionMap_.count(accountId) == 0) {
            HILOGE("user %{public}d not exist!", accountId);
            return missionId;
        }
        for (const auto& record : missionMap_[accountId]) {
            if (record.second.isFocused) {
                missionId = record.first;
                break;
            }
        }
    }
    return missionId;
}

std::string DmsContinueConditionMgr::TypeEnumToString(MissionEventType type)
{
    switch (type) {
        case MISSION_EVENT_FOCUSED:
            return "FOCUSED";
        case MISSION_EVENT_UNFOCUSED:
            return "UNFOCUSED";
        case MISSION_EVENT_DESTORYED:
            return "DESTORYED";
        case MISSION_EVENT_ACTIVE:
            return "ACTIVE";
        case MISSION_EVENT_INACTIVE:
            return "INACTIVE";
        case MISSION_EVENT_TIMEOUT:
            return "TIMEOUT";
        case MISSION_EVENT_MMI:
            return "MMI";
        default:
            return "UNDEFINED";
    }
}
} // namespace DistributedSchedule
} // namespace OHOS
