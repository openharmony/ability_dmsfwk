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

#ifndef DMS_CONTINUE_SEND_MANAGER_H
#define DMS_CONTINUE_SEND_MANAGER_H

#include <deque>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "bundle/bundle_manager_internal.h"
#include "distributed_mission_died_listener.h"
#include "event_handler.h"
#include "mission_info.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string CONTINUE_MANAGER = "continue_manager";
struct currentMissionInfo {
    int32_t currentMissionId;
    bool currentIsContinuable;
};

struct lastUnfoInfo {
    int32_t missionId;
    int32_t unfoTime;
    std::string bundleName;
    uint32_t accessToken;
    std::string abilityName;
};

struct ContinueLaunchMissionInfo {
    std::string bundleName;
    std::string abilityName;

    bool operator == (const ContinueLaunchMissionInfo &other) const
    {
        return this->bundleName == other.bundleName && this->abilityName == other.abilityName;
    }

    bool operator < (const ContinueLaunchMissionInfo &other) const
    {
        return this->bundleName == other.bundleName
            ? this->abilityName < other.abilityName
            : this->bundleName < other.bundleName;
    }
};

struct LastFocusedMissionInfo {
    int32_t missionId;
    std::string bundleName;
};

enum class FocusedReason {
    MIN = -1,
    NORMAL,
    INIT,
    SCREENOFF,
    ONLINE,
    MMI,
    MAX
};

enum class UnfocusedReason {
    MIN = -1,
    NORMAL,
    DESTORY,
    CLOSE,
    TIMEOUT,
    SCREENOFF,
    MAX
};

class DMSContinueSendMgr {
    DECLARE_SINGLE_INSTANCE(DMSContinueSendMgr);

public:
    constexpr static uint8_t DMS_DATA_LEN = 3; // Dms data Length
    constexpr static int32_t DMS_SEND_LEN = 4; // Maximum broadcast length
    constexpr static uint8_t DMS_0XF0 = 0xf0;
    constexpr static uint8_t DMS_0X0F = 0x0f;
    constexpr static uint8_t DMS_0XFF = 0xff;
    constexpr static uint8_t DMS_FOCUSED_TYPE = 0x00;
    constexpr static uint8_t DMS_UNFOCUSED_TYPE = 0x01;
    constexpr static uint8_t CONTINUE_SHIFT_24 = 0x18;
    constexpr static uint8_t CONTINUE_SHIFT_16 = 0x10;
    constexpr static uint8_t CONTINUE_SHIFT_08 = 0x08;
    constexpr static uint8_t CONTINUE_SHIFT_04 = 0x04;
    constexpr static int32_t INVALID_MISSION_ID = -1;

    class ScreenOffHandler {
    public:
        ScreenOffHandler() = default;
        virtual ~ScreenOffHandler() = default;

        int32_t GetMissionId();
        std::string GetBundleName();
        std::string GetAbilityName();
        uint32_t GetAccessTokenId();
        bool IsDeviceScreenOn();
        void OnDeviceScreenOff(int32_t missionId);
        void OnDeviceScreenOn();
        void ClearScreenOffInfo();
        void SetScreenOffInfo(int32_t missionId, std::string bundleName, uint16_t bundleNameId,
            std::string abilityName);

    private:
        bool isScreenOn_ = true;
        lastUnfoInfo unfoInfo_ = { INVALID_MISSION_ID, 0, "", 0 };
    };

    void Init();
    void UnInit();
    void NotifyMissionFocused(const int32_t missionId, FocusedReason reason);
    void NotifyMissionUnfocused(const int32_t missionId, UnfocusedReason reason);
    int32_t GetMissionIdByBundleName(const std::string& bundleName, int32_t& missionId);
    int32_t SetMissionContinueState(const int32_t missionId, const AAFwk::ContinueState& state);
    void OnMMIEvent();
    void OnDeviceScreenOff();
    void OnDeviceScreenOn();
    int32_t NotifyDeviceOnline();
    int32_t SendScreenOffEvent(uint8_t type);
    void DeleteContinueLaunchMissionInfo(const int32_t missionId);
    int32_t GetContinueLaunchMissionInfo(const int32_t missionId, ContinueLaunchMissionInfo& missionInfo);

private:
    int32_t GetCurrentMissionId();
    void PostUnfocusedTaskWithDelay(const int32_t missionId, UnfocusedReason reason);
    int32_t SendSoftbusEvent(uint16_t bundleNameId, uint8_t continueTypeId, uint8_t type);
    void StartEvent();
    int32_t DealFocusedBusiness(const int32_t missionId);
    int32_t DealUnfocusedBusiness(const int32_t missionId, UnfocusedReason reason);
    void DealScreenOff();
    void DealTimerUnfocusedBussiness(const int32_t missionId);
    int32_t GetBundleNameByMissionId(const int32_t missionId, std::string& bundleName);
    bool IsContinue(const int32_t& missionId, const std::string& bundleName);
    int32_t DealSetMissionContinueStateBusiness(const int32_t missionId, const AAFwk::ContinueState& state);
    int32_t CheckContinueState(const int32_t missionId);
    void AddMMIListener();
    void RemoveMMIListener();
    int32_t GetAccessTokenIdSendEvent(std::string bundleName, UnfocusedReason reason, uint16_t& bundleNameId,
        uint8_t& continueTypeId);
    int32_t SetStateSendEvent(const uint16_t bundleNameId, const uint8_t& continueTypeId,
        const AAFwk::ContinueState &state);
    int32_t GetAbilityNameByMissionId(const int32_t missionId, std::string& abilityName);
    int32_t FocusedBusinessSendEvent(std::string bundleName, const std::string& abilityName);
    int32_t GetBundleNameIdAndContinueTypeId(const int32_t missionId, const AAFwk::ContinueState& state,
        uint16_t& bundleNameId, uint8_t& continueTypeId);
    void EraseFocusedMission(const std::string& bundleName, const int32_t& missionId, const UnfocusedReason& reason);
    bool UpdateContinueLaunchMission(const AAFwk::MissionInfo& info);
private:
    currentMissionInfo info_ = { INVALID_MISSION_ID, false };
    // Record the bundleName and missionId of the focused application, and clear them when out of focus
    std::map<std::string, int32_t> focusedMission_;
    // Record the missionId and abilityName of the focused application, and clear them when out of focus
    std::map<int32_t, std::string> focusedMissionAbility_;
    std::thread eventThread_;
    std::condition_variable eventCon_;
    std::mutex eventMutex_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler_;
    std::shared_ptr<ScreenOffHandler> screenOffHandler_;
    int32_t mmiMonitorId_ = INVALID_MISSION_ID;
    // Record the mission information of the continuation application, and clear them when the application is destroyed
    std::map<ContinueLaunchMissionInfo, int32_t> continueLaunchMission_;
    // Record the missionId and bundle name of the previous focused application
    LastFocusedMissionInfo lastFocusedMissionInfo_ = { INVALID_MISSION_ID, "" };
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DMS_CONTINUE_SEND_MANAGER_H
