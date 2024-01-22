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

#ifndef DISTRIBUTEDSCHED_CONTINUE_MANAGER_H
#define DISTRIBUTEDSCHED_CONTINUE_MANAGER_H

#include <deque>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <vector>

#include "bundle/bundle_manager_internal.h"
#ifdef SUPPORT_COMMON_EVENT_SERVICE
#include "common_event_listener.h"
#endif
#include "distributed_mission_died_listener.h"
#include "distributed_mission_focused_listener.h"
#include "event_handler.h"
#include "mission_info.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string CONTINUE_MANAGER = "continue_manager";
struct currentMissionInfo {
    int32_t currentMissionId;
    bool currentIsContinuable;
};

enum class FocusedReason {
    MIN,
    NORMAL,
    INIT,
    SCREENOFF,
    MMI,
    MAX
};

class DistributedSchedContinueManager {
    DECLARE_SINGLE_INSTANCE(DistributedSchedContinueManager);

public:
    constexpr static int32_t DMS_SEND_LEN = 5;
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

    void Init();
    void UnInit();
    void NotifyMissionFocused(const int32_t missionId, FocusedReason focusedReason);
    void NotifyMissionUnfocused(const int32_t missionId);
    void NotifyScreenOff();
    int32_t GetMissionId(const std::string& bundleName, int32_t& missionId);
    void NotifyDeid(const sptr<IRemoteObject>& obj);
    int32_t SetMissionContinueState(const int32_t missionId, const AAFwk::ContinueState& state);
    void OnMMIEvent();

private:
    int32_t GetCurrentMissionId();
    void AddCancelMissionFocusedTimer(const int32_t missionId, const std::string eventName, const int32_t delay);
    int32_t SendSoftbusEvent(uint32_t accessTokenId, uint8_t type);
    void StartEvent();
    int32_t DealFocusedBusiness(const int32_t missionId);
    int32_t DealUnfocusedBusiness(const int32_t missionId, bool isUnfocused);
    void DealScreenOff();
    void DealTimerUnfocusedBussiness(const int32_t missionId);
    int32_t GetBundleName(const int32_t missionId, std::string& bundleName);
    bool IsContinue(const int32_t& missionId, const std::string& bundleName);
    int32_t DealSetMissionContinueStateBusiness(const int32_t missionId, const AAFwk::ContinueState& state);
    int32_t CheckContinueState(const int32_t missionId);
    void AddMMIListener();
    void RemoveMMIListener();
private:
    currentMissionInfo info_ = { INVALID_MISSION_ID, false };
    sptr<DistributedMissionFocusedListener> missionFocusedListener_;
    sptr<DistributedMissionDiedListener> missionDiedListener_;
    std::string onType_;
    std::map<std::string, int32_t> focusedMission_;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> registerOnListener_;
    std::thread eventThread_;
    std::condition_variable eventCon_;
    std::mutex eventMutex_;
    std::mutex iconMutex_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler_;
    int32_t mmiMonitorId_ = INVALID_MISSION_ID;
    std::map<int32_t, int64_t> screenLockInfo_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DISTRIBUTEDSCHED_CONTINUE_MANAGER_H
