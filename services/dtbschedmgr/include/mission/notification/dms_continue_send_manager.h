/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <cstdint>

#include "event_handler.h"
#include "single_instance.h"
#include "mission/dms_continue_condition_manager.h"
#include "mission/notification/dms_continue_send_strategy.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
    constexpr uint8_t BROADCAST_TYPE_APPEAR = 0;
    constexpr uint8_t BROADCAST_TYPE_DISAPPEAR = 1;
    constexpr int32_t DEFAULT_USER = 100;
}

class DMSContinueSendMgr : public std::enable_shared_from_this<DMSContinueSendMgr> {
friend class SendStrategyFocused;
friend class SendStrategyUnfocused;
friend class SendStrategyDestoryed;
friend class SendStrategyActive;
friend class SendStrategyInactive;
friend class SendStrategyTimeout;
friend class SendStrategyMMI;

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
    constexpr static int32_t INVALID_ID = -1;
    constexpr static int32_t INVALID_MISSION_ID = -1;

    ~DMSContinueSendMgr();
    void Init(int32_t currentUserId);
    void UnInit();

    void OnMissionStatusChanged(int32_t missionId, MissionEventType type);
    void OnMMIEvent();
    int32_t OnDeviceOnline();
    void OnDeviceScreenLocked();
    void OnDeviceScreenOn();
    void OnUserSwitched();

private:
    void StartEvent();
    void SendContinueBroadcast(int32_t missionId, MissionEventType type);
    void SendContinueBroadcast(const MissionStatus& status, MissionEventType type);
    void SendContinueBroadcastAfterDelay(int32_t missionId);
    int32_t ExecuteSendStrategy(MissionEventType type, const MissionStatus& status, uint8_t &sendType);
    int32_t QueryBroadcastInfo(const MissionStatus& status, uint16_t& bundleNameId, uint8_t& continueTypeId);
    void SendSoftbusEvent(uint16_t& bundleNameId, uint8_t& continueTypeId, uint8_t type);
    void AddMMIListener();
    void RemoveMMIListener();

private:
    class ScreenLockedHandler {
    public:
        struct LastUnfoInfo {
            int32_t missionId;
            int32_t unfoTime;
            MissionStatus status;
        };

        ScreenLockedHandler() = default;
        explicit ScreenLockedHandler(const std::shared_ptr<DMSContinueSendMgr>& dmsContinueSendMgr);
        virtual ~ScreenLockedHandler() = default;

        int32_t GetMissionId();
        MissionStatus GetMissionStatus();
        void OnDeviceScreenLocked();
        void ResetScreenLockedInfo();
        void SetScreenLockedInfo(LastUnfoInfo info);
        void SetMissionContinueStateInfo(const MissionStatus& status);

    private:
        LastUnfoInfo unfoInfo_ = { INVALID_MISSION_ID, 0, { INVALID_MISSION_ID, "", "", "", false, 0, false } };
        std::weak_ptr<DMSContinueSendMgr> dmsContinueSendMgr_;
    };

    int32_t SendScreenLockedEvent(uint8_t type);
    void PostScreenLockedEventAfterDelay(int32_t missionId, uint8_t type, int32_t timeout);

private:
    int32_t accountId_ = DEFAULT_USER;
    int32_t mmiMonitorId_ = INVALID_ID;
    std::thread eventThread_;
    std::condition_variable eventCon_;
    std::mutex eventMutex_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler_;
    std::shared_ptr<ScreenLockedHandler> screenLockedHandler_;
    std::map<MissionEventType, std::shared_ptr<ContinueSendStrategy>> strategyMap_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DMS_CONTINUE_SEND_MANAGER_H
