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

#ifndef DISTRIBUTEDSCHED_CONTINUE_RECV_MANAGER_H
#define DISTRIBUTEDSCHED_CONTINUE_RECV_MANAGER_H

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
#include "distributed_mission_broadcast_listener.h"
#include "distributed_mission_died_listener.h"
#include "distributed_mission_focused_listener.h"
#include "event_handler.h"
#include "mission_info.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string CONTINUE_RECV_MANAGER = "continue_recv_manager";
struct currentIconInfo {
    std::string senderNetworkId;
    std::string bundleName;

    bool isEmpty()
    {
        return (this->senderNetworkId == "" && this->bundleName == "");
    }
};

class DistributedSchedContinueRecvManager {
    DECLARE_SINGLE_INSTANCE(DistributedSchedContinueRecvManager);

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
    void NotifyDataRecv(std::string& senderNetworkId, uint8_t* payload, uint32_t dataLen);
    int32_t RegisterOnListener(const std::string& type, const sptr<IRemoteObject>& obj);
    int32_t RegisterOffListener(const std::string& type, const sptr<IRemoteObject>& obj);
    void NotifyDeid(const sptr<IRemoteObject>& obj);
    void NotifyDeviceOffline(const std::string& networkId);
#ifdef SUPPORT_COMMON_EVENT_SERVICE
    void NotifyScreenOff();
#endif

private:
    int32_t GetCurrentMissionId();
    void StartEvent();
    int32_t VerifyBroadcastSource(const std::string& senderNetworkId, const std::string& bundleName,
        const int32_t state);
    void PostOnBroadcastBusiness(const std::string& senderNetworkId, uint32_t accessTokenId, const int32_t state,
        const int32_t delay = 0, const int32_t retry = 0);
    int32_t DealOnBroadcastBusiness(const std::string& senderNetworkId, uint32_t accessTokenId, const int32_t state,
        const int32_t retry = 0);
    void NotifyRecvBroadcast(const sptr<IRemoteObject>& obj, const std::string& networkId,
        const std::string& bundleName, const int32_t state);
private:
    currentIconInfo iconInfo_;
    sptr<DistributedMissionDiedListener> missionDiedListener_;
    std::string onType_;
    std::map<std::string, std::vector<sptr<IRemoteObject>>> registerOnListener_;
    std::thread eventThread_;
    std::condition_variable eventCon_;
    std::mutex eventMutex_;
    std::mutex iconMutex_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DISTRIBUTEDSCHED_CONTINUE_RECV_MANAGER_H
