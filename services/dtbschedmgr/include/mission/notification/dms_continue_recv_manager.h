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

#ifndef DMS_CONTINUE_RECV_MANAGER_H
#define DMS_CONTINUE_RECV_MANAGER_H

#include <deque>
#include <map>
#include <mutex>
#include <queue>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#include "bundle/bundle_manager_internal.h"
#include "event_handler.h"
#include "mission_info.h"
#include "mission/distributed_mission_broadcast_listener.h"
#include "mission/distributed_mission_died_listener.h"
#include "mission/distributed_mission_focused_listener.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string CONTINUE_RECV_MANAGER = "continue_recv_manager";
struct currentIconInfo {
    std::string senderNetworkId;
    std::string bundleName;
    std::string continueType;

    std::string sourceBundleName;

    bool isEmpty()
    {
        return (this->senderNetworkId == "" && this->bundleName == "" && this->continueType == "");
    }

    currentIconInfo(const std::string &source_device_id, const std::string &source_bundle_name,
        const std::string &sink_bundle_name, const std::string &continueType = "")
        : senderNetworkId(source_device_id),
          bundleName(sink_bundle_name),
          continueType(continueType),
          sourceBundleName(source_bundle_name) {
    }

    currentIconInfo() = default;

    ~currentIconInfo() = default;
};

class DMSContinueRecvMgr {
public:
    constexpr static uint8_t DMS_DATA_LEN = 3; // Dms data Length
    constexpr static int32_t DMS_SEND_LEN = 4; // Maximum Broadcast Length
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

    ~DMSContinueRecvMgr();
    void Init(int32_t accountId);
    void UnInit();
    void NotifyDataRecv(std::string& senderNetworkId, uint8_t* payload, uint32_t dataLen);
    int32_t RegisterOnListener(const std::string& type, const sptr<IRemoteObject>& obj);
    int32_t RegisterOffListener(const std::string& type, const sptr<IRemoteObject>& obj);
    void NotifyDied(const sptr<IRemoteObject>& obj);
    void NotifyDeviceOffline(const std::string& networkId);
    void NotifyPackageRemoved(const std::string& sinkBundleName);
    void NotifyIconDisappear(uint16_t bundleNameId, const std::string &senderNetworkId, const int32_t state);
    int32_t NotifyDockDisplay(uint16_t bundleNameId, const currentIconInfo& continueInfo, const int32_t state);
    void OnDeviceScreenOff();
    void OnDeviceScreenOn();
    void OnContinueSwitchOff();
    void OnUserSwitch();
    std::string GetContinueType(const std::string& bundleName);

private:
    void StartEvent();
    int32_t RetryPostBroadcast(const std::string& senderNetworkId, uint16_t bundleNameId, uint8_t continueTypeId,
        const int32_t state, const int32_t retry);
    bool GetFinalBundleName(DmsBundleInfo& distributedBundleInfo,  std::string &finalBundleName,
        AppExecFwk::BundleInfo& localBundleInfo, std::string& continueType);
    int32_t VerifyBroadcastSource(const std::string& senderNetworkId, const std::string& srcBundleName,
        const std::string& sinkBundleName, const std::string& continueType, const int32_t state);
    void PostOnBroadcastBusiness(const std::string& senderNetworkId, uint16_t bundleNameId, uint8_t continueTypeId,
        const int32_t state, const int32_t delay = 0, const int32_t retry = 0);
    void FindContinueType(const DmsBundleInfo &distributedBundleInfo, uint8_t &continueTypeId,
        std::string &continueType, DmsAbilityInfo &abilityInfo);
    int32_t DealOnBroadcastBusiness(const std::string& senderNetworkId, uint16_t bundleNameId, uint8_t continueTypeId,
        const int32_t state, const int32_t retry = 0);
    void NotifyRecvBroadcast(const sptr<IRemoteObject>& obj, const currentIconInfo& continueInfo, const int32_t state);
    bool IsBundleContinuable(const AppExecFwk::BundleInfo& bundleInfo, const std::string &srcAbilityName,
        const std::string &srcModuleName, const std::string &srcContinueType);
    std::string ContinueTypeFormat(const std::string &continueType);
    void FindToNotifyRecvBroadcast(const std::string& senderNetworkId, const std::string& bundleName,
        const std::string& continueType);
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
    int32_t accountId_ = -1;
    std::atomic<bool> isScreenOn = true;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DMS_CONTINUE_RECV_MANAGER_H
