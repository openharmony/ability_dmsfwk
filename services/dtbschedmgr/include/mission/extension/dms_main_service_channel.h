/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef ABILITY_DMSFWK_DMS_MAIN_SERVICE_CHANNEL_H
#define ABILITY_DMSFWK_DMS_MAIN_SERVICE_CHANNEL_H

#include <string>
#include "deviceManager/dms_device_info.h"
#include "mission/distributed_mission_change_listener.h"
#include "mission_snapshot.h"
#include "mission/distributed_mission_info.h"

namespace OHOS::DistributedSchedule {
class DmsMainServiceChannel {
public:

    virtual ~DmsMainServiceChannel() = default;

    // DtbschedmgrDeviceInfoStorage
    virtual std::shared_ptr<DmsDeviceInfo> GetDeviceInfoById(const std::string& deviceId) = 0;
    virtual std::string GetUuidByNetworkId(const std::string& networkId) = 0;
    virtual bool GetLocalDeviceId(std::string& networkId) = 0;
    virtual std::string GetNetworkIdByUuid(const std::string& uuid) = 0;

    // DistributedSchedAdapter
    virtual int32_t GetLocalMissionInfos(int32_t numMissions, std::vector<DstbMissionInfo>& missionInfos) = 0;
    virtual int32_t RegisterMissionListener(const sptr<AAFwk::IMissionListener>& listener) = 0;
    virtual int32_t UnRegisterMissionListener(const sptr<AAFwk::IMissionListener>& listener) = 0;
    virtual int32_t GetLocalMissionSnapshotInfo(const std::string& networkId, int32_t missionId,
                                                AAFwk::MissionSnapshot& missionSnapshot) = 0;

    // string utils
    virtual std::string GetAnonymStr(const std::string &value) = 0;
};
}

#endif // ABILITY_DMSFWK_DMS_MAIN_SERVICE_CHANNEL_H