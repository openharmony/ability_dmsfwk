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

#ifndef ABILITY_DMSFWK_DMS_MAIN_SERVICE_CHANNEL_IMPL_H
#define ABILITY_DMSFWK_DMS_MAIN_SERVICE_CHANNEL_IMPL_H

#include "dms_main_service_channel.h"

namespace OHOS::DistributedSchedule {
class DmsMainServiceChannelImpl : public DmsMainServiceChannel {
public:
    // DtbschedmgrDeviceInfoStorage
    std::shared_ptr<DmsDeviceInfo> GetDeviceInfoById(const std::string& deviceId) override;
    std::string GetUuidByNetworkId(const std::string& networkId) override;
    bool GetLocalDeviceId(std::string& networkId) override;
    std::string GetNetworkIdByUuid(const std::string& uuid) override;

    // DistributedSchedAdapter
    int32_t GetLocalMissionInfos(int32_t numMissions, std::vector<DstbMissionInfo>& missionInfos) override;
    int32_t RegisterMissionListener(const sptr<AAFwk::IMissionListener>& listener) override;
    int32_t UnRegisterMissionListener(const sptr<AAFwk::IMissionListener>& listener) override;
    int32_t GetLocalMissionSnapshotInfo(const std::string& networkId, int32_t missionId,
                                        AAFwk::MissionSnapshot& missionSnapshot) override;

    // string utils
    std::string GetAnonymStr(const std::string &value) override;
};
}

#endif // ABILITY_DMSFWK_DMS_MAIN_SERVICE_CHANNEL_IMPL_H