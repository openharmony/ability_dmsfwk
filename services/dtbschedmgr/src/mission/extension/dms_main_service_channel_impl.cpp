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
#include "mission/extension/dms_main_service_channel_impl.h"
#include "dtbschedmgr_device_info_storage.h"
#include "distributed_sched_adapter.h"
#include "mission/mission_constant.h"
#include "distributed_sched_utils.h"

namespace OHOS::DistributedSchedule {
namespace {
    constexpr size_t INT32_SHORT_ID_LEN = 20;
    constexpr size_t INT32_MIN_ID_LEN = 6;
    constexpr size_t INT32_PLAINTEXT_LEN = 4;
}

// DtbschedmgrDeviceInfoStorage
std::shared_ptr<DmsDeviceInfo> DmsMainServiceChannelImpl::GetDeviceInfoById(const std::string& deviceId)
{
    return DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(deviceId);
}

std::string DmsMainServiceChannelImpl::GetUuidByNetworkId(const std::string &networkId)
{
    return DtbschedmgrDeviceInfoStorage::GetInstance().GetUuidByNetworkId(networkId);
}

bool DmsMainServiceChannelImpl::GetLocalDeviceId(std::string &networkId)
{
    return DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(networkId);
}

std::string DmsMainServiceChannelImpl::GetNetworkIdByUuid(const std::string &uuid)
{
    return DtbschedmgrDeviceInfoStorage::GetInstance().GetNetworkIdByUuid(uuid);
}

int32_t DmsMainServiceChannelImpl::GetLocalMissionInfos(int32_t numMissions, std::vector<DstbMissionInfo> &missionInfos)
{
    return DistributedSchedAdapter::GetInstance().GetLocalMissionInfos(numMissions, missionInfos);
}

int32_t DmsMainServiceChannelImpl::RegisterMissionListener(const sptr<AAFwk::IMissionListener> &listener)
{
    return DistributedSchedAdapter::GetInstance().RegisterMissionListener(listener);
}


int32_t DmsMainServiceChannelImpl::UnRegisterMissionListener(const sptr<AAFwk::IMissionListener> &listener)
{
    return DistributedSchedAdapter::GetInstance().UnRegisterMissionListener(listener);
}

int32_t DmsMainServiceChannelImpl::GetLocalMissionSnapshotInfo(const std::string &networkId, int32_t missionId,
                                                               AAFwk::MissionSnapshot &missionSnapshot)
{
    return DistributedSchedAdapter::GetInstance()
            .GetLocalMissionSnapshotInfo(networkId, missionId, missionSnapshot);
}

std::string DmsMainServiceChannelImpl::GetAnonymStr(const std::string &value)
{
    std::string res;
    std::string tmpStr("******");
    size_t strLen = value.length();
    if (strLen < INT32_MIN_ID_LEN) {
        return tmpStr;
    }

    if (strLen <= INT32_SHORT_ID_LEN) {
        res += value[0];
        res += tmpStr;
        res += value[strLen - 1];
    } else {
        res.append(value, 0, INT32_PLAINTEXT_LEN);
        res += tmpStr;
        res.append(value, strLen - INT32_PLAINTEXT_LEN, INT32_PLAINTEXT_LEN);
    }

    return res;
}
}
