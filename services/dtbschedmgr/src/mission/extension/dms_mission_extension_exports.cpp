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

// C interface exports for dynamic loading from distributedsched_mission_core.so

#include "mission/distributed_sched_mission_manager.h"
#include "mission/snapshot.h"
#include "mission/distributed_mission_info.h"
#include "mission/mission_info_converter.h"
#include "mission/distributed_mission_info.h"
#include "distributed_sched_interface.h"
#include "mission/snapshot_converter.h"
#include <iremote_object.h>
#include <memory>

extern "C" {
// Original 10 interfaces
int32_t GetMissionInfos(const std::string& deviceId, int32_t numMissions,
    std::vector<OHOS::AAFwk::MissionInfo>& missionInfoSet)
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            GetMissionInfos(deviceId, numMissions, missionInfoSet);
}

int32_t StoreSnapshotInfo(const std::string& deviceId, int32_t missionId,
    const uint8_t* byteStream, size_t len)
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            StoreSnapshotInfo(deviceId, missionId, byteStream, len);
}

int32_t RemoveSnapshotInfo(const std::string& deviceId, int32_t missionId)
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            RemoveSnapshotInfo(deviceId, missionId);
}

int32_t GetRemoteMissionSnapshotInfo(const std::string& networkId, int32_t missionId,
    std::unique_ptr<OHOS::AAFwk::MissionSnapshot>& missionSnapshot)
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            GetRemoteMissionSnapshotInfo(networkId, missionId, missionSnapshot);
}

void DeviceOnlineNotify(const std::string& deviceId)
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            DeviceOnlineNotify(deviceId);
}

void DeviceOfflineNotify(const std::string& deviceId)
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            DeviceOfflineNotify(deviceId);
}

int32_t RegisterMissionListener(const std::u16string& devId, const OHOS::sptr<OHOS::IRemoteObject>& obj)
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            RegisterMissionListener(devId, obj);
}

int32_t UnRegisterMissionListener(const std::u16string& devId, const OHOS::sptr<OHOS::IRemoteObject>& obj)
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            UnRegisterMissionListener(devId, obj);
}

int32_t StartSyncRemoteMissions(const std::string& devId, bool fixConflict, int64_t tag,
    uint32_t callingTokenId)
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            StartSyncRemoteMissions(devId, fixConflict, tag, callingTokenId);
}

int32_t StopSyncRemoteMissions(const std::string& dstDevId, bool offline, bool exit)
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            StopSyncRemoteMissions(dstDevId, offline, exit);
}

// Additional interfaces
void MissionInit()
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().Init();
}

int32_t MissionInitDataStorage()
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().InitDataStorage();
}

void MissionNotifyNetDisconnectOffline()
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().NotifyNetDisconnectOffline();
}

bool MissionGetOsAccountData(OHOS::DistributedSchedule::AccountInfo& dmsAccountInfo)
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().GetOsAccountData(dmsAccountInfo);
}

void MissionEnqueueCachedSnapshotInfo(const std::string& deviceId, int32_t missionId,
    OHOS::DistributedSchedule::Snapshot* snapshot)
{
    std::unique_ptr<OHOS::DistributedSchedule::Snapshot> snapshotPtr(snapshot);
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            EnqueueCachedSnapshotInfo(deviceId, missionId, std::move(snapshotPtr));
}

OHOS::DistributedSchedule::Snapshot* MissionDequeueCachedSnapshotInfo(
    const std::string& deviceId, int32_t missionId)
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            DequeueCachedSnapshotInfo(deviceId, missionId).release();
}

void MissionNotifySnapshotChanged(const std::string& networkId, int32_t missionId)
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            NotifySnapshotChanged(networkId, missionId);
}

void MissionNotifyLocalMissionsChanged()
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().NotifyLocalMissionsChanged();
}

void MissionNotifyMissionSnapshotCreated(int32_t missionId)
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().NotifyMissionSnapshotCreated(missionId);
}

void MissionNotifyMissionSnapshotDestroyed(int32_t missionId)
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().NotifyMissionSnapshotDestroyed(missionId);
}

void MissionNotifyMissionSnapshotChanged(int32_t missionId)
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().NotifyMissionSnapshotChanged(missionId);
}

void MissionNotifyRemoteDied(const OHOS::wptr<OHOS::IRemoteObject>& remote)
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().NotifyRemoteDied(remote);
}

int32_t MissionStartSyncMissionsFromRemote(const OHOS::DistributedSchedule::CallerInfo& callerInfo,
    std::vector<OHOS::DistributedSchedule::DstbMissionInfo>& missionInfoSet)
{
    return OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().
            StartSyncMissionsFromRemote(callerInfo, missionInfoSet);
}

void MissionStopSyncMissionsFromRemote(const std::string& deviceId)
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().StopSyncMissionsFromRemote(deviceId);
}

int32_t g_convertToDstbMissionInfos(std::vector<OHOS::AAFwk::MissionInfo>& missionInfoSet,
    std::vector<OHOS::DistributedSchedule::DstbMissionInfo>& dstbMissionInfoSet)
{
    return OHOS::DistributedSchedule::MissionInfoConverter::ConvertToDstbMissionInfos(
        missionInfoSet, dstbMissionInfoSet);
}

bool ReadDstbMissionInfosFromParcel(OHOS::Parcel& parcel,
    std::vector<OHOS::DistributedSchedule::DstbMissionInfo>& missionInfos)
{
    return OHOS::DistributedSchedule::DstbMissionInfo::ReadDstbMissionInfosFromParcel(parcel, missionInfos);
}

bool WriteDstbMissionInfosToParcel(OHOS::Parcel& parcel,
    const std::vector<OHOS::DistributedSchedule::DstbMissionInfo>& missionInfos)
{
    return OHOS::DistributedSchedule::DstbMissionInfo::WriteDstbMissionInfosToParcel(parcel, missionInfos);
}

bool ReadMissionInfosFromParcel(OHOS::Parcel& parcel, std::vector<OHOS::AAFwk::MissionInfo>& missionInfoSet)
{
    return OHOS::DistributedSchedule::MissionInfoConverter::ReadMissionInfosFromParcel(parcel, missionInfoSet);
}

bool WriteMissionInfosToParcel(OHOS::Parcel& parcel, const std::vector<OHOS::AAFwk::MissionInfo>& missionInfoSet)
{
    return OHOS::DistributedSchedule::MissionInfoConverter::WriteMissionInfosToParcel(parcel, missionInfoSet);
}

int32_t ConvertToSnapshot(OHOS::AAFwk::MissionSnapshot& missionSnapshot,
    std::unique_ptr<OHOS::DistributedSchedule::Snapshot>& snapshot)
{
    return OHOS::DistributedSchedule::SnapshotConverter::ConvertToSnapshot(missionSnapshot, snapshot);
}

void SetMainServiceChannel(std::shared_ptr<OHOS::DistributedSchedule::DmsMainServiceChannel>& mainServiceChannel)
{
    OHOS::DistributedSchedule::DistributedSchedMissionManager::GetInstance().SetMainServiceChannel(mainServiceChannel);
}
} // extern "C"