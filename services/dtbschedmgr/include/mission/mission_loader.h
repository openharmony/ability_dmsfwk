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

#ifndef MISSION_LOADER_H
#define MISSION_LOADER_H

#include <string>
#include <vector>
#include <memory>
#include <iremote_object.h>
#include "mission/distributed_mission_info.h"
#include "distributed_sched_interface.h"
#include "distributed_sched_mission_manager.h"
#include "mission_info.h"

namespace OHOS {
namespace DistributedSchedule {

class MissionLoader {
public:
    static MissionLoader& GetInstance();

    bool Load();
    bool IsLoaded() const;
    void Unload();

    // Original 10 interfaces
    int32_t (*GetMissionInfos)(const std::string& deviceId, int32_t numMissions,
        std::vector<AAFwk::MissionInfo>& missionInfoSet);
    int32_t (*StoreSnapshotInfo)(const std::string& deviceId, int32_t missionId,
        const uint8_t* byteStream, size_t len);
    int32_t (*RemoveSnapshotInfo)(const std::string& deviceId, int32_t missionId);
    int32_t (*GetRemoteMissionSnapshotInfo)(const std::string& networkId, int32_t missionId,
        std::unique_ptr<AAFwk::MissionSnapshot>& missionSnapshot);
    void (*DeviceOnlineNotify)(const std::string& deviceId);
    void (*DeviceOfflineNotify)(const std::string& deviceId);
    int32_t (*RegisterMissionListener)(const std::u16string& devId, const sptr<IRemoteObject>& obj);
    int32_t (*UnRegisterMissionListener)(const std::u16string& devId, const sptr<IRemoteObject>& obj);
    int32_t (*StartSyncRemoteMissions)(const std::string& devId, bool fixConflict, int64_t tag,
        uint32_t callingTokenId);
    int32_t (*StopSyncRemoteMissions)(const std::string& dstDevId, bool offline, bool exit);

    // Additional interfaces
    void (*MissionInit)();
    int32_t (*MissionInitDataStorage)();
    void (*MissionNotifyNetDisconnectOffline)();
    bool (*MissionGetOsAccountData)(AccountInfo& dmsAccountInfo);
    void (*MissionEnqueueCachedSnapshotInfo)(const std::string& deviceId, int32_t missionId,
        Snapshot* snapshot);
    Snapshot* (*MissionDequeueCachedSnapshotInfo)(const std::string& deviceId, int32_t missionId);
    void (*MissionNotifySnapshotChanged)(const std::string& networkId, int32_t missionId);
    void (*MissionNotifyLocalMissionsChanged)();
    void (*MissionNotifyMissionSnapshotCreated)(int32_t missionId);
    void (*MissionNotifyMissionSnapshotDestroyed)(int32_t missionId);
    void (*MissionNotifyMissionSnapshotChanged)(int32_t missionId);
    void (*MissionNotifyRemoteDied)(const wptr<IRemoteObject>& remote);
    int32_t (*MissionStartSyncMissionsFromRemote)(const CallerInfo& callerInfo,
        std::vector<DstbMissionInfo>& missionInfoSet);
    void (*MissionStopSyncMissionsFromRemote)(const std::string& deviceId);

    int32_t (*MissionInfoConverter)(std::vector<OHOS::AAFwk::MissionInfo>& missionInfoSet,
        std::vector<OHOS::DistributedSchedule::DstbMissionInfo>& dstbMissionInfoSet);
    bool (*ReadDstbMissionInfosFromParcel)(Parcel& parcel, std::vector<DstbMissionInfo>& missionInfos);
    bool (*WriteDstbMissionInfosToParcel)(Parcel& parcel, const std::vector<DstbMissionInfo>& missionInfos);
    bool (*ReadMissionInfosFromParcel)(Parcel& parcel, std::vector<AAFwk::MissionInfo> &missionInfoSet);
    bool (*WriteMissionInfosToParcel)(Parcel& parcel, const std::vector<AAFwk::MissionInfo> &missionInfoSet);

    // SnapshotConverter
    int32_t (*ConvertToSnapshot)(AAFwk::MissionSnapshot& missionSnapshot, std::unique_ptr<Snapshot>& snapshot);

    void (*SetMainServiceChannel)(std::shared_ptr<DmsMainServiceChannel> &mainServiceChannel);

private:
    MissionLoader() = default;
    ~MissionLoader();

    void CleanupOnError();

    // Symbol loading helper methods
    bool LoadBasicSymbols();
    bool LoadDeviceNotifySymbols();
    bool LoadListenerSymbols();
    bool LoadSyncSymbols();
    bool LoadCoreSymbols();
    bool LoadSnapshotSymbols();
    bool LoadSnapshotNotifySymbols();
    bool LoadConverterSymbols();
    bool LoadChannelSymbol();
    bool InitializeServiceChannel();

    std::mutex missionLoadLock_;
    void* handle_ = nullptr;
    bool loaded_ = false;
};

} // namespace DistributedSchedule
} // namespace OHOS

#endif // MISSION_LOADER_H