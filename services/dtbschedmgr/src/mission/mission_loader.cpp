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

#include "mission/mission_loader.h"
#include "mission/snapshot.h"
#include "dtbschedmgr_log.h"
#include "mission/extension/dms_main_service_channel_impl.h"
#include <dlfcn.h>

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string TAG = "MissionLoader";
}

MissionLoader& MissionLoader::GetInstance()
{
    static MissionLoader instance;
    return instance;
}

bool MissionLoader::Load()
{
    std::lock_guard<std::mutex> autoLock(missionLoadLock_);
    if (loaded_) {
        return true;
    }

    const char *libPath = "/system/lib64/platformsdk/libdms_mission_extension.z.so";
    handle_ = dlopen(libPath, RTLD_LAZY);
    if (!handle_) {
        HILOGE("Failed to load mission library: %{public}s", dlerror());
        return false;
    }

    // Load original 10 symbols
    GetMissionInfos = reinterpret_cast<int32_t(*)(const std::string &, int32_t,
        std::vector<AAFwk::MissionInfo> &)>(dlsym(handle_, "GetMissionInfos"));
    StoreSnapshotInfo = reinterpret_cast<int32_t(*)(const std::string &, int32_t,
        const uint8_t *, size_t)>(dlsym(handle_, "StoreSnapshotInfo"));
    RemoveSnapshotInfo = reinterpret_cast<int32_t(*)(const std::string &, int32_t)>(dlsym(handle_,
        "RemoveSnapshotInfo"));
    GetRemoteMissionSnapshotInfo = reinterpret_cast<int32_t(*)(const std::string &, int32_t,
        std::unique_ptr<AAFwk::MissionSnapshot> &)>(dlsym(handle_, "GetRemoteMissionSnapshotInfo"));
    DeviceOnlineNotify = reinterpret_cast<void (*)(const std::string &)>(dlsym(handle_, "DeviceOnlineNotify"));
    DeviceOfflineNotify = reinterpret_cast<void (*)(const std::string &)>(dlsym(handle_, "DeviceOfflineNotify"));
    RegisterMissionListener = reinterpret_cast<int32_t(*)(const std::u16string &, const sptr <IRemoteObject> &)>(dlsym(
        handle_, "RegisterMissionListener"));
    UnRegisterMissionListener = reinterpret_cast<int32_t(*)(const std::u16string &,
        const sptr <IRemoteObject> &)>(dlsym(handle_, "UnRegisterMissionListener"));
    StartSyncRemoteMissions = reinterpret_cast<int32_t(*)(const std::string &, bool, int64_t, uint32_t)>(dlsym(handle_,
        "StartSyncRemoteMissions"));
    StopSyncRemoteMissions = reinterpret_cast<int32_t(*)(const std::string &, bool, bool)>(dlsym(handle_,
        "StopSyncRemoteMissions"));

    if (!LoadPart2()) {
        return false;
    }
    MissionInit();
    MissionInitDataStorage();
    loaded_ = true;
    return true;
}

bool MissionLoader::LoadPart2()
{
    // Load additional symbols
    MissionInit = reinterpret_cast<void (*)()>(dlsym(handle_, "MissionInit"));
    MissionInitDataStorage = reinterpret_cast<int32_t(*)()>(dlsym(handle_, "MissionInitDataStorage"));
    MissionNotifyNetDisconnectOffline = reinterpret_cast<void (*)()>(dlsym(
        handle_, "MissionNotifyNetDisconnectOffline"));
    MissionGetOsAccountData = reinterpret_cast<bool (*)(AccountInfo &)>(dlsym(
        handle_, "MissionGetOsAccountData"));
    MissionEnqueueCachedSnapshotInfo = reinterpret_cast<void (*)(const std::string &, int32_t, Snapshot *)>(dlsym(
        handle_, "MissionEnqueueCachedSnapshotInfo"));
    MissionDequeueCachedSnapshotInfo = reinterpret_cast<Snapshot *(*)(const std::string &, int32_t)>(dlsym(
        handle_, "MissionDequeueCachedSnapshotInfo"));
    MissionNotifySnapshotChanged = reinterpret_cast<void (*)(const std::string &, int32_t)>(dlsym(
        handle_, "MissionNotifySnapshotChanged"));
    MissionNotifyLocalMissionsChanged = reinterpret_cast<void (*)()>(dlsym(
        handle_, "MissionNotifyLocalMissionsChanged"));
    MissionNotifyMissionSnapshotCreated = reinterpret_cast<void (*)(int32_t)>(dlsym(
        handle_, "MissionNotifyMissionSnapshotCreated"));
    MissionNotifyMissionSnapshotDestroyed = reinterpret_cast<void (*)(int32_t)>(dlsym(
        handle_, "MissionNotifyMissionSnapshotDestroyed"));
    MissionNotifyMissionSnapshotChanged = reinterpret_cast<void (*)(int32_t)>(dlsym(
        handle_, "MissionNotifyMissionSnapshotChanged"));
    MissionNotifyRemoteDied = reinterpret_cast<void (*)(const wptr <IRemoteObject> &)>(dlsym(
        handle_, "MissionNotifyRemoteDied"));
    MissionStartSyncMissionsFromRemote = reinterpret_cast<int32_t(*)(
        const CallerInfo &, std::vector<DstbMissionInfo> &)>(dlsym(
            handle_, "MissionStartSyncMissionsFromRemote"));
    MissionStopSyncMissionsFromRemote = reinterpret_cast<void (*)(const std::string &)>(dlsym(
        handle_, "MissionStopSyncMissionsFromRemote"));

    // MissionInfoConverter
    MissionInfoConverter = reinterpret_cast<int32_t(*)(
        std::vector<OHOS::AAFwk::MissionInfo> &, std::vector<OHOS::DistributedSchedule::DstbMissionInfo> &)>(dlsym(
            handle_, "ConvertToDstbMissionInfos"));

    ReadDstbMissionInfosFromParcel = reinterpret_cast<bool (*)(Parcel &, std::vector<DstbMissionInfo> &)>(dlsym(
        handle_, "ReadDstbMissionInfosFromParcel"));
    WriteDstbMissionInfosToParcel = reinterpret_cast<bool (*)(Parcel &, const std::vector<DstbMissionInfo> &)>(dlsym(
        handle_, "WriteDstbMissionInfosToParcel"));
    ReadMissionInfosFromParcel = reinterpret_cast<bool (*)(Parcel &, std::vector<AAFwk::MissionInfo> &)>(dlsym(
        handle_, "ReadMissionInfosFromParcel"));
    WriteMissionInfosToParcel = reinterpret_cast<bool (*)(Parcel &, const std::vector<AAFwk::MissionInfo> &)>(dlsym(
        handle_, "WriteMissionInfosToParcel"));

    // SnapshotConverter
    ConvertToSnapshot = reinterpret_cast<int32_t(*)(AAFwk::MissionSnapshot &, std::unique_ptr<Snapshot> &)>(dlsym(
        handle_, "ConvertToSnapshot"));

    // MainServiceChannel
    SetMainServiceChannel = reinterpret_cast<void (*)(std::shared_ptr<DmsMainServiceChannel> &)>(dlsym(
        handle_, "SetMainServiceChannel"));
    std::shared_ptr<DmsMainServiceChannel> mainServiceChannel = std::make_shared<DmsMainServiceChannelImpl>();
    SetMainServiceChannel(mainServiceChannel);
    return true;
}

void MissionLoader::Unload()
{
    std::lock_guard<std::mutex> autoLock(missionLoadLock_);
    if (handle_) {
        dlclose(handle_);
        handle_ = nullptr;
    }
    loaded_ = false;
}

MissionLoader::~MissionLoader()
{
    Unload();
}

bool MissionLoader::IsLoaded() const
{
    return loaded_;
}
} // namespace DistributedSchedule
} // namespace OHOS