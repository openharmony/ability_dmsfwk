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

    if (!LoadBasicSymbols() || !LoadDeviceNotifySymbols() || !LoadListenerSymbols()) {
        CleanupOnError();
        return false;
    }
    if (!LoadSyncSymbols() || !LoadCoreSymbols() || !LoadSnapshotSymbols()) {
        CleanupOnError();
        return false;
    }
    if (!LoadSnapshotNotifySymbols() || !LoadConverterSymbols() || !LoadChannelSymbol()) {
        CleanupOnError();
        return false;
    }
    if (!InitializeServiceChannel()) {
        CleanupOnError();
        return false;
    }

    MissionInit();
    MissionInitDataStorage();
    loaded_ = true;
    return true;
}

bool MissionLoader::LoadBasicSymbols()
{
    GetMissionInfos = reinterpret_cast<int32_t(*)(const std::string &, int32_t,
        std::vector<AAFwk::MissionInfo> &)>(dlsym(handle_, "GetMissionInfos"));
    if (!GetMissionInfos) {
        HILOGE("Failed to load symbol: GetMissionInfos");
        return false;
    }

    StoreSnapshotInfo = reinterpret_cast<int32_t(*)(const std::string &, int32_t,
        const uint8_t *, size_t)>(dlsym(handle_, "StoreSnapshotInfo"));
    if (!StoreSnapshotInfo) {
        HILOGE("Failed to load symbol: StoreSnapshotInfo");
        return false;
    }

    RemoveSnapshotInfo = reinterpret_cast<int32_t(*)(const std::string &, int32_t)>(dlsym(handle_,
        "RemoveSnapshotInfo"));
    if (!RemoveSnapshotInfo) {
        HILOGE("Failed to load symbol: RemoveSnapshotInfo");
        return false;
    }

    GetRemoteMissionSnapshotInfo = reinterpret_cast<int32_t(*)(const std::string &, int32_t,
        std::unique_ptr<AAFwk::MissionSnapshot> &)>(dlsym(handle_, "GetRemoteMissionSnapshotInfo"));
    if (!GetRemoteMissionSnapshotInfo) {
        HILOGE("Failed to load symbol: GetRemoteMissionSnapshotInfo");
        return false;
    }

    return true;
}

bool MissionLoader::LoadDeviceNotifySymbols()
{
    DeviceOnlineNotify = reinterpret_cast<void (*)(const std::string &)>(dlsym(handle_, "DeviceOnlineNotify"));
    if (!DeviceOnlineNotify) {
        HILOGE("Failed to load symbol: DeviceOnlineNotify");
        return false;
    }

    DeviceOfflineNotify = reinterpret_cast<void (*)(const std::string &)>(dlsym(handle_, "DeviceOfflineNotify"));
    if (!DeviceOfflineNotify) {
        HILOGE("Failed to load symbol: DeviceOfflineNotify");
        return false;
    }

    return true;
}

bool MissionLoader::LoadListenerSymbols()
{
    RegisterMissionListener = reinterpret_cast<int32_t(*)(const std::u16string &, const sptr <IRemoteObject> &)>(dlsym(
        handle_, "RegisterMissionListener"));
    if (!RegisterMissionListener) {
        HILOGE("Failed to load symbol: RegisterMissionListener");
        return false;
    }

    UnRegisterMissionListener = reinterpret_cast<int32_t(*)(const std::u16string &,
        const sptr <IRemoteObject> &)>(dlsym(handle_, "UnRegisterMissionListener"));
    if (!UnRegisterMissionListener) {
        HILOGE("Failed to load symbol: UnRegisterMissionListener");
        return false;
    }

    return true;
}

bool MissionLoader::LoadSyncSymbols()
{
    StartSyncRemoteMissions = reinterpret_cast<int32_t(*)(const std::string &, bool, int64_t, uint32_t)>(dlsym(handle_,
        "StartSyncRemoteMissions"));
    if (!StartSyncRemoteMissions) {
        HILOGE("Failed to load symbol: StartSyncRemoteMissions");
        return false;
    }

    StopSyncRemoteMissions = reinterpret_cast<int32_t(*)(const std::string &, bool, bool)>(dlsym(handle_,
        "StopSyncRemoteMissions"));
    if (!StopSyncRemoteMissions) {
        HILOGE("Failed to load symbol: StopSyncRemoteMissions");
        return false;
    }

    return true;
}

bool MissionLoader::LoadCoreSymbols()
{
    MissionInit = reinterpret_cast<void (*)()>(dlsym(handle_, "MissionInit"));
    if (!MissionInit) {
        HILOGE("Failed to load symbol: MissionInit");
        return false;
    }

    MissionInitDataStorage = reinterpret_cast<int32_t(*)()>(dlsym(handle_, "MissionInitDataStorage"));
    if (!MissionInitDataStorage) {
        HILOGE("Failed to load symbol: MissionInitDataStorage");
        return false;
    }

    MissionNotifyNetDisconnectOffline = reinterpret_cast<void (*)()>(dlsym(
        handle_, "MissionNotifyNetDisconnectOffline"));
    if (!MissionNotifyNetDisconnectOffline) {
        HILOGE("Failed to load symbol: MissionNotifyNetDisconnectOffline");
        return false;
    }

    MissionGetOsAccountData = reinterpret_cast<bool (*)(AccountInfo &)>(dlsym(
        handle_, "MissionGetOsAccountData"));
    if (!MissionGetOsAccountData) {
        HILOGE("Failed to load symbol: MissionGetOsAccountData");
        return false;
    }

    return true;
}

bool MissionLoader::LoadSnapshotSymbols()
{
    MissionEnqueueCachedSnapshotInfo = reinterpret_cast<void (*)(const std::string &, int32_t, Snapshot *)>(dlsym(
        handle_, "MissionEnqueueCachedSnapshotInfo"));
    if (!MissionEnqueueCachedSnapshotInfo) {
        HILOGE("Failed to load symbol: MissionEnqueueCachedSnapshotInfo");
        return false;
    }

    MissionDequeueCachedSnapshotInfo = reinterpret_cast<Snapshot *(*)(const std::string &, int32_t)>(dlsym(
        handle_, "MissionDequeueCachedSnapshotInfo"));
    if (!MissionDequeueCachedSnapshotInfo) {
        HILOGE("Failed to load symbol: MissionDequeueCachedSnapshotInfo");
        return false;
    }

    MissionNotifySnapshotChanged = reinterpret_cast<void (*)(const std::string &, int32_t)>(dlsym(
        handle_, "MissionNotifySnapshotChanged"));
    if (!MissionNotifySnapshotChanged) {
        HILOGE("Failed to load symbol: MissionNotifySnapshotChanged");
        return false;
    }

    MissionNotifyLocalMissionsChanged = reinterpret_cast<void (*)()>(dlsym(
        handle_, "MissionNotifyLocalMissionsChanged"));
    if (!MissionNotifyLocalMissionsChanged) {
        HILOGE("Failed to load symbol: MissionNotifyLocalMissionsChanged");
        return false;
    }

    return true;
}

bool MissionLoader::LoadSnapshotNotifySymbols()
{
    MissionNotifyMissionSnapshotCreated = reinterpret_cast<void (*)(int32_t)>(dlsym(
        handle_, "MissionNotifyMissionSnapshotCreated"));
    if (!MissionNotifyMissionSnapshotCreated) {
        HILOGE("Failed to load symbol: MissionNotifyMissionSnapshotCreated");
        return false;
    }

    MissionNotifyMissionSnapshotDestroyed = reinterpret_cast<void (*)(int32_t)>(dlsym(
        handle_, "MissionNotifyMissionSnapshotDestroyed"));
    if (!MissionNotifyMissionSnapshotDestroyed) {
        HILOGE("Failed to load symbol: MissionNotifyMissionSnapshotDestroyed");
        return false;
    }

    MissionNotifyMissionSnapshotChanged = reinterpret_cast<void (*)(int32_t)>(dlsym(
        handle_, "MissionNotifyMissionSnapshotChanged"));
    if (!MissionNotifyMissionSnapshotChanged) {
        HILOGE("Failed to load symbol: MissionNotifyMissionSnapshotChanged");
        return false;
    }

    MissionNotifyRemoteDied = reinterpret_cast<void (*)(const wptr <IRemoteObject> &)>(dlsym(
        handle_, "MissionNotifyRemoteDied"));
    if (!MissionNotifyRemoteDied) {
        HILOGE("Failed to load symbol: MissionNotifyRemoteDied");
        return false;
    }

    return true;
}

bool MissionLoader::LoadConverterSymbols()
{
    MissionInfoConverter = reinterpret_cast<int32_t(*)(
        std::vector<OHOS::AAFwk::MissionInfo> &, std::vector<OHOS::DistributedSchedule::DstbMissionInfo> &)>(dlsym(
            handle_, "ConvertToDstbMissionInfos"));
    if (!MissionInfoConverter) {
        HILOGE("Failed to load symbol: ConvertToDstbMissionInfos");
        return false;
    }

    ReadDstbMissionInfosFromParcel = reinterpret_cast<bool (*)(Parcel &, std::vector<DstbMissionInfo> &)>(dlsym(
        handle_, "ReadDstbMissionInfosFromParcel"));
    if (!ReadDstbMissionInfosFromParcel) {
        HILOGE("Failed to load symbol: ReadDstbMissionInfosFromParcel");
        return false;
    }

    WriteDstbMissionInfosToParcel = reinterpret_cast<bool (*)(Parcel &, const std::vector<DstbMissionInfo> &)>(dlsym(
        handle_, "WriteDstbMissionInfosToParcel"));
    if (!WriteDstbMissionInfosToParcel) {
        HILOGE("Failed to load symbol: WriteDstbMissionInfosToParcel");
        return false;
    }

    ReadMissionInfosFromParcel = reinterpret_cast<bool (*)(Parcel &, std::vector<AAFwk::MissionInfo> &)>(dlsym(
        handle_, "ReadMissionInfosFromParcel"));
    if (!ReadMissionInfosFromParcel) {
        HILOGE("Failed to load symbol: ReadMissionInfosFromParcel");
        return false;
    }

    WriteMissionInfosToParcel = reinterpret_cast<bool (*)(Parcel &, const std::vector<AAFwk::MissionInfo> &)>(dlsym(
        handle_, "WriteMissionInfosToParcel"));
    if (!WriteMissionInfosToParcel) {
        HILOGE("Failed to load symbol: WriteMissionInfosToParcel");
        return false;
    }

    ConvertToSnapshot = reinterpret_cast<int32_t(*)(AAFwk::MissionSnapshot &, std::unique_ptr<Snapshot> &)>(dlsym(
        handle_, "ConvertToSnapshot"));
    if (!ConvertToSnapshot) {
        HILOGE("Failed to load symbol: ConvertToSnapshot");
        return false;
    }

    return true;
}

bool MissionLoader::LoadChannelSymbol()
{
    SetMainServiceChannel = reinterpret_cast<void (*)(std::shared_ptr<DmsMainServiceChannel> &)>(dlsym(
        handle_, "SetMainServiceChannel"));
    if (!SetMainServiceChannel) {
        HILOGE("Failed to load symbol: SetMainServiceChannel");
        return false;
    }

    MissionStartSyncMissionsFromRemote = reinterpret_cast<int32_t(*)>(
        const CallerInfo &, std::vector<DstbMissionInfo> &)>(dlsym(
            handle_, "MissionStartSyncMissionsFromRemote"));
    if (!MissionStartSyncMissionsFromRemote) {
        HILOGE("Failed to load symbol: MissionStartSyncMissionsFromRemote");
        return false;
    }

    MissionStopSyncMissionsFromRemote = reinterpret_cast<void (*)(const std::string &)>(dlsym(
        handle_, "MissionStopSyncMissionsFromRemote"));
    if (!MissionStopSyncMissionsFromRemote) {
        HILOGE("Failed to load symbol: MissionStopSyncMissionsFromRemote");
        return false;
    }

    return true;
}

bool MissionLoader::InitializeServiceChannel()
{
    if (!SetMainServiceChannel) {
        HILOGE("SetMainServiceChannel symbol not loaded");
        return false;
    }

    std::shared_ptr<DmsMainServiceChannel> mainServiceChannel = std::make_shared<DmsMainServiceChannelImpl>();
    SetMainServiceChannel(mainServiceChannel);
    return true;
}

void MissionLoader::CleanupOnError()
{
    if (handle_) {
        dlclose(handle_);
        handle_ = nullptr;
    }
    loaded_ = false;
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
