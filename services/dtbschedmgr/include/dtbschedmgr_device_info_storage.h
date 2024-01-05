/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DTBSCHEDMGR_DEVICE_INFO_INTERFACE_H
#define OHOS_DISTRIBUTED_DTBSCHEDMGR_DEVICE_INFO_INTERFACE_H

#include <map>
#include <set>

#include "adapter/dnetwork_adapter.h"
#include "deviceManager/dms_device_info.h"
#include "distributed_device_node_listener.h"
#include "event_handler.h"
#include "iremote_object.h"
#include "single_instance.h"
#include "sync_completed_callback_stub.h"

namespace OHOS {
namespace DistributedSchedule {
class DnetServiceDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    DnetServiceDeathRecipient() = default;
    ~DnetServiceDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
};

class DtbschedmgrDeviceInfoStorage {
    DECLARE_SINGLE_INSTANCE(DtbschedmgrDeviceInfoStorage);

public:
    bool Init();
    void Stop();
    bool GetLocalDeviceId(std::string& networkId);
    bool GetLocalUdid(std::string& udid);
    void DeviceOnlineNotify(const std::shared_ptr<DmsDeviceInfo> devInfo);
    void DeviceOfflineNotify(const std::string& networkId);
    void OnDeviceInfoChanged(const std::string& networkId);

    /**
     * get device info by device id
     *
     * @param networkId, string
     * @return shared_ptr<DmsDeviceInfo>
     */
    std::shared_ptr<DmsDeviceInfo> GetDeviceInfoById(const std::string& networkId);

    /**
     * get uuid by networkId
     *
     * @param networkId
     */
    std::string GetUuidByNetworkId(const std::string& networkId);

    /**
     * get networkId by uuid
     *
     * @param uuid
     */
    std::string GetNetworkIdByUuid(const std::string& uuid);

    /**
     * GetDeviceIdSet get all of the device Id in same network
     *
     * @param networkIdSet Returns the device set.
     */
    void GetDeviceIdSet(std::set<std::string>& deviceIdSet);

    /**
     * UpdateDeviceInfoStorage update device Info cache
     *
     * @param dmDeviceInfoList
     */
    void UpdateDeviceInfoStorage(const std::vector<DistributedHardware::DmDeviceInfo>& dmDeviceInfoList);

    /**
     * Sync dms version info to remote
     *
     * @param remoteNetworkId
     */
    int32_t SyncDmsVersionInfoToRemote(const std::string& remoteNetworkId);

private:
    bool InitNetworkIdManager(std::shared_ptr<DnetworkAdapter> dnetworkAdapter);
    bool ConnectSoftbus();
    void ClearAllDevices();
    bool WaitForDnetworkReady();
    bool GetLocalDeviceFromDnet(std::string& networkId);
    bool GetLocalDeviceUdid(std::string& udid);
    void RegisterUuidNetworkIdMap(const std::string& networkId);
    void UnregisterUuidNetworkIdMap(const std::string& networkId);
    std::mutex deviceLock_;
    std::shared_ptr<DistributedDeviceNodeListener> deviceNodeListener_;
    std::map<std::string, std::shared_ptr<DmsDeviceInfo>> remoteDevices_;
    std::string deviceId_;
    std::map<std::string, std::string> uuidNetworkIdMap_;
    std::mutex uuidNetworkIdLock_;
    std::shared_ptr<AppExecFwk::EventHandler> initHandler_;
    std::shared_ptr<AppExecFwk::EventHandler> networkIdMgrHandler_;
    class SyncCallback : public OHOS::DistributedDeviceProfile::SyncCompletedCallbackStub {
        void OnSyncCompleted(const std::map<std::string, OHOS::DistributedDeviceProfile::SyncStatus> &syncResults);
    };
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DTBSCHEDMGR_DEVICE_INFO_INTERFACE_H
