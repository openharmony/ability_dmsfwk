/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DNETWORK_ADAPTER_H
#define OHOS_DISTRIBUTED_DNETWORK_ADAPTER_H

#include <iosfwd>
#include <memory>
#include <mutex>
#include <set>
#include <string>

#include "device_manager.h"
#include "event_handler.h"
#include "nocopyable.h"

namespace OHOS {
namespace DistributedSchedule {
enum DeviceInfoType {
    UNKNOWN_INFO = 0,
    BASIC_INFO = 1,
    NETWORK_INFO = 2,
    TRUST_INFO = 3,
};

enum NodeDeviceInfoKey {
    NODE_KEY_UDID = 0,
    NODE_KEY_UUID = 1,
};

class DeviceListener {
public:
    DeviceListener() = default;
    virtual ~DeviceListener() = default;

    virtual void OnDeviceOnline(const DistributedHardware::DmDeviceInfo& deviceInfo) = 0;
    virtual void OnDeviceOffline(const DistributedHardware::DmDeviceInfo& deviceInfo) = 0;
    virtual void OnDeviceInfoChanged(const DistributedHardware::DmDeviceInfo& deviceInfo) = 0;
};

class DnetworkAdapter {
public:
    DnetworkAdapter() = default;
    ~DnetworkAdapter() = default;

    void Init();
    bool AddDeviceChangeListener(const std::shared_ptr<DeviceListener>& listener);
    void RemoveDeviceChangeListener(const std::shared_ptr<DeviceListener>& listener);
    std::string GetUdidByNetworkId(const std::string& networkId);
    std::string GetUuidByNetworkId(const std::string& networkId);
    bool GetLocalBasicInfo(DistributedHardware::DmDeviceInfo& dmDeviceInfo);

    static std::string AnonymizeDeviceId(const std::string& deviceId);
    static std::shared_ptr<DnetworkAdapter> GetInstance();

private:
    DISALLOW_COPY_AND_MOVE(DnetworkAdapter);

    static std::shared_ptr<AppExecFwk::EventHandler> dnetworkHandler_;
    static std::mutex listenerSetMutex_;
    static std::set<std::shared_ptr<DeviceListener>> listenerSet_;

    std::shared_ptr<DistributedHardware::DeviceStateCallback> stateCallback_;
    std::shared_ptr<DistributedHardware::DmInitCallback> initCallback_;
class DeviceInitCallBack : public DistributedHardware::DmInitCallback {
    void OnRemoteDied() override;
};

class DmsDeviceStateCallback : public DistributedHardware::DeviceStateCallback {
    void OnDeviceOnline(const DistributedHardware::DmDeviceInfo& deviceInfo) override;
    void OnDeviceOffline(const DistributedHardware::DmDeviceInfo& deviceInfo) override;
    void OnDeviceChanged(const DistributedHardware::DmDeviceInfo& deviceInfo) override;
    void OnDeviceReady(const DistributedHardware::DmDeviceInfo& deviceInfo) override;
};
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_DNETWORK_ADAPTER_H