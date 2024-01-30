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

#include "adapter/dnetwork_adapter.h"

#include <chrono>
#include <functional>
#include <thread>
#include <unistd.h>

#include "errors.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "event_runner.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace std::chrono_literals;
using namespace DistributedHardware;

namespace {
constexpr int32_t RETRY_REGISTER_CALLBACK_TIMES = 5;
constexpr int32_t RETRY_REGISTER_CALLBACK_DELAY_TIME = 1000; // 1s
const std::string PKG_NAME = "DBinderBus_Dms_" + std::to_string(getpid());

constexpr int32_t NON_ANONYMIZED_LENGTH = 6;
const std::string EMPTY_DEVICE_ID = "";
const std::string TAG = "DnetworkAdapter";
}

std::shared_ptr<AppExecFwk::EventHandler> DnetworkAdapter::dnetworkHandler_;
std::mutex DnetworkAdapter::listenerSetMutex_;
std::set<std::shared_ptr<DeviceListener>> DnetworkAdapter::listenerSet_;

std::shared_ptr<DnetworkAdapter> DnetworkAdapter::GetInstance()
{
    static auto instance = std::make_shared<DnetworkAdapter>();
    return instance;
}

void DnetworkAdapter::Init()
{
    initCallback_ = std::make_shared<DeviceInitCallBack>();
    stateCallback_ = std::make_shared<DmsDeviceStateCallback>();
    auto runner = AppExecFwk::EventRunner::Create("dmsDnetwork");
    dnetworkHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
}

void DnetworkAdapter::DeviceInitCallBack::OnRemoteDied()
{
    HILOGI("DeviceInitCallBack OnRemoteDied");
    DtbschedmgrDeviceInfoStorage::GetInstance().Init();
}

void DnetworkAdapter::DmsDeviceStateCallback::OnDeviceOnline(const DmDeviceInfo& deviceInfo)
{
    std::string networkId = deviceInfo.networkId;
    HILOGI("OnNodeOnline netwokId = %{public}s", AnonymizeNetworkId(networkId).c_str());
    auto onlineNotifyTask = [deviceInfo]() {
        std::lock_guard<std::mutex> autoLock(listenerSetMutex_);
        for (auto& listener : listenerSet_) {
            listener->OnDeviceOnline(deviceInfo);
        }
    };
    if (!dnetworkHandler_->PostTask(onlineNotifyTask)) {
        HILOGE("OnNodeOnline post task failed");
        return;
    }
}

void DnetworkAdapter::DmsDeviceStateCallback::OnDeviceOffline(const DmDeviceInfo& deviceInfo)
{
    HILOGI("OnNodeOffline networkId = %{public}s", AnonymizeNetworkId(deviceInfo.networkId).c_str());
    auto offlineNotifyTask = [deviceInfo]() {
        std::lock_guard<std::mutex> autoLock(listenerSetMutex_);
        for (auto& listener : listenerSet_) {
            listener->OnDeviceOffline(deviceInfo);
        }
    };
    if (!dnetworkHandler_->PostTask(offlineNotifyTask)) {
        HILOGE("OnNodeOffline post task failed");
        return;
    }
}

void DnetworkAdapter::DmsDeviceStateCallback::OnDeviceChanged(const DmDeviceInfo& deviceInfo)
{
    HILOGI("called");
    std::string networkId = deviceInfo.networkId;
    HILOGI("OnDeviceChanged netwokId = %{public}s", AnonymizeNetworkId(networkId).c_str());
    auto onlineNotifyTask = [deviceInfo]() {
        std::lock_guard<std::mutex> autoLock(listenerSetMutex_);
        for (auto& listener : listenerSet_) {
            listener->OnDeviceOnline(deviceInfo);
        }
    };
    if (!dnetworkHandler_->PostTask(onlineNotifyTask)) {
        HILOGE("OnNodeOnline post task failed");
        return;
    }
}

void DnetworkAdapter::DmsDeviceStateCallback::OnDeviceReady(const DmDeviceInfo& deviceInfo)
{
    HILOGD("called");
}

bool DnetworkAdapter::AddDeviceChangeListener(const std::shared_ptr<DeviceListener>& listener)
{
    HILOGD("AddDeviceChangeListener called");
    if (dnetworkHandler_ == nullptr) {
        HILOGE("handler is null");
        return false;
    }
    {
        std::lock_guard<std::mutex> autoLock(listenerSetMutex_);
        if (listenerSet_.find(listener) == listenerSet_.end()) {
            listenerSet_.insert(listener);
        }
        if (listenerSet_.size() > 1) {
            return true;
        }
    }
    auto registerTask = [this]() {
        HILOGD("AddDeviceChangeListener register mission...");
        int32_t retryTimes = 0;
        int32_t errCode = ERR_OK;
        while (retryTimes++ < RETRY_REGISTER_CALLBACK_TIMES) {
            int32_t ret = DeviceManager::GetInstance().InitDeviceManager(PKG_NAME, initCallback_);
            if (ret != ERR_OK) {
                HILOGE("init device manager failed, ret:%{public}d", ret);
                std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_REGISTER_CALLBACK_DELAY_TIME));
                continue;
            }
            errCode = DeviceManager::GetInstance().RegisterDevStateCallback(PKG_NAME, "", stateCallback_);
            if (errCode != ERR_OK) {
                HILOGD("AddDeviceChangeListener Reg errCode = %{public}d, retrying...", errCode);
                errCode = DeviceManager::GetInstance().UnRegisterDevStateCallback(PKG_NAME);
                HILOGD("AddDeviceChangeListener Unreg errCode = %{public}d", errCode);
                std::this_thread::sleep_for(std::chrono::milliseconds(RETRY_REGISTER_CALLBACK_DELAY_TIME));
                continue;
            }
            if (UpdateDeviceInfoStorage()) {
                break;
            }
        }
        HILOGI("AddDeviceChangeListener %{public}s", (errCode == ERR_OK) ? "success" : "timeout");
    };
    if (!dnetworkHandler_->PostTask(registerTask)) {
        HILOGE("AddDeviceChangeListener post task failed");
        return false;
    }
    return true;
}

bool DnetworkAdapter::UpdateDeviceInfoStorage()
{
    std::vector<DistributedHardware::DmDeviceInfo> dmDeviceInfoList;
    int32_t errCode = DeviceManager::GetInstance().GetTrustedDeviceList(PKG_NAME, "", dmDeviceInfoList);
    if (errCode != ERR_OK) {
        HILOGE("GetTrustedDeviceList failed, errCode = %{public}d", errCode);
        return false;
    }
    DtbschedmgrDeviceInfoStorage::GetInstance().UpdateDeviceInfoStorage(dmDeviceInfoList);
    HILOGI("UpdateDeviceInfoStorage success");
    return true;
}

void DnetworkAdapter::RemoveDeviceChangeListener(const std::shared_ptr<DeviceListener>& listener)
{
    HILOGD("RemoveDeviceChangeListener called");
    {
        std::lock_guard<std::mutex> autoLock(listenerSetMutex_);
        listenerSet_.erase(listener);
        if (listenerSet_.size() > 0) {
            return;
        }
    }

    int32_t errCode = DeviceManager::GetInstance().UnRegisterDevStateCallback(PKG_NAME);
    if (errCode != ERR_OK) {
        HILOGE("RemoveDeviceChangeListener remove failed, errCode = %{public}d", errCode);
    }
    HILOGD("RemoveDeviceChangeListener remove ok");
}

bool DnetworkAdapter::GetLocalBasicInfo(DmDeviceInfo& dmDeviceInfo)
{
    int32_t errCode = DeviceManager::GetInstance().GetLocalDeviceInfo(PKG_NAME, dmDeviceInfo);
    if (errCode != ERR_OK) {
        HILOGE("GetLocalBasicInfo errCode = %{public}d", errCode);
        return false;
    }
    return true;
}

std::string DnetworkAdapter::GetUdidByNetworkId(const std::string& networkId)
{
    if (networkId.empty()) {
        HILOGE("networkId is empty");
        return "";
    }
    std::string udid = "";
    int32_t errCode = DeviceManager::GetInstance().GetUdidByNetworkId(PKG_NAME, networkId, udid);
    if (errCode != ERR_OK) {
        HILOGE("GetUdidByNetworkId errCode = %{public}d", errCode);
        return "";
    }
    return udid;
}

std::string DnetworkAdapter::GetUuidByNetworkId(const std::string& networkId)
{
    if (networkId.empty()) {
        HILOGE("networkId is empty");
        return "";
    }
    std::string uuid = "";
    int32_t errCode = DeviceManager::GetInstance().GetUuidByNetworkId(PKG_NAME, networkId, uuid);
    if (errCode != ERR_OK) {
        HILOGE("GetUuidByNetworkId errCode = %{public}d", errCode);
        return "";
    }
    return uuid;
}

std::string DnetworkAdapter::AnonymizeNetworkId(const std::string& networkId)
{
    if (networkId.length() < NON_ANONYMIZED_LENGTH) {
        return EMPTY_DEVICE_ID;
    }
    std::string anonNetworkId = networkId.substr(0, NON_ANONYMIZED_LENGTH);
    anonNetworkId.append("******");
    return anonNetworkId;
}
} // namespace DistributedSchedule
} // namespace OHOS
