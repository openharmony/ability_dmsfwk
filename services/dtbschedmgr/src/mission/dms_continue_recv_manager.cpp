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

#include "mission/dms_continue_recv_manager.h"

#include "adapter/dnetwork_adapter.h"
#include "datetime_ex.h"
#include "distributed_sched_utils.h"
#include "distributed_radar.h"
#include "distributed_sched_adapter.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "parcel_helper.h"
#include "softbus_adapter/softbus_adapter.h"
#include <sys/prctl.h>
#include "switch_status_dependency.h"
#include "datashare_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t ON_CALLBACK = 0;
constexpr int32_t ACTIVE = 0;
constexpr int32_t INACTIVE = 1;
constexpr int32_t INDEX_2 = 2;
constexpr int32_t INDEX_3 = 3;
constexpr int32_t DBMS_RETRY_MAX_TIME = 5;
constexpr int32_t DBMS_RETRY_DELAY = 1000;
const std::string TAG = "DMSContinueRecvMgr";
const std::string DBMS_RETRY_TASK = "retry_on_boradcast_task";
const std::u16string DESCRIPTOR = u"ohos.aafwk.RemoteOnListener";
}

IMPLEMENT_SINGLE_INSTANCE(DMSContinueRecvMgr);

void DMSContinueRecvMgr::Init()
{
    HILOGI("Init start");
    {
        std::shared_ptr<SoftbusAdapterListener> missionBroadcastListener =
            std::make_shared<DistributedMissionBroadcastListener>();
        int32_t ret = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(missionBroadcastListener);
        if (ret != ERR_OK) {
            HILOGE("get RegisterSoftbusEventListener failed, ret: %{public}d", ret);
            return;
        }
        missionDiedListener_ = new DistributedMissionDiedListener();
        eventThread_ = std::thread(&DMSContinueRecvMgr::StartEvent, this);
        std::unique_lock<std::mutex> lock(eventMutex_);
        eventCon_.wait(lock, [this] {
            return eventHandler_ != nullptr;
        });
    }
    HILOGI("Init end");
}

void DMSContinueRecvMgr::UnInit()
{
    HILOGI("UnInit start");
    if (eventHandler_ != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        eventThread_.join();
        eventHandler_ = nullptr;
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("UnInit end");
}

void DMSContinueRecvMgr::NotifyDataRecv(std::string& senderNetworkId,
    uint8_t* payload, uint32_t dataLen)
{
    HILOGI("NotifyDataRecv start, senderNetworkId: %{public}s, dataLen: %{public}u",
        DnetworkAdapter::AnonymizeNetworkId(senderNetworkId).c_str(), dataLen);
    bool IsContinueSwitchOn = SwitchStatusDependency::GetInstance().IsContinueSwitchOn();
    if (!IsContinueSwitchOn) {
        HILOGE("ContinueSwitch status is off");
        return;
    }
    if (dataLen > DMS_SEND_LEN) {
        HILOGE("dataLen error, dataLen: %{public}u", dataLen);
        return;
    }
    uint8_t type = (payload[0] & DMS_0XF0) >> CONTINUE_SHIFT_04;
    uint8_t len = payload[0] & DMS_0X0F;
    if (len < DMS_DATA_LEN || (type > DMS_0X0F)) {
        HILOGE("len or type error, len: %{public}u, type: %{public}u", len, type);
        return;
    }
    uint16_t bundleNameId = (payload[1] << CONTINUE_SHIFT_08) | payload[INDEX_2];
    uint16_t continueTypeId = payload[INDEX_3];
    HILOGD("bundleNameId: %{public}u, continueTypeId: %{public}u", bundleNameId, continueTypeId);
    int32_t state = ACTIVE;
    if (type == DMS_UNFOCUSED_TYPE) {
        state = INACTIVE;
        DmsRadar::GetInstance().RecvUnfocused("NotifyDataRecv");
    } else {
        DmsRadar::GetInstance().RecvFocused("NotifyDataRecv");
    }
    PostOnBroadcastBusiness(senderNetworkId, bundleNameId, state);
    HILOGI("NotifyDataRecv end");
}

int32_t DMSContinueRecvMgr::RegisterOnListener(const std::string& type, const sptr<IRemoteObject>& obj)
{
    HILOGI("RegisterOnListener start, type: %{public}s", type.c_str());
    if (obj == nullptr) {
        HILOGE("obj is null, type: %{public}s", type.c_str());
        return INVALID_PARAMETERS_ERR;
    }
    onType_ = type;
    std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
    auto iterItem = registerOnListener_.find(type);
    if (iterItem == registerOnListener_.end()) {
        HILOGD("The itemItem does not exist in the registerOnListener_, adding, type: %{public}s", type.c_str());
        std::vector<sptr<IRemoteObject>> objs;
        obj->AddDeathRecipient(missionDiedListener_);
        objs.emplace_back(obj);
        registerOnListener_[type] = objs;
        HILOGI("RegisterOnListener end");
        return ERR_OK;
    }
    for (auto iter : iterItem->second) {
        if (iter == obj) {
            HILOGI("already have obj");
            return NO_MISSION_INFO_FOR_MISSION_ID;
        }
    }
    obj->AddDeathRecipient(missionDiedListener_);
    iterItem->second.emplace_back(obj);
    HILOGI("RegisterOnListener end");
    return ERR_OK;
}

int32_t DMSContinueRecvMgr::RegisterOffListener(const std::string& type,
    const sptr<IRemoteObject>& obj)
{
    HILOGI("RegisterOffListener start, type: %{public}s", type.c_str());
    if (obj == nullptr) {
        HILOGE("obj is null, type: %{public}s", type.c_str());
        return INVALID_PARAMETERS_ERR;
    }
    for (auto iterItem = registerOnListener_.begin(); iterItem != registerOnListener_.end();) {
        for (auto iter = iterItem->second.begin(); iter != iterItem->second.end();) {
            if (*iter == obj) {
                std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
                iter = iterItem->second.erase(iter);
                obj->RemoveDeathRecipient(missionDiedListener_);
                break;
            } else {
                iter++;
            }
        }
        if (iterItem->second.empty()) {
            std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
            iterItem = registerOnListener_.erase(iterItem);
        } else {
            iterItem++;
        }
    }
    HILOGI("RegisterOffListener end");
    return ERR_OK;
}

void DMSContinueRecvMgr::StartEvent()
{
    HILOGI("StartEvent start");
    prctl(PR_SET_NAME, CONTINUE_RECV_MANAGER.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    runner->Run();
    HILOGI("StartEvent end");
}

int32_t DMSContinueRecvMgr::VerifyBroadcastSource(const std::string& senderNetworkId,
    const std::string& bundleName, const int32_t state)
{
    std::lock_guard<std::mutex> currentIconLock(iconMutex_);
    if (state == ACTIVE) {
        iconInfo_.senderNetworkId = senderNetworkId;
        iconInfo_.bundleName = bundleName;
    } else {
        if (senderNetworkId != iconInfo_.senderNetworkId) {
            HILOGW("Sender not match, task abort. senderNetworkId: %{public}s, saved NetworkId: %{public}s",
                DnetworkAdapter::AnonymizeNetworkId(senderNetworkId).c_str(),
                DnetworkAdapter::AnonymizeNetworkId(iconInfo_.senderNetworkId).c_str());
            return INVALID_PARAMETERS_ERR;
        }

        if (bundleName != iconInfo_.bundleName) {
            HILOGW("BundleName not match, task abort. bundleName: %{public}s, saved bundleName: %{public}s",
                bundleName.c_str(), iconInfo_.bundleName.c_str());
            return INVALID_PARAMETERS_ERR;
        }
        iconInfo_.senderNetworkId = "";
        iconInfo_.bundleName = "";
    }
    return ERR_OK;
}

void DMSContinueRecvMgr::PostOnBroadcastBusiness(const std::string& senderNetworkId,
    uint16_t accessTokenId, const int32_t state, const int32_t delay, const int32_t retry)
{
    auto feedfunc = [this, senderNetworkId, accessTokenId, state, retry]() mutable {
        DealOnBroadcastBusiness(senderNetworkId, accessTokenId, state, retry);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(DBMS_RETRY_TASK);
        eventHandler_->PostTask(feedfunc, DBMS_RETRY_TASK, delay);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
}

int32_t DMSContinueRecvMgr::RetryPostBroadcast(const std::string& senderNetworkId,
    uint16_t accessTokenId, const int32_t state, const int32_t retry)
{
    HILOGI("Retry post broadcast, current retry times %{public}d", retry);
    if (retry == DBMS_RETRY_MAX_TIME) {
        HILOGE("meet max retry time!");
        return INVALID_PARAMETERS_ERR;
    }
    PostOnBroadcastBusiness(senderNetworkId, accessTokenId, state, DBMS_RETRY_DELAY, retry + 1);
    return ERR_OK;
}

int32_t DMSContinueRecvMgr::DealOnBroadcastBusiness(const std::string& senderNetworkId,
    uint16_t accessTokenId, const int32_t state, const int32_t retry)
{
    HILOGI("DealOnBroadcastBusiness start, senderNetworkId: %{public}s, accessTokenId: %{public}u, state: %{public}d",
        DnetworkAdapter::AnonymizeNetworkId(senderNetworkId).c_str(), accessTokenId, state);
    std::string bundleName;
    int32_t ret = BundleManagerInternal::GetBundleNameFromDbms(senderNetworkId, accessTokenId, bundleName);
    bool res = (state == INACTIVE) ? DmsRadar::GetInstance().UnfocusedGetBundleName("GetBundleNameFromDbms", ret)
        : DmsRadar::GetInstance().FocusedGetBundleName("GetBundleNameFromDbms", ret);
    if (!res) {
        HILOGE("%{public}s failed", (state == INACTIVE) ? "UnfocusedGetBundleName" : "FocusedGetBundleName");
    }
    if (ret != ERR_OK) {
        HILOGW("get bundleName failed, ret: %{public}d, try = %{public}d", ret, retry);
        return RetryPostBroadcast(senderNetworkId, accessTokenId, state, retry);
    }

    if (!CheckBundleContinueConfig(bundleName)) {
        HILOGI("App does not allow continue in config file, bundle name %{public}s", bundleName.c_str());
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }

    HILOGI("get bundleName, bundleName: %{public}s", bundleName.c_str());
    AppExecFwk::BundleInfo localBundleInfo;
    if (BundleManagerInternal::GetLocalBundleInfoV9(bundleName, localBundleInfo) != ERR_OK) {
        HILOGE("The app is not installed on the local device.");
        return INVALID_PARAMETERS_ERR;
    }
    if (localBundleInfo.applicationInfo.bundleType != AppExecFwk::BundleType::APP) {
        HILOGE("The bundleType must be app, but it is %{public}d", localBundleInfo.applicationInfo.bundleType);
        return INVALID_PARAMETERS_ERR;
    }

    ret = VerifyBroadcastSource(senderNetworkId, bundleName, state);
    if (ret != ERR_OK) {
        return ret;
    }
    std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
    auto iterItem = registerOnListener_.find(onType_);
    if (iterItem == registerOnListener_.end()) {
        HILOGE("get iterItem failed from registerOnListener_, accessTokenId: %{public}u", accessTokenId);
        return INVALID_PARAMETERS_ERR;
    }
    std::vector<sptr<IRemoteObject>> objs = iterItem->second;
    for (auto iter : objs) {
        NotifyRecvBroadcast(iter, senderNetworkId, bundleName, state);
    }
    HILOGI("DealOnBroadcastBusiness end");
    return ERR_OK;
}

void DMSContinueRecvMgr::NotifyRecvBroadcast(const sptr<IRemoteObject>& obj,
    const std::string& networkId, const std::string& bundleName, const int32_t state)
{
    HILOGI("NotifyRecvBroadcast start");
    if (obj == nullptr) {
        HILOGE("obj is null");
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_ASYNC);
    if (!data.WriteInterfaceToken(DESCRIPTOR)) {
        HILOGE("NotifyRecvBroadcast write interface token failed");
        return;
    }
    PARCEL_WRITE_HELPER_NORET(data, Int32, state);
    PARCEL_WRITE_HELPER_NORET(data, String, networkId);
    PARCEL_WRITE_HELPER_NORET(data, String, bundleName);
    HILOGI("[PerformanceTest] NotifyRecvBroadcast called, IPC begin = %{public}" PRId64, GetTickCount());
    int32_t error = obj->SendRequest(ON_CALLBACK, data, reply, option);
    bool res = (state == INACTIVE) ? DmsRadar::GetInstance().NotifyDockUnfocused("NotifyRecvBroadcast", error)
        : DmsRadar::GetInstance().NotifyDockFocused("NotifyRecvBroadcast", error);
    if (!res) {
        HILOGE("%{public}s failed", (state == INACTIVE) ? "NotifyDockUnfocused" : "NotifyDockFocused");
    }
    if (error != ERR_NONE) {
        HILOGE("NotifyRecvBroadcast fail, error: %{public}d", error);
        return;
    }
    HILOGI("NotifyRecvBroadcast end");
}

void DMSContinueRecvMgr::NotifyDied(const sptr<IRemoteObject>& obj)
{
    HILOGI("NotifyDied start");
    if (obj == nullptr) {
        HILOGE("obj is null");
        return;
    }
    for (auto iterItem = registerOnListener_.begin(); iterItem != registerOnListener_.end();) {
        for (auto iter = iterItem->second.begin(); iter != iterItem->second.end();) {
            if (*iter == obj) {
                obj->RemoveDeathRecipient(missionDiedListener_);
                iter = iterItem->second.erase(iter);
            } else {
                iter++;
            }
        }
        if (iterItem->second.empty()) {
            std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
            iterItem = registerOnListener_.erase(iterItem);
        } else {
            iterItem++;
        }
    }
    HILOGI("NotifyDied end");
}

#ifdef SUPPORT_COMMON_EVENT_SERVICE
void DMSContinueRecvMgr::OnDeviceScreenOff()
{
    HILOGI("OnDeviceScreenOff called");
    auto func = [this]() {
        std::string senderNetworkId;
        std::string bundleName;
        {
            std::lock_guard<std::mutex> currentIconLock(iconMutex_);
            if (iconInfo_.isEmpty()) {
                HILOGW("Saved iconInfo has already been cleared, task abort.");
                return;
            }
            senderNetworkId = iconInfo_.senderNetworkId;
            bundleName = iconInfo_.bundleName;
            iconInfo_.senderNetworkId = "";
            iconInfo_.bundleName = "";
        }
        HILOGI("Saved iconInfo cleared, networkId = %{public}s, bundleName = %{public}s",
            DnetworkAdapter::AnonymizeNetworkId(senderNetworkId).c_str(), bundleName.c_str());
        {
            std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
            auto iterItem = registerOnListener_.find(onType_);
            if (iterItem == registerOnListener_.end()) {
                HILOGI("Get iterItem failed from registerOnListener_, nobody registed");
                return;
            }
            std::vector<sptr<IRemoteObject>> objs = iterItem->second;
            for (auto iter : objs) {
                NotifyRecvBroadcast(iter, senderNetworkId, bundleName, INACTIVE);
            }
        }
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->PostTask(func);
}
#endif

void DMSContinueRecvMgr::OnContinueSwitchOff()
{
    auto func = [this]() {
        std::string senderNetworkId;
        std::string bundleName;
        {
            std::lock_guard<std::mutex> currentIconLock(iconMutex_);
            if (iconInfo_.isEmpty()) {
                HILOGW("Saved iconInfo has already been cleared, task abort.");
                return;
            }
            senderNetworkId = iconInfo_.senderNetworkId;
            bundleName = iconInfo_.bundleName;
            iconInfo_.senderNetworkId = "";
            iconInfo_.bundleName = "";
        }
        HILOGI("Saved iconInfo cleared, networkId = %{public}s, bundleName = %{public}s",
            DnetworkAdapter::AnonymizeNetworkId(senderNetworkId).c_str(), bundleName.c_str());
        {
            std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
            auto iterItem = registerOnListener_.find(onType_);
            if (iterItem == registerOnListener_.end()) {
                HILOGI("Get iterItem failed from registerOnListener_, nobody registed");
                return;
            }
            std::vector<sptr<IRemoteObject>> objs = iterItem->second;
            for (auto iter : objs) {
                NotifyRecvBroadcast(iter, senderNetworkId, bundleName, INACTIVE);
            }
        }
    };
    if (eventHandler_ == nullptr) {
        HILOGE("eventHandler_ is nullptr");
        return;
    }
    eventHandler_->PostTask(func);
}

void DMSContinueRecvMgr::NotifyDeviceOffline(const std::string& networkId)
{
    if (networkId.empty()) {
        HILOGE("NotifyDeviceOffline networkId empty");
        return;
    }
    HILOGI("NotifyDeviceOffline begin. networkId = %{public}s", DnetworkAdapter::AnonymizeNetworkId(networkId).c_str());
    std::string localNetworkId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localNetworkId)) {
        HILOGE("Get local networkId failed");
        return;
    }
    std::string senderNetworkId;
    std::string bundleName;
    {
        std::lock_guard<std::mutex> currentIconLock(iconMutex_);
        if (networkId != iconInfo_.senderNetworkId && networkId != localNetworkId) {
            HILOGI("NotifyDeviceOffline irrelevant device offline, ignore");
            return;
        }
        senderNetworkId = iconInfo_.senderNetworkId;
        bundleName = iconInfo_.bundleName;
        iconInfo_.senderNetworkId = "";
        iconInfo_.bundleName = "";
    }
    HILOGI("Saved iconInfo cleared, networkId = %{public}s, bundleName = %{public}s",
        DnetworkAdapter::AnonymizeNetworkId(senderNetworkId).c_str(), bundleName.c_str());
    {
        std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
        auto iterItem = registerOnListener_.find(onType_);
        if (iterItem == registerOnListener_.end()) {
            HILOGI("Get iterItem failed from registerOnListener_, nobody registed");
            return;
        }
        std::vector<sptr<IRemoteObject>> objs = iterItem->second;
        for (auto iter : objs) {
            NotifyRecvBroadcast(iter, senderNetworkId, bundleName, INACTIVE);
        }
    }
    HILOGI("NotifyDeviceOffline end");
}
} // namespace DistributedSchedule
} // namespace OHOS
