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

#include <sys/prctl.h>

#include "datetime_ex.h"

#include "datashare_manager.h"
#include "dfx/distributed_radar.h"
#include "dfx/distributed_ue.h"
#include "distributed_sched_utils.h"
#include "distributed_sched_adapter.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "mission/dsched_sync_e2e.h"
#include "mission/wifi_state_adapter.h"
#include "parcel_helper.h"
#include "softbus_adapter/softbus_adapter.h"
#include "switch_status_dependency.h"
#include "os_account_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t ON_CALLBACK = 0;
constexpr int32_t ACTIVE = 0;
constexpr int32_t INACTIVE = 1;
constexpr int32_t INDEX_2 = 2;
constexpr int32_t INDEX_3 = 3;
constexpr int32_t DBMS_RETRY_MAX_TIME = 5;
constexpr int32_t DBMS_RETRY_DELAY = 2000;
constexpr int32_t LAST_RECV_INFO_QUEUE_SIZE = 5;
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
        hasRegSoftbusEventListener_ = true;
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
    if (eventHandler_ != nullptr && eventHandler_->GetEventRunner() != nullptr) {
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
    HILOGI("NotifyDataRecv start, senderNetworkId: %{public}s, dataLen: %{public}u.",
        GetAnonymStr(senderNetworkId).c_str(), dataLen);
    if (!DmsKvSyncE2E::GetInstance()->CheckCtrlRule()) {
        HILOGE("Forbid sending and receiving");
        return;
    }
    bool IsContinueSwitchOn = SwitchStatusDependency::GetInstance().IsContinueSwitchOn();
    if (!IsContinueSwitchOn) {
        HILOGE("ContinueSwitch status is off");
        return;
    }
    if (!WifiStateAdapter::GetInstance().IsWifiActive()) {
        HILOGE("wifi is not activated");
        return;
    }
    if (dataLen < DMS_SEND_LEN) {
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
    uint8_t continueTypeId = payload[INDEX_3];
    HILOGI("bundleNameId: %{public}u, continueTypeId: %{public}u", bundleNameId, continueTypeId);
    int32_t state = ACTIVE;
    if (type == DMS_UNFOCUSED_TYPE) {
        state = INACTIVE;
    }
    PostOnBroadcastBusiness(senderNetworkId, bundleNameId, continueTypeId, state);
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
    if (runner != nullptr) {
        runner->Run();
    } else {
        HILOGE("runner is null");
    }
    HILOGI("StartEvent end");
}

int32_t DMSContinueRecvMgr::VerifyBroadcastSource(const std::string& senderNetworkId,
    const std::string& bundleName, const std::string& continueType, const int32_t state)
{
    std::lock_guard<std::mutex> currentIconLock(iconMutex_);
    if (state == ACTIVE) {
        iconInfo_.senderNetworkId = senderNetworkId;
        iconInfo_.bundleName = bundleName;
        iconInfo_.continueType = continueType;
    } else {
        if (senderNetworkId != iconInfo_.senderNetworkId) {
            HILOGW("Sender not match, task abort. senderNetworkId: %{public}s, saved NetworkId: %{public}s.",
                GetAnonymStr(senderNetworkId).c_str(), GetAnonymStr(iconInfo_.senderNetworkId).c_str());
            return INVALID_PARAMETERS_ERR;
        }

        if (bundleName != iconInfo_.bundleName) {
            HILOGW("BundleName not match, task abort. bundleName: %{public}s, saved bundleName: %{public}s",
                bundleName.c_str(), iconInfo_.bundleName.c_str());
            return INVALID_PARAMETERS_ERR;
        }

        iconInfo_.senderNetworkId = "";
        iconInfo_.bundleName = "";
        iconInfo_.continueType = "";
    }
    return ERR_OK;
}

void DMSContinueRecvMgr::PostOnBroadcastBusiness(const std::string& senderNetworkId,
    uint16_t bundleNameId, uint8_t continueTypeId, const int32_t state, const int32_t delay, const int32_t retry)
{
    auto feedfunc = [this, senderNetworkId, bundleNameId, continueTypeId, state, retry]() mutable {
        DealOnBroadcastBusiness(senderNetworkId, bundleNameId, continueTypeId, state, retry);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(DBMS_RETRY_TASK);
        eventHandler_->PostTask(feedfunc, DBMS_RETRY_TASK, delay);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
}

int32_t DMSContinueRecvMgr::RetryPostBroadcast(const std::string& senderNetworkId,
    uint16_t bundleNameId, uint8_t continueTypeId, const int32_t state, const int32_t retry)
{
    HILOGI("Retry post broadcast, current retry times %{public}d", retry);
    if (retry == DBMS_RETRY_MAX_TIME) {
        HILOGE("meet max retry time!");
        return INVALID_PARAMETERS_ERR;
    }
    PostOnBroadcastBusiness(senderNetworkId, bundleNameId, continueTypeId, state, DBMS_RETRY_DELAY, retry + 1);
    return ERR_OK;
}

bool DMSContinueRecvMgr::GetFinalBundleName(DmsBundleInfo &distributedBundleInfo, std::string &finalBundleName,
    AppExecFwk::BundleInfo &localBundleInfo, std::string &continueType)
{
    std::string bundleName = distributedBundleInfo.bundleName;
    if (BundleManagerInternal::GetLocalBundleInfo(bundleName, localBundleInfo) == ERR_OK
        && ContinueTypeCheck(localBundleInfo, continueType)) {
        finalBundleName = bundleName;
        return true;
    }
    std::vector<std::string> bundleNameList;
    bool continueBundleGot = BundleManagerInternal::GetContinueBundle4Src(bundleName, bundleNameList);
    if (!continueBundleGot) {
        HILOGE("can not get local bundle info or continue bundle for bundle name: %{public}s", bundleName.c_str());
        return false;
    }

    for (std::string &bundleNameItem: bundleNameList) {
        HILOGI("find dst bundle name for diff bundle continue. src developer id: %{public}s; ",
            GetAnonymStr(distributedBundleInfo.developerId).c_str());
        AppExecFwk::AppProvisionInfo appProvisionInfo;
        if (BundleManagerInternal::GetAppProvisionInfo4CurrentUser(bundleNameItem, appProvisionInfo)
            && appProvisionInfo.developerId == distributedBundleInfo.developerId
            && BundleManagerInternal::GetLocalBundleInfo(bundleName, localBundleInfo) == ERR_OK
            && ContinueTypeCheck(localBundleInfo, continueType)) {
            finalBundleName = bundleNameItem;
            return true;
        }
    }
    HILOGE("continue type is not empty and can not get local bundle info and continue nundle for "
        "bundle name: %{public}s", bundleName.c_str());
    return false;
}

bool DMSContinueRecvMgr::ContinueTypeCheck(const AppExecFwk::BundleInfo &bundleInfo, const std::string &continueType)
{
    for (const auto &abilityInfo: bundleInfo.abilityInfos) {
        for (const auto &continueTypeItem: abilityInfo.continueType) {
            if (continueTypeItem == continueType) {
                return true;
            }
        }
    }
    HILOGE("can not mate continue type: %{public}s in buninfo for bundleName: %{public}s", continueType.c_str(),
           bundleInfo.name.c_str());
    return false;
}

void DMSContinueRecvMgr::FindContinueType(const DmsBundleInfo &distributedBundleInfo,
    uint8_t &continueTypeId, std::string &continueType)
{
    uint32_t pos = 0;
    for (auto dmsAbilityInfo: distributedBundleInfo.dmsAbilityInfos) {
        for (auto continueTypeElement: dmsAbilityInfo.continueType) {
            if (pos == continueTypeId) {
                continueType = continueTypeElement;
                return;
            }
            ++pos;
        }
    }
    continueType = "";
}

int32_t DMSContinueRecvMgr::DealOnBroadcastBusiness(const std::string& senderNetworkId,
    uint16_t bundleNameId, uint8_t continueTypeId, const int32_t state, const int32_t retry)
{
    HILOGI("DealOnBroadcastBusiness start, senderNetworkId: %{public}s, bundleNameId: %{public}u, state: %{public}d.",
        GetAnonymStr(senderNetworkId).c_str(), bundleNameId, state);
    DmsBundleInfo distributedBundleInfo;
    if (!DmsBmStorage::GetInstance()->GetDistributedBundleInfo(senderNetworkId, bundleNameId,
        distributedBundleInfo)) {
        HILOGW("get distributedBundleInfo failed, try = %{public}d", retry);
        return RetryPostBroadcast(senderNetworkId, bundleNameId, continueTypeId, state, retry);
    }

    std::string bundleName = distributedBundleInfo.bundleName;
    if (!CheckBundleContinueConfig(bundleName)) {
        HILOGI("App does not allow continue in config file, bundle name %{public}s", bundleName.c_str());
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }

    HILOGI("get distributedBundleInfo success, bundleName: %{public}s", bundleName.c_str());
    std::string finalBundleName;
    AppExecFwk::BundleInfo localBundleInfo;
    std::string continueType;
    FindContinueType(distributedBundleInfo, continueTypeId, continueType);
    if (!GetFinalBundleName(distributedBundleInfo, finalBundleName, localBundleInfo, continueType)) {
        HILOGE("The app is not installed on the local device.");
        return INVALID_PARAMETERS_ERR;
    }
    HILOGI("got finalBundleName: %{public}s", finalBundleName.c_str());
    currentIconInfo lastRecvInfo = currentIconInfo(senderNetworkId, bundleName, finalBundleName);
    PushLatRecvCache(lastRecvInfo);

    if (localBundleInfo.applicationInfo.bundleType != AppExecFwk::BundleType::APP) {
        HILOGE("The bundleType must be app, but it is %{public}d", localBundleInfo.applicationInfo.bundleType);
        return INVALID_PARAMETERS_ERR;
    }

    int32_t ret = VerifyBroadcastSource(senderNetworkId, finalBundleName, continueType, state);
    if (ret != ERR_OK) {
        return ret;
    }
    std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
    auto iterItem = registerOnListener_.find(onType_);
    if (iterItem == registerOnListener_.end()) {
        HILOGE("get iterItem failed from registerOnListener_, bundleNameId: %{public}u", bundleNameId);
        return INVALID_PARAMETERS_ERR;
    }
    std::vector<sptr<IRemoteObject>> objs = iterItem->second;
    for (auto iter : objs) {
        NotifyRecvBroadcast(iter, senderNetworkId, finalBundleName, state, continueType);
    }
    HILOGI("DealOnBroadcastBusiness end");
    return ERR_OK;
}

void DMSContinueRecvMgr::PushLatRecvCache(currentIconInfo &lastRecvInfo)
{
    if (lastRecvList_.size() >= LAST_RECV_INFO_QUEUE_SIZE) {
        lastRecvList_.erase(lastRecvList_.begin());
    }
    lastRecvList_.push_back(lastRecvInfo);
}

void DMSContinueRecvMgr::NotifyRecvBroadcast(const sptr<IRemoteObject>& obj,
    const std::string& networkId, const std::string& bundleName, const int32_t state, const std::string& continueType)
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
    PARCEL_WRITE_HELPER_NORET(data, String, continueType);
    HILOGI("[PerformanceTest] NotifyRecvBroadcast called, IPC begin = %{public}" PRId64, GetTickCount());
    int32_t error = obj->SendRequest(ON_CALLBACK, data, reply, option);
    if (state != INACTIVE) {
        std::string bName = bundleName;
        std::string cType = continueType;
        std::string abilityName = BundleManagerInternal::GetInstance().GetAbilityName(networkId,
            bName, cType);
        DmsUE::GetInstance().NotifyDockShowIcon(bundleName, abilityName, networkId, error);
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
        std::string continueType;
        {
            std::lock_guard<std::mutex> currentIconLock(iconMutex_);
            if (iconInfo_.isEmpty()) {
                HILOGW("Saved iconInfo has already been cleared, task abort.");
                return;
            }
            senderNetworkId = iconInfo_.senderNetworkId;
            bundleName = iconInfo_.bundleName;
            continueType = iconInfo_.continueType;
            iconInfo_.senderNetworkId = "";
            iconInfo_.bundleName = "";
            iconInfo_.continueType = "";
        }
        HILOGI("Saved iconInfo cleared, networkId: %{public}s, bundleName: %{public}s.",
            GetAnonymStr(senderNetworkId).c_str(), bundleName.c_str());
        {
            std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
            auto iterItem = registerOnListener_.find(onType_);
            if (iterItem == registerOnListener_.end()) {
                HILOGI("Get iterItem failed from registerOnListener_, nobody registed");
                return;
            }
            std::vector<sptr<IRemoteObject>> objs = iterItem->second;
            for (auto iter : objs) {
                NotifyRecvBroadcast(iter, senderNetworkId, bundleName, INACTIVE, continueType);
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
        std::string continueType;
        {
            std::lock_guard<std::mutex> currentIconLock(iconMutex_);
            if (iconInfo_.isEmpty()) {
                HILOGW("Saved iconInfo has already been cleared, task abort.");
                return;
            }
            senderNetworkId = iconInfo_.senderNetworkId;
            bundleName = iconInfo_.bundleName;
            continueType = iconInfo_.continueType;
            iconInfo_.senderNetworkId = "";
            iconInfo_.bundleName = "";
            iconInfo_.continueType = "";
        }
        HILOGI("Saved iconInfo cleared, networkId: %{public}s, bundleName: %{public}s.",
            GetAnonymStr(senderNetworkId).c_str(), bundleName.c_str());
        {
            std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
            auto iterItem = registerOnListener_.find(onType_);
            if (iterItem == registerOnListener_.end()) {
                HILOGI("Get iterItem failed from registerOnListener_, nobody registed");
                return;
            }
            std::vector<sptr<IRemoteObject>> objs = iterItem->second;
            for (auto iter : objs) {
                NotifyRecvBroadcast(iter, senderNetworkId, bundleName, INACTIVE, continueType);
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
    HILOGI("NotifyDeviceOffline begin. networkId: %{public}s.", GetAnonymStr(networkId).c_str());
    std::string localNetworkId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localNetworkId)) {
        HILOGE("Get local networkId failed");
        return;
    }
    std::string senderNetworkId;
    std::string bundleName;
    std::string continueType;
    {
        std::lock_guard<std::mutex> currentIconLock(iconMutex_);
        if (networkId != iconInfo_.senderNetworkId && networkId != localNetworkId) {
            HILOGI("NotifyDeviceOffline irrelevant device offline, ignore");
            return;
        }
        senderNetworkId = iconInfo_.senderNetworkId;
        bundleName = iconInfo_.bundleName;
        continueType = iconInfo_.continueType;
        iconInfo_.senderNetworkId = "";
        iconInfo_.bundleName = "";
        iconInfo_.continueType = "";
    }
    HILOGI("Saved iconInfo cleared, networkId: %{public}s, bundleName: %{public}s.",
        GetAnonymStr(senderNetworkId).c_str(), bundleName.c_str());
    {
        std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
        auto iterItem = registerOnListener_.find(onType_);
        if (iterItem == registerOnListener_.end()) {
            HILOGI("Get iterItem failed from registerOnListener_, nobody registed");
            return;
        }
        std::vector<sptr<IRemoteObject>> objs = iterItem->second;
        for (auto iter : objs) {
            NotifyRecvBroadcast(iter, senderNetworkId, bundleName, INACTIVE, continueType);
        }
    }
    HILOGI("NotifyDeviceOffline end");
}

std::string DMSContinueRecvMgr::GetContinueType(const std::string& bundleName)
{
    std::lock_guard<std::mutex> currentIconLock(iconMutex_);
    if (iconInfo_.isEmpty()) {
        HILOGW("get continueType failed, Saved iconInfo has already been cleared.");
        return "";
    }
    if (iconInfo_.bundleName != bundleName) {
        HILOGW("BundleName not match, task abort. bundleName: %{public}s, saved bundleName: %{public}s",
            bundleName.c_str(), iconInfo_.bundleName.c_str());
        return "";
    }

    return iconInfo_.continueType;
}

bool DMSContinueRecvMgr::CheckRegSoftbusListener()
{
    return hasRegSoftbusEventListener_;
}
} // namespace DistributedSchedule
} // namespace OHOS
