/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "mission/distributed_sched_continue_manager.h"

#include "adapter/dnetwork_adapter.h"
#include "datetime_ex.h"
#include "distributed_sched_adapter.h"
#include "dtbschedmgr_log.h"
#include "parcel_helper.h"
#include "softbus_adapter/softbus_adapter.h"
#include <sys/prctl.h>

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t ON_CALLBACK = 0;
constexpr int32_t ACTIVE = 0;
constexpr int32_t INACTIVE = 1;
constexpr int32_t INDEX_2 = 2;
constexpr int32_t INDEX_3 = 3;
constexpr int32_t INDEX_4 = 4;
const std::string TAG = "DistributedSchedContinueManager";
const std::u16string DESCRIPTOR = u"ohos.aafwk.RemoteOnListener";
}

IMPLEMENT_SINGLE_INSTANCE(DistributedSchedContinueManager);

void DistributedSchedContinueManager::Init()
{
    HILOGI("Init start");
    missionFocusedListener_ = new DistributedMissionFocusedListener();
    int32_t ret = DistributedSchedAdapter::GetInstance().RegisterMissionListener(missionFocusedListener_);
    if (ret != ERR_OK) {
        HILOGE("get RegisterMissionListener failed, ret: %{public}d", ret);
        return;
    }
    std::shared_ptr<SoftbusAdapterListener> missionBroadcastListener =
        std::make_shared<DistributedMissionBroadcastListener>();
    ret = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(missionBroadcastListener);
    if (ret != ERR_OK) {
        HILOGE("get RegisterSoftbusEventListener failed, ret: %{public}d", ret);
        return;
    }
    missionDiedListener_ = new DistributedMissionDiedListener();
    eventThread_ = std::thread(&DistributedSchedContinueManager::StartEvent, this);
    std::unique_lock<std::mutex> lock(eventMutex_);
    eventCon_.wait(lock, [this] {
        return eventHandler_ != nullptr;
    });
    HILOGI("Init end");
}

void DistributedSchedContinueManager::UnInit()
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

void DistributedSchedContinueManager::NotifyMissionFocused(const int32_t missionId)
{
    HILOGI("NotifyMissionFocused start, missionId: %{public}d", missionId);
    auto feedfunc = [this, missionId]() {
        DealFocusedBusiness(missionId);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(feedfunc);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("NotifyMissionFocused end");
}

void DistributedSchedContinueManager::NotifyMissionUnfocused(const int32_t missionId)
{
    HILOGI("NotifyMissionUnfocused start, missionId: %{public}d", missionId);
    auto feedfunc = [this, missionId]() {
        DealUnfocusedBusiness(missionId);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(feedfunc);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("NotifyMissionUnfocused end");
}

void DistributedSchedContinueManager::NotifyDataRecv(std::string& senderNetworkId, uint8_t* payload, uint32_t dataLen)
{
    HILOGI("NotifyDataRecv start, senderNetworkId: %{public}s, dataLen: %{public}d",
        DnetworkAdapter::AnonymizeNetworkId(senderNetworkId).c_str(), dataLen);
    if (dataLen != DMS_SEND_LEN) {
        HILOGE("dataLen error, dataLen: %{public}d", dataLen);
        return;
    }
    uint8_t type = (payload[0] & DMS_0XF0) >> CONTINUE_SHIFT_04;
    uint8_t len = payload[0] & DMS_0X0F;
    if (len != sizeof(uint32_t) || (type != DMS_UNFOCUSED_TYPE && type != DMS_FOCUSED_TYPE)) {
        HILOGE("len or type error, len: %{public}d, type: %{public}d", len, type);
        return;
    }
    uint32_t accessTokenId = payload[1] << CONTINUE_SHIFT_24 | payload[INDEX_2] << CONTINUE_SHIFT_16 |
        payload[INDEX_3] << CONTINUE_SHIFT_08 | payload[INDEX_4];
    int32_t state = ACTIVE;
    if (type == DMS_UNFOCUSED_TYPE) {
        state = INACTIVE;
    }
    auto feedfunc = [this, senderNetworkId, accessTokenId, state]() mutable {
        DealUnBroadcastdBusiness(senderNetworkId, accessTokenId, state);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(feedfunc);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("NotifyDataRecv end");
}

int32_t DistributedSchedContinueManager::RegisterOnListener(const std::string& type, const sptr<IRemoteObject>& obj)
{
    HILOGI("RegisterOnListener start, type: %{public}s", type.c_str());
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

int32_t DistributedSchedContinueManager::RegisterOffListener(const std::string& type, const sptr<IRemoteObject>& obj)
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

int32_t DistributedSchedContinueManager::GetMissionId(const std::string& bundleName, int32_t& missionId)
{
    HILOGI("GetMissionId start, bundleName: %{public}s", bundleName.c_str());
    std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
    auto iterItem = focusedMission_.find(bundleName);
    if (iterItem == focusedMission_.end()) {
        HILOGE("get iterItem failed from focusedMission_, bundleName: %{public}s", bundleName.c_str());
        return INVALID_PARAMETERS_ERR;
    }
    missionId = iterItem->second;
    HILOGI("get missionId end, missionId: %{public}d", missionId);
    return ERR_OK;
}

void DistributedSchedContinueManager::StartEvent()
{
    HILOGI("StartEvent start");
    prctl(PR_SET_NAME, CONTINUE_MANAGER.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    runner->Run();
    HILOGI("StartEvent end");
}

int32_t DistributedSchedContinueManager::DealFocusedBusiness(const int32_t missionId)
{
    HILOGI("DealFocusedBusiness start, missionId: %{public}d", missionId);
    AAFwk::MissionInfo info;
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->GetMissionInfo("", missionId, info);
    if (ret != ERR_OK) {
        HILOGE("get missionInfo failed, missionId: %{public}d, ret: %{public}d", missionId, ret);
        return ret;
    }
    bool isMissionContibuable = info.continuable;
    {
        std::lock_guard<std::mutex> currentMissionIdLock(eventMutex_);
        info_.currentMissionId = missionId;
        info_.currentIsContibuable = isMissionContibuable;
    }
    if (!isMissionContibuable) {
        HILOGE("can not MissionContinue, missionId: %{public}d", missionId);
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }
    std::string bundleName = info.want.GetBundle();
    focusedMission_[bundleName] = missionId;

    if (info.continueState != AAFwk::ContinueState::CONTINUESTATE_ACTIVE) {
        HILOGE("Mission continue state set to INACTIVE. Broadcast task abort.");
        return INVALID_PARAMETERS_ERR;
    }

    uint32_t accessTokenId;
    ret = BundleManagerInternal::GetBundleIdFromBms(bundleName, accessTokenId);
    if (ret != ERR_OK) {
        HILOGE("get focused accessTokenId failed, accessTokenId: %{public}d, ret: %{public}d", accessTokenId, ret);
        return ret;
    }
    HILOGE("get focused accessTokenId success, accessTokenId: %{public}d", accessTokenId);
    uint32_t sendDataLen = DMS_SEND_LEN;
    uint8_t data[DMS_SEND_LEN];
    uint8_t type = DMS_FOCUSED_TYPE;
    uint8_t len = sizeof(uint32_t);
    data[0] = (type << CONTINUE_SHIFT_04) | len;
    data[1] = (accessTokenId >> CONTINUE_SHIFT_24) & DMS_0XFF;
    data[INDEX_2] = (accessTokenId >> CONTINUE_SHIFT_16) & DMS_0XFF;
    data[INDEX_3] = (accessTokenId >> CONTINUE_SHIFT_08) & DMS_0XFF;
    data[INDEX_4] = accessTokenId & DMS_0XFF;
    ret = SoftbusAdapter::GetInstance().SendSoftbusEvent(data, sendDataLen);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent focused failed,ret: %{public}d", ret);
        return ret;
    }
    HILOGI("DealFocusedBusiness end");
    return ERR_OK;
}

int32_t DistributedSchedContinueManager::CheckContinueState(const int32_t missionId)
{
    AAFwk::MissionInfo info;
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->GetMissionInfo("", missionId, info);
    if (ret != ERR_OK) {
        HILOGE("get missionInfo failed, missionId: %{public}d, ret: %{public}d", missionId, ret);
        return ERR_OK;
    }
    if (info.continueState != AAFwk::ContinueState::CONTINUESTATE_ACTIVE) {
        HILOGE("Mission continue state set to INACTIVE. Broadcast task abort.");
        return INVALID_PARAMETERS_ERR;
    }
    return ERR_OK;
}

int32_t DistributedSchedContinueManager::DealUnfocusedBusiness(const int32_t missionId)
{
    HILOGI("DealUnfocusedBusiness start, missionId: %{public}d", missionId);
    std::string bundleName;
    int32_t ret = GetBundleName(missionId, bundleName);
    if (ret != ERR_OK) {
        HILOGE("get bundleName failed, mission can not change, missionId: %{public}d, ret: %{public}d", missionId, ret);
        return ret;
    }
    HILOGI("get bundleName ,mission can change, missionId: %{public}d, bundleName: %{public}s",
        missionId, bundleName.c_str());

    bool isContinue = IsContinue(missionId, bundleName);
    if (!isContinue) {
        HILOGE("mission is not continue, missionId: %{public}d", missionId);
        return NO_MISSION_INFO_FOR_MISSION_ID;
    }

    ret = CheckContinueState(missionId);
    if (ret != ERR_OK) {
        HILOGE("Check mission continue state error, mission id : %{public}d, ret: %{public}d", missionId, ret);
        return ret;
    }

    uint32_t accessTokenId;
    ret = BundleManagerInternal::GetBundleIdFromBms(bundleName, accessTokenId);
    if (ret != ERR_OK) {
        HILOGE("get unfocused accessTokenId failed, accessTokenId: %{public}d, ret: %{public}d", accessTokenId, ret);
        return ret;
    }
    uint32_t sendDataLen = DMS_SEND_LEN;
    uint8_t data[DMS_SEND_LEN];
    uint8_t type = DMS_UNFOCUSED_TYPE;
    uint8_t len = sizeof(uint32_t);
    data[0] = (type << CONTINUE_SHIFT_04) | len;
    data[1] = (accessTokenId >> CONTINUE_SHIFT_24) & DMS_0XFF;
    data[INDEX_2] = (accessTokenId >> CONTINUE_SHIFT_16) & DMS_0XFF;
    data[INDEX_3] = (accessTokenId >> CONTINUE_SHIFT_08) & DMS_0XFF;
    data[INDEX_4] = accessTokenId & DMS_0XFF;
    ret = SoftbusAdapter::GetInstance().SendSoftbusEvent(data, sendDataLen);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent unfocused failed, sendDataLen: %{public}d, ret: %{public}d", sendDataLen, ret);
    }
    std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
    auto iterItem = focusedMission_.find(bundleName);
    if (iterItem == focusedMission_.end()) {
        HILOGE("get iterItem failed from focusedMission_, missionId: %{public}d", missionId);
    }
    focusedMission_.erase(iterItem);
    HILOGI("DealUnfocusedBusiness end");
    return ERR_OK;
}

int32_t DistributedSchedContinueManager::DealUnBroadcastdBusiness(std::string& senderNetworkId,
    uint32_t accessTokenId, const int32_t state)
{
    HILOGI("DealUnBroadcastdBusiness start, senderNetworkId: %{public}s, accessTokenId: %{public}d, state: %{public}d",
        DnetworkAdapter::AnonymizeNetworkId(senderNetworkId).c_str(), accessTokenId, state);
    std::string bundleName;
    int32_t ret = BundleManagerInternal::GetBundleNameFromDbms(senderNetworkId, accessTokenId, bundleName);
    if (ret != ERR_OK) {
        HILOGE("get bundleName failed, senderNetworkId: %{public}s, accessTokenId: %{public}d, ret: %{public}d",
            DnetworkAdapter::AnonymizeNetworkId(senderNetworkId).c_str(), accessTokenId, ret);
        return ret;
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
    std::lock_guard<std::mutex> registerOnListenerMapLock(eventMutex_);
    auto iterItem = registerOnListener_.find(onType_);
    if (iterItem == registerOnListener_.end()) {
        HILOGE("get iterItem failed from registerOnListener_, accessTokenId: %{public}d", accessTokenId);
        return INVALID_PARAMETERS_ERR;
    }
    std::vector<sptr<IRemoteObject>> objs = iterItem->second;
    for (auto iter : objs) {
        NotifyRecvBroadcast(iter, senderNetworkId, bundleName, state);
    }
    HILOGI("DealUnBroadcastdBusiness end");
    return ERR_OK;
}

void DistributedSchedContinueManager::NotifyRecvBroadcast(const sptr<IRemoteObject>& obj,
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
    if (error != ERR_NONE) {
        HILOGE("NotifyRecvBroadcast fail, error: %{public}d", error);
        return;
    }
    HILOGI("NotifyRecvBroadcast end");
}

int32_t DistributedSchedContinueManager::GetBundleName(const int32_t missionId, std::string& bundleName)
{
    for (auto iterItem = focusedMission_.begin(); iterItem != focusedMission_.end(); iterItem++) {
        if (iterItem->second == missionId) {
            bundleName = iterItem->first;
            return ERR_OK;
        }
    }
    return INVALID_PARAMETERS_ERR;
}

bool DistributedSchedContinueManager::IsContinue(const int32_t& missionId, const std::string& bundleName)
{
    if ((missionId != info_.currentMissionId && info_.currentIsContibuable == true)) {
        /*missionId and currentMissionId are not equal but currentMission can change,
            continue to not send unfocus broadcast*/
        std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
        focusedMission_.erase(bundleName);
        HILOGI("mission is not continue, missionId: %{public}d, currentMissionId: %{public}d",
            missionId, info_.currentMissionId);
        return false;
    }
    /*missionId and currentMissionId are equal, or missionId and currentMissionId are not equal
        and currentIsContibuable not change, continue to send unfocus broadcast*/
    HILOGI("mission is continue, missionId: %{public}d, currentMissionId: %{public}d",
        missionId, info_.currentMissionId);
    return true;
}

int32_t DistributedSchedContinueManager::SetMissionContinueState(const int32_t missionId,
    const AAFwk::ContinueState &state)
{
    HILOGI("SetMissionContinueState start, missionId: %{public}d, state: %{public}d", missionId, state);
    auto feedfunc = [this, missionId, state]() {
        DealSetMissionContinueStateBusiness(missionId, state);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(feedfunc);
    } else {
        HILOGE("eventHandler_ is nullptr");
        return ERR_NULL_OBJECT;
    }
    HILOGI("SetMissionContinueState end");
    return ERR_OK;
}

int32_t DistributedSchedContinueManager::DealSetMissionContinueStateBusiness(const int32_t missionId,
    const AAFwk::ContinueState &state)
{
    HILOGI("DealSetMissionContinueStateBusiness start, missionId: %{public}d, state: %{public}d", missionId, state);

    if (info_.currentMissionId != missionId) {
        HILOGE("mission is not focused, broadcast task abort, missionId: %{public}d", missionId);
        return INVALID_PARAMETERS_ERR;
    }

    if (!info_.currentIsContibuable) {
        HILOGE("mission is not continuable, broadcast task abort, missionId: %{public}d", missionId);
        return INVALID_PARAMETERS_ERR;
    }

    std::string bundleName;
    int32_t ret = GetBundleName(missionId, bundleName);
    if (ret != ERR_OK) {
        HILOGE("get bundleName failed, broadcast task abort, missionId: %{public}d, ret: %{public}d",
            missionId, ret);
        return ret;
    }
    HILOGI("get bundleName success, missionId: %{public}d, bundleName: %{public}s", missionId, bundleName.c_str());

    uint32_t accessTokenId;
    ret = BundleManagerInternal::GetBundleIdFromBms(bundleName, accessTokenId);
    if (ret != ERR_OK) {
        HILOGE("get setContinueState accessTokenId failed, accessTokenId: %{public}d, ret: %{public}d",
            accessTokenId, ret);
        return ret;
    }

    uint32_t sendDataLen = DMS_SEND_LEN;
    uint8_t data[DMS_SEND_LEN];
    uint8_t len = sizeof(uint32_t);
    uint8_t type = DMS_FOCUSED_TYPE;
    if (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE) {
        type = DMS_UNFOCUSED_TYPE;
    }
    data[0] = (type << CONTINUE_SHIFT_04) | len;
    data[1] = (accessTokenId >> CONTINUE_SHIFT_24) & DMS_0XFF;
    data[INDEX_2] = (accessTokenId >> CONTINUE_SHIFT_16) & DMS_0XFF;
    data[INDEX_3] = (accessTokenId >> CONTINUE_SHIFT_08) & DMS_0XFF;
    data[INDEX_4] = accessTokenId & DMS_0XFF;
    ret = SoftbusAdapter::GetInstance().SendSoftbusEvent(data, sendDataLen);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent setContinueState failed, sendDataLen: %{public}d, ret: %{public}d", sendDataLen, ret);
        return ret;
    }

    HILOGI("DealSetMissionContinueStateBusiness end. ContinueState set to: %{public}d", state);
    return ERR_OK;
}

void DistributedSchedContinueManager::NotifyDeid(const sptr<IRemoteObject>& obj)
{
    HILOGI("NotifyDeid start");
    if (obj == nullptr) {
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
    HILOGI("NotifyDeid end");
}
} // namespace DistributedSchedule
} // namespace OHOS
