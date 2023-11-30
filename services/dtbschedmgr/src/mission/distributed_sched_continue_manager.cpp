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
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
#include "adapter/mmi_adapter.h"
#endif
#include "datetime_ex.h"
#include "distributed_sched_adapter.h"
#include "dtbschedmgr_device_info_storage.h"
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
constexpr int32_t CANCEL_FOCUSED_DELAYED = 60000;
const std::string TAG = "DistributedSchedContinueManager";
const std::string CANCEL_FOCUSED_TASK = "cancel_mission_focused_task";
const std::u16string DESCRIPTOR = u"ohos.aafwk.RemoteOnListener";
}

IMPLEMENT_SINGLE_INSTANCE(DistributedSchedContinueManager);

void DistributedSchedContinueManager::Init()
{
    HILOGI("Init start");
    {
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
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
        MMIAdapter::GetInstance().Init();
#endif
#ifdef SUPPORT_COMMON_EVENT_SERVICE
        EventFwk::MatchingSkills matchingSkills;
        matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
        EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
        auto applyMonitor = std::make_shared<CommonEventListener>(subscribeInfo);
        EventFwk::CommonEventManager::SubscribeCommonEvent(applyMonitor);
#endif
        eventThread_ = std::thread(&DistributedSchedContinueManager::StartEvent, this);
        std::unique_lock<std::mutex> lock(eventMutex_);
        eventCon_.wait(lock, [this] {
            return eventHandler_ != nullptr;
        });
    }

    int32_t missionId = GetCurrentMissionId();
    if (missionId <= 0) {
        HILOGW("GetCurrentMissionId failed, init end. ret: %{public}d", missionId);
        return;
    }
    NotifyMissionFocused(missionId);
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

int32_t DistributedSchedContinueManager::GetCurrentMissionId()
{
    HILOGI("GetCurrentMission begin");
    sptr<IRemoteObject> token;
    int ret = AAFwk::AbilityManagerClient::GetInstance()->GetTopAbility(token);
    if (ret != ERR_OK || token == nullptr) {
        HILOGE("GetTopAbility failed, ret: %{public}d", ret);
        return INVALID_MISSION_ID;
    }
    int32_t missionId = INVALID_MISSION_ID;
    AAFwk::AbilityManagerClient::GetInstance()->GetMissionIdByToken(token, missionId);
    return missionId;
}

void DistributedSchedContinueManager::AddCancelMissionFocusedTimer(const int32_t missionId, const int32_t delay)
{
    HILOGI("AddCancelMissionFocusedTimer start, missionId: %{public}d", missionId);
    auto cancelfunc = [this, missionId]() {
        DealTimerUnfocusedBussiness(missionId);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(cancelfunc, CANCEL_FOCUSED_TASK, delay);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("AddCancelMissionFocusedTimer end");
}

void DistributedSchedContinueManager::NotifyMissionFocused(const int32_t missionId)
{
    HILOGI("NotifyMissionFocused start, missionId: %{public}d", missionId);
    auto feedfunc = [this, missionId]() {
        DealFocusedBusiness(missionId);
        if (missionId == info_.currentMissionId && info_.currentIsContinuable) {
            AddCancelMissionFocusedTimer(missionId, CANCEL_FOCUSED_DELAYED);
        }
    };

    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
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
        DealUnfocusedBusiness(missionId, true);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
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
        DealOnBroadcastBusiness(senderNetworkId, accessTokenId, state);
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

int32_t DistributedSchedContinueManager::SendSoftbusEvent(uint32_t accessTokenId, uint8_t type)
{
    HILOGD("SendSoftbusEvent start, accessTokenId: %{public}d", accessTokenId);
    uint8_t data[DMS_SEND_LEN];
    uint8_t len = sizeof(uint32_t);
    data[0] = (type << CONTINUE_SHIFT_04) | len;
    data[1] = (accessTokenId >> CONTINUE_SHIFT_24) & DMS_0XFF;
    data[INDEX_2] = (accessTokenId >> CONTINUE_SHIFT_16) & DMS_0XFF;
    data[INDEX_3] = (accessTokenId >> CONTINUE_SHIFT_08) & DMS_0XFF;
    data[INDEX_4] = accessTokenId & DMS_0XFF;
    int32_t ret = SoftbusAdapter::GetInstance().SendSoftbusEvent(data, DMS_SEND_LEN);
    HILOGD("SendSoftbusEvent end. Result: %{public}d", ret);
    return ret;
}

#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
void DistributedSchedContinueManager::AddMMIListener()
{
    if (mmiMonitorId_ >= 0) {
        HILOGI("MMI listener already exist, monitor id: %{public}d", mmiMonitorId_);
        return;
    }
    mmiMonitorId_ = MMIAdapter::GetInstance().AddMMIListener();
    if (mmiMonitorId_ < 0) {
        HILOGW("Add MMI listener failed, ret: %{public}d", mmiMonitorId_);
        return;
    }
    HILOGI("MMI listener has been added, monitor id: %{public}d", mmiMonitorId_);
}

void DistributedSchedContinueManager::RemoveMMIListener()
{
    std::lock_guard<std::mutex> mmiEventLock(mmiMutex_);
    if (mmiMonitorId_ < 0) {
        HILOGI("No MMI listener to be removed, monitor id: %{public}d", mmiMonitorId_);
        return;
    }
    MMIAdapter::GetInstance().RemoveMMIListener(mmiMonitorId_);
    HILOGI("MMI listener has been removed, monitor id: %{public}d", mmiMonitorId_);

    mmiMonitorId_ = INVALID_MISSION_ID;
    needMMIBroadcast_ = false;
    return;
}
#endif

int32_t DistributedSchedContinueManager::DealFocusedBusiness(const int32_t missionId)
{
    HILOGI("DealFocusedBusiness start, missionId: %{public}d", missionId);
    AAFwk::MissionInfo info;
    int32_t ret = AAFwk::AbilityManagerClient::GetInstance()->GetMissionInfo("", missionId, info);
    if (ret != ERR_OK) {
        HILOGE("get missionInfo failed, missionId: %{public}d, ret: %{public}d", missionId, ret);
        return ret;
    }
    bool isMissionContinuable = info.continuable;
    {
        std::lock_guard<std::mutex> currentMissionIdLock(eventMutex_);
        info_.currentMissionId = missionId;
        info_.currentIsContinuable = isMissionContinuable;
    }
    if (!isMissionContinuable) {
        HILOGE("Mission is not continuable, task abort, missionId: %{public}d", missionId);
        return REMOTE_DEVICE_BIND_ABILITY_ERR;
    }
    std::string bundleName = info.want.GetBundle();
    focusedMission_[bundleName] = missionId;

    if (info.continueState != AAFwk::ContinueState::CONTINUESTATE_ACTIVE) {
        HILOGE("Mission continue state set to INACTIVE. Broadcast task abort.");
        return INVALID_PARAMETERS_ERR;
    }
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
    AddMMIListener();
#endif
    uint32_t accessTokenId;
    ret = BundleManagerInternal::GetBundleIdFromBms(bundleName, accessTokenId);
    if (ret != ERR_OK) {
        HILOGE("Get focused accessTokenId failed, accessTokenId: %{public}d, ret: %{public}d", accessTokenId, ret);
        return ret;
    }
    HILOGI("Get focused accessTokenId success, accessTokenId: %{public}d", accessTokenId);

    uint8_t type = DMS_FOCUSED_TYPE;
    ret = SendSoftbusEvent(accessTokenId, type);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent focused failed, ret: %{public}d", ret);
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

void DistributedSchedContinueManager::DealTimerUnfocusedBussiness(const int32_t missionId)
{
    HILOGI("DealTimerUnfocusedBussiness start, missionId: %{public}d", missionId);
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
    int64_t interval = GetTickCount() - lastMMIEvent_;
    if (interval < CANCEL_FOCUSED_DELAYED) {
        HILOGD("Last MMI event happened in interval, keep mission focused.");
        auto refocusedTask = [this, missionId, interval]() {
            if (missionId == info_.currentMissionId && info_.currentIsContinuable) {
                AddCancelMissionFocusedTimer(missionId, CANCEL_FOCUSED_DELAYED - static_cast<int32_t>(interval));
            }
            DealFocusedBusiness(missionId);
        };
        if (eventHandler_ != nullptr) {
            eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
            eventHandler_->PostTask(refocusedTask);
        } else {
            HILOGE("eventHandler_ is nullptr");
        }
        return;
    }
    {
        HILOGD("Last MMI event happened out of interval, set mission unfocused.");
        std::lock_guard<std::mutex> mmiEventLock(mmiMutex_);
        needMMIBroadcast_ = true;
        auto unfocusedTask = [this, missionId]() {
            DealUnfocusedBusiness(missionId, false);
        };
        if (eventHandler_ != nullptr) {
            eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
            eventHandler_->PostTask(unfocusedTask);
        } else {
            HILOGE("eventHandler_ is nullptr");
        }
        return;
    }
#else
    auto unfocusedTask = [this, missionId]() {
        DealUnfocusedBusiness(missionId, false);
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
        eventHandler_->PostTask(unfocusedTask);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    return;
#endif
}

int32_t DistributedSchedContinueManager::DealUnfocusedBusiness(const int32_t missionId, bool isUnfocused)
{
    HILOGI("DealUnfocusedBusiness start, missionId: %{public}d", missionId);
    std::string bundleName;
    int32_t ret = GetBundleName(missionId, bundleName);
    if (ret != ERR_OK) {
        HILOGE("Get bundleName failed, mission is not continuable, missionId: %{public}d, ret: %{public}d",
            missionId, ret);
        return ret;
    }
    HILOGI("Get bundleName success, mission is continuable, missionId: %{public}d, bundleName: %{public}s",
        missionId, bundleName.c_str());

    if (isUnfocused) {
        bool isContinue = IsContinue(missionId, bundleName);
        if (!isContinue) {
            HILOGE("Not current mission to be continued, missionId: %{public}d", missionId);
            return NO_MISSION_INFO_FOR_MISSION_ID;
        }
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
        RemoveMMIListener();
#endif
    }

    ret = CheckContinueState(missionId);
    if (ret != ERR_OK) {
        HILOGE("Continue state is inactive or can't be obtained, mission id : %{public}d, ret: %{public}d",
            missionId, ret);
        return ret;
    }

    uint32_t accessTokenId;
    ret = BundleManagerInternal::GetBundleIdFromBms(bundleName, accessTokenId);
    if (ret != ERR_OK) {
        HILOGE("Get unfocused accessTokenId failed, accessTokenId: %{public}d, ret: %{public}d", accessTokenId, ret);
        return ret;
    }

    uint8_t type = DMS_UNFOCUSED_TYPE;
    ret = SendSoftbusEvent(accessTokenId, type);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent unfocused failed, ret: %{public}d", ret);
    }

    if (isUnfocused) {
        std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
        focusedMission_.erase(bundleName);
    }
    HILOGI("DealUnfocusedBusiness end");
    return ERR_OK;
}

int32_t DistributedSchedContinueManager::VerifyBroadcastSource(const std::string& senderNetworkId,
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

int32_t DistributedSchedContinueManager::DealOnBroadcastBusiness(const std::string& senderNetworkId,
    uint32_t accessTokenId, const int32_t state)
{
    HILOGI("DealOnBroadcastBusiness start, senderNetworkId: %{public}s, accessTokenId: %{public}d, state: %{public}d",
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
    ret = VerifyBroadcastSource(senderNetworkId, bundleName, state);
    if (ret != ERR_OK) {
        return ret;
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
    HILOGI("DealOnBroadcastBusiness end");
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
    if (missionId != info_.currentMissionId && info_.currentIsContinuable) {
        /*missionId and currentMissionId are not equal but currentMission can change,
            continue to not send unfocus broadcast*/
        std::lock_guard<std::mutex> focusedMissionMapLock(eventMutex_);
        focusedMission_.erase(bundleName);
        HILOGI("mission is not continue, missionId: %{public}d, currentMissionId: %{public}d",
            missionId, info_.currentMissionId);
        return false;
    }
    /*missionId and currentMissionId are equal, or missionId and currentMissionId are not equal
        and currentIsContinuable not change, continue to send unfocus broadcast*/
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
        if (state == AAFwk::ContinueState::CONTINUESTATE_ACTIVE && missionId == info_.currentMissionId &&
            info_.currentIsContinuable) {
            AddCancelMissionFocusedTimer(missionId, CANCEL_FOCUSED_DELAYED);
        }
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->RemoveTask(CANCEL_FOCUSED_TASK);
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

    if (!info_.currentIsContinuable) {
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

    uint8_t type = DMS_FOCUSED_TYPE;
    if (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE) {
        type = DMS_UNFOCUSED_TYPE;
    }
#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
    if (state == AAFwk::ContinueState::CONTINUESTATE_INACTIVE) {
        RemoveMMIListener();
    } else {
        AddMMIListener();
    }
#endif

    ret = SendSoftbusEvent(accessTokenId, type);
    if (ret != ERR_OK) {
        HILOGE("SendSoftbusEvent setContinueState failed, ret: %{public}d", ret);
        return ret;
    }

    HILOGI("DealSetMissionContinueStateBusiness end. ContinueState set to: %{public}d", state);
    return ERR_OK;
}

void DistributedSchedContinueManager::NotifyDeid(const sptr<IRemoteObject>& obj)
{
    HILOGI("NotifyDeid start");
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
    HILOGI("NotifyDeid end");
}

#ifdef SUPPORT_COMMON_EVENT_SERVICE
void DistributedSchedContinueManager::NotifyScreenLockorOff()
{
    HILOGI("NotifyScreenLockorOff begin");
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
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(func);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("NotifyScreenLockorOff end");
}
#endif

void DistributedSchedContinueManager::NotifyDeviceOffline(const std::string& networkId)
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

#ifdef SUPPORT_MULTIMODALINPUT_SERVICE
void DistributedSchedContinueManager::OnMMIEvent()
{
    std::lock_guard<std::mutex> mmiEventLock(mmiMutex_);
    lastMMIEvent_ = GetTickCount();

    if (!needMMIBroadcast_) {
        return;
    }
    HILOGD("Need to resend focus broadcast, missionId = %{public}d", info_.currentMissionId);
    DistributedSchedContinueManager::GetInstance().NotifyMissionFocused(info_.currentMissionId);
    needMMIBroadcast_ = false;
}
#endif
} // namespace DistributedSchedule
} // namespace OHOS
