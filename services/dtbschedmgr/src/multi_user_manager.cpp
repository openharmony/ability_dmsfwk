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
#include "multi_user_manager.h"

#include "adapter/mmi_adapter.h"
#include "datashare_manager.h"
#include "distributed_sched_service.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_log.h"
#include "mission/distributed_sched_mission_manager.h"
#include "softbus_adapter/softbus_adapter.h"
#include "os_account_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
    constexpr static uint8_t DMS_UNFOCUSED_TYPE = 0x01;
    constexpr static int32_t INVALID_ID = 0;
    const std::string TAG = "MultiUserManager";
}

MultiUserManager& MultiUserManager::GetInstance()
{
    static auto instance = new MultiUserManager();
    return *instance;
}

MultiUserManager::MultiUserManager()
{
    HILOGI("Start.");
    if (currentUserId_ <= 0) {
        Init();
    }
}

void MultiUserManager::Init()
{
    HILOGI("Init start.");
    currentUserId_ = GetForegroundUser();
    MMIAdapter::GetInstance().Init();
    SoftbusAdapter::GetInstance().Init();
    auto sendMgr = GetCurrentSendMgr();
    if (sendMgr == nullptr) {
        HILOGI("GetSendMgr failed.");
        return;
    }
    auto recvMgr = GetCurrentRecvMgr();
    if (recvMgr == nullptr) {
        HILOGI("GetRecvMgr failed.");
        return;
    }
    if (!CheckRegSoftbusListener()) {
        RegisterSoftbusListener();
    }
    HILOGI("Init end.");
}

void MultiUserManager::UnInit()
{
    HILOGI("UnInit start");
    MMIAdapter::GetInstance().UnInit();
    SoftbusAdapter::GetInstance().UnInit();

    {
        std::lock_guard<std::mutex> lock(sendMutex_);
        if (!sendMgrMap_.empty()) {
            auto it = sendMgrMap_.begin();
            while (it != sendMgrMap_.end()) {
                if (it->second == nullptr) {
                    sendMgrMap_.erase(it++);
                    continue;
                }
                it->second->UnInit();
                sendMgrMap_.erase(it++);
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(recvMutex_);
        if (!recvMgrMap_.empty()) {
            auto it = recvMgrMap_.begin();
            while (it != recvMgrMap_.end()) {
                if (it->second == nullptr) {
                    recvMgrMap_.erase(it++);
                    continue;
                }
                it->second->UnInit();
                recvMgrMap_.erase(it++);
            }
        }
    }
    HILOGI("UnInit end");
}

void MultiUserManager::OnUserSwitched(int32_t accountId)
{
    HILOGI("UserSwitched start");
    auto recvMgr = GetCurrentRecvMgr();
    if (recvMgr == nullptr) {
        HILOGI("GetRecvMgr failed.");
        return;
    }
    recvMgr->OnUserSwitch();
    auto sendMgr = GetCurrentSendMgr();
    if (sendMgr == nullptr) {
        HILOGI("GetSendMgr failed.");
        return;
    }
    sendMgr->SendScreenOffEvent(DMS_UNFOCUSED_TYPE);
    sendMgr->UserSwitchedRemoveMMIListener();
    currentUserId_ = accountId;

    AccountSA::OsAccountType type = GetOsAccountType(currentUserId_);
    HILOGI("OnUserSwitched called, currentUserId = %{public}d, type = %{public}d", currentUserId_, type);
    if (type == AccountSA::OsAccountType::PRIVATE) {
        HILOGI("GetOsAccountType : OsAccountType is PRIVATE, type : %{public}d", type);
        DataShareManager::GetInstance().UpdateSwitchStatus(SwitchStatusDependency::GetInstance()
            .CONTINUE_SWITCH_STATUS_KEY, SwitchStatusDependency::GetInstance().CONTINUE_SWITCH_OFF);
    }

    DataShareManager::GetInstance().SetCurrentContinueSwitch(SwitchStatusDependency::GetInstance()
        .IsContinueSwitchOn());
    sendMgr = GetCurrentSendMgr();
    if (sendMgr == nullptr) {
        HILOGI("GetSendMgr failed.");
        return;
    }
    sendMgr->NotifyDeviceOnline();
    recvMgr = GetCurrentRecvMgr();
    if (recvMgr == nullptr) {
        HILOGI("GetRecvMgr failed.");
        return;
    }
    if (!DataShareManager::GetInstance().IsCurrentContinueSwitchOn()) {
        recvMgr->OnContinueSwitchOff();
        HILOGI("ICurrentContinueSwitch is off, %{public}d", DataShareManager::GetInstance()
            .IsCurrentContinueSwitchOn());
    };
    UserSwitchedOnRegisterListenerCache();
    HILOGI("UserSwitched end");
}

void MultiUserManager::UserSwitchedOnRegisterListenerCache()
{
    HILOGI("UserSwitchedOnRegisterListenerCache start");
    {
        std::lock_guard<std::mutex> lock(listenerMutex_);
        if (!listenerCache_.empty()) {
            HILOGI("Cache invoke register listener. userId: %{public}d.", currentUserId_);
            auto recvMgr = GetCurrentRecvMgr();
            if (recvMgr == nullptr) {
                HILOGI("GetRecvMgr failed.");
                return;
            }
            auto it = listenerCache_.find(currentUserId_);
            if (it != listenerCache_.end() && !it->second.empty()) {
                for (auto param = it->second.begin(); param != it->second.end(); param ++) {
                    std::string type = param->first;
                    sptr<IRemoteObject> obj = param->second;
                    recvMgr->RegisterOnListener(type, obj);
                }
                listenerCache_.erase(it);
                HILOGI("Cache remove. userId: %{public}d.", currentUserId_);
            }
        }
    }
    HILOGI("UserSwitchedOnRegisterListenerCache end");
}

void MultiUserManager::OnUserRemoved(int32_t accountId)
{
    HILOGI("UserRemoved start");
    {
        std::lock_guard<std::mutex> lock(sendMutex_);
        if (!sendMgrMap_.empty()) {
            auto it = sendMgrMap_.find(accountId);
            if (it != sendMgrMap_.end()) {
                if (it->second != nullptr) {
                    it->second->UnInit();
                }
                sendMgrMap_.erase(it);
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(recvMutex_);
        if (!recvMgrMap_.empty()) {
            auto it = recvMgrMap_.find(accountId);
            if (it != recvMgrMap_.end()) {
                if (it->second != nullptr) {
                    it->second->UnInit();
                }
                recvMgrMap_.erase(it);
            }
        }
    }
    HILOGI("UserRemoved end");
}

AccountSA::OsAccountType MultiUserManager::GetOsAccountType(int32_t &accountId)
{
    AccountSA::OsAccountType type;
    ErrCode err = AccountSA::OsAccountManager::GetOsAccountType(accountId, type);
    if (err != ERR_OK) {
        HILOGE("GetOsAccountType passing param invalid or return error!, err : %{public}d", err);
    }
    return type;
}

int32_t MultiUserManager::CreateNewSendMgrLocked()
{
    HILOGI("CreateNewSendMgr begin. accountId: %{public}d.", currentUserId_);
    auto sendMgr = std::make_shared<DMSContinueSendMgr>();
    sendMgr->Init();
    sendMgrMap_.emplace(currentUserId_, sendMgr);
    HILOGI("CreateNewSendMgr end.");
    return ERR_OK;
}

int32_t MultiUserManager::CreateNewRecvMgrLocked()
{
    HILOGI("CreateNewRecvMgr begin. accountId: %{public}d.", currentUserId_);
    auto recvMgr = std::make_shared<DMSContinueRecvMgr>();
    recvMgr->Init();
    recvMgrMap_.emplace(currentUserId_, recvMgr);
    HILOGI("CreateNewRecvMgr end.");
    return ERR_OK;
}

std::shared_ptr<DMSContinueSendMgr> MultiUserManager::GetCurrentSendMgr()
{
    HILOGI("GetCurrentSendMgr. accountId: %{public}d.", currentUserId_);
    std::lock_guard<std::mutex> lock(sendMutex_);
    if (sendMgrMap_.empty() || sendMgrMap_.find(currentUserId_) == sendMgrMap_.end()) {
        HILOGI("sendMgr need to create.");
        CreateNewSendMgrLocked();
    }
    auto cur = sendMgrMap_.find(currentUserId_);
    return cur->second;
}

std::shared_ptr<DMSContinueRecvMgr> MultiUserManager::GetCurrentRecvMgr()
{
    HILOGI("GetCurrentRecvMgr. accountId: %{public}d.", currentUserId_);
    std::lock_guard<std::mutex> lock(recvMutex_);
    if (recvMgrMap_.empty() || recvMgrMap_.find(currentUserId_) == recvMgrMap_.end()) {
        HILOGI("recvMgr need to create.");
        CreateNewRecvMgrLocked();
    }
    auto cur = recvMgrMap_.find(currentUserId_);
    return cur->second;
}

std::shared_ptr<DMSContinueSendMgr> MultiUserManager::GetSendMgrByCallingUid(int32_t callingUid)
{
    int32_t accountId = -1;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, accountId);
    HILOGI("GetSendMgrByCallingUid. accountId: %{public}d , callingUid: %{public}d.", accountId, callingUid);
    std::lock_guard<std::mutex> lock(sendMutex_);
    if (sendMgrMap_.empty() || sendMgrMap_.find(accountId) == sendMgrMap_.end()) {
        HILOGI("sendMgr need to create.");
        CreateNewSendMgrLocked();
    }
    auto cur = sendMgrMap_.find(accountId);
    return cur->second;
}

std::shared_ptr<DMSContinueRecvMgr> MultiUserManager::GetRecvMgrByCallingUid(int32_t callingUid)
{
    int32_t accountId = -1;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, accountId);
    HILOGI("GetRecvMgrByCallingUid. userId: %{public}d , callingUid: %{public}d.", accountId, callingUid);
    std::lock_guard<std::mutex> lock(recvMutex_);
    if (recvMgrMap_.empty() || recvMgrMap_.find(accountId) == recvMgrMap_.end()) {
        HILOGI("recvMgr need to create.");
        CreateNewRecvMgrLocked();
    }
    auto cur = recvMgrMap_.find(accountId);
    return cur->second;
}

int32_t MultiUserManager::OnRegisterOnListener(const std::string& type,
    const sptr<IRemoteObject>& obj, int32_t callingUid)
{
    int32_t accountId = -1;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, accountId);
    HILOGI("OnRegisterOnListener. accountId: %{public}d , callingUid: %{public}d.", accountId, callingUid);
    {
        std::lock_guard<std::mutex> lock(listenerMutex_);
        if (!IsUserForeground(accountId) || accountId != currentUserId_) {
            HILOGW("The current user is not foreground. accountId: %{public}d , currentUserId_: %{public}d.",
                accountId, currentUserId_);
            std::map<std::string, sptr<IRemoteObject>> param;
            param.emplace(type, obj);
            listenerCache_.emplace(accountId, param);
            return ERR_OK;
        }
    }
    auto recvMgr = GetCurrentRecvMgr();
    if (recvMgr == nullptr) {
        HILOGI("GetRecvMgr failed.");
        return DMS_NOT_GET_MANAGER;
    }
    return recvMgr->RegisterOnListener(type, obj);
}

int32_t MultiUserManager::OnRegisterOffListener(const std::string& type,
    const sptr<IRemoteObject>& obj, int32_t callingUid)
{
    int32_t accountId = -1;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, accountId);
    HILOGI("OnRegisterOffListener. accountId: %{public}d , callingUid: %{public}d.", accountId, callingUid);
    if (!IsUserForeground(accountId) || accountId != currentUserId_) {
        HILOGW("The current user is not foreground. accountId: %{public}d , currentUserId_: %{public}d.",
            accountId, currentUserId_);
        return DMS_NOT_FOREGROUND_USER;
    }
    auto recvMgr = GetCurrentRecvMgr();
    if (recvMgr == nullptr) {
        HILOGI("GetRecvMgr failed.");
        return DMS_NOT_GET_MANAGER;
    }
    return recvMgr->RegisterOffListener(type, obj);
}

int32_t MultiUserManager::GetForegroundUser()
{
    int32_t accountId = INVALID_ID;
    ErrCode err = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(accountId);
    if (err != ERR_OK || accountId == INVALID_ID) {
        HILOGE("GetForegroundOsAccountLocalId passing param invalid or return error!, err : %{public}d", err);
        return INVALID_PARAMETERS_ERR;
    }
    HILOGD("GetForegroundOsAccountLocalId accountId is: %{public}d", accountId);
    return accountId;
}

bool MultiUserManager::IsUserForeground(int32_t accountId)
{
    bool isForeground = false;
    std::vector<AccountSA::ForegroundOsAccount> accounts;
    ErrCode err = OHOS::AccountSA::OsAccountManager::GetForegroundOsAccounts(accounts);
    if (err != ERR_OK) {
        HILOGE("GetForegroundOsAccounts passing param inval id or return error!, err : %{public}d", err);
    }
    if (!accounts.empty() && accounts[0].localId == accountId) {
        isForeground = true;
    }
    HILOGD("Current account. accounts[0].localId: %{public}d, accountId: %{public}d.", accounts[0].localId, accountId);
    return isForeground;
}

bool MultiUserManager::IsCallerForeground(int32_t callingUid)
{
    int32_t accountId = -1;
    OHOS::AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, accountId);
    return IsUserForeground(accountId);
}

void MultiUserManager::RegisterSoftbusListener()
{
    HILOGI("Register softbusListener start. accountId: %{public}d.", currentUserId_);
    std::shared_ptr<SoftbusAdapterListener> missionBroadcastListener =
        std::make_shared<DistributedMissionBroadcastListener>();
    int32_t ret = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(missionBroadcastListener);
    if (ret != ERR_OK) {
        HILOGE("get RegisterSoftbusEventListener failed, ret: %{public}d", ret);
    }
    hasRegSoftbusEventListener_ = true;
    HILOGI("Register softbusListener end.");
}

bool MultiUserManager::CheckRegSoftbusListener()
{
    return hasRegSoftbusEventListener_;
}
}  // namespace DistributedSchedule
}  // namespace OHOS
