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

#ifndef OHOS_MULTI_USER_MANAGER_H
#define OHOS_MULTI_USER_MANAGER_H

#include <map>

#include "mission/dms_continue_recv_manager.h"
#include "mission/dms_continue_send_manager.h"
#include "switch_status_dependency.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
class MultiUserManager {
public:
    static MultiUserManager& GetInstance();
private:
    MultiUserManager(const MultiUserManager&) = delete;
    MultiUserManager& operator= (const MultiUserManager&) = delete;
    MultiUserManager(MultiUserManager&&) = delete;
    MultiUserManager& operator= (MultiUserManager&&) = delete;
    MultiUserManager();
    ~MultiUserManager() = default;

public:
    void Init();
    void UnInit();
    void OnUserSwitched(int32_t userId);
    void OnUserRemoved(int32_t userId);
    AccountSA::OsAccountType GetOsAccountType(int32_t &accountId);
    int32_t CreateNewSendMgrLocked();
    int32_t CreateNewRecvMgrLocked();
    int32_t CreateNewSendMgrLocked(int32_t accountId);
    int32_t CreateNewRecvMgrLocked(int32_t accountId);
    std::shared_ptr<DMSContinueSendMgr> GetCurrentSendMgr();
    std::shared_ptr<DMSContinueRecvMgr> GetCurrentRecvMgr();
    std::shared_ptr<DMSContinueSendMgr> GetSendMgrByCallingUid(int32_t callingUid);
    std::shared_ptr<DMSContinueRecvMgr> GetRecvMgrByCallingUid(int32_t callingUid);
    int32_t OnRegisterOnListener(const std::string& type, const sptr<IRemoteObject>& obj, int32_t callingUid);
    int32_t OnRegisterOffListener(const std::string& type, const sptr<IRemoteObject>& obj, int32_t callingUid);
    int32_t GetForegroundUser();
    bool IsUserForeground(int32_t userId);
    bool IsCallerForeground(int32_t callingUid);
    bool CheckRegSoftbusListener();
    void RegisterSoftbusListener();

private:
    void UserSwitchedOnRegisterListenerCache();

private:
    int32_t currentUserId_;
    std::map<int32_t, std::shared_ptr<DMSContinueSendMgr>> sendMgrMap_;
    std::map<int32_t, std::shared_ptr<DMSContinueRecvMgr>> recvMgrMap_;
    std::map<int32_t, std::map<std::string, sptr<IRemoteObject>>> listenerCache_;
    std::mutex sendMutex_;
    std::mutex recvMutex_;
    std::mutex listenerMutex_;
    bool hasRegSoftbusEventListener_ = false;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_MULTI_USER_MANAGER_H
