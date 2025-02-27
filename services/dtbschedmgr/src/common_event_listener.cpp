/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "common_event_listener.h"

#include "datashare_manager.h"
#include "dtbschedmgr_log.h"
#include "mission/distributed_bm_storage.h"
#include "mission/notification/dms_continue_recv_manager.h"
#include "mission/notification/dms_continue_send_manager.h"
#include "multi_user_manager.h"
#include "os_account_manager.h"
#include "switch_status_dependency.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "CommonEventListener";
const uint8_t SCREEN_LOCKED = 0;
const uint8_t SCREEN_OFF = 1;
const uint8_t SCREEN_UNLOCKED = 2;
const uint8_t SCREEN_ON = 3;
const uint8_t USER_SWITCHED = 4;
const uint8_t PACKAGE_ADDED = 5;
const uint8_t PACKAGE_CHANGED = 6;
const uint8_t PACKAGE_REMOVED = 7;
const uint8_t USER_REMOVED = 8;
constexpr static int32_t INVALID_ID = 0;
std::map<std::string, uint8_t> receiveEvent = {
    {EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED, SCREEN_LOCKED},
    {EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF, SCREEN_OFF},
    {EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED, SCREEN_UNLOCKED},
    {EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON, SCREEN_ON},
    {EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED, USER_SWITCHED},
    {EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED, PACKAGE_ADDED},
    {EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED, PACKAGE_CHANGED},
    {EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED, PACKAGE_REMOVED},
    {EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED, USER_REMOVED},
};
}

void CommonEventListener::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    auto want = eventData.GetWant();
    std::string action = want.GetAction();
    int32_t accountId = GetForegroundOsAccountLocalId();
    HILOGI("OnReceiveEvent called, action = %{public}s", action.c_str());
    switch (receiveEvent[action]) {
        case SCREEN_LOCKED :
            HandleScreenLocked();
            break;
        case SCREEN_OFF :
            HandleScreenOff();
            break;
        case SCREEN_UNLOCKED :
            HandleScreenUnLocked();
            break;
        case SCREEN_ON :
            HandleScreenOn();
            break;
        case USER_SWITCHED :
            HandleUserSwitched(accountId);
            break;
        case PACKAGE_ADDED :
            HandlePackageAdded(want.GetElement().GetBundleName());
            break;
        case PACKAGE_CHANGED :
            HandlePackageChange(want.GetElement().GetBundleName());
            break;
        case PACKAGE_REMOVED :
            HandlePackageRemoved(want.GetElement().GetBundleName());
            break;
        case USER_REMOVED :
            HandleUserRemoved(accountId);
            break;
        default:
            HILOGW("OnReceiveEvent undefined action");
    }
}

void CommonEventListener::HandleScreenLocked()
{
    HILOGI("SCREEN_LOCKED");
    DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_SCREEN_LOCK, true);
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    if (sendMgr == nullptr) {
        HILOGE("SendMgr is nullptr.");
        return;
    }
    sendMgr->OnDeviceScreenLocked();
}

void CommonEventListener::HandleScreenOff()
{
    HILOGI("SCREEN_OFF");
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    if (recvMgr == nullptr) {
        HILOGE("RecvMgr is nullptr.");
    } else {
        recvMgr->OnDeviceScreenOff();
    }

#ifdef DMS_ICON_HOLD_ON
    DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_SCREEN_LOCK, true);
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    if (sendMgr == nullptr) {
        HILOGE("SendMgr is nullptr.");
    } else {
        sendMgr->OnDeviceScreenLocked();
    }
#endif
}

void CommonEventListener::HandleScreenUnLocked()
{
    HILOGI("SCREEN_UNLOCKED");
    DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_SCREEN_LOCK, false);
}

void CommonEventListener::HandleScreenOn()
{
    HILOGI("SCREEN_ON");
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    if (recvMgr == nullptr) {
        HILOGE("RecvMgr is nullptr.");
    } else {
        recvMgr->OnDeviceScreenOn();
    }
#ifdef DMS_ICON_HOLD_ON
    DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_SCREEN_LOCK, false);
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    if (sendMgr == nullptr) {
        HILOGE("SendMgr is nullptr.");
        return;
    }
    sendMgr->OnDeviceOnline();
#endif
}

void CommonEventListener::HandleUserSwitched(int32_t accountId)
{
    HILOGI("USER_SWITCHED");
    MultiUserManager::GetInstance().OnUserSwitched(accountId);
}

void CommonEventListener::HandlePackageAdded(const std::string& bundleName)
{
    HILOGI("PACKAGE_ADDED: %{public}s", bundleName.c_str());
    DmsBmStorage::GetInstance()->SaveStorageDistributeInfo(bundleName);
}

void CommonEventListener::HandlePackageChange(const std::string& bundleName)
{
    HILOGI("PACKAGE_CHANGED: %{public}s", bundleName.c_str());
    DmsBmStorage::GetInstance()->SaveStorageDistributeInfo(bundleName, true);
}

void CommonEventListener::HandlePackageRemoved(const std::string& bundleName)
{
    HILOGI("PACKAGE_REMOVED: %{public}s", bundleName.c_str());
    DmsBmStorage::GetInstance()->DeleteStorageDistributeInfo(bundleName);
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    if (recvMgr == nullptr) {
        HILOGE("RecvMgr is nullptr.");
        return;
    }
    recvMgr->NotifyPackageRemoved(bundleName);
}

void CommonEventListener::HandleUserRemoved(int32_t accountId)
{
    HILOGI("USER_REMOVED");
    MultiUserManager::GetInstance().OnUserRemoved(accountId);
}

int32_t CommonEventListener::GetForegroundOsAccountLocalId()
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
} // namespace DistributedSchedule
} // namespace OHOS
