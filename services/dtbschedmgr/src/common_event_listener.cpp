/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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
#include "mission/dms_continue_recv_manager.h"
#include "mission/dms_continue_send_manager.h"
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
};
}
void CommonEventListener::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    auto want = eventData.GetWant();
    std::string action = want.GetAction();
    HILOGI("OnReceiveEvent called, action = %{public}s", action.c_str());
    switch (receiveEvent[action]) {
        case SCREEN_LOCKED :
            HILOGI("SCREEN_LOCKED");
            DMSContinueSendMgr::GetInstance().OnDeviceScreenOff();
            break;
        case SCREEN_OFF :
            HILOGI("SCREEN_OFF");
            DMSContinueRecvMgr::GetInstance().OnDeviceScreenOff();
            break;
        case SCREEN_UNLOCKED :
            HILOGI("SCREEN_UNLOCKED");
            DMSContinueSendMgr::GetInstance().OnDeviceScreenOn();
            break;
        case SCREEN_ON :
            HILOGI("SCREEN_ON");
            break;
        case USER_SWITCHED :
            HILOGI("USER_SWITCHED");
            OnUserSwitched();
            break;
        case PACKAGE_ADDED :
            HILOGI("PACKAGE_ADDED: %{public}s", want.GetElement().GetBundleName().c_str());
            DmsBmStorage::GetInstance()->SaveStorageDistributeInfo(want.GetElement().GetBundleName());
            break;
        case PACKAGE_CHANGED :
            HILOGI("PACKAGE_CHANGED: %{public}s", want.GetElement().GetBundleName().c_str());
            DmsBmStorage::GetInstance()->SaveStorageDistributeInfo(want.GetElement().GetBundleName(), true);
            break;
        case PACKAGE_REMOVED :
            HILOGI("PACKAGE_REMOVED: %{public}s", want.GetElement().GetBundleName().c_str());
            DmsBmStorage::GetInstance()->DeleteStorageDistributeInfo(want.GetElement().GetBundleName());
            DMSContinueRecvMgr::GetInstance().NotifyPackageRemove(want.GetElement().GetBundleName());
            break;
        default:
            HILOGW("OnReceiveEvent undefined action");
    }
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

AccountSA::OsAccountType CommonEventListener::GetOsAccountType(int32_t& accountId)
{
    AccountSA::OsAccountType type;
    ErrCode err = AccountSA::OsAccountManager::GetOsAccountType(accountId, type);
    if (err != ERR_OK) {
        HILOGE("GetOsAccountType passing param invalid or return error!, err : %{public}d", err);
    }
    return type;
}

void CommonEventListener::OnUserSwitched()
{
    int32_t accountId = GetForegroundOsAccountLocalId();
    AccountSA::OsAccountType type = GetOsAccountType(accountId);
    HILOGI("OnUserSwitched called, accountId = %{public}d, type = %{public}d", accountId, type);
    if (type == AccountSA::OsAccountType::PRIVATE) {
        HILOGI("GetOsAccountType : OsAccountType is PRIVATE, type : %{public}d", type);
        DataShareManager::GetInstance().UpdateSwitchStatus(SwitchStatusDependency::GetInstance()
            .CONTINUE_SWITCH_STATUS_KEY, SwitchStatusDependency::GetInstance().CONTINUE_SWITCH_OFF);
    }

    DataShareManager::GetInstance().SetCurrentContinueSwitch(SwitchStatusDependency::GetInstance()
        .IsContinueSwitchOn());
    if (!DataShareManager::GetInstance().IsCurrentContinueSwitchOn()) {
        DMSContinueRecvMgr::GetInstance().OnContinueSwitchOff();
        HILOGI("ICurrentContinueSwitch is off, %{public}d", DataShareManager::GetInstance()
            .IsCurrentContinueSwitchOn());
    };
}
} // namespace DistributedSchedule
} // namespace OHOS