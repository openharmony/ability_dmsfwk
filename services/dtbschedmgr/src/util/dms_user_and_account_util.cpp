/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "util/dms_user_and_account_util.h"
#include "dtbschedmgr_log.h"
#include "os_account_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsUserAndAccountUtil";
constexpr int32_t INVALID_USER_ID = 0;
}

ErrCode DmsUserAndAccountUtil::GetForegroundUserId(int32_t& userId)
{
    HILOGI("GetForegroundOsAccountUserId start");
    userId = INVALID_USER_ID;
    ErrCode ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != ERR_OK) {
        HILOGE("GetForegroundOsAccountLocalId failed, ret: %{public}d", ret);
        return ret;
    }
    HILOGI("GetForegroundOsAccountUserId end, userId: %{public}d", userId);
    return ERR_OK;
}

OHOS::ErrCode OHOS::DistributedSchedule::DmsUserAndAccountUtil::GetForegroundAccountInfo(
    AccountSA::OhosAccountInfo& accountInfo)
{
    HILOGI("GetForegroundAccountInfo start");
    int32_t userId = INVALID_USER_ID;
    ErrCode ret = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (ret != ERR_OK) {
        HILOGE("GetForegroundOsAccountLocalId failed, ret: %{public}d", ret);
        return ret;
    }
    ret = AccountSA::OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(userId, accountInfo);
    if (ret != ERR_OK) {
        HILOGE("GetOsAccountDistributedInfo failed, ret: %{public}d", ret);
        return ret;
    }
    HILOGI("GetForegroundAccountInfo end, userId: %{public}s", accountInfo.uid_.c_str());
    return ERR_OK;
}

ErrCode DmsUserAndAccountUtil::GetAccountInfoFromUserId(int32_t userId, OHOS::AccountSA::OhosAccountInfo& accountInfo)
{
    HILOGI("GetOsAccountInfoFromUserId start, userId: %{public}d", userId);
    ErrCode ret = AccountSA::OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(userId, accountInfo);
    if (ret != ERR_OK) {
        HILOGE("GetOsAccountDistributedInfo failed, ret: %{public}d", ret);
        return ret;
    }
    HILOGI("GetOsAccountInfoFromUserId end, userId: %{public}s", accountInfo.uid_.c_str());
    return ERR_OK;
}

ErrCode DmsUserAndAccountUtil::GetUserIdFromCallingUid(int32_t callingUid, int32_t& userId)
{
    HILOGI("GetOsAccountLocalIdFromUid start, callingUid: %{public}d", callingUid);
    ErrCode ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, userId);
    if (ret != ERR_OK) {
        HILOGE("GetOsAccountLocalIdFromUid failed, ret: %{public}d", ret);
        return ret;
    }
    HILOGI("GetOsAccountLocalIdFromUid end, userId: %{public}d", userId);
    return ERR_OK;
}

ErrCode DmsUserAndAccountUtil::GetAccountInfoFromCallingUid(int32_t callingUid,
    OHOS::AccountSA::OhosAccountInfo& accountInfo)
{
    HILOGI("GetOsAccountInfoFromCallingUid start, callingUid: %{public}d", callingUid);
    int32_t localId = INVALID_USER_ID;
    ErrCode ret = AccountSA::OsAccountManager::GetOsAccountLocalIdFromUid(callingUid, localId);
    if (ret != ERR_OK) {
        HILOGE("GetOsAccountLocalIdFromUid failed, ret: %{public}d", ret);
        return ret;
    }
    ret = AccountSA::OhosAccountKits::GetInstance().GetOsAccountDistributedInfo(localId, accountInfo);
    if (ret != ERR_OK) {
        HILOGE("GetOsAccountDistributedInfo failed, ret: %{public}d", ret);
        return ret;
    }
    HILOGI("GetOsAccountInfoFromCallingUid end, userId: %{public}s", accountInfo.uid_.c_str());
    return ERR_OK;
}
}
}
