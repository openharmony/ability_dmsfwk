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


#ifndef ABILITY_DMSFWK_DMS_USER_AND_ACCOUNT_UTIL_H
#define ABILITY_DMSFWK_DMS_USER_AND_ACCOUNT_UTIL_H

#include <string>
#include <cstdint>

#include "account_info.h"
#include "ohos_account_kits.h"

namespace OHOS {
namespace DistributedSchedule {
class DmsUserAndAccountUtil {
public:
    static ErrCode GetForegroundUserId(int32_t& userId);
    static ErrCode GetForegroundAccountInfo(OHOS::AccountSA::OhosAccountInfo& accountInfo);
    static ErrCode GetAccountInfoFromUserId(int32_t userId, OHOS::AccountSA::OhosAccountInfo& accountInfo);
    static ErrCode GetUserIdFromCallingUid(int32_t callingUid, int32_t& userId);
    static ErrCode GetAccountInfoFromCallingUid(int32_t callingUid, OHOS::AccountSA::OhosAccountInfo& accountInfo);

private:
    DmsUserAndAccountUtil() = default;
    ~DmsUserAndAccountUtil() = default;
};
}
}

#endif // ABILITY_DMSFWK_DMS_USER_AND_ACCOUNT_UTIL_H
