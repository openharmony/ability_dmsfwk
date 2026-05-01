/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "os_account_manager_mock.h"
#include "os_account_manager.h"

namespace OHOS {
namespace AccountSA {

const int ERR_FAIL = -1;

ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids)
{
    if (IOsAccountManager::osAccountMock == nullptr) {
        return ERR_FAIL;
    }
    return IOsAccountManager::osAccountMock->QueryActiveOsAccountIds(ids);
}

} // namespace AccountSA
} // namespace OHOS
