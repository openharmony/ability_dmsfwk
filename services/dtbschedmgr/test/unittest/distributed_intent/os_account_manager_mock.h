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

#ifndef OS_ACCOUNT_MANAGER_MOCK_H
#define OS_ACCOUNT_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include <vector>
#include "errors.h"

namespace OHOS {
namespace AccountSA {

class IOsAccountManager {
public:
    virtual ~IOsAccountManager() = default;
    virtual ErrCode QueryActiveOsAccountIds(std::vector<int32_t>& ids) = 0;
public:
    static inline std::shared_ptr<IOsAccountManager> osAccountMock = nullptr;
};

class OsAccountManagerMock : public IOsAccountManager {
public:
    MOCK_METHOD1(QueryActiveOsAccountIds, ErrCode(std::vector<int32_t>& ids));
};

} // namespace AccountSA
} // namespace OHOS
#endif // OS_ACCOUNT_MANAGER_MOCK_H