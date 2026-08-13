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

#ifndef DMS_USER_AND_ACCOUNT_UTIL_TEST_H
#define DMS_USER_AND_ACCOUNT_UTIL_TEST_H

#include "gtest/gtest.h"
#include "mock/ohos_account_kits_mock.h"
#include "mock/os_account_manager_mock.h"

namespace OHOS {
namespace DistributedSchedule {
class DmsUserAndAccountUtilTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    static std::shared_ptr<AccountSA::OhosAccountKitsMock> ohosAccountMock_;
    static std::shared_ptr<AccountSA::OsAccountManagerMock> osAccountMock_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DMS_USER_AND_ACCOUNT_UTIL_TEST_H