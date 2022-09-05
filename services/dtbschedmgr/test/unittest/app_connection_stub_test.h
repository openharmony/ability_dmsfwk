/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef APP_CONNECTION_STUB_TEST_H
#define APP_CONNECTION_STUB_TEST_H

#include "gtest/gtest.h"

#define private public
#include "app_connection_stub.h"
#undef private

namespace OHOS {
namespace DistributedSchedule {
class AppConnectionStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    sptr<AppConnectionStub> appConnectionStub_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // APP_CONNECTION_STUB_TEST_H