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

#ifndef DSCHED_CONTINUE_SUP_TEST_H
#define DSCHED_CONTINUE_SUP_TEST_H

#include "gtest/gtest.h"

#include "dsched_continue.h"
#include "mock_dtbschedmgr_device_info.h"
#include "mock/ability_manager_client_mock.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace AAFwk;

class DSchedContinueTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static inline std::shared_ptr<AbilityManagerClientMock> clientMock_ = nullptr;
    static inline std::shared_ptr<MockDmsMgrDeviceInfoStore> dmsStoreMock = nullptr;
    static inline std::shared_ptr<DSchedContinue> conti_ = nullptr;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DSCHED_CONTINUE_TEST_H
