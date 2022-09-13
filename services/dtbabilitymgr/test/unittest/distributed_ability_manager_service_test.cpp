/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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
#include "distributed_ability_manager_service_test.h"

#define private public
#include "distributed_ability_manager_service.h"
#undef private
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    constexpr int32_t DISTRIBUTED_SCHED_SA_ID = 1401;
}

void DistributedAbilityManagerServiceTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest::SetUpTestCase" << std::endl;
}

void DistributedAbilityManagerServiceTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest::TearDownTestCase" << std::endl;
}

void DistributedAbilityManagerServiceTest::SetUp()
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest::SetUp" << std::endl;
}

void DistributedAbilityManagerServiceTest::TearDown()
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest::TearDown" << std::endl;
}

/**
 * @tc.name: IsDistributedSchedLoaded_001
 * @tc.desc: test IsDistributedSchedLoaded
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, IsDistributedSchedLoaded_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest IsDistributedSchedLoaded_001 start" << std::endl;
    DistributedAbilityManagerService  *dtbabilitymgrService =
        new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    int32_t result = dtbabilitymgrService->IsDistributedSchedLoaded();
    EXPECT_EQ(false, result);
    delete dtbabilitymgrService;
    DTEST_LOG << "DistributedAbilityManagerServiceTest IsDistributedSchedLoaded_001 end" << std::endl;
}
}
}