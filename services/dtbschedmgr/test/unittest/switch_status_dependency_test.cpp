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

#include "switch_status_dependency_test.h"

#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string CONTINUE_SWITCH_STATUS_KEY = "Continue_Switch_Status";
    const std::string CONTINUE_SWITCH_OFF = "0";
    const std::string CONTINUE_SWITCH_ON = "1";
}

void SwitchStatusDependencyTest::SetUpTestCase()
{
    DTEST_LOG << "SwitchStatusDependencyTest::SetUpTestCase" << std::endl;
}

void SwitchStatusDependencyTest::TearDownTestCase()
{
    DTEST_LOG << "SwitchStatusDependencyTest::TearDownTestCase" << std::endl;
}

void SwitchStatusDependencyTest::TearDown()
{
    DTEST_LOG << "SwitchStatusDependencyTest::TearDown" << std::endl;
}

void SwitchStatusDependencyTest::SetUp()
{
    DTEST_LOG << "SwitchStatusDependencyTest::SetUp" << std::endl;
}

/**
 * @tc.name: IsContinueSwitchOn_001
 * @tc.desc: IsContinueSwitchOn
 * @tc.type: FUNC
 * @tc.require: SR20240116513791
 */
HWTEST_F(SwitchStatusDependencyTest, IsContinueSwitchOn_001, TestSize.Level3)
{
    DTEST_LOG << "SwitchStatusDependencyTest IsContinueSwitchOn_001 begin" << std::endl;
    EXPECT_TRUE(SwitchStatusDependency::GetInstance().IsContinueSwitchOn());
    DTEST_LOG << "SwitchStatusDependencyTest IsContinueSwitchOn_001 end" << std::endl;
}

/**
 * @tc.name: IsCreateDataShareHelper_001
 * @tc.desc: IsCreateDataShareHelper
 * @tc.type: FUNC
 * @tc.require: SR20240116513791
 */
HWTEST_F(SwitchStatusDependencyTest, IsCreateDataShareHelper_001, TestSize.Level3)
{
    DTEST_LOG << "SwitchStatusDependencyTest IsCreateDataShareHelper_001 begin" << std::endl;
    std::string key = "";
    std::string defaultValue = CONTINUE_SWITCH_ON;
    SwitchStatusDependency::GetInstance().GetDataShareHelper();
    EXPECT_EQ(CONTINUE_SWITCH_ON,
        SwitchStatusDependency::GetInstance().GetSwitchStatus(key, defaultValue));
    key = CONTINUE_SWITCH_STATUS_KEY;
    defaultValue = CONTINUE_SWITCH_ON;
    EXPECT_EQ(CONTINUE_SWITCH_ON,
        SwitchStatusDependency::GetInstance().GetSwitchStatus(key, defaultValue));
    DTEST_LOG << "SwitchStatusDependencyTest IsCreateDataShareHelper_001 end" << std::endl;
}
}
}