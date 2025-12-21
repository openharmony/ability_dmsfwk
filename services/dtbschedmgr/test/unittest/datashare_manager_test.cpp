/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "datashare_manager_test.h"
#include "dtbschedmgr_log.h"
#include "parameters.h"
#include "switch_status_dependency_test.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedSchedule;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string DISABLE_CONTINUATION_SERVICE = "const.continuation.disable_application_continuation";
}

void DataShareManagerTest::SetUpTestCase()
{
    DTEST_LOG << "DataShareManagerTest::SetUpTestCase" << std::endl;
}

void DataShareManagerTest::TearDownTestCase()
{
    DTEST_LOG << "DataShareManagerTest::TearDownTestCase" << std::endl;
}

void DataShareManagerTest::SetUp()
{
    DTEST_LOG << "DataShareManagerTest::SetUp" << std::endl;
}

void DataShareManagerTest::TearDown()
{
    DTEST_LOG << "DataShareManagerTest::TearDown" << std::endl;
}

/**
 * @tc.number: DataShareManager_UpdateSwitchStatus_001
 * @tc.name: UpdateSwitchStatus
 * @tc.desc: Test normal update with valid parameters
 */
HWTEST_F(DataShareManagerTest, DataShareManager_UpdateSwitchStatus_001, TestSize.Level1)
{
    DTEST_LOG << "DataShareManagerTest-begin DataShareManager_UpdateSwitchStatus_001" << std::endl;
    DataShareManager dataShareManager;
    std::string key = SwitchStatusDependency::GetInstance().CONTINUE_SWITCH_STATUS_KEY;
    std::string value = SwitchStatusDependency::GetInstance().CONTINUE_SWITCH_ON;
    
    EXPECT_NO_FATAL_FAILURE(dataShareManager.UpdateSwitchStatus(key, value));
    
    DTEST_LOG << "DataShareManagerTest-end DataShareManager_UpdateSwitchStatus_001" << std::endl;
}

/**
 * @tc.number: DataShareManager_UpdateSwitchStatus_002
 * @tc.name: UpdateSwitchStatus
 * @tc.desc: Test normal update with valid parameters
 */
HWTEST_F(DataShareManagerTest, DataShareManager_UpdateSwitchStatus_002, TestSize.Level1)
{
    DTEST_LOG << "DataShareManagerTest-begin DataShareManager_UpdateSwitchStatus_001" << std::endl;
    DataShareManager dataShareManager;
    std::string key = SwitchStatusDependency::GetInstance().CONTINUE_SWITCH_STATUS_KEY;
    std::string value = SwitchStatusDependency::GetInstance().CONTINUE_SWITCH_OFF;
    
    EXPECT_NO_FATAL_FAILURE(dataShareManager.UpdateSwitchStatus(key, value));
    
    DTEST_LOG << "DataShareManagerTest-end DataShareManager_UpdateSwitchStatus_001" << std::endl;
}

/**
 * @tc.number: DataShareManager_UpdateSwitchStatus_003
 * @tc.name: UpdateSwitchStatus
 * @tc.desc: Test update with empty key
 */
HWTEST_F(DataShareManagerTest, DataShareManager_UpdateSwitchStatus_003, TestSize.Level1)
{
    DTEST_LOG << "DataShareManagerTest-begin DataShareManager_UpdateSwitchStatus_002" << std::endl;
    DataShareManager dataShareManager;
    std::string key = "";
    std::string value = SwitchStatusDependency::GetInstance().CONTINUE_SWITCH_ON;
    
    EXPECT_NO_FATAL_FAILURE(dataShareManager.UpdateSwitchStatus(key, value));
    
    DTEST_LOG << "DataShareManagerTest-end DataShareManager_UpdateSwitchStatus_002" << std::endl;
}

/**
 * @tc.number: DataShareManager_UpdateSwitchStatus_004
 * @tc.name: UpdateSwitchStatus
 * @tc.desc: Test update with empty value
 */
HWTEST_F(DataShareManagerTest, DataShareManager_UpdateSwitchStatus_004, TestSize.Level1)
{
    DTEST_LOG << "DataShareManagerTest-begin DataShareManager_UpdateSwitchStatus_003" << std::endl;
    DataShareManager dataShareManager;
    // Test with empty value
    std::string key = SwitchStatusDependency::GetInstance().CONTINUE_SWITCH_STATUS_KEY;
    std::string value = "";
    
    EXPECT_NO_FATAL_FAILURE(dataShareManager.UpdateSwitchStatus(key, value));
    
    DTEST_LOG << "DataShareManagerTest-end DataShareManager_UpdateSwitchStatus_003" << std::endl;
}

/**
 * @tc.number: DataShareManager_CheckAndHandleContinueSwitch_003
 * @tc.name: CheckAndHandleContinueSwitch
 * @tc.desc: Test case when continue switch should not be closed
 */
HWTEST_F(DataShareManagerTest, CheckAndHandleContinueSwitch_003, TestSize.Level1)
{
    DTEST_LOG << "DataShareManagerTest-begin CheckAndHandleContinueSwitch_003" << std::endl;
    bool result = DataShareManager::GetInstance().CheckAndHandleContinueSwitch();
    EXPECT_NO_FATAL_FAILURE(SwitchStatusDependency::GetInstance().IsContinueSwitchOn());
    DTEST_LOG << "DataShareManagerTest-end CheckAndHandleContinueSwitch_003" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
