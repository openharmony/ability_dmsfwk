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

#include "datashare_manager_test.h"

#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
void DataShareManagerTest::SetUpTestCase()
{
    DTEST_LOG << "DataShareManagerTest::SetUpTestCase" << std::endl;
}

void DataShareManagerTest::TearDownTestCase()
{
    DTEST_LOG << "DataShareManagerTest::TearDownTestCase" << std::endl;
}

void DataShareManagerTest::TearDown()
{
    DTEST_LOG << "DataShareManagerTest::TearDown" << std::endl;
}

void DataShareManagerTest::SetUp()
{
    DTEST_LOG << "DataShareManagerTest::SetUp" << std::endl;
}

/**
 * @tc.name: CreateDataShareHelper_001
 * @tc.desc: CreateDataShareHelper
 * @tc.type: FUNC
 * @tc.require: SR20240116513791
 */
HWTEST_F(DataShareManagerTest, CreateDataShareHelper_001, TestSize.Level3)
{
    DTEST_LOG << "DataShareManagerTest CreateDataShareHelper_001 begin" << std::endl;
    DataShareManager::GetInstance().CreateDataShareHelper();
    DTEST_LOG << "DataShareManagerTest CreateDataShareHelper_001 end" << std::endl;
}

/**
 * @tc.name: IsCreateDataShareHelper_001
 * @tc.desc: IsCreateDataShareHelper
 * @tc.type: FUNC
 * @tc.require: SR20240116513791
 */
HWTEST_F(DataShareManagerTest, IsCreateDataShareHelper_001, TestSize.Level3)
{
    DTEST_LOG << "DataShareManagerTest IsCreateDataShareHelper_001 begin" << std::endl;
    DataShareManager::GetInstance().IsCreateDataShareHelper(SETTINGS_DATA_URI);
    DTEST_LOG << "DataShareManagerTest IsCreateDataShareHelper_001 end" << std::endl;
}

/**
 * @tc.name: RegisterObserver_001
 * @tc.desc: RegisterObserver
 * @tc.type: FUNC
 * @tc.require: SR20240116513791
 */
HWTEST_F(DataShareManagerTest, RegisterObserver_001, TestSize.Level3)
{
    DTEST_LOG << "DataShareManagerTest RegisterObserver_001 begin" << std::endl;
    DataShareManager::GetInstance().RegisterObserver("");
    DataShareManager::GetInstance().RegisterObserver(SETTINGS_DATA_URI);
    DTEST_LOG << "DataShareManagerTest RegisterObserver_001 end" << std::endl;
}

/**
 * @tc.name: OnChange_001
 * @tc.desc: OnChange
 * @tc.type: FUNC
 * @tc.require: SR20240116513791
 */
HWTEST_F(DataShareManagerTest, OnChange_001, TestSize.Level3)
{
    DTEST_LOG << "DataShareManagerTest OnChange_001 begin" << std::endl;
    DataShareRegisterObserver dataShareRegisterObserver;
    ChangeInfo changeInfo;
    dataShareRegisterObserver.OnChange(changeInfo);
    DTEST_LOG << "DataShareManagerTest OnChange_001 end" << std::endl;
}
}
}