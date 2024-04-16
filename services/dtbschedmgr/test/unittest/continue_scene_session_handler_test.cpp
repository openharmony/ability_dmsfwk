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

#include "continue_scene_session_handler_test.h"

#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

void ContinueSceneSessionHandlerTest::SetUpTestCase()
{
    DTEST_LOG << "ContinueSceneSessionHandlerTest::SetUpTestCase" << std::endl;
}

void ContinueSceneSessionHandlerTest::TearDownTestCase()
{
    DTEST_LOG << "ContinueSceneSessionHandlerTest::TearDownTestCase" << std::endl;
}

void ContinueSceneSessionHandlerTest::TearDown()
{
    DTEST_LOG << "ContinueSceneSessionHandlerTest::TearDown" << std::endl;
}

void ContinueSceneSessionHandlerTest::SetUp()
{
    DTEST_LOG << "ContinueSceneSessionHandlerTest::SetUp" << std::endl;
}

/**
 * @tc.name: UpdateContinueSessionId_001
 * @tc.desc: generated continueSessionId by bundleName and abilityName
 * @tc.type: FUNC
 * @tc.require: SR20240116512594
 */
HWTEST_F(ContinueSceneSessionHandlerTest, UpdateContinueSessionId_001, TestSize.Level3)
{
    DTEST_LOG << "ContinueSceneSessionHandlerTest UpdateContinueSessionId_001 begin" << std::endl;
    std::string bundleName = "ohos.dms.bundleName_001";
    std::string abilityName = "ohos.dms.abilityName_001";
    ContinueSceneSessionHandler::GetInstance().UpdateContinueSessionId(bundleName, abilityName);
    std::string continueSessionId = ContinueSceneSessionHandler::GetInstance().GetContinueSessionId();
    EXPECT_FALSE(continueSessionId.empty());
    DTEST_LOG << "ContinueSceneSessionHandlerTest UpdateContinueSessionId_001 end" << std::endl;
}

/**
 * @tc.name: GetContinueSessionId_001
 * @tc.desc: get continueSessionId test
 * @tc.type: FUNC
 * @tc.require: SR20240116512594
 */
    HWTEST_F(ContinueSceneSessionHandlerTest, GetContinueSessionId_001, TestSize.Level3)
{
    DTEST_LOG << "ContinueSceneSessionHandlerTest GetContinueSessionId_001 begin" << std::endl;
    std::string continueSessionId = ContinueSceneSessionHandler::GetInstance().GetContinueSessionId();
    EXPECT_FALSE(continueSessionId.empty());
    DTEST_LOG << "ContinueSceneSessionHandlerTest GetContinueSessionId_001 end" << std::endl;
}

/**
 * @tc.name: GetPersistentId_001
 * @tc.desc: get persistentId by continueSessionId
 * @tc.type: FUNC
 * @tc.require: SR20240116512594
 */
HWTEST_F(ContinueSceneSessionHandlerTest, GetPersistentId_001, TestSize.Level3)
{
    DTEST_LOG << "ContinueSceneSessionHandlerTest GetPersistentId_001 begin" << std::endl;
    int32_t persistentId;
    int32_t err = ContinueSceneSessionHandler::GetInstance().GetPersistentId(persistentId);
    EXPECT_EQ(static_cast<int32_t>(INVALID_PARAMETERS_ERR), err);
    DTEST_LOG << "ContinueSceneSessionHandlerTest GetPersistentId_001 end" << std::endl;
}

/**
 * @tc.name: ClearContinueSessionId_001
 * @tc.desc: clear continueSessionId test
 * @tc.type: FUNC
 * @tc.require: SR20240116512594
 */
HWTEST_F(ContinueSceneSessionHandlerTest, ClearContinueSessionId_001, TestSize.Level3)
{
    DTEST_LOG << "ContinueSceneSessionHandlerTest ClearContinueSessionId_001 begin" << std::endl;
    ContinueSceneSessionHandler::GetInstance().ClearContinueSessionId();
    std::string continueSessionId = ContinueSceneSessionHandler::GetInstance().GetContinueSessionId();
    EXPECT_TRUE(continueSessionId.empty());
    DTEST_LOG << "ContinueSceneSessionHandlerTest ClearContinueSessionId_001 end" << std::endl;
}
}
}