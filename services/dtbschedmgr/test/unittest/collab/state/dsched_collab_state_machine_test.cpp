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

#include "dsched_collab_state_machine_test.h"

#include "dsched_collab.h"
#include "dsched_collab_state.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t ENUM = 9;
}

void DSchedCollabStateMachineTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedCollabStateMachineTest::SetUpTestCase" << std::endl;
}

void DSchedCollabStateMachineTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedCollabStateMachineTest::TearDownTestCase" << std::endl;
}

void DSchedCollabStateMachineTest::TearDown()
{
    DTEST_LOG << "DSchedCollabStateMachineTest::TearDown" << std::endl;
}

void DSchedCollabStateMachineTest::SetUp()
{
    DTEST_LOG << "DSchedCollabStateMachineTest::SetUp" << std::endl;
}

/**
 * @tc.name: GetStateType_001
 * @tc.desc: call GetStateType
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabStateMachineTest, GetStateType_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabStateMachineTest GetStateType_001 begin" << std::endl;
    std::shared_ptr<DSchedCollabStateMachine> machinePtr = std::make_shared<DSchedCollabStateMachine>(nullptr);

    //currentState_ not is nullptr
    machinePtr->UpdateState(SOURCE_START_STATE);
    auto ret = machinePtr->GetStateType();
    EXPECT_EQ(ret, SOURCE_START_STATE);

    machinePtr->UpdateState(SOURCE_WAIT_RESULT_STATE);
    ret = machinePtr->GetStateType();
    EXPECT_EQ(ret, SOURCE_WAIT_RESULT_STATE);

    machinePtr->UpdateState(SOURCE_WAIT_END_STATE);
    ret = machinePtr->GetStateType();
    EXPECT_EQ(ret, SOURCE_WAIT_END_STATE);

    machinePtr->UpdateState(SINK_START_STATE);
    ret = machinePtr->GetStateType();
    EXPECT_EQ(ret, SINK_START_STATE);

    machinePtr->UpdateState(SINK_CONNECT_STATE);
    ret = machinePtr->GetStateType();
    EXPECT_EQ(ret, SINK_CONNECT_STATE);

    machinePtr->UpdateState(SINK_WAIT_END_STATE);
    ret = machinePtr->GetStateType();
    EXPECT_EQ(ret, SINK_WAIT_END_STATE);

    //currentState_ is nullptr
    machinePtr->UpdateState(static_cast<CollabStateType>(ENUM));
    ret = machinePtr->GetStateType();
    EXPECT_EQ(ret, SOURCE_START_STATE);
    DTEST_LOG << "DSchedCollabStateMachineTest GetStateType_001 end" << std::endl;
}

/**
 * @tc.name: Execute_001
 * @tc.desc: call Execute
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabStateMachineTest, Execute_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabStateMachineTest Execute_001 begin" << std::endl;
    std::shared_ptr<DSchedCollabStateMachine> machinePtr1 = std::make_shared<DSchedCollabStateMachine>(nullptr);
    auto ret = machinePtr1->Execute(AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::string collabToken;
    DSchedCollabInfo info;
    std::shared_ptr<DSchedCollab> dCollab = std::make_shared<DSchedCollab>(collabToken, info);
    dCollab->Init();
    std::shared_ptr<DSchedCollabStateMachine> machinePtr2 = std::make_shared<DSchedCollabStateMachine>(dCollab);
    machinePtr2->currentState_ = nullptr;
    ret = machinePtr2->Execute(AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollabStateMachineTest Execute_001 end" << std::endl;
}
}
}
