/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "dsched_continue_state_test.h"

#include "dsched_continue.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string BASEDIR = "/data/service/el1/public/database/DistributedSchedule";
    const int32_t WAITTIME = 2000;
}

//DSchedContinueStateMachineTest
void DSchedContinueStateMachineTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    dContinue_ = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue_->Init();
    stateMachineTest_ = std::make_shared<DSchedContinueStateMachine>(dContinue_);
    DTEST_LOG << "DSchedContinueStateMachineTest::SetUpTestCase" << std::endl;
}

void DSchedContinueStateMachineTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DSchedContinueStateMachineTest::TearDownTestCase" << std::endl;
}

void DSchedContinueStateMachineTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueStateMachineTest::TearDown" << std::endl;
}

void DSchedContinueStateMachineTest::SetUp()
{
    DTEST_LOG << "DSchedContinueStateMachineTest::SetUp" << std::endl;
}

int32_t DSchedContinue::ExecuteQuickStartSuccess()
{
    return ERR_OK;
}

int32_t DSchedContinue::ExecuteQuickStartFailed(int32_t result)
{
    return ERR_OK;
}

 /**
 * @tc.name: Execute_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueStateMachineTest, Execute_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueStateMachineTest Execute_001 begin" << std::endl;
    ASSERT_NE(stateMachineTest_, nullptr);
    AppExecFwk::InnerEvent *event = nullptr;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    stateMachineTest_->currentState_ = nullptr;
    int32_t ret = stateMachineTest_->Execute(AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueStateMachineTest Execute_001 end" << std::endl;
}

 /**
 * @tc.name: UpdateState_001
 * @tc.desc: UpdateState
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueStateMachineTest, UpdateState_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueStateMachineTest UpdateState_001 begin" << std::endl;
    ASSERT_NE(stateMachineTest_, nullptr);
    DSchedContinueStateType stateType = DSCHED_CONTINUE_SOURCE_START_STATE;
    stateMachineTest_->UpdateState(stateType);
    EXPECT_NE(stateMachineTest_->currentState_, nullptr);
    DTEST_LOG << "DSchedContinueStateMachineTest UpdateState_001 end" << std::endl;
}

 /**
 * @tc.name: UpdateState_002
 * @tc.desc: UpdateState
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueStateMachineTest, UpdateState_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueStateMachineTest UpdateState_002 begin" << std::endl;
    ASSERT_NE(stateMachineTest_, nullptr);
    DSchedContinueStateType stateType = DSCHED_CONTINUE_ABILITY_STATE;
    stateMachineTest_->currentState_ = stateMachineTest_->CreateState(stateType);
    stateMachineTest_->UpdateState(stateType);
    EXPECT_NE(stateMachineTest_->currentState_, nullptr);
    DTEST_LOG << "DSchedContinueStateMachineTest UpdateState_002 end" << std::endl;
}

 /**
 * @tc.name: CreateState_001
 * @tc.desc: CreateState
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueStateMachineTest, CreateState_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueStateMachineTest CreateState_001 begin" << std::endl;
    ASSERT_NE(stateMachineTest_, nullptr);
    std::shared_ptr<DSchedContinueState> state = stateMachineTest_->CreateState(DSCHED_CONTINUE_SOURCE_START_STATE);
    EXPECT_TRUE(state != nullptr);

    state = stateMachineTest_->CreateState(DSCHED_CONTINUE_ABILITY_STATE);
    EXPECT_TRUE(state != nullptr);

    state = stateMachineTest_->CreateState(DSCHED_CONTINUE_SOURCE_WAIT_END_STATE);
    EXPECT_TRUE(state != nullptr);

    state = stateMachineTest_->CreateState(DSCHED_CONTINUE_SOURCE_END_STATE);
    EXPECT_TRUE(state != nullptr);

    state = stateMachineTest_->CreateState(DSCHED_CONTINUE_SINK_START_STATE);
    EXPECT_TRUE(state != nullptr);

    state = stateMachineTest_->CreateState(DSCHED_CONTINUE_DATA_STATE);
    EXPECT_TRUE(state != nullptr);

    state = stateMachineTest_->CreateState(DSCHED_CONTINUE_SINK_WAIT_END_STATE);
    EXPECT_TRUE(state != nullptr);

    state = stateMachineTest_->CreateState(DSCHED_CONTINUE_SINK_END_STATE);
    EXPECT_TRUE(state != nullptr);

    state = stateMachineTest_->CreateState(static_cast<DSchedContinueStateType>(-1));
    EXPECT_TRUE(state == nullptr);
    DTEST_LOG << "DSchedContinueStateMachineTest CreateState_001 end" << std::endl;
}

 /**
 * @tc.name: GetStateType_001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueStateMachineTest, GetStateType_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueStateMachineTest GetStateType_001 begin" << std::endl;
    ASSERT_NE(stateMachineTest_, nullptr);
    stateMachineTest_->currentState_ = nullptr;
    DSchedContinueStateType ret = stateMachineTest_->GetStateType();
    EXPECT_EQ(ret, DSCHED_CONTINUE_SOURCE_START_STATE);
    DTEST_LOG << "DSchedContinueStateMachineTest GetStateType_001 end" << std::endl;
}
}
}
