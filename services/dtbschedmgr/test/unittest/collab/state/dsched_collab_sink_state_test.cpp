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

#include "dsched_collab_sink_state_test.h"

#include "dsched_collab.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const int32_t WAITTIME = 2000;
}

//CollabSinkConnectStateTest
void CollabSinkConnectStateTest::SetUpTestCase()
{
    DTEST_LOG << "CollabSinkConnectStateTest::SetUpTestCase" << std::endl;
    std::string collabToken;
    DSchedCollabInfo info;
    dCollab_ = std::make_shared<DSchedCollab>(collabToken, info);
    dCollab_->Init();
    std::shared_ptr<DSchedCollabStateMachine> stateMachine = std::make_shared<DSchedCollabStateMachine>(dCollab_);
    sinkConState_ = std::make_shared<CollabSinkConnectState>(stateMachine);
    usleep(WAITTIME);
}

void CollabSinkConnectStateTest::TearDownTestCase()
{
    DTEST_LOG << "CollabSinkConnectStateTest::TearDownTestCase" << std::endl;
}

void CollabSinkConnectStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "CollabSinkConnectStateTest::TearDown" << std::endl;
}

void CollabSinkConnectStateTest::SetUp()
{
    DTEST_LOG << "CollabSinkConnectStateTest::SetUp" << std::endl;
}

//CollabSinkStartStateTest
void CollabSinkStartStateTest::SetUpTestCase()
{
    DTEST_LOG << "CollabSinkStartStateTest::SetUpTestCase" << std::endl;
    std::string collabToken;
    DSchedCollabInfo info;
    dCollab_ = std::make_shared<DSchedCollab>(collabToken, info);
    dCollab_->Init();
    std::shared_ptr<DSchedCollabStateMachine> stateMachine = std::make_shared<DSchedCollabStateMachine>(dCollab_);
    sinkStartState_ = std::make_shared<CollabSinkStartState>(stateMachine);
    usleep(WAITTIME);
}

void CollabSinkStartStateTest::TearDownTestCase()
{
    DTEST_LOG << "CollabSinkStartStateTest::TearDownTestCase" << std::endl;
}

void CollabSinkStartStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "CollabSinkStartStateTest::TearDown" << std::endl;
}

void CollabSinkStartStateTest::SetUp()
{
    DTEST_LOG << "CollabSinkStartStateTest::SetUp" << std::endl;
}

//CollabSinkWaitEndStateTest
void CollabSinkWaitEndStateTest::SetUpTestCase()
{
    DTEST_LOG << "CollabSinkWaitEndStateTest::SetUpTestCase" << std::endl;
    std::string collabToken;
    DSchedCollabInfo info;
    dCollab_ = std::make_shared<DSchedCollab>(collabToken, info);
    dCollab_->Init();
    std::shared_ptr<DSchedCollabStateMachine> stateMachine = std::make_shared<DSchedCollabStateMachine>(dCollab_);
    sinkWaitState_ = std::make_shared<CollabSinkWaitEndState>(stateMachine);
    usleep(WAITTIME);
}

void CollabSinkWaitEndStateTest::TearDownTestCase()
{
    DTEST_LOG << "CollabSinkWaitEndStateTest::TearDownTestCase" << std::endl;
}

void CollabSinkWaitEndStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "CollabSinkWaitEndStateTest::TearDown" << std::endl;
}

void CollabSinkWaitEndStateTest::SetUp()
{
    DTEST_LOG << "CollabSinkWaitEndStateTest::SetUp" << std::endl;
}

//CollabSinkConnectStateTest
/**
 * @tc.name: ConnectExecute_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(CollabSinkConnectStateTest, ConnectExecute_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSinkConnectStateTest ConnectExecute_001 begin" << std::endl;
    ASSERT_NE(sinkConState_, nullptr);
    DSchedCollabEventType eventType = SOURCE_START_EVENT;
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType);
    ASSERT_NE(msgEvent, nullptr);
    msgEvent->innerEventId_ = static_cast<uint32_t>(-1);

    int32_t ret = sinkConState_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkConState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, COLLAB_STATE_MACHINE_INVALID_STATE);

    msgEvent->innerEventId_ = static_cast<uint32_t>(NOTIFY_PREPARE_RESULT_EVENT);
    ret = sinkConState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "CollabSinkConnectStateTest ConnectExecute_001 end" << std::endl;
}

/**
 * @tc.name: DoSinkPrepareResult_001
 * @tc.desc: DoSinkPrepareResult
 * @tc.type: FUNC
 */
HWTEST_F(CollabSinkConnectStateTest, DoSinkPrepareResult_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSinkConnectStateTest DoSinkPrepareResult_001 begin" << std::endl;
    ASSERT_NE(sinkConState_, nullptr);
    int32_t ret = sinkConState_->DoSinkPrepareResult(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkConState_->DoSinkPrepareResult(dCollab_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto data = std::make_shared<int32_t>(COLLAB_ABILITY_REJECT_ERR);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    ret = sinkConState_->DoSinkPrepareResult(dCollab_, msgEvent);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "CollabSinkConnectStateTest DoSinkPrepareResult_001 end" << std::endl;
}

/**
 * @tc.name: DoAbilityRejectError_001
 * @tc.desc: DoAbilityRejectError
 * @tc.type: FUNC
 */
HWTEST_F(CollabSinkConnectStateTest, DoAbilityRejectError_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSinkConnectStateTest DoAbilityRejectError_001 begin" << std::endl;
    ASSERT_NE(sinkConState_, nullptr);
    int32_t ret = sinkConState_->DoAbilityRejectError(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkConState_->DoAbilityRejectError(dCollab_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::string reason = "reason";
    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto data = std::make_shared<std::string>(reason);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    ret = sinkConState_->DoAbilityRejectError(dCollab_, msgEvent);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "CollabSinkConnectStateTest DoAbilityRejectError_001 end" << std::endl;
}

/**
 * @tc.name: DoConnectError_001
 * @tc.desc: DoConnectError
 * @tc.type: FUNC
 */
HWTEST_F(CollabSinkConnectStateTest, DoConnectError_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSinkConnectStateTest DoConnectError_001 begin" << std::endl;
    ASSERT_NE(sinkConState_, nullptr);
    int32_t ret = sinkConState_->DoConnectError(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkConState_->DoConnectError(dCollab_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto data = std::make_shared<int32_t>(COLLAB_ABILITY_REJECT_ERR);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    ret = sinkConState_->DoConnectError(dCollab_, msgEvent);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "CollabSinkConnectStateTest DoConnectError_001 end" << std::endl;
}

//CollabSinkStartStateTest
/**
 * @tc.name: StartExecute_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(CollabSinkStartStateTest, StartExecute_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSinkStartStateTest StartExecute_001 begin" << std::endl;
    ASSERT_NE(sinkStartState_, nullptr);
    DSchedCollabEventType eventType = SOURCE_START_EVENT;
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType);
    ASSERT_NE(msgEvent, nullptr);
    msgEvent->innerEventId_ = static_cast<uint32_t>(-1);

    int32_t ret = sinkStartState_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, COLLAB_STATE_MACHINE_INVALID_STATE);

    msgEvent->innerEventId_ = static_cast<uint32_t>(START_ABILITY_EVENT);
    ret = sinkStartState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "CollabSinkStartStateTest StartExecute_001 end" << std::endl;
}

/**
 * @tc.name: DoStartAbility_001
 * @tc.desc: DoStartAbility
 * @tc.type: FUNC
 */
HWTEST_F(CollabSinkStartStateTest, DoStartAbility_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSinkStartStateTest DoStartAbility_001 begin" << std::endl;
    ASSERT_NE(sinkStartState_, nullptr);
    int32_t ret = sinkStartState_->DoStartAbility(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartState_->DoStartAbility(dCollab_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto data = std::make_shared<int32_t>(COLLAB_ABILITY_REJECT_ERR);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    ret = sinkStartState_->DoStartAbility(dCollab_, msgEvent);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "CollabSinkStartStateTest DoStartAbility_001 end" << std::endl;
}

/**
 * @tc.name: DoSinkStartError_001
 * @tc.desc: DoSinkStartError
 * @tc.type: FUNC
 */
HWTEST_F(CollabSinkStartStateTest, DoSinkStartError_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSinkStartStateTest DoSinkStartError_001 begin" << std::endl;
    ASSERT_NE(sinkStartState_, nullptr);
    int32_t ret = sinkStartState_->DoSinkStartError(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartState_->DoSinkStartError(dCollab_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto data = std::make_shared<int32_t>(COLLAB_ABILITY_REJECT_ERR);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    ret = sinkStartState_->DoSinkStartError(dCollab_, msgEvent);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "CollabSinkStartStateTest DoSinkStartError_001 end" << std::endl;
}

//CollabSinkWaitEndStateTest
/**
 * @tc.name: WaitExecute_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(CollabSinkWaitEndStateTest, WaitExecute_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSinkWaitEndStateTest WaitExecute_001 begin" << std::endl;
    ASSERT_NE(sinkWaitState_, nullptr);
    DSchedCollabEventType eventType = SOURCE_START_EVENT;
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType);
    ASSERT_NE(msgEvent, nullptr);
    msgEvent->innerEventId_ = static_cast<uint32_t>(-1);

    int32_t ret = sinkWaitState_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkWaitState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, COLLAB_STATE_MACHINE_INVALID_STATE);

    msgEvent->innerEventId_ = static_cast<uint32_t>(ERR_END_EVENT);
    ret = sinkWaitState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "CollabSinkWaitEndStateTest WaitExecute_001 end" << std::endl;
}

/**
 * @tc.name: DoDisconnect_001
 * @tc.desc: DoDisconnect
 * @tc.type: FUNC
 */
HWTEST_F(CollabSinkWaitEndStateTest, DoStartAbility_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSinkWaitEndStateTest DoStartAbility_001 begin" << std::endl;
    ASSERT_NE(sinkWaitState_, nullptr);
    int32_t ret = sinkWaitState_->DoDisconnect(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkWaitState_->DoDisconnect(dCollab_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto data = std::make_shared<int32_t>(COLLAB_ABILITY_REJECT_ERR);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    ret = sinkWaitState_->DoDisconnect(dCollab_, msgEvent);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "CollabSinkWaitEndStateTest DoStartAbility_001 end" << std::endl;
}
}
}
