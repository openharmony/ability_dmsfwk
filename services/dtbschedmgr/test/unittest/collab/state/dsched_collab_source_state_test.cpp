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

#include "dsched_collab_source_state_test.h"

#include "dsched_collab.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const int32_t WAITTIME = 2000;
}

//CollabSrcGetPeerVersionStateTest
void CollabSrcGetPeerVersionStateTest::SetUpTestCase()
{
    DTEST_LOG << "CollabSrcGetPeerVersionStateTest::SetUpTestCase" << std::endl;
    std::string collabToken;
    DSchedCollabInfo info;
    dCollab_ = std::make_shared<DSchedCollab>(collabToken, info);
    dCollab_->Init();
    usleep(WAITTIME);
}

void CollabSrcGetPeerVersionStateTest::TearDownTestCase()
{
    DTEST_LOG << "CollabSrcGetPeerVersionStateTest::TearDownTestCase" << std::endl;
    dCollab_ = nullptr;
    srcGetPeerVersionState_ = nullptr;
}

void CollabSrcGetPeerVersionStateTest::TearDown()
{
    DTEST_LOG << "CollabSrcGetPeerVersionStateTest::TearDown" << std::endl;
    usleep(WAITTIME);
}

void CollabSrcGetPeerVersionStateTest::SetUp()
{
    DTEST_LOG << "CollabSrcGetPeerVersionStateTest::SetUp" << std::endl;
}

//CollabSrcStartStateTest
void CollabSrcStartStateTest::SetUpTestCase()
{
    DTEST_LOG << "CollabSrcStartStateTest::SetUpTestCase" << std::endl;
    std::string collabToken;
    DSchedCollabInfo info;
    dCollab_ = std::make_shared<DSchedCollab>(collabToken, info);
    dCollab_->Init();
    std::shared_ptr<DSchedCollabStateMachine> stateMachine = std::make_shared<DSchedCollabStateMachine>(dCollab_);
    srcStateState_ = std::make_shared<CollabSrcStartState>(stateMachine);
    usleep(WAITTIME);
}

void CollabSrcStartStateTest::TearDownTestCase()
{
    DTEST_LOG << "CollabSrcStartStateTest::TearDownTestCase" << std::endl;
    dCollab_ = nullptr;
    srcStateState_ = nullptr;
}

void CollabSrcStartStateTest::TearDown()
{
    DTEST_LOG << "CollabSrcStartStateTest::TearDown" << std::endl;
    usleep(WAITTIME);
}

void CollabSrcStartStateTest::SetUp()
{
    DTEST_LOG << "CollabSrcStartStateTest::SetUp" << std::endl;
}

//CollabSrcWaitEndStateTest
void CollabSrcWaitEndStateTest::SetUpTestCase()
{
    DTEST_LOG << "CollabSrcWaitEndStateTest::SetUpTestCase" << std::endl;
    std::string collabToken;
    DSchedCollabInfo info;
    dCollab_ = std::make_shared<DSchedCollab>(collabToken, info);
    dCollab_->Init();
    std::shared_ptr<DSchedCollabStateMachine> stateMachine = std::make_shared<DSchedCollabStateMachine>(dCollab_);
    srcWaitEndState_ = std::make_shared<CollabSrcWaitEndState>(stateMachine);
    usleep(WAITTIME);
}

void CollabSrcWaitEndStateTest::TearDownTestCase()
{
    DTEST_LOG << "CollabSrcWaitEndStateTest::TearDownTestCase" << std::endl;
    dCollab_ = nullptr;
    srcWaitEndState_ = nullptr;
}

void CollabSrcWaitEndStateTest::TearDown()
{
    DTEST_LOG << "CollabSrcWaitEndStateTest::TearDown" << std::endl;
    usleep(WAITTIME);
}

void CollabSrcWaitEndStateTest::SetUp()
{
    DTEST_LOG << "CollabSrcWaitEndStateTest::SetUp" << std::endl;
}

//CollabSrcWaitResultStateTest
void CollabSrcWaitResultStateTest::SetUpTestCase()
{
    DTEST_LOG << "CollabSrcWaitResultStateTest::SetUpTestCase" << std::endl;
    std::string collabToken;
    DSchedCollabInfo info;
    dCollab_ = std::make_shared<DSchedCollab>(collabToken, info);
    dCollab_->Init();
    std::shared_ptr<DSchedCollabStateMachine> stateMachine = std::make_shared<DSchedCollabStateMachine>(dCollab_);
    srcWaitRltState_ = std::make_shared<CollabSrcWaitResultState>(stateMachine);
    usleep(WAITTIME);
}

void CollabSrcWaitResultStateTest::TearDownTestCase()
{
    DTEST_LOG << "CollabSrcWaitResultStateTest::TearDownTestCase" << std::endl;
    dCollab_ = nullptr;
    srcWaitRltState_ = nullptr;
}

void CollabSrcWaitResultStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "CollabSrcWaitResultStateTest::TearDown" << std::endl;
}

void CollabSrcWaitResultStateTest::SetUp()
{
    DTEST_LOG << "CollabSrcWaitResultStateTest::SetUp" << std::endl;
}

//CollabSrcStartStateTest
/**
 * @tc.name: StartExecute_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(CollabSrcStartStateTest, StartExecute_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSrcStartStateTest StartExecute_001 begin" << std::endl;
    ASSERT_NE(srcStateState_, nullptr);
    ASSERT_NE(dCollab_, nullptr);
    DSchedCollabEventType eventType = SOURCE_START_EVENT;
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType);
    ASSERT_NE(msgEvent, nullptr);
    msgEvent->innerEventId_ = static_cast<uint32_t>(-1);

    int32_t ret = srcStateState_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcStateState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, COLLAB_STATE_MACHINE_INVALID_STATE);

    msgEvent->innerEventId_ = static_cast<uint32_t>(SOURCE_START_EVENT);
    ret = srcStateState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcStateState_->Execute(dCollab_, msgEvent);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "CollabSrcStartStateTest ConnectExecute_001 end" << std::endl;
}

/**
 * @tc.name: DoSrcStartError_001
 * @tc.desc: DoSrcStartError
 * @tc.type: FUNC
 */
HWTEST_F(CollabSrcStartStateTest, DoSrcStartError_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSrcStartStateTest DoSrcStartError_001 begin" << std::endl;
    ASSERT_NE(srcStateState_, nullptr);
    int32_t ret = srcStateState_->DoSrcStartError(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ASSERT_NE(dCollab_, nullptr);
    ret = srcStateState_->DoSrcStartError(dCollab_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto data = std::make_shared<int32_t>(0);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    ret = srcStateState_->DoSrcStartError(dCollab_, msgEvent);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "CollabSrcStartStateTest DoSrcStartError_001 end" << std::endl;
}

//CollabSrcWaitEndStateTest
/**
 * @tc.name: EndExecute_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(CollabSrcWaitEndStateTest, EndExecute_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSrcWaitEndStateTest EndExecute_001 begin" << std::endl;
    ASSERT_NE(srcWaitEndState_, nullptr);
    int32_t ret = srcWaitEndState_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType);
    ASSERT_NE(msgEvent, nullptr);
    msgEvent->innerEventId_ = static_cast<uint32_t>(-1);
    ret = srcWaitEndState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, COLLAB_STATE_MACHINE_INVALID_STATE);

    msgEvent->innerEventId_ = static_cast<uint32_t>(ERR_END_EVENT);
    ret = srcWaitEndState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ASSERT_NE(dCollab_, nullptr);
    ret = srcWaitEndState_->Execute(dCollab_, msgEvent);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "CollabSrcWaitEndStateTest EndExecute_001 end" << std::endl;
}

/**
 * @tc.name: DoDisconnect_001
 * @tc.desc: DoDisconnect
 * @tc.type: FUNC
 */
HWTEST_F(CollabSrcWaitEndStateTest, DoDisconnect_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSrcWaitEndStateTest DoDisconnect_001 begin" << std::endl;
    ASSERT_NE(srcWaitEndState_, nullptr);
    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType);
    ASSERT_NE(msgEvent, nullptr);

    int32_t ret = srcWaitEndState_->DoDisconnect(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcWaitEndState_->DoDisconnect(dCollab_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ASSERT_NE(dCollab_, nullptr);
    ret = srcWaitEndState_->DoDisconnect(dCollab_, msgEvent);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "CollabSrcWaitEndStateTest DoDisconnect_001 end" << std::endl;
}

//CollabSrcWaitResultStateTest
/**
 * @tc.name: WaitExecute_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(CollabSrcWaitResultStateTest, WaitExecute_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSrcWaitResultStateTest WaitExecute_001 begin" << std::endl;
    ASSERT_NE(srcWaitRltState_, nullptr);
    DSchedCollabEventType eventType = NOTIFY_RESULT_EVENT;
    auto data = std::make_shared<int32_t>(0);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    ASSERT_NE(msgEvent, nullptr);
    msgEvent->innerEventId_ = static_cast<uint32_t>(-1);

    int32_t ret = srcWaitRltState_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcWaitRltState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, COLLAB_STATE_MACHINE_INVALID_STATE);

    msgEvent->innerEventId_ = static_cast<uint32_t>(NOTIFY_RESULT_EVENT);
    ret = srcWaitRltState_->Execute(nullptr, msgEvent);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ASSERT_NE(dCollab_, nullptr);
    ret = srcWaitRltState_->Execute(dCollab_, msgEvent);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "CollabSrcWaitResultStateTest WaitExecute_001 end" << std::endl;
}

/**
 * @tc.name: DoSrcResultNotifyTask_001
 * @tc.desc: DoSrcResultNotifyTask
 * @tc.type: FUNC
 */
HWTEST_F(CollabSrcWaitResultStateTest, DoSrcResultNotifyTask_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSrcWaitResultStateTest DoSrcResultNotifyTask_001 begin" << std::endl;
    ASSERT_NE(srcWaitRltState_, nullptr);
    int32_t ret = srcWaitRltState_->DoSrcResultNotifyTask(
        nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ASSERT_NE(dCollab_, nullptr);
    ret = srcWaitRltState_->DoSrcResultNotifyTask(
        dCollab_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DSchedCollabEventType eventType = NOTIFY_RESULT_EVENT;
    auto data = std::make_shared<int32_t>(0);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    ASSERT_NE(msgEvent, nullptr);
    ret = srcWaitRltState_->DoSrcResultNotifyTask(dCollab_, msgEvent);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "CollabSrcWaitResultStateTest DoSrcResultNotifyTask_001 end" << std::endl;
}

/**
 * @tc.name: DoAbilityRejectTask_001
 * @tc.desc: DoAbilityRejectTask
 * @tc.type: FUNC
 */
HWTEST_F(CollabSrcWaitResultStateTest, DoAbilityRejectTask_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSrcWaitResultStateTest DoAbilityRejectTask_001 begin" << std::endl;
    ASSERT_NE(srcWaitRltState_, nullptr);
    int32_t ret = srcWaitRltState_->DoAbilityRejectTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ASSERT_NE(dCollab_, nullptr);
    ret = srcWaitRltState_->DoAbilityRejectTask(dCollab_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DSchedCollabEventType eventType = ABILITY_REJECT_EVENT;
    auto data = std::make_shared<std::string>("test");
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    ASSERT_NE(msgEvent, nullptr);
    ret = srcWaitRltState_->DoAbilityRejectTask(dCollab_, msgEvent);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "CollabSrcWaitResultStateTest DoAbilityRejectTask_001 end" << std::endl;
}

/**
 * @tc.name: DoSrcWaitResultError_001
 * @tc.desc: DoSrcWaitResultError
 * @tc.type: FUNC
 */
HWTEST_F(CollabSrcWaitResultStateTest, DoSrcWaitResultError_001, TestSize.Level3)
{
    DTEST_LOG << "CollabSrcWaitResultStateTest DoSrcWaitResultError_001 begin" << std::endl;
    ASSERT_NE(srcWaitRltState_, nullptr);
    int32_t ret = srcWaitRltState_->DoSrcWaitResultError(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ASSERT_NE(dCollab_, nullptr);
    ret = srcWaitRltState_->DoSrcWaitResultError(dCollab_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto data = std::make_shared<int32_t>(0);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    ASSERT_NE(msgEvent, nullptr);
    ret = srcWaitRltState_->DoSrcWaitResultError(dCollab_, msgEvent);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "CollabSrcWaitResultStateTest DoSrcWaitResultError_001 end" << std::endl;
}
}
}
