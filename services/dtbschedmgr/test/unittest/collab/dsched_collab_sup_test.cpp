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

#include "dsched_collab_sup_test.h"

#include "dsched_collab_source_start_state.h"
#include "mock_distributed_sched.h"
#include "mock_remote_sup_stub.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const int32_t WAITTIME = 2000;
    constexpr int32_t FOREGROUND = 2;
    constexpr int32_t BACKGROUND = 4;
}

void DSchedCollabSupTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedCollabSupTest::SetUpTestCase" << std::endl;
    handleMock_ = std::make_shared<EventHandlerMock>();
    EventHandlerMock::handlerMock = handleMock_;
    std::string collabToken;
    DSchedCollabInfo info;
    dSchedCollab_ = std::make_shared<DSchedCollab>(collabToken, info);
    (void)dSchedCollab_->Init();
    usleep(WAITTIME);
}

void DSchedCollabSupTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedCollabSupTest::TearDownTestCase" << std::endl;
    EventHandlerMock::handlerMock = nullptr;
    handleMock_ = nullptr;
    dSchedCollab_ = nullptr;
}

void DSchedCollabSupTest::TearDown()
{
    DTEST_LOG << "DSchedCollabSupTest::TearDown" << std::endl;
    usleep(WAITTIME);
}

void DSchedCollabSupTest::SetUp()
{
    DTEST_LOG << "DSchedCollabSupTest::SetUp" << std::endl;
}

/**
 * @tc.name: PostSrcStartTask_001
 * @tc.desc: call PostSrcStartTask
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, PostSrcStartTask_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest PostSrcStartTask_002 begin" << std::endl;
    ASSERT_NE(dSchedCollab_, nullptr);
    ASSERT_NE(dSchedCollab_->eventHandler_, nullptr);
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(false));
    EXPECT_EQ(dSchedCollab_->PostSrcStartTask(), COLLAB_SEND_EVENT_FAILED);

    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(true));
    EXPECT_EQ(dSchedCollab_->PostSrcStartTask(), ERR_OK);
    DTEST_LOG << "DSchedCollabSupTest PostSrcStartTask_001 end" << std::endl;
}

/**
 * @tc.name: PostSinkStartTask_001
 * @tc.desc: call PostSinkStartTask
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, PostSinkStartTask_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest PostSinkStartTask_001 begin" << std::endl;
    ASSERT_NE(dSchedCollab_, nullptr);
    ASSERT_NE(dSchedCollab_->eventHandler_, nullptr);
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(false));
    EXPECT_EQ(dSchedCollab_->PostSinkStartTask(), COLLAB_SEND_EVENT_FAILED);

    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(true));
    EXPECT_EQ(dSchedCollab_->PostSinkStartTask(), ERR_OK);
    DTEST_LOG << "DSchedCollabSupTest PostSinkStartTask_001 end" << std::endl;
}

/**
 * @tc.name: PostSinkPrepareResultTask_001
 * @tc.desc: call PostSinkPrepareResultTask
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, PostSinkPrepareResultTask_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest PostSinkPrepareResultTask_001 begin" << std::endl;
    ASSERT_NE(dSchedCollab_, nullptr);
    ASSERT_NE(dSchedCollab_->eventHandler_, nullptr);
    int32_t result = 100;
    int32_t collabSessionId = 0;
    std::string socketName = "test";
    sptr<IRemoteObject> clientCB = sptr<DistributedSchedService>(new DistributedSchedService());
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(false));
    EXPECT_EQ(dSchedCollab_->PostSinkPrepareResultTask(
        result, collabSessionId, socketName, clientCB), COLLAB_SEND_EVENT_FAILED);

    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(true));
    EXPECT_EQ(dSchedCollab_->PostSinkPrepareResultTask(
        result, collabSessionId, socketName, clientCB), ERR_OK);
    DTEST_LOG << "DSchedCollabSupTest PostSinkPrepareResultTask_001 end" << std::endl;
}

/**
 * @tc.name: PostSrcResultTask_001
 * @tc.desc: call PostSrcResultTask
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, PostSrcResultTask_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest PostSrcResultTask_001 begin" << std::endl;
    ASSERT_NE(dSchedCollab_, nullptr);
    ASSERT_NE(dSchedCollab_->eventHandler_, nullptr);
    std::shared_ptr<NotifyResultCmd> cmd = std::make_shared<NotifyResultCmd>();
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(false));
    EXPECT_EQ(dSchedCollab_->PostSrcResultTask(cmd), COLLAB_SEND_EVENT_FAILED);

    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(true));
    EXPECT_EQ(dSchedCollab_->PostSrcResultTask(cmd), ERR_OK);

    cmd->abilityRejectReason_ = "test";
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(false));
    EXPECT_EQ(dSchedCollab_->PostSrcResultTask(cmd), COLLAB_SEND_EVENT_FAILED);

    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(true));
    EXPECT_EQ(dSchedCollab_->PostSrcResultTask(cmd), ERR_OK);
    DTEST_LOG << "DSchedCollabSupTest PostSrcResultTask_001 end" << std::endl;
}

/**
 * @tc.name: PostErrEndTask_001
 * @tc.desc: call PostErrEndTask
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, PostErrEndTask_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest PostErrEndTask_001 begin" << std::endl;
    ASSERT_NE(dSchedCollab_, nullptr);
    ASSERT_NE(dSchedCollab_->eventHandler_, nullptr);
    int32_t result = 100;
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(false));
    EXPECT_EQ(dSchedCollab_->PostErrEndTask(result), COLLAB_SEND_EVENT_FAILED);

    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(true));
    EXPECT_EQ(dSchedCollab_->PostErrEndTask(result), ERR_OK);
    DTEST_LOG << "DSchedCollabSupTest PostErrEndTask_001 end" << std::endl;
}

/**
 * @tc.name: PostAbilityRejectTask_001
 * @tc.desc: call PostAbilityRejectTask
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, PostAbilityRejectTask_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest PostAbilityRejectTask_001 begin" << std::endl;
    ASSERT_NE(dSchedCollab_, nullptr);
    ASSERT_NE(dSchedCollab_->eventHandler_, nullptr);
    std::string reason = "test";
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(false));
    EXPECT_EQ(dSchedCollab_->PostAbilityRejectTask(reason), COLLAB_SEND_EVENT_FAILED);

    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(true));
    EXPECT_EQ(dSchedCollab_->PostAbilityRejectTask(reason), ERR_OK);
    DTEST_LOG << "DSchedCollabSupTest PostAbilityRejectTask_001 end" << std::endl;
}

/**
 * @tc.name: PostEndTask_001
 * @tc.desc: call PostEndTask
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, PostEndTask_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest PostEndTask_001 begin" << std::endl;
    ASSERT_NE(dSchedCollab_, nullptr);
    ASSERT_NE(dSchedCollab_->eventHandler_, nullptr);
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(false));
    EXPECT_EQ(dSchedCollab_->PostEndTask(), COLLAB_SEND_EVENT_FAILED);

    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(true));
    EXPECT_EQ(dSchedCollab_->PostEndTask(), ERR_OK);
    DTEST_LOG << "DSchedCollabSupTest PostEndTask_001 end" << std::endl;
}

/**
 * @tc.name: OnDataRecv_001
 * @tc.desc: call OnDataRecv
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, OnDataRecv_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest OnDataRecv_001 begin" << std::endl;
    ASSERT_NE(dSchedCollab_, nullptr);
    ASSERT_NE(dSchedCollab_->eventHandler_, nullptr);
    dSchedCollab_->collabInfo_.direction_ = COLLAB_SINK;
    dSchedCollab_->collabInfo_.srcClientCB_ = nullptr;
    dSchedCollab_->collabInfo_.sinkClientCB_ = nullptr;
    std::shared_ptr<DSchedDataBuffer> dataBuffer = nullptr;
    int32_t command = static_cast<int32_t>(MAX_CMD);
    dSchedCollab_->OnDataRecv(command, dataBuffer);

    dataBuffer = std::make_shared<DSchedDataBuffer>(20);
    dSchedCollab_->OnDataRecv(command, dataBuffer);

    command = static_cast<int32_t>(SINK_START_CMD);
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(true));
    dSchedCollab_->OnDataRecv(command, dataBuffer);

    command = static_cast<int32_t>(NOTIFY_RESULT_CMD);
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(true));
    dSchedCollab_->OnDataRecv(command, dataBuffer);

    command = static_cast<int32_t>(DISCONNECT_CMD);
    dSchedCollab_->OnDataRecv(command, dataBuffer);
    DTEST_LOG << "DSchedCollabSupTest OnDataRecv_001 end" << std::endl;
}

/**
 * @tc.name: ProcessEvent_001
 * @tc.desc: call ProcessEvent
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, ProcessEvent_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest ProcessEvent_001 begin" << std::endl;
    ASSERT_NE(dSchedCollab_, nullptr);
    ASSERT_NE(dSchedCollab_->eventHandler_, nullptr);
    dSchedCollab_->stateMachine_ = nullptr;
    dSchedCollab_->ProcessEvent(AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));

    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto data = std::make_shared<int32_t>(0);
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType, data, 0);
    dSchedCollab_->ProcessEvent(msgEvent);

    dSchedCollab_->stateMachine_ = std::make_shared<DSchedCollabStateMachine>(dSchedCollab_);
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(false));
    dSchedCollab_->ProcessEvent(msgEvent);

    dSchedCollab_->stateMachine_->currentState_ =
        std::make_shared<CollabSrcStartState>(dSchedCollab_->stateMachine_);
    dSchedCollab_->ProcessEvent(msgEvent);
    DTEST_LOG << "DSchedCollabSupTest ProcessEvent_001 end" << std::endl;
}

/**
 * @tc.name: PackNotifyResultCmd_001
 * @tc.desc: call PackNotifyResultCmd
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, PackNotifyResultCmd_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest PackNotifyResultCmd_001 begin" << std::endl;
    ASSERT_NE(dSchedCollab_, nullptr);
    ASSERT_NE(dSchedCollab_->eventHandler_, nullptr);
    std::shared_ptr<NotifyResultCmd> cmd = nullptr;
    int32_t result = 5;
    std::string abilityRejectReason = "test";
    EXPECT_EQ(dSchedCollab_->PackNotifyResultCmd(cmd, result, abilityRejectReason), INVALID_PARAMETERS_ERR);

    cmd = std::make_shared<NotifyResultCmd>();
    EXPECT_EQ(dSchedCollab_->PackNotifyResultCmd(cmd, result, abilityRejectReason), ERR_OK);
    EXPECT_EQ(cmd->result_, result);
    EXPECT_EQ(cmd->abilityRejectReason_, abilityRejectReason);
    DTEST_LOG << "DSchedCollabSupTest PackNotifyResultCmd_001 end" << std::endl;
}

/**
 * @tc.name: RegisterAbilityLifecycleObserver_001
 * @tc.desc: call RegisterAbilityLifecycleObserver
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, RegisterAbilityLifecycleObserver_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest RegisterAbilityLifecycleObserver_001 begin" << std::endl;
    ASSERT_NE(dSchedCollab_, nullptr);
    std::string bundleName = "test";
    EXPECT_EQ(dSchedCollab_->RegisterAbilityLifecycleObserver(bundleName), false);
    EXPECT_NE(dSchedCollab_->appStateObserver_, nullptr);
    AppExecFwk::AbilityStateData abilityStateData;
    abilityStateData.abilityState = BACKGROUND;
    dSchedCollab_->appStateObserver_->OnAbilityStateChanged(abilityStateData);

    abilityStateData.abilityState = FOREGROUND;
    dSchedCollab_->appStateObserver_->OnAbilityStateChanged(abilityStateData);
    dSchedCollab_->UnregisterAbilityLifecycleObserver();
    DTEST_LOG << "DSchedCollabSupTest RegisterAbilityLifecycleObserver_001 end" << std::endl;
}

/**
 * @tc.name: DSchedCollabEventHandler_001
 * @tc.desc: call DSchedCollabEventHandler
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollabSupTest, DSchedCollabEventHandler_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabSupTest DSchedCollabEventHandler_001 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create(false);
    auto errHandler = std::make_shared<DSchedCollabEventHandler>(runner, nullptr);
    errHandler->ProcessEvent(AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));

    DSchedCollabEventType eventType = ERR_END_EVENT;
    auto msgEvent = AppExecFwk::InnerEvent::Get(eventType);
    errHandler->ProcessEvent(msgEvent);

    auto handler = std::make_shared<DSchedCollabEventHandler>(runner, dSchedCollab_);
    EXPECT_CALL(*handleMock_, SendEvent(_, _, _)).WillOnce(Return(true));
    handler->ProcessEvent(msgEvent);
    DTEST_LOG << "DSchedCollabSupTest DSchedCollabEventHandler_001 end" << std::endl;
}
}
}