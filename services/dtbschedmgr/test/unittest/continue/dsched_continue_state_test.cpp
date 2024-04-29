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

#include "dsched_continue_state_test.h"

#include "dsched_continue.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

//DSchedContinueDataStateTest
void DSchedContinueDataStateTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueDataStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueDataStateTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueDataStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueDataStateTest::TearDown()
{
    dataStateTest_ = nullptr;
    DTEST_LOG << "DSchedContinueDataStateTest::TearDown" << std::endl;
}

void DSchedContinueDataStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine = std::make_shared<DSchedContinueStateMachine>(dContinue);
    dataStateTest_ = std::make_shared<DSchedContinueDataState>(stateMachine);
    DTEST_LOG << "DSchedContinueDataStateTest::SetUp" << std::endl;
}

std::shared_ptr<DSchedContinue> DSchedContinueDataStateTest::CreateObject()
{
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    std::shared_ptr<DSchedContinue> dContinue = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue->Init();
    return dContinue;
}

//DSchedContinueSinkEndStateTest
void DSchedContinueSinkEndStateTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueSinkEndStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueSinkEndStateTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueSinkEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSinkEndStateTest::TearDown()
{
    sinkEndStateTest_ = nullptr;
    DTEST_LOG << "DSchedContinueSinkEndStateTest::TearDown" << std::endl;
}

void DSchedContinueSinkEndStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine = std::make_shared<DSchedContinueStateMachine>(dContinue);
    sinkEndStateTest_ = std::make_shared<DSchedContinueSinkEndState>(stateMachine);
    DTEST_LOG << "DSchedContinueSinkEndStateTest::SetUp" << std::endl;
}

std::shared_ptr<DSchedContinue> DSchedContinueSinkEndStateTest::CreateObject()
{
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    std::shared_ptr<DSchedContinue> dContinue = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue->Init();
    return dContinue;
}

//DSchedContinueSinkStartStateTest
void DSchedContinueSinkStartStateTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueSinkStartStateTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSinkStartStateTest::TearDown()
{
    sinkStartStateTest_ = nullptr;
    DTEST_LOG << "DSchedContinueSinkStartStateTest::TearDown" << std::endl;
}

void DSchedContinueSinkStartStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine = std::make_shared<DSchedContinueStateMachine>(dContinue);
    sinkStartStateTest_ = std::make_shared<DSchedContinueSinkStartState>(stateMachine);
    DTEST_LOG << "DSchedContinueSinkStartStateTest::SetUp" << std::endl;
}

std::shared_ptr<DSchedContinue> DSchedContinueSinkStartStateTest::CreateObject()
{
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    std::shared_ptr<DSchedContinue> dContinue = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue->Init();
    return dContinue;
}

//DSchedContinueSinkWaitEndStateTest
void DSchedContinueSinkWaitEndStateTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueSinkWaitEndStateTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSinkWaitEndStateTest::TearDown()
{
    sinkWaitEndTest_ = nullptr;
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::TearDown" << std::endl;
}

void DSchedContinueSinkWaitEndStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue);
    sinkWaitEndTest_ = std::make_shared<DSchedContinueSinkWaitEndState>(stateMachine);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::SetUp" << std::endl;
}

std::shared_ptr<DSchedContinue> DSchedContinueSinkWaitEndStateTest::CreateObject()
{
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    std::shared_ptr<DSchedContinue> dContinue = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue->Init();
    return dContinue;
}

//DSchedContinueAbilityStateTest
void DSchedContinueAbilityStateTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueAbilityStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueAbilityStateTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueAbilityStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueAbilityStateTest::TearDown()
{
    abilityStateTest_ = nullptr;
    DTEST_LOG << "DSchedContinueAbilityStateTest::TearDown" << std::endl;
}

void DSchedContinueAbilityStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue);
    abilityStateTest_ = std::make_shared<DSchedContinueAbilityState>(stateMachine);
    DTEST_LOG << "DSchedContinueAbilityStateTest::SetUp" << std::endl;
}

std::shared_ptr<DSchedContinue> DSchedContinueAbilityStateTest::CreateObject()
{
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    std::shared_ptr<DSchedContinue> dContinue = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue->Init();
    return dContinue;
}

//DSchedContinueEndStateTest
void DSchedContinueEndStateTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueEndStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueEndStateTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueEndStateTest::TearDown()
{
    srcEndStateTest_ = nullptr;
    DTEST_LOG << "DSchedContinueEndStateTest::TearDown" << std::endl;
}

void DSchedContinueEndStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue);
    srcEndStateTest_ = std::make_shared<DSchedContinueEndState>(stateMachine);
    DTEST_LOG << "DSchedContinueEndStateTest::SetUp" << std::endl;
}

std::shared_ptr<DSchedContinue> DSchedContinueEndStateTest::CreateObject()
{
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    std::shared_ptr<DSchedContinue> dContinue = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue->Init();
    return dContinue;
}

//DSchedContinueSourceStartStateTest
void DSchedContinueSourceStartStateTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueSourceStartStateTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSourceStartStateTest::TearDown()
{
    srcStartStateTest_ == nullptr;
    DTEST_LOG << "DSchedContinueSourceStartStateTest::TearDown" << std::endl;
}

void DSchedContinueSourceStartStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue);
    srcStartStateTest_ = std::make_shared<DSchedContinueSourceStartState>(stateMachine);
    DTEST_LOG << "DSchedContinueSourceStartStateTest::SetUp" << std::endl;
}

std::shared_ptr<DSchedContinue> DSchedContinueSourceStartStateTest::CreateObject()
{
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    std::shared_ptr<DSchedContinue> dContinue = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue->Init();
    return dContinue;
}

//DSchedContinueWaitEndStateTest
void DSchedContinueWaitEndStateTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueWaitEndStateTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueWaitEndStateTest::TearDown()
{
    srcWaitEndTest_ = nullptr;
    DTEST_LOG << "DSchedContinueWaitEndStateTest::TearDown" << std::endl;
}

void DSchedContinueWaitEndStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue);
    srcWaitEndTest_ = std::make_shared<DSchedContinueWaitEndState>(stateMachine);
    DTEST_LOG << "DSchedContinueWaitEndStateTest::SetUp" << std::endl;
}

std::shared_ptr<DSchedContinue> DSchedContinueWaitEndStateTest::CreateObject()
{
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    std::shared_ptr<DSchedContinue> dContinue = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue->Init();
    return dContinue;
}

//DSchedContinueStateMachineTest
void DSchedContinueStateMachineTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueStateMachineTest::SetUpTestCase" << std::endl;
}

void DSchedContinueStateMachineTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueStateMachineTest::TearDownTestCase" << std::endl;
}

void DSchedContinueStateMachineTest::TearDown()
{
    DTEST_LOG << "DSchedContinueStateMachineTest::TearDown" << std::endl;
}

void DSchedContinueStateMachineTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    stateMachineTest_ = std::make_shared<DSchedContinueStateMachine>(dContinue);
    DTEST_LOG << "DSchedContinueStateMachineTest::SetUp" << std::endl;
}

std::shared_ptr<DSchedContinue> DSchedContinueStateMachineTest::CreateObject()
{
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    std::shared_ptr<DSchedContinue> dContinue = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue->Init();
    return dContinue;
}

/**
 * @tc.name: SinkExecuteTest001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkExecuteTest001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkExecuteTest001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = dataStateTest_->Execute(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);
    DTEST_LOG << "DSchedContinueDataStateTest SinkExecuteTest001 end" << std::endl;
}

/**
 * @tc.name: SinkGetStateType001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkGetStateType001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkGetStateType001 begin" << std::endl;
    int32_t ret = dataStateTest_->GetStateType();
    EXPECT_EQ(ret, DSCHED_CONTINUE_DATA_STATE);
    DTEST_LOG << "DSchedContinueDataStateTest SinkGetStateType001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueDataTask001
 * @tc.desc: DoContinueData
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkDoContinueDataTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueDataTask001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = dataStateTest_->DoContinueDataTask(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, DSCHED_CONTINUE_DATA_STATE);
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueDataTask001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueEndTask001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkDoContinueEndTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueEndTask001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = dataStateTest_->DoContinueEndTask(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueEndTask001 end" << std::endl;
}

 /**
 * @tc.name: TestSinkExecute001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkEndStateTest, TestSinkExecute001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkEndStateTest SinkExecuteTest001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = sinkEndStateTest_->Execute(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);
    DTEST_LOG << "DSchedContinueSinkEndStateTest TestSinkExecute001 end" << std::endl;
}

/**
 * @tc.name: TestSinkGetStateType001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkEndStateTest, TestSinkGetStateType001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkEndStateTest TestSinkGetStateType001 begin" << std::endl;
    int32_t ret = sinkEndStateTest_->GetStateType();
    EXPECT_EQ(ret, DSCHED_CONTINUE_SINK_END_STATE);
    DTEST_LOG << "DSchedContinueSinkEndStateTest TestSinkGetStateType001 end" << std::endl;
}

/**
 * @tc.name: TestSinkDoContinueEndTask001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkEndStateTest, TestSinkDoContinueEndTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkEndStateTest TestSinkDoContinueEndTask001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = sinkEndStateTest_->DoContinueEndTask(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueSinkEndStateTest TestSinkDoContinueEndTask001 end" << std::endl;
}

 /**
 * @tc.name: SinkExecuteTest_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkStartStateTest, SinkExecuteTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkExecuteTest_001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = sinkStartStateTest_->Execute(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkExecuteTest_001 end" << std::endl;
}

 /**
 * @tc.name: SinkGetStateTypeTest_001
 * @tc.desc: GetStateTypeTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkStartStateTest, SinkGetStateTypeTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkGetStateTypeTest_001 begin" << std::endl;
    int32_t ret = sinkStartStateTest_->GetStateType();
    EXPECT_EQ(ret, DSCHED_CONTINUE_SINK_START_STATE);
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkGetStateTypeTest_001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinuePullReqTaskTest_001
 * @tc.desc: DoContinuePullReqTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkStartStateTest, SinkDoContinuePullReqTaskTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkDoContinuePullReqTaskTest_001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = sinkStartStateTest_->DoContinuePullReqTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkDoContinuePullReqTaskTest_001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueAbilityTaskTest_001
 * @tc.desc: DoContinueAbilityTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkStartStateTest, SinkDoContinueAbilityTaskTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkDoContinueAbilityTaskTest_001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = sinkStartStateTest_->DoContinueAbilityTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkDoContinueAbilityTaskTest_001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueEndTaskTest_001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkStartStateTest, SinkDoContinueEndTaskTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkDoContinueEndTaskTest_001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = sinkStartStateTest_->DoContinueEndTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkDoContinueEndTaskTest_001 end" << std::endl;
}

 /**
 * @tc.name: SinkExecute001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkWaitEndStateTest, SinkExecute001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkExecute001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = sinkWaitEndTest_->Execute(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkExecute001 end" << std::endl;
}


 /**
 * @tc.name: SinkGetStateType001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkWaitEndStateTest, SinkGetStateType001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkGetStateType001 begin" << std::endl;
    int32_t ret = sinkWaitEndTest_->GetStateType();
    EXPECT_EQ(ret, DSCHED_CONTINUE_SINK_WAIT_END_STATE);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkGetStateType001 end" << std::endl;
}


 /**
 * @tc.name: SinkDoNotifyCompleteTask001
 * @tc.desc: DoNotifyCompleteTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkWaitEndStateTest, SinkDoNotifyCompleteTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoNotifyCompleteTask001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = sinkWaitEndTest_->DoNotifyCompleteTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoNotifyCompleteTask001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueEndTask001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkWaitEndStateTest, SinkDoContinueEndTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoContinueEndTask001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = sinkWaitEndTest_->DoContinueEndTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoContinueEndTask001 end" << std::endl;
}

 /**
 * @tc.name: SrcExecuteTest001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcExecuteTest001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcExecuteTest001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = abilityStateTest_->Execute(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcExecuteTest001 end" << std::endl;
}

 /**
 * @tc.name: SrcGetStateType001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcGetStateType001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcGetStateType001 begin" << std::endl;
    int32_t ret = abilityStateTest_->GetStateType();
    EXPECT_EQ(ret, DSCHED_CONTINUE_ABILITY_STATE);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcGetStateType001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueSendTask001
 * @tc.desc: DoContinueSendTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcDoContinueSendTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueSendTask001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = abilityStateTest_->DoContinueSendTask(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueSendTask001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueEndTask001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcDoContinueEndTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueEndTask001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = abilityStateTest_->DoContinueEndTask(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueEndTask001 end" << std::endl;
}

 /**
 * @tc.name: SrcExecuteTest001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEndStateTest, SrcExecuteTest001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEndStateTest SrcExecuteTest001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcEndStateTest_->Execute(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);
    DTEST_LOG << "DSchedContinueEndStateTest SrcExecuteTest001 end" << std::endl;
}

 /**
 * @tc.name: SrcGetStateTypeTest001
 * @tc.desc: GetStateTypeTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEndStateTest, SrcGetStateTypeTest001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEndStateTest SrcGetStateTypeTest001 begin" << std::endl;
    int32_t ret = srcEndStateTest_->GetStateType();
    EXPECT_EQ(ret, DSCHED_CONTINUE_SOURCE_END_STATE);
    DTEST_LOG << "DSchedContinueEndStateTest SrcGetStateTypeTest001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueEndTaskTest001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEndStateTest, SrcDoContinueEndTaskTest001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEndStateTest SrcDoContinueEndTaskTest001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcEndStateTest_->DoContinueEndTask(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueEndStateTest SrcDoContinueEndTaskTest001 end" << std::endl;
}

 /**
 * @tc.name: SrcExecuteTest_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcExecuteTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcExecuteTest_001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcStartStateTest_->Execute(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcExecuteTest_001 end" << std::endl;
}

 /**
 * @tc.name: SrcGetStateTypeTest_001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcGetStateTypeTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcGetStateTypeTest_001 begin" << std::endl;
    int32_t ret = srcStartStateTest_->GetStateType();
    EXPECT_EQ(ret, DSCHED_CONTINUE_SOURCE_START_STATE);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcGetStateTypeTest_001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinuePushReqTaskTest_001
 * @tc.desc: DoContinuePushReqTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcDoContinuePushReqTaskTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinuePushReqTaskTest_001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcStartStateTest_->DoContinuePushReqTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinuePushReqTaskTest_001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueAbilityTaskTest_001
 * @tc.desc: DoContinueAbilityTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcDoContinueAbilityTaskTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueAbilityTaskTest_001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcStartStateTest_->DoContinueAbilityTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueAbilityTaskTest_001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueEndTaskTest_001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcDoContinueEndTaskTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueEndTaskTest_001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcStartStateTest_->DoContinueEndTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueEndTaskTest_001 end" << std::endl;
}

 /**
 * @tc.name: SrcExecute_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueWaitEndStateTest, SrcExecute_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcExecute_001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcWaitEndTest_->Execute(dContinue, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcExecute_001 end" << std::endl;
}

 /**
 * @tc.name: SrcGetStateType_001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueWaitEndStateTest, SrcGetStateType_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcGetStateType_001 begin" << std::endl;
    int32_t ret = srcWaitEndTest_->GetStateType();
    EXPECT_EQ(ret, DSCHED_CONTINUE_SOURCE_WAIT_END_STATE);
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcGetStateType_001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoNotifyCompleteTask_001
 * @tc.desc: DoNotifyCompleteTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueWaitEndStateTest, SrcDoNotifyCompleteTask_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoNotifyCompleteTask_001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcWaitEndTest_->DoNotifyCompleteTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoNotifyCompleteTask_001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueEndTask_001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueWaitEndStateTest, SrcDoContinueEndTask_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoContinueEndTask_001 begin" << std::endl;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    event->innerEventId_ = static_cast<uint32_t>(-1);;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcWaitEndTest_->DoContinueEndTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoContinueEndTask_001 end" << std::endl;
}


 /**
 * @tc.name: Execute_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueStateMachineTest, Execute_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueStateMachineTest Execute_001 begin" << std::endl;
    AppExecFwk::InnerEvent *event = nullptr;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
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
    DSchedContinueStateType stateType = DSCHED_CONTINUE_ABILITY_STATE;
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    std::shared_ptr<DSchedContinue> dContinue = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue->Init();
    auto stateMachine = std::make_shared<DSchedContinueStateMachine>(dContinue);
    stateMachineTest_->currentState_ = std::make_shared<DSchedContinueDataState>(stateMachine);
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
    stateMachineTest_->currentState_ = nullptr;
    DSchedContinueStateType ret = stateMachineTest_->GetStateType();
    EXPECT_EQ(ret, DSCHED_CONTINUE_SOURCE_START_STATE);
    DTEST_LOG << "DSchedContinueStateMachineTest GetStateType_001 end" << std::endl;
}
}
}