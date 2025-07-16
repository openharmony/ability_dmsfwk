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

#include "dsched_continue_sink_state_test.h"

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


//DSchedContinueDataStateTest
void DSchedContinueDataStateTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    dContinue_ = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue_->Init();
    auto stateMachine = std::make_shared<DSchedContinueStateMachine>(dContinue_);
    dataStateTest_ = std::make_shared<DSchedContinueDataState>(stateMachine);
    usleep(WAITTIME);

    mockStateTest_ = std::make_shared<MockDmsMgrDeviceInfoStore>();
    DmsMgrDeviceInfoStore::dmsStore = mockStateTest_;
    DTEST_LOG << "DSchedContinueDataStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueDataStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DmsMgrDeviceInfoStore::dmsStore = nullptr;
    mockStateTest_ = nullptr;

    dContinue_ = nullptr;
    dataStateTest_ = nullptr;
    DTEST_LOG << "DSchedContinueDataStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueDataStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueDataStateTest::TearDown" << std::endl;
}

void DSchedContinueDataStateTest::SetUp()
{
    DTEST_LOG << "DSchedContinueDataStateTest::SetUp" << std::endl;
}


/**
 * @tc.name: SinkExecuteTest001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkExecuteTest001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkExecuteTest001 begin" << std::endl;
    ASSERT_NE(dataStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = dataStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);

    ret = dataStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueDataStateTest SinkExecuteTest001 end" << std::endl;
}

/**
 * @tc.name: SinkExecuteTest002
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkExecuteTest002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkExecuteTest002 begin" << std::endl;
    ASSERT_NE(dataStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(DSCHED_CONTINUE_DATA_EVENT);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = dataStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueDataStateTest SinkExecuteTest002 end" << std::endl;
}

/**
 * @tc.name: SinkGetStateType001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkGetStateType001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkGetStateType001 begin" << std::endl;
    ASSERT_NE(dataStateTest_, nullptr);
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
    ASSERT_NE(dataStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = dataStateTest_->DoContinueDataTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, DSCHED_CONTINUE_DATA_STATE);

    ret = dataStateTest_->DoContinueDataTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = dataStateTest_->DoContinueDataTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueDataTask001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueDataTask002
 * @tc.desc: DoContinueDataTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkDoContinueDataTask002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueDataTask002 begin" << std::endl;
    ASSERT_NE(dataStateTest_, nullptr);
    auto data = std::make_shared<DSchedContinueDataCmd>();
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_DATA_EVENT, data, 0);

    EXPECT_CALL(*mockStateTest_, GetLocalDeviceId(_)).WillOnce(Return(true)).WillOnce(Return(true));
    int32_t ret = dataStateTest_->DoContinueDataTask(dContinue_, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueDataTask002 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueEndTask001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkDoContinueEndTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueEndTask001 begin" << std::endl;
    ASSERT_NE(dataStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = dataStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    ret = dataStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = dataStateTest_->DoContinueEndTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueEndTask001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueEndTask002
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkDoContinueEndTask002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueEndTask002 begin" << std::endl;
    ASSERT_NE(dataStateTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_END_EVENT, data, 0);

    int32_t ret = dataStateTest_->DoContinueEndTask(dContinue_, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueEndTask002 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueErrorTask001
 * @tc.desc: DoContinueErrorTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkDoContinueErrorTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueErrorTask001 begin" << std::endl;
    ASSERT_NE(dataStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = dataStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    ret = dataStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = dataStateTest_->DoContinueErrorTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueErrorTask001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueErrorTask002
 * @tc.desc: DoContinueErrorTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueDataStateTest, SinkDoContinueErrorTask002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueErrorTask002 begin" << std::endl;
    ASSERT_NE(dataStateTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_COMPLETE_EVENT, data, 0);

    int32_t ret = dataStateTest_->DoContinueErrorTask(dContinue_, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueErrorTask002 end" << std::endl;
}

//DSchedContinueSinkEndStateTest
void DSchedContinueSinkEndStateTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueSinkEndStateTest::SetUpTestCase" << std::endl;
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    dContinue_ = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue_->Init();
    auto stateMachine = std::make_shared<DSchedContinueStateMachine>(dContinue_);
    sinkEndStateTest_ = std::make_shared<DSchedContinueSinkEndState>(stateMachine);
    usleep(WAITTIME);
}

void DSchedContinueSinkEndStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    dContinue_ = nullptr;
    sinkEndStateTest_ = nullptr;
    DTEST_LOG << "DSchedContinueSinkEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSinkEndStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueSinkEndStateTest::TearDown" << std::endl;
}

void DSchedContinueSinkEndStateTest::SetUp()
{
    DTEST_LOG << "DSchedContinueSinkEndStateTest::SetUp" << std::endl;
}

//DSchedContinueSinkStartStateTest
void DSchedContinueSinkStartStateTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueSinkStartStateTest::SetUpTestCase" << std::endl;
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    dContinue_ = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue_->Init();
    auto stateMachine = std::make_shared<DSchedContinueStateMachine>(dContinue_);
    sinkStartStateTest_ = std::make_shared<DSchedContinueSinkStartState>(stateMachine);
    usleep(WAITTIME);
}

void DSchedContinueSinkStartStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    dContinue_ = nullptr;
    sinkStartStateTest_ = nullptr;
    DTEST_LOG << "DSchedContinueSinkStartStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSinkStartStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueSinkStartStateTest::TearDown" << std::endl;
}

void DSchedContinueSinkStartStateTest::SetUp()
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest::SetUp" << std::endl;
}

//DSchedContinueSinkWaitEndStateTest
void DSchedContinueSinkWaitEndStateTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::SetUpTestCase" << std::endl;
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    dContinue_ = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue_->Init();
    auto stateMachine = std::make_shared<DSchedContinueStateMachine>(dContinue_);
    sinkWaitEndTest_ = std::make_shared<DSchedContinueSinkWaitEndState>(stateMachine);
    usleep(WAITTIME);
}

void DSchedContinueSinkWaitEndStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    dContinue_ = nullptr;
    sinkWaitEndTest_ = nullptr;
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSinkWaitEndStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::TearDown" << std::endl;
}

void DSchedContinueSinkWaitEndStateTest::SetUp()
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::SetUp" << std::endl;
}

 /**
 * @tc.name: TestSinkExecute001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkEndStateTest, TestSinkExecute001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkEndStateTest SinkExecuteTest001 begin" << std::endl;
    ASSERT_NE(sinkEndStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkEndStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);
    DTEST_LOG << "DSchedContinueSinkEndStateTest TestSinkExecute001 end" << std::endl;
}

 /**
 * @tc.name: TestSinkExecute002
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkEndStateTest, TestSinkExecute002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkEndStateTest SinkExecuteTest001 begin" << std::endl;
    ASSERT_NE(sinkEndStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(DSCHED_CONTINUE_END_EVENT);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkEndStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    ret = sinkEndStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkEndStateTest TestSinkExecute002 end" << std::endl;
}

/**
 * @tc.name: TestSinkGetStateType001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkEndStateTest, TestSinkGetStateType001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkEndStateTest TestSinkGetStateType001 begin" << std::endl;
    ASSERT_NE(sinkEndStateTest_, nullptr);
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
    ASSERT_NE(sinkEndStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkEndStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    sinkEndStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_NE(ret, ERR_OK);

    sinkEndStateTest_->DoContinueEndTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueSinkEndStateTest TestSinkDoContinueEndTask001 end" << std::endl;
}

/**
 * @tc.name: TestSinkDoContinueEndTask002
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkEndStateTest, TestSinkDoContinueEndTask002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkEndStateTest TestSinkDoContinueEndTask002 begin" << std::endl;
    ASSERT_NE(sinkEndStateTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_END_EVENT, data, 0);

    int32_t ret = sinkEndStateTest_->DoContinueEndTask(dContinue_, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkEndStateTest TestSinkDoContinueEndTask002 end" << std::endl;
}

 /**
 * @tc.name: SinkExecuteTest_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkStartStateTest, SinkExecuteTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkExecuteTest_001 begin" << std::endl;
    ASSERT_NE(sinkStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkStartStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);

    ret = sinkStartStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkExecuteTest_001 end" << std::endl;
}

 /**
 * @tc.name: SinkExecuteTest_002
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkStartStateTest, SinkExecuteTest_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkExecuteTest_002 begin" << std::endl;
    ASSERT_NE(sinkStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(DSCHED_CONTINUE_REQ_PULL_EVENT);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkStartStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkExecuteTest_002 end" << std::endl;
}

 /**
 * @tc.name: SinkGetStateTypeTest_001
 * @tc.desc: GetStateTypeTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkStartStateTest, SinkGetStateTypeTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkGetStateTypeTest_001 begin" << std::endl;
    ASSERT_NE(sinkStartStateTest_, nullptr);
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
    ASSERT_NE(sinkStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkStartStateTest_->DoContinuePullReqTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartStateTest_->DoContinuePullReqTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartStateTest_->DoContinuePullReqTask(dContinue_,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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
    ASSERT_NE(sinkStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkStartStateTest_->DoContinueAbilityTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartStateTest_->DoContinueAbilityTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartStateTest_->DoContinueAbilityTask(dContinue_,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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
    ASSERT_NE(sinkStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkStartStateTest_->DoContinueEndTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartStateTest_->DoContinueEndTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartStateTest_->DoContinueEndTask(dContinue_,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkDoContinueEndTaskTest_001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueErrorTask001
 * @tc.desc: DoContinueErrorTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkStartStateTest, SinkDoContinueErrorTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkDoContinueErrorTask001 begin" << std::endl;
    ASSERT_NE(sinkStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkStartStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    ret = sinkStartStateTest_->DoContinueErrorTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartStateTest_->DoContinueErrorTask(dContinue_,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkStartStateTest SinkDoContinueErrorTask001 end" << std::endl;
}

 /**
 * @tc.name: SinkExecute001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkWaitEndStateTest, SinkExecute001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkExecute001 begin" << std::endl;
    ASSERT_NE(sinkWaitEndTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkWaitEndTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);

    ret = sinkWaitEndTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkExecute001 end" << std::endl;
}

 /**
 * @tc.name: SinkExecute002
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkWaitEndStateTest, SinkExecute002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkExecute002 begin" << std::endl;
    ASSERT_NE(sinkWaitEndTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(DSCHED_CONTINUE_COMPLETE_EVENT);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkWaitEndTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkExecute002 end" << std::endl;
}

 /**
 * @tc.name: SinkGetStateType001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkWaitEndStateTest, SinkGetStateType001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkGetStateType001 begin" << std::endl;
    ASSERT_NE(sinkWaitEndTest_, nullptr);
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
    ASSERT_NE(sinkWaitEndTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkWaitEndTest_->DoNotifyCompleteTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkWaitEndTest_->DoNotifyCompleteTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkWaitEndTest_->DoNotifyCompleteTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoNotifyCompleteTask001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoNotifyCompleteTask002
 * @tc.desc: DoNotifyCompleteTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkWaitEndStateTest, SinkDoNotifyCompleteTask002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoNotifyCompleteTask002 begin" << std::endl;
    ASSERT_NE(sinkWaitEndTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_COMPLETE_EVENT, data, 0);

    int32_t ret = sinkWaitEndTest_->DoNotifyCompleteTask(dContinue_, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoNotifyCompleteTask002 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueEndTask001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkWaitEndStateTest, SinkDoContinueEndTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoContinueEndTask001 begin" << std::endl;
    ASSERT_NE(sinkWaitEndTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    int32_t ret = sinkWaitEndTest_->DoContinueEndTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkWaitEndTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkWaitEndTest_->DoContinueEndTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoContinueEndTask001 end" << std::endl;
}

 /**
 * @tc.name: SinkDoContinueEndTask002
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSinkWaitEndStateTest, SinkDoContinueEndTask002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoContinueEndTask002 begin" << std::endl;
    ASSERT_NE(sinkWaitEndTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_END_EVENT, data, 0);

    int32_t ret = sinkWaitEndTest_->DoContinueEndTask(dContinue_, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoContinueEndTask002 end" << std::endl;
}
}
}
