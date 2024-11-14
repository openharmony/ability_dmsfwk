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
namespace {
    const std::string BASEDIR = "/data/service/el1/public/database/DistributedSchedule";
    const int32_t WAITTIME = 2000;
}
//DSchedContinueDataStateTest
void DSchedContinueDataStateTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    mockStateTest_ = std::make_shared<MockDmsMgrDeviceInfoStore>();
    DmsMgrDeviceInfoStore::dmsStore = mockStateTest_;
    DTEST_LOG << "DSchedContinueDataStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueDataStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DmsMgrDeviceInfoStore::dmsStore = nullptr;
    mockStateTest_ = nullptr;
    DTEST_LOG << "DSchedContinueDataStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueDataStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueDataStateTest::TearDown" << std::endl;
}

void DSchedContinueDataStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine = std::make_shared<DSchedContinueStateMachine>(dContinue);
    dataStateTest_ = std::make_shared<DSchedContinueDataState>(stateMachine);
    DTEST_LOG << "DSchedContinueDataStateTest::SetUp" << std::endl;
    usleep(WAITTIME);
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
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueSinkEndStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueSinkEndStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DSchedContinueSinkEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSinkEndStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueSinkEndStateTest::TearDown" << std::endl;
}

void DSchedContinueSinkEndStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine = std::make_shared<DSchedContinueStateMachine>(dContinue);
    sinkEndStateTest_ = std::make_shared<DSchedContinueSinkEndState>(stateMachine);
    DTEST_LOG << "DSchedContinueSinkEndStateTest::SetUp" << std::endl;
    usleep(WAITTIME);
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
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueSinkStartStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueSinkStartStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DSchedContinueSinkStartStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSinkStartStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueSinkStartStateTest::TearDown" << std::endl;
}

void DSchedContinueSinkStartStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine = std::make_shared<DSchedContinueStateMachine>(dContinue);
    sinkStartStateTest_ = std::make_shared<DSchedContinueSinkStartState>(stateMachine);
    DTEST_LOG << "DSchedContinueSinkStartStateTest::SetUp" << std::endl;
    usleep(WAITTIME);
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
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueSinkWaitEndStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSinkWaitEndStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::TearDown" << std::endl;
}

void DSchedContinueSinkWaitEndStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue);
    sinkWaitEndTest_ = std::make_shared<DSchedContinueSinkWaitEndState>(stateMachine);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest::SetUp" << std::endl;
    usleep(WAITTIME);
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
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueAbilityStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueAbilityStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DSchedContinueAbilityStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueAbilityStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueAbilityStateTest::TearDown" << std::endl;
}

void DSchedContinueAbilityStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue);
    ASSERT_NE(dContinue, nullptr);
    ASSERT_NE(stateMachine, nullptr);
    abilityStateTest_ = std::make_shared<DSchedContinueAbilityState>(stateMachine);
    DTEST_LOG << "DSchedContinueAbilityStateTest::SetUp" << std::endl;
    usleep(WAITTIME);
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
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueEndStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueEndStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DSchedContinueEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueEndStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueEndStateTest::TearDown" << std::endl;
}

void DSchedContinueEndStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue);
    srcEndStateTest_ = std::make_shared<DSchedContinueEndState>(stateMachine);
    DTEST_LOG << "DSchedContinueEndStateTest::SetUp" << std::endl;
    usleep(WAITTIME);
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
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueSourceStartStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueSourceStartStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DSchedContinueSourceStartStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSourceStartStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueSourceStartStateTest::TearDown" << std::endl;
}

void DSchedContinueSourceStartStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue);
    srcStartStateTest_ = std::make_shared<DSchedContinueSourceStartState>(stateMachine);
    DTEST_LOG << "DSchedContinueSourceStartStateTest::SetUp" << std::endl;
    usleep(WAITTIME);
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
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueWaitEndStateTest::SetUpTestCase" << std::endl;
}

void DSchedContinueWaitEndStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DSchedContinueWaitEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueWaitEndStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueWaitEndStateTest::TearDown" << std::endl;
}

void DSchedContinueWaitEndStateTest::SetUp()
{
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue);
    srcWaitEndTest_ = std::make_shared<DSchedContinueWaitEndState>(stateMachine);
    DTEST_LOG << "DSchedContinueWaitEndStateTest::SetUp" << std::endl;
    usleep(WAITTIME);
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
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
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
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    stateMachineTest_ = std::make_shared<DSchedContinueStateMachine>(dContinue);
    DTEST_LOG << "DSchedContinueStateMachineTest::SetUp" << std::endl;
    usleep(WAITTIME);
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
    ASSERT_NE(dataStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
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
        }
    };
    int32_t ret = dataStateTest_->DoContinueDataTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, DSCHED_CONTINUE_DATA_STATE);

    ret = dataStateTest_->DoContinueDataTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = dataStateTest_->DoContinueDataTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    EXPECT_CALL(*mockStateTest_, GetLocalDeviceId(_)).WillOnce(Return(true));
    int32_t ret = dataStateTest_->DoContinueDataTask(dContinue, event);
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
        }
    };
    int32_t ret = dataStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    ret = dataStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = dataStateTest_->DoContinueEndTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = dataStateTest_->DoContinueEndTask(dContinue, event);
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
        }
    };
    int32_t ret = dataStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    ret = dataStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = dataStateTest_->DoContinueErrorTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = dataStateTest_->DoContinueErrorTask(dContinue, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueDataStateTest SinkDoContinueErrorTask002 end" << std::endl;
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
        }
    };
    int32_t ret = sinkEndStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    sinkEndStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_NE(ret, ERR_OK);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    sinkEndStateTest_->DoContinueEndTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = sinkEndStateTest_->DoContinueEndTask(dContinue, event);
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
        }
    };
    int32_t ret = sinkStartStateTest_->DoContinuePullReqTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartStateTest_->DoContinuePullReqTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = sinkStartStateTest_->DoContinuePullReqTask(dContinue,
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
        }
    };
    int32_t ret = sinkStartStateTest_->DoContinueAbilityTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartStateTest_->DoContinueAbilityTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = sinkStartStateTest_->DoContinueAbilityTask(dContinue,
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
        }
    };
    int32_t ret = sinkStartStateTest_->DoContinueEndTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkStartStateTest_->DoContinueEndTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = sinkStartStateTest_->DoContinueEndTask(dContinue,
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
        }
    };
    int32_t ret = sinkStartStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    ret = sinkStartStateTest_->DoContinueErrorTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = sinkStartStateTest_->DoContinueErrorTask(dContinue,
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
        }
    };
    int32_t ret = sinkWaitEndTest_->DoNotifyCompleteTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkWaitEndTest_->DoNotifyCompleteTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = sinkWaitEndTest_->DoNotifyCompleteTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = sinkWaitEndTest_->DoNotifyCompleteTask(dContinue, event);
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
        }
    };
    int32_t ret = sinkWaitEndTest_->DoContinueEndTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = sinkWaitEndTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = sinkWaitEndTest_->DoContinueEndTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = sinkWaitEndTest_->DoContinueEndTask(dContinue, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSinkWaitEndStateTest SinkDoContinueEndTask002 end" << std::endl;
}

 /**
 * @tc.name: SrcExecuteTest001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcExecuteTest001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcExecuteTest001 begin" << std::endl;
    ASSERT_NE(abilityStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = abilityStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);

    ret = abilityStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcExecuteTest001 end" << std::endl;
}

 /**
 * @tc.name: SrcExecuteTest002
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcExecuteTest002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcExecuteTest002 begin" << std::endl;
    ASSERT_NE(abilityStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(DSHCED_CONTINUE_SEND_DATA_EVENT);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = abilityStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcExecuteTest002 end" << std::endl;
}

 /**
 * @tc.name: SrcGetStateType001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcGetStateType001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcGetStateType001 begin" << std::endl;
    ASSERT_NE(abilityStateTest_, nullptr);
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
    ASSERT_NE(abilityStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = abilityStateTest_->DoContinueSendTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = abilityStateTest_->DoContinueSendTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = abilityStateTest_->DoContinueSendTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueSendTask001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueSendTask002
 * @tc.desc: DoContinueSendTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcDoContinueSendTask002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueSendTask002 begin" << std::endl;
    ASSERT_NE(abilityStateTest_, nullptr);
    auto data = std::make_shared<ContinueAbilityData>();
    auto event = AppExecFwk::InnerEvent::Get(DSHCED_CONTINUE_SEND_DATA_EVENT, data, 0);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = abilityStateTest_->DoContinueSendTask(dContinue, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueSendTask002 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueEndTask001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcDoContinueEndTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueEndTask001 begin" << std::endl;
    ASSERT_NE(abilityStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = abilityStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = abilityStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = abilityStateTest_->DoContinueEndTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueEndTask001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueErrorTask002
 * @tc.desc: DoContinueErrorTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcDoContinueErrorTask002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueErrorTask002 begin" << std::endl;
    ASSERT_NE(abilityStateTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_COMPLETE_EVENT, data, 0);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = abilityStateTest_->DoContinueErrorTask(dContinue, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueErrorTask002 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueErrorTask001
 * @tc.desc: DoContinueErrorTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcDoContinueErrorTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueErrorTask001 begin" << std::endl;
    ASSERT_NE(abilityStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = abilityStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    ret = abilityStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = abilityStateTest_->DoContinueErrorTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueErrorTask001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueEndTask002
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueAbilityStateTest, SrcDoContinueEndTask002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueEndTask002 begin" << std::endl;
    ASSERT_NE(abilityStateTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_END_EVENT, data, 0);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = abilityStateTest_->DoContinueEndTask(dContinue, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueEndTask002 end" << std::endl;
}

 /**
 * @tc.name: SrcExecuteTest001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEndStateTest, SrcExecuteTest001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEndStateTest SrcExecuteTest001 begin" << std::endl;
    ASSERT_NE(srcEndStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcEndStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);

    ret = srcEndStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueEndStateTest SrcExecuteTest001 end" << std::endl;
}

 /**
 * @tc.name: SrcExecuteTest002
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEndStateTest, SrcExecuteTest002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEndStateTest SrcExecuteTest002 begin" << std::endl;
    ASSERT_NE(srcEndStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(DSCHED_CONTINUE_END_EVENT);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcEndStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueEndStateTest SrcExecuteTest002 end" << std::endl;
}

 /**
 * @tc.name: SrcGetStateTypeTest001
 * @tc.desc: GetStateTypeTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEndStateTest, SrcGetStateTypeTest001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEndStateTest SrcGetStateTypeTest001 begin" << std::endl;
    ASSERT_NE(srcEndStateTest_, nullptr);
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
    ASSERT_NE(srcEndStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcEndStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcEndStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = srcEndStateTest_->DoContinueEndTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueEndStateTest SrcDoContinueEndTaskTest001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueEndTaskTest002
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEndStateTest, SrcDoContinueEndTaskTest002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEndStateTest SrcDoContinueEndTaskTest002 begin" << std::endl;
    ASSERT_NE(srcEndStateTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_END_EVENT, data, 0);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = srcEndStateTest_->DoContinueEndTask(dContinue, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueEndStateTest SrcDoContinueEndTaskTest002 end" << std::endl;
}

 /**
 * @tc.name: SrcExecuteTest_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcExecuteTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcExecuteTest_001 begin" << std::endl;
    ASSERT_NE(srcStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcStartStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);

    ret = srcStartStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcExecuteTest_001 end" << std::endl;
}

 /**
 * @tc.name: SrcExecuteTest_002
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcExecuteTest_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcExecuteTest_002 begin" << std::endl;
    ASSERT_NE(srcStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(DSHCED_CONTINUE_REQ_PUSH_EVENT);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcStartStateTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcExecuteTest_002 end" << std::endl;
}

 /**
 * @tc.name: SrcGetStateTypeTest_001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcGetStateTypeTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcGetStateTypeTest_001 begin" << std::endl;
    ASSERT_NE(srcStartStateTest_, nullptr);
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
    ASSERT_NE(srcStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcStartStateTest_->DoContinuePushReqTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcStartStateTest_->DoContinuePushReqTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinuePushReqTaskTest_001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinuePushReqTaskTest_002
 * @tc.desc: DoContinuePushReqTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcDoContinuePushReqTaskTest_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinuePushReqTaskTest_002 begin" << std::endl;
    ASSERT_NE(srcStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = srcStartStateTest_->DoContinuePushReqTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcStartStateTest_->DoContinueErrorTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcStartStateTest_->DoContinueAbilityTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcStartStateTest_->DoContinueEndTask(dContinue,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinuePushReqTaskTest_002 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinuePushReqTaskTest_003
 * @tc.desc: DoContinuePushReqTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcDoContinuePushReqTaskTest_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinuePushReqTaskTest_003 begin" << std::endl;
    ASSERT_NE(srcStartStateTest_, nullptr);
    AAFwk::WantParams wantParams;
    auto wantParamsPtr = std::make_shared<OHOS::AAFwk::WantParams>(wantParams);
    auto event = AppExecFwk::InnerEvent::Get(DSHCED_CONTINUE_REQ_PUSH_EVENT, wantParamsPtr, 0);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = srcStartStateTest_->DoContinuePushReqTask(dContinue, event);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinuePushReqTaskTest_003 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueAbilityTaskTest_001
 * @tc.desc: DoContinueAbilityTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcDoContinueAbilityTaskTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueAbilityTaskTest_001 begin" << std::endl;
    ASSERT_NE(srcStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcStartStateTest_->DoContinueAbilityTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcStartStateTest_->DoContinueAbilityTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueAbilityTaskTest_001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueAbilityTaskTest_002
 * @tc.desc: DoContinueAbilityTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcDoContinueAbilityTaskTest_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueAbilityTaskTest_002 begin" << std::endl;
    ASSERT_NE(srcStartStateTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSHCED_CONTINUE_ABILITY_EVENT, data, 0);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = srcStartStateTest_->DoContinueAbilityTask(dContinue, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueAbilityTaskTest_002 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueEndTaskTest_001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcDoContinueEndTaskTest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueEndTaskTest_001 begin" << std::endl;
    ASSERT_NE(srcStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcStartStateTest_->DoContinueEndTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcStartStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueEndTaskTest_001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueEndTaskTest_002
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcDoContinueEndTaskTest_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueEndTaskTest_002 begin" << std::endl;
    ASSERT_NE(srcStartStateTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_END_EVENT, data, 0);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = srcStartStateTest_->DoContinueEndTask(dContinue, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueEndTaskTest_002 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueErrorTask001
 * @tc.desc: DoContinueErrorTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcDoContinueErrorTask001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueErrorTask001 begin" << std::endl;
    ASSERT_NE(srcStartStateTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcStartStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    ret = srcStartStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueErrorTask001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueErrorTaskTest_002
 * @tc.desc: DoContinueErrorTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSourceStartStateTest, SrcDoContinueErrorTaskTest_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueErrorTaskTest_002 begin" << std::endl;
    ASSERT_NE(srcStartStateTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_COMPLETE_EVENT, data, 0);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = srcStartStateTest_->DoContinueErrorTask(dContinue, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSourceStartStateTest SrcDoContinueErrorTaskTest_002 end" << std::endl;
}

 /**
 * @tc.name: SrcExecute_001
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueWaitEndStateTest, SrcExecute_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcExecute_001 begin" << std::endl;
    ASSERT_NE(srcWaitEndTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcWaitEndTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, CONTINUE_STATE_MACHINE_INVALID_STATE);

    ret = srcWaitEndTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcExecute_001 end" << std::endl;
}

 /**
 * @tc.name: SrcExecute_002
 * @tc.desc: Execute
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueWaitEndStateTest, SrcExecute_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcExecute_002 begin" << std::endl;
    ASSERT_NE(srcWaitEndTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(DSCHED_CONTINUE_COMPLETE_EVENT);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcWaitEndTest_->Execute(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcExecute_002 end" << std::endl;
}

 /**
 * @tc.name: SrcGetStateType_001
 * @tc.desc: GetStateType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueWaitEndStateTest, SrcGetStateType_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcGetStateType_001 begin" << std::endl;
    ASSERT_NE(srcWaitEndTest_, nullptr);
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
    ASSERT_NE(srcWaitEndTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcWaitEndTest_->DoNotifyCompleteTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcWaitEndTest_->DoNotifyCompleteTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = srcWaitEndTest_->DoNotifyCompleteTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoNotifyCompleteTask_001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoNotifyCompleteTask_002
 * @tc.desc: DoNotifyCompleteTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueWaitEndStateTest, SrcDoNotifyCompleteTask_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoNotifyCompleteTask_002 begin" << std::endl;
    ASSERT_NE(srcWaitEndTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_COMPLETE_EVENT, data, 0);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = srcWaitEndTest_->DoNotifyCompleteTask(dContinue, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoNotifyCompleteTask_002 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueEndTask_001
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueWaitEndStateTest, SrcDoContinueEndTask_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoContinueEndTask_001 begin" << std::endl;
    ASSERT_NE(srcWaitEndTest_, nullptr);
    AppExecFwk::InnerEvent *event = new AppExecFwk::InnerEvent();
    ASSERT_NE(event, nullptr);
    event->innerEventId_ = static_cast<uint32_t>(-1);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    int32_t ret = srcWaitEndTest_->DoContinueEndTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcWaitEndTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    ret = srcWaitEndTest_->DoContinueEndTask(dContinue, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoContinueEndTask_001 end" << std::endl;
}

 /**
 * @tc.name: SrcDoContinueEndTask_002
 * @tc.desc: DoContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueWaitEndStateTest, SrcDoContinueEndTask_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoContinueEndTask_002 begin" << std::endl;
    ASSERT_NE(srcWaitEndTest_, nullptr);
    auto data = std::make_shared<int32_t>(1);
    auto event = AppExecFwk::InnerEvent::Get(DSCHED_CONTINUE_END_EVENT, data, 0);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    int32_t ret = srcWaitEndTest_->DoContinueEndTask(dContinue, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoContinueEndTask_002 end" << std::endl;
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
