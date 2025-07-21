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

#include "dsched_continue_src_state_test.h"

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

//DSchedContinueEndStateTest
void DSchedContinueEndStateTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueEndStateTest::SetUpTestCase" << std::endl;
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    dContinue_ = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue_->Init();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue_);
    srcEndStateTest_ = std::make_shared<DSchedContinueEndState>(stateMachine);
}

void DSchedContinueEndStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    dContinue_ = nullptr;
    srcEndStateTest_ = nullptr;
    DTEST_LOG << "DSchedContinueEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueEndStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueEndStateTest::TearDown" << std::endl;
}

void DSchedContinueEndStateTest::SetUp()
{
    DTEST_LOG << "DSchedContinueEndStateTest::SetUp" << std::endl;
}

//DSchedContinueSourceStartStateTest
void DSchedContinueSourceStartStateTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    dContinue_ = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue_->Init();

    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue_);
    srcStartStateTest_ = std::make_shared<DSchedContinueSourceStartState>(stateMachine);
    DTEST_LOG << "DSchedContinueSourceStartStateTest::SetUpTestCase" << std::endl;
    usleep(WAITTIME);
}

void DSchedContinueSourceStartStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    dContinue_ = nullptr;
    srcStartStateTest_ = nullptr;
    DTEST_LOG << "DSchedContinueSourceStartStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSourceStartStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueSourceStartStateTest::TearDown" << std::endl;
}

void DSchedContinueSourceStartStateTest::SetUp()
{
    DTEST_LOG << "DSchedContinueSourceStartStateTest::SetUp" << std::endl;
}

//DSchedContinueWaitEndStateTest
void DSchedContinueWaitEndStateTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueWaitEndStateTest::SetUpTestCase" << std::endl;
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    dContinue_ = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue_->Init();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue_);
    srcWaitEndTest_ = std::make_shared<DSchedContinueWaitEndState>(stateMachine);
    usleep(WAITTIME);
}

void DSchedContinueWaitEndStateTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    dContinue_ = nullptr;
    srcWaitEndTest_ = nullptr;
    DTEST_LOG << "DSchedContinueWaitEndStateTest::TearDownTestCase" << std::endl;
}

void DSchedContinueWaitEndStateTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueWaitEndStateTest::TearDown" << std::endl;
}

void DSchedContinueWaitEndStateTest::SetUp()
{
    DTEST_LOG << "DSchedContinueWaitEndStateTest::SetUp" << std::endl;
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
            event = nullptr;
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
            event = nullptr;
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
            event = nullptr;
        }
    };
    int32_t ret = srcEndStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcEndStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcEndStateTest_->DoContinueEndTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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
    int32_t ret = srcEndStateTest_->DoContinueEndTask(dContinue_, event);
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
            event = nullptr;
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
            event = nullptr;
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
            event = nullptr;
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
            event = nullptr;
        }
    };

    int32_t ret = srcStartStateTest_->DoContinuePushReqTask(dContinue_,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcStartStateTest_->DoContinueErrorTask(dContinue_,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcStartStateTest_->DoContinueAbilityTask(dContinue_,
        AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcStartStateTest_->DoContinueEndTask(dContinue_,
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

    int32_t ret = srcStartStateTest_->DoContinuePushReqTask(dContinue_, event);
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
            event = nullptr;
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

    int32_t ret = srcStartStateTest_->DoContinueAbilityTask(dContinue_, event);
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
            event = nullptr;
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

    int32_t ret = srcStartStateTest_->DoContinueEndTask(dContinue_, event);
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
            event = nullptr;
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

    int32_t ret = srcStartStateTest_->DoContinueErrorTask(dContinue_, event);
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
            event = nullptr;
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
            event = nullptr;
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
            event = nullptr;
        }
    };
    int32_t ret = srcWaitEndTest_->DoNotifyCompleteTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcWaitEndTest_->DoNotifyCompleteTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcWaitEndTest_->DoNotifyCompleteTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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

    int32_t ret = srcWaitEndTest_->DoNotifyCompleteTask(dContinue_, event);
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
            event = nullptr;
        }
    };
    int32_t ret = srcWaitEndTest_->DoContinueEndTask(nullptr,
        AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcWaitEndTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = srcWaitEndTest_->DoContinueEndTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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

    int32_t ret = srcWaitEndTest_->DoContinueEndTask(dContinue_, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueWaitEndStateTest SrcDoContinueEndTask_002 end" << std::endl;
}


//DSchedContinueAbilityStateTest
void DSchedContinueAbilityStateTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueAbilityStateTest::SetUpTestCase" << std::endl;
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    dContinue_ = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue_->Init();
    std::shared_ptr<DSchedContinueStateMachine> stateMachine =
        std::make_shared<DSchedContinueStateMachine>(dContinue_);
    ASSERT_NE(dContinue_, nullptr);
    ASSERT_NE(stateMachine, nullptr);
    abilityStateTest_ = std::make_shared<DSchedContinueAbilityState>(stateMachine);
    usleep(WAITTIME);
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
    DTEST_LOG << "DSchedContinueAbilityStateTest::SetUp" << std::endl;
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
            event = nullptr;
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
            event = nullptr;
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
            event = nullptr;
        }
    };
    int32_t ret = abilityStateTest_->DoContinueSendTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = abilityStateTest_->DoContinueSendTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = abilityStateTest_->DoContinueSendTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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

    int32_t ret = abilityStateTest_->DoContinueSendTask(dContinue_, event);
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
            event = nullptr;
        }
    };
    int32_t ret = abilityStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = abilityStateTest_->DoContinueEndTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = abilityStateTest_->DoContinueEndTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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

    int32_t ret = abilityStateTest_->DoContinueErrorTask(dContinue_, event);
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
            event = nullptr;
        }
    };
    int32_t ret = abilityStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(event, destructor));
    EXPECT_NE(ret, ERR_OK);

    ret = abilityStateTest_->DoContinueErrorTask(nullptr, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = abilityStateTest_->DoContinueErrorTask(dContinue_, AppExecFwk::InnerEvent::Pointer(nullptr, nullptr));
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

    int32_t ret = abilityStateTest_->DoContinueEndTask(dContinue_, event);
    EXPECT_NE(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueAbilityStateTest SrcDoContinueEndTask002 end" << std::endl;
}
}
}
