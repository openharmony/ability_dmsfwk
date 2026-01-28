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

#include "dsched_continue_event_handler_test.h"

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

void DSchedContinueEventHandlerTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    dContinue_ = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue_->Init();

    runner_ = AppExecFwk::EventRunner::Create();
    eventHandler_ = std::make_shared<DSchedContinueEventHandler>(runner_, dContinue_);

    DTEST_LOG << "DSchedContinueEventHandlerTest::SetUpTestCase" << std::endl;
}

void DSchedContinueEventHandlerTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DSchedContinueEventHandlerTest::TearDownTestCase" << std::endl;
}

void DSchedContinueEventHandlerTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueEventHandlerTest::TearDown" << std::endl;
}

void DSchedContinueEventHandlerTest::SetUp()
{
    DTEST_LOG << "DSchedContinueEventHandlerTest::SetUp" << std::endl;
}

/**
 * @tc.name: Constructor_001
 * @tc.desc: Test DSchedContinueEventHandler constructor with valid parameters
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventHandlerTest, Constructor_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEventHandlerTest Constructor_001 begin" << std::endl;

    auto testRunner = AppExecFwk::EventRunner::Create();
    ASSERT_NE(testRunner, nullptr);

    auto testHandler = std::make_shared<DSchedContinueEventHandler>(testRunner, dContinue_);
    EXPECT_NE(testHandler, nullptr);

    DTEST_LOG << "DSchedContinueEventHandlerTest Constructor_001 end" << std::endl;
}

/**
 * @tc.name: Constructor_002
 * @tc.desc: Test DSchedContinueEventHandler constructor with nullptr DSchedContinue
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventHandlerTest, Constructor_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEventHandlerTest Constructor_002 begin" << std::endl;

    auto testRunner = AppExecFwk::EventRunner::Create();
    ASSERT_NE(testRunner, nullptr);

    std::shared_ptr<DSchedContinue> nullContinue = nullptr;
    auto testHandler = std::make_shared<DSchedContinueEventHandler>(testRunner, nullContinue);
    EXPECT_NE(testHandler, nullptr);

    DTEST_LOG << "DSchedContinueEventHandlerTest Constructor_002 end" << std::endl;
}

/**
 * @tc.name: ProcessEvent_001
 * @tc.desc: Test ProcessEvent with nullptr event
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventHandlerTest, ProcessEvent_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEventHandlerTest ProcessEvent_001 begin" << std::endl;

    ASSERT_NE(eventHandler_, nullptr);

    AppExecFwk::InnerEvent *event = nullptr;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };

    // Should not crash when event is nullptr
    eventHandler_->ProcessEvent(AppExecFwk::InnerEvent::Pointer(event, destructor));

    DTEST_LOG << "DSchedContinueEventHandlerTest ProcessEvent_001 end" << std::endl;
}

/**
 * @tc.name: ProcessEvent_002
 * @tc.desc: Test ProcessEvent with valid event but expired weak_ptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventHandlerTest, ProcessEvent_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEventHandlerTest ProcessEvent_002 begin" << std::endl;

    auto testRunner = AppExecFwk::EventRunner::Create();
    ASSERT_NE(testRunner, nullptr);

    // Create handler with nullptr DSchedContinue (weak_ptr will be empty)
    std::shared_ptr<DSchedContinue> nullContinue = nullptr;
    auto testHandler = std::make_shared<DSchedContinueEventHandler>(testRunner, nullContinue);
    ASSERT_NE(testHandler, nullptr);

    // Create a valid event
    AppExecFwk::InnerEvent *event = AppExecFwk::InnerEvent::Create(0, nullptr, 0);
    ASSERT_NE(event, nullptr);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };

    // Should not crash when dContinue weak_ptr is expired
    testHandler->ProcessEvent(AppExecFwk::InnerEvent::Pointer(event, destructor));

    DTEST_LOG << "DSchedContinueEventHandlerTest ProcessEvent_002 end" << std::endl;
}

/**
 * @tc.name: ProcessEvent_003
 * @tc.desc: Test ProcessEvent with valid event and valid DSchedContinue
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventHandlerTest, ProcessEvent_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEventHandlerTest ProcessEvent_003 begin" << std::endl;

    ASSERT_NE(eventHandler_, nullptr);
    ASSERT_NE(dContinue_, nullptr);

    // Create a valid event
    AppExecFwk::InnerEvent *event = AppExecFwk::InnerEvent::Create(0, nullptr, 0);
    ASSERT_NE(event, nullptr);
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };

    // Should forward to dContinue->ProcessEvent
    eventHandler_->ProcessEvent(AppExecFwk::InnerEvent::Pointer(event, destructor));

    DTEST_LOG << "DSchedContinueEventHandlerTest ProcessEvent_003 end" << std::endl;
}

/**
 * @tc.name: ProcessEvent_004
 * @tc.desc: Test ProcessEvent with different event codes
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventHandlerTest, ProcessEvent_004, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueEventHandlerTest ProcessEvent_004 begin" << std::endl;

    ASSERT_NE(eventHandler_, nullptr);
    ASSERT_NE(dContinue_, nullptr);

    // Test with various event codes
    for (int32_t eventId = 0; eventId < 5; eventId++) {
        AppExecFwk::InnerEvent *event = AppExecFwk::InnerEvent::Create(eventId, nullptr, 0);
        ASSERT_NE(event, nullptr);
        auto destructor = [](AppExecFwk::InnerEvent *event) {
            if (event != nullptr) {
                delete event;
                event = nullptr;
            }
        };

        eventHandler_->ProcessEvent(AppExecFwk::InnerEvent::Pointer(event, destructor));
    }

    DTEST_LOG << "DSchedContinueEventHandlerTest ProcessEvent_004 end" << std::endl;
}

} // namespace DistributedSchedule
} // namespace OHOS
