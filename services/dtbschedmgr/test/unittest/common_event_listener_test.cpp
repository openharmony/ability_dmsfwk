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

#include "common_event_listener.h"

#include "gtest/gtest.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
class CommonEventListenerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<CommonEventListener> applyMonitor = nullptr;
};

void CommonEventListenerTest::SetUpTestCase()
{
}

void CommonEventListenerTest::TearDownTestCase()
{
}

void CommonEventListenerTest::SetUp()
{
    EventFwk::MatchingSkills matchingSkills;
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    matchingSkills.AddEvent(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    EventFwk::CommonEventSubscribeInfo subscribeInfo(matchingSkills);
    applyMonitor = std::make_shared<CommonEventListener>(subscribeInfo);
}

void CommonEventListenerTest::TearDown()
{
}

/**
 * @tc.name: OnReceiveEvent001
 * @tc.desc: call OnReceiveEvent
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventListenerTest, OnReceiveEvent001, TestSize.Level3)
{
    DTEST_LOG << "CommonEventListenerTest OnReceiveEvent001 start" << std::endl;
    AAFwk::Want want;
    EventFwk::CommonEventData eventData;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_LOCKED);
    eventData.SetWant(want);
    applyMonitor->OnReceiveEvent(eventData);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF);
    eventData.SetWant(want);
    applyMonitor->OnReceiveEvent(eventData);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_UNLOCKED);
    eventData.SetWant(want);
    applyMonitor->OnReceiveEvent(eventData);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON);
    eventData.SetWant(want);
    applyMonitor->OnReceiveEvent(eventData);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED);
    eventData.SetWant(want);
    EXPECT_NO_FATAL_FAILURE(applyMonitor->OnReceiveEvent(eventData));
    DTEST_LOG << "CommonEventListenerTest OnReceiveEvent001 end" << std::endl;
}

/**
 * @tc.name: OnReceiveEvent002
 * @tc.desc: call OnReceiveEvent
 * @tc.type: FUNC
 */
HWTEST_F(CommonEventListenerTest, OnReceiveEvent002, TestSize.Level3)
{
    DTEST_LOG << "CommonEventListenerTest OnReceiveEvent002 start" << std::endl;
    AAFwk::Want want;
    EventFwk::CommonEventData eventData;
    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED);
    eventData.SetWant(want);
    applyMonitor->OnReceiveEvent(eventData);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED);
    eventData.SetWant(want);
    applyMonitor->OnReceiveEvent(eventData);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED);
    eventData.SetWant(want);
    applyMonitor->OnReceiveEvent(eventData);

    want.SetAction(EventFwk::CommonEventSupport::COMMON_EVENT_USER_REMOVED);
    eventData.SetWant(want);
    applyMonitor->OnReceiveEvent(eventData);

    want.SetAction("receiveEvent");
    eventData.SetWant(want);
    EXPECT_NO_FATAL_FAILURE(applyMonitor->OnReceiveEvent(eventData));
    DTEST_LOG << "CommonEventListenerTest OnReceiveEvent002 end" << std::endl;
}
}
}
