/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "app_state_observer_test.h"

#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t FOREGROUND = 2;
constexpr int32_t BACKGROUND = 4;
}

void AppStateObserverTest::SetUpTestCase()
{
    DTEST_LOG << "AppStateObserverTest::SetUpTestCase" << std::endl;
}

void AppStateObserverTest::TearDownTestCase()
{
    DTEST_LOG << "AppStateObserverTest::TearDownTestCase" << std::endl;
}

void AppStateObserverTest::TearDown()
{
    DTEST_LOG << "AppStateObserverTest::TearDown" << std::endl;
}

void AppStateObserverTest::SetUp()
{
    DTEST_LOG << "AppStateObserverTest::SetUp" << std::endl;
    appStateObserver_ = new AppStateObserver();
}

/**
 * @tc.name: OnAbilityStateChanged_001
 * @tc.desc: call OnAbilityStateChanged from distributedsched
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AppStateObserverTest, OnAbilityStateChanged_001, TestSize.Level3)
{
    DTEST_LOG << "AppStateObserverTest OnAbilityStateChanged_001 begin" << std::endl;

    AppExecFwk::AppStateData appStateData;
    appStateObserver_->OnForegroundApplicationChanged(appStateData);

    AppExecFwk::AbilityStateData extensionStateData;
    appStateObserver_->OnExtensionStateChanged(extensionStateData);

    AppExecFwk::ProcessData processData;
    appStateObserver_->OnProcessCreated(processData);
    appStateObserver_->OnProcessDied(processData);

    AppExecFwk::AbilityStateData abilityStateData;
    appStateObserver_->OnAbilityStateChanged(abilityStateData);
    EXPECT_NE(appStateObserver_, nullptr);
    DTEST_LOG << "AppStateObserverTest OnAbilityStateChanged_001 end" << std::endl;
}

/**
 * @tc.name: OnAbilityStateChanged_002
 * @tc.desc: call OnAbilityStateChanged from distributedsched
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AppStateObserverTest, OnAbilityStateChanged_002, TestSize.Level3)
{
    DTEST_LOG << "AppStateObserverTest OnAbilityStateChanged_001 begin" << std::endl;
    AppExecFwk::AbilityStateData abilityStateData;
    abilityStateData.abilityState = FOREGROUND;
    appStateObserver_->OnAbilityStateChanged(abilityStateData);
    EXPECT_NE(appStateObserver_, nullptr);

    appStateObserver_->OnAbilityStateChanged(abilityStateData);
    EXPECT_NE(appStateObserver_, nullptr);
    DTEST_LOG << "AppStateObserverTest OnAbilityStateChanged_001 end" << std::endl;
}

/**
 * @tc.name: OnAbilityStateChanged_003
 * @tc.desc: call OnAbilityStateChanged from distributedsched
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(AppStateObserverTest, OnAbilityStateChanged_003, TestSize.Level3)
{
    DTEST_LOG << "AppStateObserverTest OnAbilityStateChanged_001 begin" << std::endl;
    AppExecFwk::AbilityStateData abilityStateData;
    abilityStateData.abilityState = BACKGROUND;
    appStateObserver_->OnAbilityStateChanged(abilityStateData);
    EXPECT_NE(appStateObserver_, nullptr);

    appStateObserver_->OnAbilityStateChanged(abilityStateData);
    EXPECT_NE(appStateObserver_, nullptr);
    DTEST_LOG << "AppStateObserverTest OnAbilityStateChanged_003 end" << std::endl;
}
}
}