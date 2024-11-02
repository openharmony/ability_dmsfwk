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

#ifndef DSCHED_CONTINUE_STATE_TEST_H
#define DSCHED_CONTINUE_STATE_TEST_H

#include "gtest/gtest.h"

#include "dsched_continue_data_state.h"
#include "dsched_continue_sink_end_state.h"
#include "dsched_continue_sink_start_state.h"
#include "dsched_continue_sink_wait_end_state.h"
#include "dsched_continue_ability_state.h"
#include "dsched_continue_source_end_state.h"
#include "dsched_continue_source_start_state.h"
#include "dsched_continue_source_wait_end_state.h"
#include "dsched_continue_state_machine.h"
#include "mock_dtbschedmgr_device_info.h"

namespace OHOS {
namespace DistributedSchedule {

class DSchedContinueDataStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedContinue> CreateObject();
    std::shared_ptr<DSchedContinueDataState> dataStateTest_;
    static inline std::shared_ptr<MockDmsMgrDeviceInfoStore> mockStateTest_ = nullptr;
};

class DSchedContinueSinkEndStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedContinue> CreateObject();
    std::shared_ptr<DSchedContinueSinkEndState> sinkEndStateTest_;
};

class DSchedContinueSinkStartStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedContinue> CreateObject();
    std::shared_ptr<DSchedContinueSinkStartState> sinkStartStateTest_;
};

class DSchedContinueSinkWaitEndStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedContinue> CreateObject();
    std::shared_ptr<DSchedContinueSinkWaitEndState> sinkWaitEndTest_;
};

class DSchedContinueAbilityStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedContinue> CreateObject();
    std::shared_ptr<DSchedContinueAbilityState> abilityStateTest_;
};

class DSchedContinueEndStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedContinue> CreateObject();
    std::shared_ptr<DSchedContinueEndState> srcEndStateTest_;
};

class DSchedContinueSourceStartStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedContinue> CreateObject();
    std::shared_ptr<DSchedContinueSourceStartState> srcStartStateTest_;
};

class DSchedContinueWaitEndStateTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedContinue> CreateObject();
    std::shared_ptr<DSchedContinueWaitEndState> srcWaitEndTest_;
};

class DSchedContinueStateMachineTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedContinue> CreateObject();
    std::shared_ptr<DSchedContinueStateMachine> stateMachineTest_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DSCHED_CONTINUE_STATE_TEST_H