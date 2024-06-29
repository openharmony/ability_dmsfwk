/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "dms_client_test.h"

#include "ability_manager_errors.h"
#include "distributed_parcel_helper.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string DEVICE_ID = "123456789ABCD";
}

void DistributedClientTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedClientTest::SetUpTestCase" << std::endl;
}

void DistributedClientTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedClientTest::TearDownTestCase" << std::endl;
}

void DistributedClientTest::SetUp()
{
    DTEST_LOG << "DistributedClientTest::SetUp" << std::endl;
}

void DistributedClientTest::TearDown()
{
    DTEST_LOG << "DistributedClientTest::TearDown" << std::endl;
}

void BusinessHandlerTest::DSchedEventNotify(EventNotify &notify)
{
}

/**
 * @tc.name: RegisterDSchedEventListener_001
 * @tc.desc: RegisterDSchedEventListener
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedClientTest, RegisterDSchedEventListener_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedClientTest RegisterDSchedEventListener_001 start" << std::endl;
    sptr<IDSchedEventListener> listener = sptr<IDSchedEventListener>(new BusinessHandlerTest());
    int32_t result = distributedClient_.RegisterDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedClientTest RegisterDSchedEventListener_001 end" << std::endl;
}

/**
 * @tc.name: UnRegisterDSchedEventListener_001
 * @tc.desc: UnRegisterDSchedEventListener
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedClientTest, UnRegisterDSchedEventListener_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedClientTest UnRegisterDSchedEventListener_001 start" << std::endl;
    sptr<IDSchedEventListener> listener = sptr<IDSchedEventListener>(new BusinessHandlerTest());
    int32_t result = distributedClient_.UnRegisterDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedClientTest UnRegisterDSchedEventListener_001 end" << std::endl;
}

/**
 * @tc.name: GetContinueInfo_001
 * @tc.desc: GetContinueInfo
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedClientTest, GetContinueInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedClientTest GetContinueInfo_001 start" << std::endl;
    ContinueInfo continueInfo;
    int32_t result = distributedClient_.GetContinueInfo(continueInfo);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);
    DTEST_LOG << "DistributedClientTest GetContinueInfo_001 end" << std::endl;
}

/**
 * @tc.name: GetDSchedEventInfo_001
 * @tc.desc: GetDSchedEventInfo
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedClientTest, GetDSchedEventInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedClientTest GetDSchedEventInfo_001 start" << std::endl;
    std::vector<EventNotify> events;
    int32_t result = distributedClient_.GetDSchedEventInfo(DMS_UNKNOW, events);
    EXPECT_NE(result, ERR_NONE);
    DTEST_LOG << "DistributedClientTest GetDSchedEventInfo_001 end" << std::endl;
}
}
}