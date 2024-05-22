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

#define PRIVATE PUBILC
#include "dms_handler_test.h"
#undef PRIVATE

#include "dtbschedmgr_log.h"
#include "single_instance.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
}

void DmsHandlerTest::SetUpTestCase()
{
    DTEST_LOG << "DmsHandlerTest::SetUpTestCase" << std::endl;
}

void DmsHandlerTest::TearDownTestCase()
{
    DTEST_LOG << "DmsHandlerTest::TearDownTestCase" << std::endl;
}

void DmsHandlerTest::SetUp()
{
    DTEST_LOG << "DmsHandlerTest::SetUp" << std::endl;
}

void DmsHandlerTest::TearDown()
{
    DTEST_LOG << "DmsHandlerTest::TearDown" << std::endl;
}

void DmsHandlerTest::DSchedEventNotify(EventNotify &notify)
{
}

void BusinessTest::DSchedEventNotify(EventNotify &notify)
{
}

/**
 * @tc.name: RegisterDSchedEventListener_001
 * @tc.desc: RegisterDSchedEventListener listener is null
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DmsHandlerTest, RegisterDSchedEventListener_001, TestSize.Level3)
{
    DTEST_LOG << "DmsHandlerTest RegisterDSchedEventListener_001 start" << std::endl;
    sptr<IDSchedEventListener> listener = nullptr;
    int32_t result = dmsHandler_.RegisterDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result, GET_REMOTE_DMS_FAIL);
    DTEST_LOG << "DmsHandlerTest RegisterDSchedEventListener_001 end" << std::endl;
}

/**
 * @tc.name: RegisterDSchedEventListener_002
 * @tc.desc: RegisterDSchedEventListener
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DmsHandlerTest, RegisterDSchedEventListener_002, TestSize.Level3)
{
    DTEST_LOG << "DmsHandlerTest RegisterDSchedEventListener_002 start" << std::endl;
    sptr<IDSchedEventListener> listener = sptr<IDSchedEventListener>(new BusinessTest());
    int32_t result = dmsHandler_.RegisterDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result, 0);
    DTEST_LOG << "DmsHandlerTest RegisterDSchedEventListener_002 end" << std::endl;
}

/**
 * @tc.name: UnRegisterDSchedEventListener_001
 * @tc.desc: UnRegisterDSchedEventListener listener is null
 * @tc.type: FUNC
 * @tc.require: I64FU7s
 */
HWTEST_F(DmsHandlerTest, UnRegisterDSchedEventListener_001, TestSize.Level3)
{
    DTEST_LOG << "DmsHandlerTest UnRegisterDSchedEventListener_001 start" << std::endl;
    sptr<IDSchedEventListener> listener = nullptr;
    int32_t result = dmsHandler_.UnRegisterDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result, GET_REMOTE_DMS_FAIL);
    DTEST_LOG << "DmsHandlerTest UnRegisterDSchedEventListener_001 end" << std::endl;
}

/**
 * @tc.name: UnRegisterDSchedEventListener_002
 * @tc.desc: UnRegisterDSchedEventListener listener not is null
 * @tc.type: FUNC
 * @tc.require: I64FU7s
 */
HWTEST_F(DmsHandlerTest, UnRegisterDSchedEventListener_002, TestSize.Level3)
{
    DTEST_LOG << "DmsHandlerTest UnRegisterDSchedEventListener_002 start" << std::endl;
    sptr<IDSchedEventListener> listener = sptr<IDSchedEventListener>(new BusinessTest());
    int32_t result = dmsHandler_.UnRegisterDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result, 0);
    DTEST_LOG << "DmsHandlerTest UnRegisterDSchedEventListener_002 end" << std::endl;
}

/**
 * @tc.name: GetContinueInfo_001
 * @tc.desc: GetContinueInfo listener not is null
 * @tc.type: FUNC
 * @tc.require: I64FU7s
 */
HWTEST_F(DmsHandlerTest, GetContinueInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsHandlerTest GetContinueInfo_001 start" << std::endl;
    ContinueInfo continueInfo;
    int32_t result = dmsHandler_.GetContinueInfo(continueInfo);
    EXPECT_EQ(result, 0);
    DTEST_LOG << "DmsHandlerTest GetContinueInfo_001 end" << std::endl;
}
}
}