/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "app_connection_stub_test.h"
#include "test_log.h"

#define private public
#include "app_connection_stub.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    AppConnectionStub* appConnectionStub;
    const std::u16string MOCK_INVALID_DESCRIPTOR = u"invalid descriptor";
    int32_t code = 0;
    MessageParcel reply;
    MessageOption option;
}

void AppConnectionStubTest::SetUpTestCase()
{
    DTEST_LOG << "AppConnectionStubTest::SetUpTestCase" << std::endl;
}

void AppConnectionStubTest::TearDownTestCase()
{
    DTEST_LOG << "AppConnectionStubTest::TearDownTestCase" << std::endl;
}

void AppConnectionStubTest::TearDown()
{
    DTEST_LOG << "AppConnectionStubTest::TearDown" << std::endl;
}

void AppConnectionStubTest::SetUp()
{
    DTEST_LOG << "AppConnectionStubTest::SetUp" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_001
 * @tc.desc: constructor
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_001, TestSize.Level2)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_001 begin" << std::endl;
    const sptr<DmsNotifier> dmsNotifier;
    int32_t token = 0;
    const std::shared_ptr<ContinuationExtraParams> continuationExtraParams;
    appConnectionStub = new AppConnectionStub(dmsNotifier, token, continuationExtraParams);
    EXPECT_EQ(appConnectionStub->token_, 0);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_001 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_002
 * @tc.desc: invalid descriptor
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_002, TestSize.Level2)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_002 begin" << std::endl;
    MessageParcel data;
    data.WriteInterfaceToken(MOCK_INVALID_DESCRIPTOR);
    int32_t result = appConnectionStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_002 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_003
 * @tc.desc: invalid element name
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_003, TestSize.Level2)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_003 begin" << std::endl;
    MessageParcel data;
    data.WriteInterfaceToken(AppConnectionStub::GetDescriptor());
    int32_t result = appConnectionStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_003 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_004
 * @tc.desc: test connect done
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_004, TestSize.Level2)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_004 begin" << std::endl;
    MessageParcel data;
    data.WriteInterfaceToken(AppConnectionStub::GetDescriptor());
    AppExecFwk::ElementName element;
    data.WriteParcelable(&element);
    code = AppConnectionStub::ON_ABILITY_CONNECT_DONE;
    int32_t result = appConnectionStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_004 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_005
 * @tc.desc: test disconnect done
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_005, TestSize.Level2)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_005 begin" << std::endl;
    MessageParcel data;
    data.WriteInterfaceToken(AppConnectionStub::GetDescriptor());
    AppExecFwk::ElementName element;
    data.WriteParcelable(&element);
    code = AppConnectionStub::ON_ABILITY_DISCONNECT_DONE;
    int32_t result = appConnectionStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_005 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_006
 * @tc.desc: invalid code
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_006, TestSize.Level2)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_006 begin" << std::endl;
    MessageParcel data;
    data.WriteInterfaceToken(AppConnectionStub::GetDescriptor());
    AppExecFwk::ElementName element;
    data.WriteParcelable(&element);
    code = -1;
    int32_t result = appConnectionStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(result, ERR_NONE);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_006 end" << std::endl;
}
}
}