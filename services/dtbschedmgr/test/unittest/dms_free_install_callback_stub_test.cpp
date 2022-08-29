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

#include "dms_free_install_callback_stub_test.h"
#include "test_log.h"

#define private public
#include "dms_free_install_callback.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    DmsFreeInstallCallbackStub* dmsFreeInstallCallbackStub;
    const std::u16string MOCK_INVALID_DESCRIPTOR = u"invalid descriptor";
    int32_t code = -1;
    MessageParcel reply;
    MessageOption option;
}

void DmsFreeInstallCallbackStubTest::SetUpTestCase()
{
    DTEST_LOG << "DmsFreeInstallCallbackStubTest::SetUpTestCase" << std::endl;
}

void DmsFreeInstallCallbackStubTest::TearDownTestCase()
{
    DTEST_LOG << "DmsFreeInstallCallbackStubTest::TearDownTestCase" << std::endl;
}

void DmsFreeInstallCallbackStubTest::TearDown()
{
    DTEST_LOG << "DmsFreeInstallCallbackStubTest::TearDown" << std::endl;
}

void DmsFreeInstallCallbackStubTest::SetUp()
{
    DTEST_LOG << "DmsFreeInstallCallbackStubTest::SetUp" << std::endl;
}

/**
 * @tc.name: DmsFreeInstallCallbackStubTest_001
 * @tc.desc: constructor
 * @tc.type: FUNC
 */
HWTEST_F(DmsFreeInstallCallbackStubTest, DmsFreeInstallCallbackStubTest_001, TestSize.Level2)
{
    DTEST_LOG << "DmsFreeInstallCallbackStubTest DmsFreeInstallCallbackStubTest_001 begin" << std::endl;
    int64_t taskId = 0;
    IDistributedSched::FreeInstallInfo info;
    dmsFreeInstallCallbackStub = new DmsFreeInstallCallback(taskId, info);
    EXPECT_EQ(dmsFreeInstallCallbackStub->memberFuncMap_.size(), 1);
    DTEST_LOG << "DmsFreeInstallCallbackStubTest DmsFreeInstallCallbackStubTest_001 end" << std::endl;
}

/**
 * @tc.name: DmsFreeInstallCallbackStubTest_002
 * @tc.desc: invalid descriptor
 * @tc.type: FUNC
 */
HWTEST_F(DmsFreeInstallCallbackStubTest, DmsFreeInstallCallbackStubTest_002, TestSize.Level2)
{
    DTEST_LOG << "DmsFreeInstallCallbackStubTest DmsFreeInstallCallbackStubTest_002 begin" << std::endl;
    MessageParcel data;
    data.WriteInterfaceToken(MOCK_INVALID_DESCRIPTOR);
    int32_t result = dmsFreeInstallCallbackStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
    DTEST_LOG << "DmsFreeInstallCallbackStubTest DmsFreeInstallCallbackStubTest_002 end" << std::endl;
}

/**
 * @tc.name: DmsFreeInstallCallbackStubTest_003
 * @tc.desc: invalid code
 * @tc.type: FUNC
 */
HWTEST_F(DmsFreeInstallCallbackStubTest, DmsFreeInstallCallbackStubTest_003, TestSize.Level2)
{
    DTEST_LOG << "DmsFreeInstallCallbackStubTest DmsFreeInstallCallbackStubTest_003 begin" << std::endl;
    MessageParcel data;
    data.WriteInterfaceToken(DmsFreeInstallCallbackStub::GetDescriptor());
    int32_t result = dmsFreeInstallCallbackStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
    DTEST_LOG << "DmsFreeInstallCallbackStubTest DmsFreeInstallCallbackStubTest_003 end" << std::endl;
}

/**
 * @tc.name: DmsFreeInstallCallbackStubTest_004
 * @tc.desc: invalid param
 * @tc.type: FUNC
 */
HWTEST_F(DmsFreeInstallCallbackStubTest, DmsFreeInstallCallbackStubTest_004, TestSize.Level2)
{
    DTEST_LOG << "DmsFreeInstallCallbackStubTest DmsFreeInstallCallbackStubTest_004 begin" << std::endl;
    MessageParcel data;
    data.WriteInterfaceToken(DmsFreeInstallCallbackStub::GetDescriptor());
    code = 0;
    int32_t result = dmsFreeInstallCallbackStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    DTEST_LOG << "DmsFreeInstallCallbackStubTest DmsFreeInstallCallbackStubTest_004 end" << std::endl;
}

/**
 * @tc.name: DmsFreeInstallCallbackStubTest_005
 * @tc.desc: test finish install
 * @tc.type: FUNC
 */
HWTEST_F(DmsFreeInstallCallbackStubTest, DmsFreeInstallCallbackStubTest_005, TestSize.Level2)
{
    DTEST_LOG << "DmsFreeInstallCallbackStubTest DmsFreeInstallCallbackStubTest_005 begin" << std::endl;
    code = 0;
    MessageParcel data;
    data.WriteInterfaceToken(DmsFreeInstallCallbackStub::GetDescriptor());
    data.WriteInt32(0);
    AAFwk::Want want;
    data.WriteParcelable(&want);
    int32_t result = dmsFreeInstallCallbackStub->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, NO_ERROR);
    DTEST_LOG << "DmsFreeInstallCallbackStubTest DmsFreeInstallCallbackStubTest_005 end" << std::endl;
}
}
}