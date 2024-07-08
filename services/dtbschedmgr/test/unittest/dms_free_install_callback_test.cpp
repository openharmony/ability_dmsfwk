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

#include "dms_free_install_callback_test.h"
#include "mock_remote_stub.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::u16string MOCK_INVALID_DESCRIPTOR = u"invalid descriptor";
}

void DmsFreeInstallCallbackTest::SetUpTestCase()
{
    DTEST_LOG << "DmsFreeInstallCallbackTest::SetUpTestCase" << std::endl;
}

void DmsFreeInstallCallbackTest::TearDownTestCase()
{
    DTEST_LOG << "DmsFreeInstallCallbackTest::TearDownTestCase" << std::endl;
}

void DmsFreeInstallCallbackTest::TearDown()
{
    DTEST_LOG << "DmsFreeInstallCallbackTest::TearDown" << std::endl;
}

void DmsFreeInstallCallbackTest::SetUp()
{
    DTEST_LOG << "DmsFreeInstallCallbackTest::SetUp" << std::endl;
    int64_t taskId = 0;
    IDistributedSched::FreeInstallInfo info;
    dmsFreeInstallCallbackStub_ = new DmsFreeInstallCallback(taskId, info);
    dmsFreeInstallCallbackProxy_ = new DmsFreeInstallCallbackProxy((new MockRemoteStub())->AsObject());
}

/**
 * @tc.name: DmsFreeInstallCallbackTest_001
 * @tc.desc: invalid descriptor
 * @tc.type: FUNC
 */
HWTEST_F(DmsFreeInstallCallbackTest, DmsFreeInstallCallbackTest_001, TestSize.Level3)
{
    DTEST_LOG << "DmsFreeInstallCallbackTest DmsFreeInstallCallbackTest_001 begin" << std::endl;
    ASSERT_NE(dmsFreeInstallCallbackStub_, nullptr);
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(MOCK_INVALID_DESCRIPTOR);
    int32_t result = dmsFreeInstallCallbackStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
    DTEST_LOG << "DmsFreeInstallCallbackTest DmsFreeInstallCallbackTest_001 end" << std::endl;
}

/**
 * @tc.name: DmsFreeInstallCallbackTest_002
 * @tc.desc: invalid code
 * @tc.type: FUNC
 */
HWTEST_F(DmsFreeInstallCallbackTest, DmsFreeInstallCallbackTest_002, TestSize.Level4)
{
    DTEST_LOG << "DmsFreeInstallCallbackTest DmsFreeInstallCallbackTest_002 begin" << std::endl;
    ASSERT_NE(dmsFreeInstallCallbackStub_, nullptr);
    int32_t code = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DmsFreeInstallCallbackStub::GetDescriptor());
    int32_t result = dmsFreeInstallCallbackStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
    DTEST_LOG << "DmsFreeInstallCallbackTest DmsFreeInstallCallbackTest_002 end" << std::endl;
}

/**
 * @tc.name: DmsFreeInstallCallbackTest_003
 * @tc.desc: invalid param
 * @tc.type: FUNC
 */
HWTEST_F(DmsFreeInstallCallbackTest, DmsFreeInstallCallbackTest_003, TestSize.Level3)
{
    DTEST_LOG << "DmsFreeInstallCallbackTest DmsFreeInstallCallbackTest_003 begin" << std::endl;
    ASSERT_NE(dmsFreeInstallCallbackStub_, nullptr);
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DmsFreeInstallCallbackStub::GetDescriptor());
    int32_t result = dmsFreeInstallCallbackStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    DTEST_LOG << "DmsFreeInstallCallbackTest DmsFreeInstallCallbackTest_003 end" << std::endl;
}

/**
 * @tc.name: DmsFreeInstallCallbackTest_004
 * @tc.desc: test finish install
 * @tc.type: FUNC
 */
HWTEST_F(DmsFreeInstallCallbackTest, DmsFreeInstallCallbackTest_004, TestSize.Level3)
{
    DTEST_LOG << "DmsFreeInstallCallbackTest DmsFreeInstallCallbackTest_004 begin" << std::endl;
    ASSERT_NE(dmsFreeInstallCallbackStub_, nullptr);
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DmsFreeInstallCallbackStub::GetDescriptor());
    data.WriteInt32(0);
    AAFwk::Want want;
    data.WriteParcelable(&want);
    int32_t result = dmsFreeInstallCallbackStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, NO_ERROR);
    DTEST_LOG << "DmsFreeInstallCallbackTest DmsFreeInstallCallbackTest_004 end" << std::endl;
}

/**
 * @tc.name: DmsFreeInstallCallbackTest_005
 * @tc.desc: test on install finished
 * @tc.type: FUNC
 */
HWTEST_F(DmsFreeInstallCallbackTest, DmsFreeInstallCallbackTest_005, TestSize.Level3)
{
    DTEST_LOG << "DmsFreeInstallCallbackTest DmsFreeInstallCallbackTest_005 begin" << std::endl;
    ASSERT_NE(dmsFreeInstallCallbackProxy_, nullptr);
    AAFwk::Want want;
    int32_t requestCode = -1;
    int32_t resultCode = -1;

    dmsFreeInstallCallbackProxy_->OnInstallFinished(want, requestCode, resultCode);
    EXPECT_NE(dmsFreeInstallCallbackProxy_, nullptr);
    DTEST_LOG << "DmsFreeInstallCallbackTest DmsFreeInstallCallbackTest_005 end" << std::endl;
}
}
}