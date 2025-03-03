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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "distributed_extension_stub_mock.h"
#include "message_parcel_mock.h"
#include "distributed_extension_proxy.h"

namespace OHOS::DistributedSchedule {
using namespace std;
using namespace testing;

class DExtensionProxyTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp() override {};
    void TearDown() override {};
public:
    static inline sptr<DExtensionProxy> proxy_ = nullptr;
    static inline sptr<DistributedExtensionStubMock> mock_ = nullptr;
    static inline shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
};

void DExtensionProxyTest::SetUpTestCase()
{
    mock_ = sptr(new DistributedExtensionStubMock());
    proxy_ = sptr(new DExtensionProxy(mock_));
    messageParcelMock_ = make_shared<MessageParcelMock>();
    MessageParcelMock::messageParcel = messageParcelMock_;
}
void DExtensionProxyTest::TearDownTestCase()
{
    mock_ = nullptr;
    proxy_ = nullptr;
    MessageParcelMock::messageParcel = nullptr;
    messageParcelMock_ = nullptr;
}

/**
 * @tc.number: DExtensionProxy_TriggerOnCreate_0100
 * @tc.name: DExtensionProxy_TriggerOnCreate_0100
 * @tc.desc: Test the function of invoking the TriggerOnCreate interface.
 */
HWTEST_F(DExtensionProxyTest, DExtensionProxy_TriggerOnCreate_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnCreate_0100 begin";
    try {
        EXPECT_TRUE(proxy_ != nullptr);
        AAFwk::Want want;
        EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(false));
        int32_t res = proxy_->TriggerOnCreate(want);
        EXPECT_EQ(res, ERR_FLATTEN_OBJECT);

        EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
        EXPECT_CALL(*messageParcelMock_, WriteParcelable(_)).WillOnce(Return(false));
        res = proxy_->TriggerOnCreate(want);
        EXPECT_EQ(res, ERR_INVALID_VALUE);

        EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
        EXPECT_CALL(*messageParcelMock_, WriteParcelable(_)).WillOnce(Return(true));
        EXPECT_CALL(*mock_, SendRequest(_, _, _, _)).WillOnce(Return(NO_ERROR));
        res = proxy_->TriggerOnCreate(want);
        EXPECT_EQ(res, NO_ERROR);

        EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
        EXPECT_CALL(*messageParcelMock_, WriteParcelable(_)).WillOnce(Return(true));
        EXPECT_CALL(*mock_, SendRequest(_, _, _, _)).WillOnce(Return(EPERM));
        res = proxy_->TriggerOnCreate(want);
        EXPECT_EQ(res, EPERM);
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnCreate_0100 end";
}

/**
 * @tc.number: DExtensionProxy_TriggerOnDestroy_0100
 * @tc.name: DExtensionProxy_TriggerOnDestroy_0100
 * @tc.desc: Test the function of invoking the TriggerOnDestroy interface.
 */
HWTEST_F(DExtensionProxyTest, DExtensionProxy_TriggerOnDestroy_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnDestroy_0100 begin";
    try {
        EXPECT_TRUE(proxy_ != nullptr);
        EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(false));
        int32_t res = proxy_->TriggerOnDestroy();
        EXPECT_EQ(res, ERR_FLATTEN_OBJECT);
        GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnDestroy_0100 case1 finished";

        EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
        EXPECT_CALL(*mock_, SendRequest(_, _, _, _)).WillOnce(Return(NO_ERROR));
        res = proxy_->TriggerOnDestroy();
        EXPECT_EQ(res, NO_ERROR);
        GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnDestroy_0100 case2 finished";

        EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
        EXPECT_CALL(*mock_, SendRequest(_, _, _, _)).WillOnce(Return(EPERM));
        res = proxy_->TriggerOnDestroy();
        EXPECT_EQ(res, EPERM);
        GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnDestroy_0100 case3 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionProxyTest an exception occurred by TriggerOnDestroy.";
    }
    GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnDestroy_0100 end";
}

/**
 * @tc.number: DExtensionProxy_TriggerOnCollaborate_0100
 * @tc.name: DExtensionProxy_TriggerOnCollaborate_0100
 * @tc.desc: Test the function of invoking the TriggerOnCollaborate interface.
 */
HWTEST_F(DExtensionProxyTest, DExtensionProxy_TriggerOnCollaborate_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnCollaborate_0100 begin";
    try {
        EXPECT_TRUE(proxy_ != nullptr);
        AAFwk::WantParams wantParam;
        EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(false));
        int32_t res = proxy_->TriggerOnCollaborate(wantParam);
        EXPECT_EQ(res, ERR_FLATTEN_OBJECT);
        GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnCollaborate_0100 case1 finished";

        EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
        EXPECT_CALL(*messageParcelMock_, WriteParcelable(_)).WillOnce(Return(false));
        res = proxy_->TriggerOnCollaborate(wantParam);
        EXPECT_EQ(res, ERR_INVALID_VALUE);
        GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnCollaborate_0100 case2 finished";

        EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
        EXPECT_CALL(*messageParcelMock_, WriteParcelable(_)).WillOnce(Return(true));
        EXPECT_CALL(*mock_, SendRequest(_, _, _, _)).WillOnce(Return(NO_ERROR));
        res = proxy_->TriggerOnCollaborate(wantParam);
        EXPECT_EQ(res, NO_ERROR);
        GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnCollaborate_0100 case3 finished";

        EXPECT_CALL(*messageParcelMock_, WriteInterfaceToken(_)).WillOnce(Return(true));
        EXPECT_CALL(*messageParcelMock_, WriteParcelable(_)).WillOnce(Return(true));
        EXPECT_CALL(*mock_, SendRequest(_, _, _, _)).WillOnce(Return(EPERM));
        res = proxy_->TriggerOnCollaborate(wantParam);
        EXPECT_EQ(res, EPERM);
        GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnCollaborate_0100 case4 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionProxyTest an exception occurred by TriggerOnCollaborate.";
    }
    GTEST_LOG_(INFO) << "DExtensionProxyTest DExtensionProxy_TriggerOnCollaborate_0100 end";
}
} // namespace OHOS::DistributedSchedule
