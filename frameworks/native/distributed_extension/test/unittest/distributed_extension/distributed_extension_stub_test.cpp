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

#include "nocopyable.h"
#include "message_parcel_mock_for_stub.h"
#include "distributed_extension_stub.h"

namespace OHOS::DistributedSchedule {
using namespace std;
using namespace testing;

class DExtensionStubMock : public DExtensionStub {
public:
    MOCK_METHOD(int32_t, TriggerOnCreate, (AAFwk::Want &want));
    MOCK_METHOD(int32_t, TriggerOnDestroy, ());
    MOCK_METHOD(int32_t, TriggerOnCollaborate, (AAFwk::WantParams &wantParam));
};

class DExtensionStubTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() {};
    void TearDown() {};
public:
    static inline shared_ptr<DExtensionStubMock> stub = nullptr;
    static inline shared_ptr<MessageParcelMockForStub> messageParcelMock = nullptr;
};

void DExtensionStubTest::SetUpTestCase()
{
    stub = make_shared<DExtensionStubMock>();
    messageParcelMock = make_shared<MessageParcelMockForStub>();
    MessageParcelMockForStub::messageParcel = messageParcelMock;
}

void DExtensionStubTest::TearDownTestCase()
{
    stub = nullptr;
    MessageParcelMockForStub::messageParcel = nullptr;
    messageParcelMock = nullptr;
}

/**
 * @tc.number: DExtensionStub_OnRemoteRequest_0100
 * @tc.name: DExtensionStub_OnRemoteRequest_0100
 * @tc.desc: Test the function of invoking the OnRemoteRequest interface.
 */
HWTEST_F(DExtensionStubTest, DExtensionStub_OnRemoteRequest_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionStubTest DExtensionStub_OnRemoteRequest_0100 begin";
    try {
        ASSERT_TRUE(stub != nullptr);
        uint32_t code = 0;
        MessageParcel data;
        MessageParcel reply;
        MessageOption option;
        EXPECT_CALL(*messageParcelMock, ReadInterfaceToken()).WillOnce(Return(u16string()));
        auto err = stub->OnRemoteRequest(code, data, reply, option);
        EXPECT_EQ(err, ERR_FLATTEN_OBJECT);

        const std::u16string descriptor = DExtensionStub::GetDescriptor();
        EXPECT_CALL(*messageParcelMock, ReadInterfaceToken()).WillOnce(Return(descriptor));
        err = stub->OnRemoteRequest(static_cast<uint32_t>(IDExtensionInterfaceCode::CMD_ON_CREATE),
            data, reply, option);
        EXPECT_EQ(err, ERR_NONE);

        EXPECT_CALL(*messageParcelMock, ReadInterfaceToken()).WillOnce(Return(descriptor));
        auto ret = stub->OnRemoteRequest(-1, data, reply, option);
        EXPECT_EQ(ret, IPC_STUB_UNKNOW_TRANS_ERR);
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionStubTest DExtensionStub_OnRemoteRequest_0100 end";
}

/**
 * @tc.number: DExtensionStub_TriggerOnCreateInner_0100
 * @tc.name: DExtensionStub_TriggerOnCreateInner_0100
 * @tc.desc: Test the function of invoking the TriggerOnCreateInner interface.
 */
HWTEST_F(DExtensionStubTest, DExtensionStub_TriggerOnCreateInner_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionStubTest DExtensionStub_TriggerOnCreateInner_0100 begin";
    try {
        ASSERT_TRUE(stub != nullptr);
        MessageParcel data;
        MessageParcel reply;
        auto err = stub->TriggerOnCreateInner(data, reply);
        EXPECT_EQ(err, ERR_NULL_OBJECT);

        AAFwk::Want want;
        data.WriteParcelable(&want);
        err = stub->TriggerOnCreateInner(data, reply);
        EXPECT_EQ(err, ERR_NONE);
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionStubTest DExtensionStub_TriggerOnCreateInner_0100 end";
}

/**
 * @tc.number: DExtensionStub_TriggerOnDestroyInner_0100
 * @tc.name: DExtensionStub_TriggerOnDestroyInner_0100
 * @tc.desc: Test the function of invoking the TriggerOnDestroyInner interface.
 */
HWTEST_F(DExtensionStubTest, DExtensionStub_TriggerOnDestroyInner_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionStubTest DExtensionStub_TriggerOnDestroyInner_0100 begin";
    try {
        ASSERT_TRUE(stub != nullptr);
        MessageParcel data;
        MessageParcel reply;
        auto err = stub->TriggerOnDestroyInner(data, reply);
        EXPECT_EQ(err, ERR_NONE);
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionStubTest DExtensionStub_TriggerOnDestroyInner_0100 end";
}

/**
 * @tc.number: DExtensionStub_TriggerOnCollaborateInner_0100
 * @tc.name: DExtensionStub_TriggerOnCollaborateInner_0100
 * @tc.desc: Test the function of invoking the TriggerOnCollaborateInner interface.
 */
HWTEST_F(DExtensionStubTest, DExtensionStub_TriggerOnCollaborateInner_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionStubTest DExtensionStub_TriggerOnCollaborateInner_0100 begin";
    try {
        ASSERT_TRUE(stub != nullptr);
        MessageParcel data;
        MessageParcel reply;
        auto err = stub->TriggerOnCollaborateInner(data, reply);
        EXPECT_EQ(err, ERR_NULL_OBJECT);

        AAFwk::WantParams wantParam;
        data.WriteParcelable(&wantParam);
        err = stub->TriggerOnCollaborateInner(data, reply);
        EXPECT_EQ(err, ERR_NONE);
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionStubTest DExtensionStub_TriggerOnCollaborateInner_0100 end";
}
} // namespace OHOS::DistributedSchedule
