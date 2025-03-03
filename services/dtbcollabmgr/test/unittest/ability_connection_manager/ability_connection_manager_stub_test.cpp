/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"
#include "gmock/gmock.h"

#include "ability_connection_manager_stub.h"
#include "ability_connection_manager_stub_mock.h"
#include "dtbcollabmgr_log.h"

namespace OHOS {
namespace DistributedCollab {
using namespace testing::ext;

namespace {
    const int ERROR_CODE = 99999;
}

class AbilityConnectionMgrStubTest : public testing::Test {
public:
    static void SetUpTestCase(void) {};
    static void TearDownTestCase(void) {};
    void SetUp() {};
    void TearDown() {};
};

/**
 * @tc.name: AbilityConnectionMgrStubTest_OnRemoteRequest_001
 * @tc.desc: Verify the OnRemoteRequest function with error descriptor.
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrStubTest, AbilityConnectionMgrStubTest_OnRemoteRequest_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_OnRemoteRequest_001 start";

    AbilityConnectionManagerStubMock mock;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);
    bool bRet = data.WriteInterfaceToken(u"error descriptor");
    ASSERT_TRUE(bRet);

    int32_t ret = mock.OnRemoteRequest(static_cast<int32_t>(IAbilityConnectionManager::Message::NOTIFY_COLLAB_RESULT),
        data, reply, option);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);

    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_OnRemoteRequest_001 end";
}

/**
 * @tc.name: AbilityConnectionMgrStubTest_OnRemoteRequest_002
 * @tc.desc: Verify the OnRemoteRequest function with error code.
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrStubTest, AbilityConnectionMgrStubTest_OnRemoteRequest_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_OnRemoteRequest_002 start";

    AbilityConnectionManagerStubMock mock;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    bool bRet = data.WriteInterfaceToken(AbilityConnectionManagerStub::GetDescriptor());
    ASSERT_TRUE(bRet);

    int32_t ret = mock.OnRemoteRequest(ERROR_CODE, data, reply, option);
    EXPECT_NE(ret, ERR_NONE) << "request code error";

    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_OnRemoteRequest_002 end";
}

/**
 * @tc.name: AbilityConnectionMgrStubTest_OnRemoteRequest_003
 * @tc.desc: Verify the OnRemoteRequest function success.
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrStubTest, AbilityConnectionMgrStubTest_OnRemoteRequest_003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_OnRemoteRequest_003 start";

    AbilityConnectionManagerStubMock mock;

    MessageParcel data;
    MessageParcel reply;
    MessageOption option(MessageOption::TF_SYNC);

    bool bRet = data.WriteInterfaceToken(AbilityConnectionManagerStub::GetDescriptor());
    ASSERT_TRUE(bRet);
    data.WriteInt32(0);
    data.WriteBool(true);
    data.WriteString("peerSocketName");
    data.WriteString("dmsServerToken");
    data.WriteString("reason");

    EXPECT_CALL(mock, NotifyCollabResult(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_FLATTEN_OBJECT));
    int32_t ret = mock.OnRemoteRequest(static_cast<int32_t>(IAbilityConnectionManager::Message::NOTIFY_COLLAB_RESULT),
        data, reply, option);
    EXPECT_EQ(ret, ERR_NONE) << "request code error";
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_OnRemoteRequest_003 end";
}

/**
 * @tc.name: AbilityConnectionMgrStubTest_NotifyCollabResultInner_001
 * @tc.desc: Verify the OnRemoteRequest function.
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrStubTest, AbilityConnectionMgrStubTest_NotifyCollabResultInner_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_NotifyCollabResultInner_001 start";
    MessageParcel data;
    MessageParcel reply;

    AbilityConnectionManagerStubMock mock;
    int32_t ret = mock.NotifyCollabResultInner(data, reply);
    EXPECT_EQ(ret, ERR_FLATTEN_OBJECT);

    data.WriteInt32(0);
    ret = mock.NotifyCollabResultInner(data, reply);
    EXPECT_EQ(ret, ERR_FLATTEN_OBJECT);

    data.WriteInt32(0);
    data.WriteBool(true);
    ret = mock.NotifyCollabResultInner(data, reply);
    EXPECT_EQ(ret, ERR_FLATTEN_OBJECT);

    data.WriteInt32(0);
    data.WriteBool(true);
    data.WriteString("peerSocketName");
    ret = mock.NotifyCollabResultInner(data, reply);
    EXPECT_EQ(ret, ERR_FLATTEN_OBJECT);

    data.WriteInt32(0);
    data.WriteBool(true);
    data.WriteString("peerSocketName");
    data.WriteString("dmsServerToken");
    ret = mock.NotifyCollabResultInner(data, reply);
    EXPECT_EQ(ret, ERR_FLATTEN_OBJECT);
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_NotifyCollabResultInner_001 end";
}

/**
 * @tc.name: AbilityConnectionMgrStubTest_NotifyCollabResultInner_002
 * @tc.desc: Verify the OnRemoteRequest function.
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrStubTest, AbilityConnectionMgrStubTest_NotifyCollabResultInner_002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_NotifyCollabResultInner_002 start";
    MessageParcel data;
    MessageParcel reply;

    data.WriteInt32(0);
    data.WriteBool(true);
    data.WriteString("peerSocketName");
    data.WriteString("dmsServerToken");
    data.WriteString("reason");

    AbilityConnectionManagerStubMock mock;
    EXPECT_CALL(mock, NotifyCollabResult(testing::_, testing::_, testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_FLATTEN_OBJECT));
    auto ret = mock.NotifyCollabResultInner(data, reply);
    EXPECT_EQ(ret, ERR_NONE);
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_NotifyCollabResultInner_002 end";
}

/**
 * @tc.name: AbilityConnectionMgrStubTest_NotifyDisconnectInner_001
 * @tc.desc: Verify the NotifyDisconnectInner function.
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrStubTest, AbilityConnectionMgrStubTest_NotifyDisconnectInner_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_NotifyDisconnectInner_001 start";
    MessageParcel data;
    MessageParcel reply;

    AbilityConnectionManagerStubMock mock;
    auto ret = mock.NotifyDisconnectInner(data, reply);
    EXPECT_EQ(ret, ERR_FLATTEN_OBJECT);

    data.WriteInt32(0);
    EXPECT_CALL(mock, NotifyDisconnect(testing::_)).WillOnce(testing::Return(ERR_FLATTEN_OBJECT));
    ret = mock.NotifyDisconnectInner(data, reply);
    EXPECT_EQ(ret, ERR_NONE);
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_NotifyDisconnectInner_001 end";
}

/**
 * @tc.name: AbilityConnectionMgrStubTest_NotifyWifiOpenInner_001
 * @tc.desc: Verify the NotifyWifiOpenInner function.
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrStubTest, AbilityConnectionMgrStubTest_NotifyWifiOpenInner_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_NotifyWifiOpenInner_001 start";
    MessageParcel data;
    MessageParcel reply;

    AbilityConnectionManagerStubMock mock;
    auto ret = mock.NotifyWifiOpenInner(data, reply);
    EXPECT_EQ(ret, ERR_FLATTEN_OBJECT);

    data.WriteInt32(0);
    EXPECT_CALL(mock, NotifyWifiOpen(testing::_)).WillOnce(testing::Return(ERR_FLATTEN_OBJECT));
    ret = mock.NotifyWifiOpenInner(data, reply);
    EXPECT_EQ(ret, ERR_NONE);
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_NotifyDisconnectInner_001 end";
}

/**
 * @tc.name: AbilityConnectionMgrStubTest_NotifyPeerVersionInner_001
 * @tc.desc: Verify the NotifyPeerVersionInner function.
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(AbilityConnectionMgrStubTest, AbilityConnectionMgrStubTest_NotifyPeerVersionInner_001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_NotifyPeerVersionInner_001 start";
    MessageParcel data;
    MessageParcel reply;

    AbilityConnectionManagerStubMock mock;
    auto ret = mock.NotifyPeerVersionInner(data, reply);
    EXPECT_EQ(ret, ERR_FLATTEN_OBJECT);

    data.WriteInt32(0);
    ret = mock.NotifyPeerVersionInner(data, reply);
    EXPECT_EQ(ret, ERR_FLATTEN_OBJECT);

    data.WriteInt32(0);
    data.WriteInt32(0);
    EXPECT_CALL(mock, NotifyPeerVersion(testing::_, testing::_)).WillOnce(testing::Return(ERR_FLATTEN_OBJECT));
    ret = mock.NotifyPeerVersionInner(data, reply);
    EXPECT_EQ(ret, ERR_NONE);
    GTEST_LOG_(INFO) << "AbilityConnectionMgrStubTest_NotifyDisconnectInner_001 end";
}
} // STORAGE_DAEMON
} // OHOS
