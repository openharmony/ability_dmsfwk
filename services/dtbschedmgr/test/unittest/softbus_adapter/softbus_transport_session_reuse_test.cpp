/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "softbus_transport_test.h"
#include "softbus_adapter/mock_softbus_adapter.h"
#include "dsched_transport_softbus_adapter.h"
#include "test_log.h"
#include "dtbschedmgr_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t SESSION_ID = 2;
constexpr uint32_t REUSE_CMD_TYPE = 6;
const std::string PEER_DEVICE_ID = "peerDeviceId";
constexpr int32_t SESSION_REUSE_CMD = 10;
constexpr int32_t SESSION_RELEASE_CMD = 11;
constexpr int32_t DATA_TYPE_SESSION_REUSE = 100;
constexpr int32_t DATA_TYPE_SESSION_RELEASE = 101;
}

class DSchedSessionReuseTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DSchedSessionReuseTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedSessionReuseTest::SetUpTestCase" << std::endl;
}

void DSchedSessionReuseTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedSessionReuseTest::TearDownTestCase" << std::endl;
}

void DSchedSessionReuseTest::SetUp()
{
    DTEST_LOG << "DSchedSessionReuseTest::SetUp" << std::endl;
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
}

void DSchedSessionReuseTest::TearDown()
{
    DTEST_LOG << "DSchedSessionReuseTest::TearDown" << std::endl;
    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
}

HWTEST_F(DSchedSessionReuseTest, GetRefCount_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest GetRefCount_001 begin" << std::endl;

    auto session = std::make_shared<DSchedSoftbusSession>();
    ASSERT_NE(session, nullptr);

    int32_t refCount = session->GetRefCount();
    EXPECT_EQ(refCount, 1);

    session->OnConnect();
    refCount = session->GetRefCount();
    EXPECT_EQ(refCount, 2);

    DTEST_LOG << "DSchedSessionReuseTest GetRefCount_001 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, SendDataWithSessionReuseType_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest SendDataWithSessionReuseType_001 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "myDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    auto reuseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(reuseMsg, nullptr);

    uint32_t cmdType = REUSE_CMD_TYPE;
    int32_t ret = memcpy_s(reuseMsg->Data(), reuseMsg->Size(), &cmdType, sizeof(cmdType));
    EXPECT_EQ(ret, ERR_OK);

    uint32_t* cmdPtr = reinterpret_cast<uint32_t*>(reuseMsg->Data());
    EXPECT_EQ(*cmdPtr, REUSE_CMD_TYPE);

    DTEST_LOG << "DSchedSessionReuseTest SendDataWithSessionReuseType_001 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, OnDataReadyWithSessionReuse_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest OnDataReadyWithSessionReuse_001 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "myDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    int32_t initialRefCount = session->GetRefCount();
    EXPECT_EQ(initialRefCount, 1);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    auto reuseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(reuseMsg, nullptr);

    uint32_t cmdType = REUSE_CMD_TYPE;
    memcpy_s(reuseMsg->Data(), reuseMsg->Size(), &cmdType, sizeof(cmdType));

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, reuseMsg,
        DATA_TYPE_SESSION_REUSE);

    int32_t syncedRefCount = session->GetRefCount();
    EXPECT_EQ(syncedRefCount, 2);

    DTEST_LOG << "DSchedSessionReuseTest OnDataReadyWithSessionReuse_001 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, OnDataReadyWithSessionReuse_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest OnDataReadyWithSessionReuse_002 begin" << std::endl;

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();

    auto reuseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(reuseMsg, nullptr);

    uint32_t cmdType = REUSE_CMD_TYPE;
    memcpy_s(reuseMsg->Data(), reuseMsg->Size(), &cmdType, sizeof(cmdType));

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, reuseMsg,
        DATA_TYPE_SESSION_REUSE);

    EXPECT_TRUE(DSchedTransportSoftbusAdapter::GetInstance().sessions_.empty());

    DTEST_LOG << "DSchedSessionReuseTest OnDataReadyWithSessionReuse_002 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, SessionReuseRefCountSync_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest SessionReuseRefCountSync_001 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "watchDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    session->OnConnect();
    EXPECT_EQ(session->GetRefCount(), 2);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    auto reuseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(reuseMsg, nullptr);

    uint32_t cmdType = REUSE_CMD_TYPE;
    memcpy_s(reuseMsg->Data(), reuseMsg->Size(), &cmdType, sizeof(cmdType));

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, reuseMsg,
        DATA_TYPE_SESSION_REUSE);

    EXPECT_EQ(session->GetRefCount(), 3);

    bool canDisconnect = session->OnDisconnect();
    EXPECT_FALSE(canDisconnect);
    EXPECT_EQ(session->GetRefCount(), 2);

    canDisconnect = session->OnDisconnect();
    EXPECT_FALSE(canDisconnect);
    EXPECT_EQ(session->GetRefCount(), 1);

    canDisconnect = session->OnDisconnect();
    EXPECT_TRUE(canDisconnect);
    EXPECT_EQ(session->GetRefCount(), 0);

    DTEST_LOG << "DSchedSessionReuseTest SessionReuseRefCountSync_001 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, DisconnectDeviceWithReuse_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest DisconnectDeviceWithReuse_001 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "myDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    session->OnConnect();
    session->OnConnect();

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    EXPECT_EQ(session->GetRefCount(), 3);

    session->OnDisconnect();
    EXPECT_EQ(session->GetRefCount(), 2);
    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(SESSION_ID), 1);

    session->OnDisconnect();
    EXPECT_EQ(session->GetRefCount(), 1);
    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(SESSION_ID), 1);

    session->OnDisconnect();
    EXPECT_EQ(session->GetRefCount(), 0);
    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(SESSION_ID), 1);

    DTEST_LOG << "DSchedSessionReuseTest DisconnectDeviceWithReuse_001 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, DataTypeValueCheck_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest DataTypeValueCheck_001 begin" << std::endl;

    EXPECT_EQ(DSchedSoftbusSession::DATA_TYPE_NULL, 0);
    EXPECT_EQ(DSchedSoftbusSession::DATA_TYPE_CONTINUE, 1);
    EXPECT_EQ(DATA_TYPE_SESSION_REUSE, 100);
    EXPECT_EQ(DATA_TYPE_SESSION_RELEASE, 101);

    DTEST_LOG << "DSchedSessionReuseTest DataTypeValueCheck_001 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, SendSessionReuseMessage_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest SendSessionReuseMessage_001 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "myDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    int32_t initialRefCount = session->GetRefCount();
    EXPECT_EQ(initialRefCount, 1);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    SoftbusMock mockSoftbus;
    EXPECT_CALL(mockSoftbus, GetSessionOption(testing::_, testing::_, testing::_, testing::_))
        .WillOnce([](int sessionId, SessionOption option, void* optionValue, uint32_t valueSize) {
            if (optionValue != nullptr && valueSize >= sizeof(uint32_t)) {
                uint32_t maxSendSize = 64 * 1024;
                *static_cast<uint32_t*>(optionValue) = maxSendSize;
            }
            return ERR_OK;
        });
    EXPECT_CALL(mockSoftbus, SendBytes(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));

    DSchedTransportSoftbusAdapter::GetInstance().SendSessionReuseMessage(SESSION_ID);

    EXPECT_EQ(session->GetRefCount(), 1);

    DTEST_LOG << "DSchedSessionReuseTest SendSessionReuseMessage_001 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, OnDataReadyWithSessionRelease_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest OnDataReadyWithSessionRelease_001 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "myDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    session->OnConnect();
    session->OnConnect();
    EXPECT_EQ(session->GetRefCount(), 3);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    auto releaseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(releaseMsg, nullptr);

    uint32_t cmdType = SESSION_RELEASE_CMD;
    memcpy_s(releaseMsg->Data(), releaseMsg->Size(), &cmdType, sizeof(cmdType));

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, releaseMsg,
        DATA_TYPE_SESSION_RELEASE);

    EXPECT_EQ(session->GetRefCount(), 2);
    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(SESSION_ID), 1);

    DTEST_LOG << "DSchedSessionReuseTest OnDataReadyWithSessionRelease_001 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, OnDataReadyWithSessionRelease_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest OnDataReadyWithSessionRelease_002 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "myDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->GetRefCount(), 1);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    auto releaseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(releaseMsg, nullptr);

    uint32_t cmdType = SESSION_RELEASE_CMD;
    memcpy_s(releaseMsg->Data(), releaseMsg->Size(), &cmdType, sizeof(cmdType));

    SoftbusMock mockSoftbus;
    EXPECT_CALL(mockSoftbus, Shutdown(testing::_))
        .Times(1);

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, releaseMsg,
        DATA_TYPE_SESSION_RELEASE);

    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(SESSION_ID), 0);

    DTEST_LOG << "DSchedSessionReuseTest OnDataReadyWithSessionRelease_002 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, OnDataReadyWithSessionRelease_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest OnDataReadyWithSessionRelease_003 begin" << std::endl;

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();

    auto releaseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(releaseMsg, nullptr);

    uint32_t cmdType = SESSION_RELEASE_CMD;
    memcpy_s(releaseMsg->Data(), releaseMsg->Size(), &cmdType, sizeof(cmdType));

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, releaseMsg,
        DATA_TYPE_SESSION_RELEASE);

    EXPECT_TRUE(DSchedTransportSoftbusAdapter::GetInstance().sessions_.empty());

    DTEST_LOG << "DSchedSessionReuseTest OnDataReadyWithSessionRelease_003 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, SessionReuseAndRelease_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest SessionReuseAndRelease_001 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "watchDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    session->OnConnect();
    EXPECT_EQ(session->GetRefCount(), 2);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    auto reuseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(reuseMsg, nullptr);
    uint32_t cmdType = SESSION_REUSE_CMD;
    memcpy_s(reuseMsg->Data(), reuseMsg->Size(), &cmdType, sizeof(cmdType));

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, reuseMsg,
        DATA_TYPE_SESSION_REUSE);

    EXPECT_EQ(session->GetRefCount(), 3);

    auto releaseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(releaseMsg, nullptr);
    cmdType = SESSION_RELEASE_CMD;
    memcpy_s(releaseMsg->Data(), releaseMsg->Size(), &cmdType, sizeof(cmdType));

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, releaseMsg,
        DATA_TYPE_SESSION_RELEASE);

    EXPECT_EQ(session->GetRefCount(), 2);
    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(SESSION_ID), 1);

    DTEST_LOG << "DSchedSessionReuseTest SessionReuseAndRelease_001 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, SessionReuseAndRelease_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest SessionReuseAndRelease_002 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "watchDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    auto reuseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(reuseMsg, nullptr);
    uint32_t cmdType = SESSION_REUSE_CMD;
    memcpy_s(reuseMsg->Data(), reuseMsg->Size(), &cmdType, sizeof(cmdType));

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, reuseMsg,
        DATA_TYPE_SESSION_REUSE);

    EXPECT_EQ(session->GetRefCount(), 2);

    auto releaseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(releaseMsg, nullptr);
    cmdType = SESSION_RELEASE_CMD;
    memcpy_s(releaseMsg->Data(), releaseMsg->Size(), &cmdType, sizeof(cmdType));

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, releaseMsg,
        DATA_TYPE_SESSION_RELEASE);

    EXPECT_EQ(session->GetRefCount(), 1);
    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(SESSION_ID), 1);

    DTEST_LOG << "DSchedSessionReuseTest SessionReuseAndRelease_002 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, SessionReuseAndRelease_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest SessionReuseAndRelease_003 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "watchDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    auto reuseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(reuseMsg, nullptr);
    uint32_t cmdType = SESSION_REUSE_CMD;
    memcpy_s(reuseMsg->Data(), reuseMsg->Size(), &cmdType, sizeof(cmdType));

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, reuseMsg,
        DATA_TYPE_SESSION_REUSE);

    EXPECT_EQ(session->GetRefCount(), 2);

    auto releaseMsg = std::make_shared<DSchedDataBuffer>(sizeof(uint32_t));
    ASSERT_NE(releaseMsg, nullptr);
    cmdType = SESSION_RELEASE_CMD;
    memcpy_s(releaseMsg->Data(), releaseMsg->Size(), &cmdType, sizeof(cmdType));

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, releaseMsg,
        DATA_TYPE_SESSION_RELEASE);

    EXPECT_EQ(session->GetRefCount(), 1);

    SoftbusMock mockSoftbus;
    EXPECT_CALL(mockSoftbus, Shutdown(testing::_))
        .Times(1);

    DSchedTransportSoftbusAdapter::GetInstance().OnDataReady(SESSION_ID, releaseMsg,
        DATA_TYPE_SESSION_RELEASE);

    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(SESSION_ID), 0);

    DTEST_LOG << "DSchedSessionReuseTest SessionReuseAndRelease_003 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, SendSessionReleaseMessage_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest SendSessionReleaseMessage_001 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "myDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    session->OnConnect();
    EXPECT_EQ(session->GetRefCount(), 2);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    SoftbusMock mockSoftbus;
    EXPECT_CALL(mockSoftbus, GetSessionOption(testing::_, testing::_, testing::_, testing::_))
        .WillOnce([](int sessionId, SessionOption option, void* optionValue, uint32_t valueSize) {
            if (optionValue != nullptr && valueSize >= sizeof(uint32_t)) {
                uint32_t maxSendSize = 64 * 1024;
                *static_cast<uint32_t*>(optionValue) = maxSendSize;
            }
            return ERR_OK;
        });
    EXPECT_CALL(mockSoftbus, SendBytes(testing::_, testing::_, testing::_))
        .WillOnce(testing::Return(ERR_OK));

    DSchedTransportSoftbusAdapter::GetInstance().SendSessionReleaseMessage(SESSION_ID);

    EXPECT_EQ(session->GetRefCount(), 2);
    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(SESSION_ID), 1);

    DTEST_LOG << "DSchedSessionReuseTest SendSessionReleaseMessage_001 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, DisconnectDeviceNotifyPeer_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest DisconnectDeviceNotifyPeer_001 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "myDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    session->OnConnect();
    EXPECT_EQ(session->GetRefCount(), 2);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    session->OnDisconnect();
    EXPECT_EQ(session->GetRefCount(), 1);
    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(SESSION_ID), 1);

    DTEST_LOG << "DSchedSessionReuseTest DisconnectDeviceNotifyPeer_001 end" << std::endl;
}

HWTEST_F(DSchedSessionReuseTest, DisconnectDeviceNotifyPeer_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedSessionReuseTest DisconnectDeviceNotifyPeer_002 begin" << std::endl;

    SessionInfo info = {SESSION_ID, "myDeviceId", PEER_DEVICE_ID, "sessionName", false};
    auto session = std::make_shared<DSchedSoftbusSession>(info);
    ASSERT_NE(session, nullptr);

    EXPECT_EQ(session->GetRefCount(), 1);

    DSchedTransportSoftbusAdapter::GetInstance().sessions_.clear();
    DSchedTransportSoftbusAdapter::GetInstance().sessions_[SESSION_ID] = session;

    SoftbusMock mockSoftbus;
    EXPECT_CALL(mockSoftbus, Shutdown(testing::_))
        .Times(1);

    DSchedTransportSoftbusAdapter::GetInstance().DisconnectDevice(PEER_DEVICE_ID);

    EXPECT_EQ(DSchedTransportSoftbusAdapter::GetInstance().sessions_.count(SESSION_ID), 0);

    DTEST_LOG << "DSchedSessionReuseTest DisconnectDeviceNotifyPeer_002 end" << std::endl;
}

}  // namespace DistributedSchedule
}  // namespace OHOS
