/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>
#include <thread>
#include <chrono>
#include "securec.h"

#define private public
#include "distributed_intent_dsoftbus_adapter.h"
#include "distributed_intent_dsoftbus_adapter.cpp"
#undef private

#include "softbus_mock.h"
#include "distributed_intent_dsoftbus_adapter_mock.h"
#include "distributed_intent_provider_mock.h"
#include "intent_all_connect_manager_mock.h"
#include "dtbschedmgr_device_info_storage_mock.h"
#include "test_log.h"
#include "dtbschedmgr_log.h"
#include "softbus_error_code.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string DEVICE_ID_1 = "device_id_11111";
const std::string DEVICE_ID_2 = "device_id_22222";
const std::string EMPTY_DEVICE_ID;
constexpr int32_t VALID_FD = 10;
constexpr int32_t ANOTHER_FD = 20;
constexpr int32_t SERVER_FD = 30;
constexpr int32_t INVALID_FD = -1;
const std::string TEST_DATA = "test_data_payload";
}

class RemoteIntentManagerMock : public testing::Mock {
public:
    static RemoteIntentManagerMock& GetInstance() { return *instance_; }
    MOCK_METHOD(void, CleanupSocketMapping, (const std::string& deviceId, int32_t socketFd));
    MOCK_METHOD(void, NotifyLinkDisconnected, (const std::string& deviceId, int32_t reason));
    MOCK_METHOD(void, OnIntentDataReceived, (const std::string& srcDeviceId, IntentDataType dataType,
        const std::string& data, int32_t socketFd));
private:
    static RemoteIntentManagerMock *instance_;
};
RemoteIntentManagerMock* RemoteIntentManagerMock::instance_ = new RemoteIntentManagerMock();

#define RemoteIntentManager RemoteIntentManagerMock

class DistributedIntentDsoftbusAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<SoftbusMock> softbusMock_;
    std::shared_ptr<DtbschedmgrDeviceInfoStorageMock> deviceInfoMock_;
};

void DistributedIntentDsoftbusAdapterTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedIntentDsoftbusAdapterTest::SetUpTestCase" << std::endl;
}

void DistributedIntentDsoftbusAdapterTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedIntentDsoftbusAdapterTest::TearDownTestCase" << std::endl;
}

void DistributedIntentDsoftbusAdapterTest::SetUp()
{
    DTEST_LOG << "DistributedIntentDsoftbusAdapterTest::SetUp" << std::endl;
    softbusMock_ = std::make_shared<SoftbusMock>();
    ISoftbusInterface::softbusMock = softbusMock_;
    deviceInfoMock_ = std::make_shared<DtbschedmgrDeviceInfoStorageMock>();
    IDtbschedmgrDeviceInfoStorage::storageMock = deviceInfoMock_;
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.StopSessionCleanupThread();
    adapter.fragBuffers_.clear();
    std::lock_guard<std::mutex> lock(adapter.sessionMutex_);
    adapter.sessions_.clear();
}

void DistributedIntentDsoftbusAdapterTest::TearDown()
{
    DTEST_LOG << "DistributedIntentDsoftbusAdapterTest::TearDown" << std::endl;
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    std::lock_guard<std::mutex> lock(adapter.sessionMutex_);
    adapter.sessions_.clear();
    ISoftbusInterface::softbusMock = nullptr;
    IDtbschedmgrDeviceInfoStorage::storageMock = nullptr;
    softbusMock_ = nullptr;
    deviceInfoMock_ = nullptr;
    testing::Mock::AllowLeak(&RemoteIntentManagerMock::GetInstance());
}

static void InsertSession(int32_t fd, const std::string& deviceId,
    bool connected = true, bool isServer = false, int32_t refCount = 1)
{
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    auto session = std::make_shared<IntentSocketSession>();
    session->peerDeviceId = deviceId;
    session->socketFd = fd;
    session->isConnected = connected;
    session->isServer = isServer;
    session->refCount = refCount;
    session->lastActivityTime = std::chrono::steady_clock::now();
    adapter.sessions_[fd] = session;
}

static void RemoveSession(int32_t fd, const std::string& deviceId)
{
    auto& adapter = DistributedIntentDsoftbusAdapter::GetInstance();
    adapter.sessions_.erase(fd);
}


/**
 * @tc.name: CreateIntentSocket_Fail_001
 * @tc.desc: CreateIntentSocket when Socket returns negative value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, CreateIntentSocket_Fail_001, TestSize.Level3)
{
    EXPECT_CALL(*softbusMock_, Socket(_)).WillOnce(Return(-1));
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.CreateIntentSocket(DEVICE_ID_1), ERR_DI_SOCKET_CREATE_FAILED);
}

/**
 * @tc.name: CreateIntentSocket_Success_002
 * @tc.desc: CreateIntentSocket success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, CreateIntentSocket_Success_002, TestSize.Level3)
{
    EXPECT_CALL(*softbusMock_, Socket(_)).WillOnce(Return(VALID_FD));
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.CreateIntentSocket(DEVICE_ID_1), VALID_FD);
}


/**
 * @tc.name: BindIntentSocket_SuccessOnFirst_001
 * @tc.desc: BindIntentSocket success on first attempt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, BindIntentSocket_SuccessOnFirst_001, TestSize.Level3)
{
    EXPECT_CALL(*softbusMock_, Bind(_, _, _, _)).WillOnce(Return(0));
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.BindIntentSocket(VALID_FD), ERR_DI_OK);
}

/**
 * @tc.name: BindIntentSocket_NonRetryableError_002
 * @tc.desc: BindIntentSocket when Bind returns a non-retryable error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, BindIntentSocket_NonRetryableError_002, TestSize.Level3)
{
    EXPECT_CALL(*softbusMock_, Bind(_, _, _, _)).WillOnce(Return(-1));
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.BindIntentSocket(VALID_FD), ERR_DI_SOCKET_BIND_FAILED);
}

/**
 * @tc.name: BindIntentSocket_MaxRetryExceeded_003
 * @tc.desc: BindIntentSocket when all retries exhausted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, BindIntentSocket_MaxRetryExceeded_003, TestSize.Level3)
{
    EXPECT_CALL(*softbusMock_, Bind(_, _, _, _))
        .WillRepeatedly(Return(-29999999));
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.BindIntentSocket(VALID_FD), ERR_DI_SOCKET_BIND_FAILED);
}

/**
 * @tc.name: BindIntentSocket_RetryThenNonRetryable_004
 * @tc.desc: BindIntentSocket retry then get non-retryable error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, BindIntentSocket_RetryThenNonRetryable_004, TestSize.Level3)
{
    EXPECT_CALL(*softbusMock_, Bind(_, _, _, _)).WillRepeatedly(Return(-426115007));
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.BindIntentSocket(VALID_FD), ERR_DI_SOCKET_BIND_FAILED);
}


/**
 * @tc.name: BindIntentSession_EmptyDeviceId_001
 * @tc.desc: BindIntentSession with empty deviceId returns ERR_DI_INVALID_PARAMETER
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, BindIntentSession_EmptyDeviceId_001, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    int32_t fd = -1;
    IDistributedIntentDsoftbusAdapter::adapterMock = nullptr;
    EXPECT_EQ(a.BindIntentSession(EMPTY_DEVICE_ID, fd), ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: ReuseOrCreateSession_ReuseExisting_002
 * @tc.desc: ReuseOrCreateSession reuses existing connected Client session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ReuseOrCreateSession_ReuseExisting_002, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    int32_t fd = -1;
    EXPECT_EQ(a.ReuseOrCreateSession(DEVICE_ID_1, fd), ERR_DI_OK);
    EXPECT_EQ(fd, VALID_FD);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: CreateIntentSocket_Fail_003
 * @tc.desc: CreateIntentSocket fails when Socket returns negative value
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, CreateIntentSocket_Fail_003, TestSize.Level3)
{
    EXPECT_CALL(*softbusMock_, Socket(_)).WillOnce(Return(-1));
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.CreateIntentSocket(DEVICE_ID_1), ERR_DI_SOCKET_CREATE_FAILED);
}

/**
 * @tc.name: ReuseOrCreateSession_BindFail_004
 * @tc.desc: ReuseOrCreateSession fails when BindIntentSocket fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ReuseOrCreateSession_BindFail_004, TestSize.Level3)
{
    EXPECT_CALL(*softbusMock_, Socket(_)).WillOnce(Return(VALID_FD));
    EXPECT_CALL(*softbusMock_, Bind(_, _, _, _)).WillOnce(Return(-1));
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    int32_t fd = -1;
    EXPECT_EQ(a.ReuseOrCreateSession(DEVICE_ID_1, fd), ERR_DI_SOCKET_BIND_FAILED);
}

/**
 * @tc.name: ReuseOrCreateSession_Success_005
 * @tc.desc: ReuseOrCreateSession creates new session successfully
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ReuseOrCreateSession_Success_005, TestSize.Level3)
{
    EXPECT_CALL(*softbusMock_, Socket(_)).WillOnce(Return(VALID_FD));
    EXPECT_CALL(*softbusMock_, Bind(_, _, _, _)).WillOnce(Return(0));
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    int32_t fd = -1;
    EXPECT_EQ(a.ReuseOrCreateSession(DEVICE_ID_1, fd), ERR_DI_OK);
    EXPECT_EQ(fd, VALID_FD);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: UnbindIntentSession_SessionNotFound_001
 * @tc.desc: UnbindIntentSession when session is not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, UnbindIntentSession_SessionNotFound_001, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_NO_FATAL_FAILURE(a.UnbindIntentSession(VALID_FD));
}

/**
 * @tc.name: UnbindIntentSession_SessionNull_002
 * @tc.desc: UnbindIntentSession when session is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, UnbindIntentSession_SessionNull_002, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.sessions_[VALID_FD] = nullptr;
    EXPECT_NO_FATAL_FAILURE(a.UnbindIntentSession(VALID_FD));
    a.sessions_.erase(VALID_FD);
}

/**
 * @tc.name: UnbindIntentSession_ServerSocket_003
 * @tc.desc: UnbindIntentSession skips Server socket
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, UnbindIntentSession_ServerSocket_003, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, true, 0);
    a.UnbindIntentSession(VALID_FD);
    EXPECT_NE(a.sessions_.find(VALID_FD), a.sessions_.end());
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: UnbindIntentSession_RefCountStillPositive_004
 * @tc.desc: UnbindIntentSession when refCount is still positive after decrement
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, UnbindIntentSession_RefCountStillPositive_004, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 2);
    a.UnbindIntentSession(VALID_FD);
    EXPECT_EQ(a.sessions_[VALID_FD]->refCount, 1);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: UnbindIntentSession_RefCountReachesZero_005
 * @tc.desc: UnbindIntentSession when refCount reaches zero triggers cleanup
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, UnbindIntentSession_RefCountReachesZero_005, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    a.UnbindIntentSession(VALID_FD);
    EXPECT_EQ(a.sessions_.find(VALID_FD), a.sessions_.end());
}


/**
 * @tc.name: SendIntentData_InvalidFd_001
 * @tc.desc: SendIntentDataBySession with invalid socketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendIntentData_InvalidFd_001, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.SendIntentDataBySession(INVALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, TEST_DATA),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: SendIntentData_EmptyData_002
 * @tc.desc: SendIntentDataBySession with empty data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendIntentData_EmptyData_002, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, ""),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: SendIntentData_OversizedData_003
 * @tc.desc: SendIntentDataBySession with data exceeding MAX_SEND_BYTES_SIZE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendIntentData_OversizedData_003, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    std::string bigData(MAX_SEND_BYTES_SIZE + 1, 'x');
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, bigData),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: SendIntentData_SessionNotFound_004
 * @tc.desc: SendIntentDataBySession when session is not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendIntentData_SessionNotFound_004, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, TEST_DATA),
        ERR_DI_SOCKET_NOT_CONNECTED);
}

/**
 * @tc.name: SendIntentData_SessionNull_005
 * @tc.desc: SendIntentDataBySession when session is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendIntentData_SessionNull_005, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.sessions_[VALID_FD] = nullptr;
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, TEST_DATA),
        ERR_DI_SOCKET_NOT_CONNECTED);
    a.sessions_.erase(VALID_FD);
}

/**
 * @tc.name: SendIntentData_NotConnected_006
 * @tc.desc: SendIntentDataBySession when session is not connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendIntentData_NotConnected_006, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, false, false, 1);
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, TEST_DATA),
        ERR_DI_SOCKET_NOT_CONNECTED);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: SendIntentData_SendBytesFail_007
 * @tc.desc: SendIntentDataBySession when SendBytes returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendIntentData_SendBytesFail_007, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, SendBytes(VALID_FD, _, _)).WillOnce(Return(-1));
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, TEST_DATA),
        ERR_DI_DATA_SEND_FAILED);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: SendIntentData_Success_008
 * @tc.desc: SendIntentDataBySession success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendIntentData_Success_008, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, SendBytes(VALID_FD, _, _)).WillOnce(Return(0));
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, TEST_DATA),
        ERR_DI_OK);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: SendIntentData_AllDataTypes_009
 * @tc.desc: SendIntentDataBySession with all IntentDataType values
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendIntentData_AllDataTypes_009, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, SendBytes(VALID_FD, _, _)).Times(4).WillRepeatedly(Return(0));
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, TEST_DATA), ERR_DI_OK);
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_DMS_RESULT, TEST_DATA), ERR_DI_OK);
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_AMGR_RESULT, TEST_DATA), ERR_DI_OK);
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE_RESULT, TEST_DATA),
        ERR_DI_OK);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}


/**
 * @tc.name: GetSocketFd_Found_001
 * @tc.desc: GetSocketFdByDeviceId when deviceId exists in map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, GetSocketFd_Found_001, TestSize.Level3)
{
    InsertSession(VALID_FD, DEVICE_ID_1);
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.GetSocketFdByDeviceId(DEVICE_ID_1), VALID_FD);
}

/**
 * @tc.name: GetSocketFd_NotFound_002
 * @tc.desc: GetSocketFdByDeviceId when deviceId not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, GetSocketFd_NotFound_002, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.GetSocketFdByDeviceId(DEVICE_ID_1), INVALID_SOCKET_FD);
}

/**
 * @tc.name: OnIntentBind_UpdateExisting_001
 * @tc.desc: OnIntentBind update existing session to connected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentBind_UpdateExisting_001, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, false, false, 1);
    a.OnIntentBind(VALID_FD, DEVICE_ID_1);
    EXPECT_TRUE(a.sessions_[VALID_FD]->isConnected);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: OnIntentBind_CreateNewServer_002
 * @tc.desc: OnIntentBind creates new Server session when not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentBind_CreateNewServer_002, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.OnIntentBind(SERVER_FD, DEVICE_ID_1);
    EXPECT_NE(a.sessions_.find(SERVER_FD), a.sessions_.end());
    EXPECT_TRUE(a.sessions_[SERVER_FD]->isConnected);
    EXPECT_TRUE(a.sessions_[SERVER_FD]->isServer);
    EXPECT_EQ(a.sessions_[SERVER_FD]->peerDeviceId, DEVICE_ID_1);
    RemoveSession(SERVER_FD, DEVICE_ID_1);
}

/**
 * @tc.name: OnIntentBind_CreateExist_003
 * @tc.desc: OnIntentBind when client exist
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentBind_CreateExist_003, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    a.OnIntentBind(SERVER_FD, DEVICE_ID_1);
    EXPECT_NE(a.sessions_.find(SERVER_FD), a.sessions_.end());
    EXPECT_TRUE(a.sessions_[SERVER_FD]->isServer);
    RemoveSession(VALID_FD, DEVICE_ID_1);
    RemoveSession(SERVER_FD, DEVICE_ID_1);
}

/**
 * @tc.name: OnIntentShutdown_CleanupClient_003
 * @tc.desc: OnIntentShutdown cleans up Client session and notifies
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentShutdown_CleanupClient_003, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    a.OnIntentShutdown(VALID_FD);
    EXPECT_EQ(a.sessions_.find(VALID_FD), a.sessions_.end());
}

/**
 * @tc.name: OnIntentShutdown_CleanupServer_004
 * @tc.desc: OnIntentShutdown cleans up Server session, Client session unaffected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentShutdown_CleanupServer_004, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    InsertSession(SERVER_FD, DEVICE_ID_1, true, true, 0);
    EXPECT_CALL(*softbusMock_, Shutdown(SERVER_FD)).Times(1);
    a.OnIntentShutdown(SERVER_FD);
    EXPECT_EQ(a.sessions_.find(SERVER_FD), a.sessions_.end());
    RemoveSession(VALID_FD, DEVICE_ID_1);
}


/**
 * @tc.name: ProcessReceivedData_NullData_001
 * @tc.desc: ProcessReceivedData with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ProcessReceivedData_NullData_001, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_NO_FATAL_FAILURE(a.ProcessReceivedData(VALID_FD, nullptr, 0));
}

/**
 * @tc.name: ProcessReceivedData_SmallData_002
 * @tc.desc: ProcessReceivedData with data smaller than header size
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ProcessReceivedData_SmallData_002, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    uint8_t data[2] = {0x01, 0x02};
    EXPECT_NO_FATAL_FAILURE(a.ProcessReceivedData(VALID_FD, data, 2));
}

/**
 * @tc.name: ProcessReceivedData_WithPayloadNoSession_003
 * @tc.desc: ProcessReceivedData with payload but no session (peerDeviceId empty)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ProcessReceivedData_WithPayloadNoSession_003, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    uint32_t typeValue = static_cast<uint32_t>(IntentDataType::INTENT_DATA_TYPE_EXECUTE);
    std::string payload = "test_payload";
    std::vector<uint8_t> frame(sizeof(uint32_t) + payload.size());
    ASSERT_EQ(memcpy_s(frame.data(), sizeof(uint32_t), &typeValue, sizeof(uint32_t)), 0);
    ASSERT_EQ(memcpy_s(frame.data() + sizeof(uint32_t), payload.size(),
        payload.data(), payload.size()), 0);
    EXPECT_NO_FATAL_FAILURE(a.ProcessReceivedData(VALID_FD, frame.data(), frame.size()));
}

/**
 * @tc.name: ProcessReceivedData_HeadOnlyNoPayload_004
 * @tc.desc: ProcessReceivedData with only header
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ProcessReceivedData_HeadOnlyNoPayload_004, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    uint32_t typeValue = static_cast<uint32_t>(IntentDataType::INTENT_DATA_TYPE_EXECUTE);
    EXPECT_NO_FATAL_FAILURE(a.ProcessReceivedData(VALID_FD, &typeValue, sizeof(uint32_t)));
}

/**
 * @tc.name: ProcessReceivedData_WithSession_005
 * @tc.desc: ProcessReceivedData with valid session and payload
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ProcessReceivedData_WithSession_005, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    uint32_t typeValue = static_cast<uint32_t>(IntentDataType::INTENT_DATA_TYPE_DMS_RESULT);
    std::string payload = "result_payload";
    std::vector<uint8_t> frame(sizeof(uint32_t) + payload.size());
    ASSERT_EQ(memcpy_s(frame.data(), sizeof(uint32_t), &typeValue, sizeof(uint32_t)), 0);
    ASSERT_EQ(memcpy_s(frame.data() + sizeof(uint32_t), payload.size(),
        payload.data(), payload.size()), 0);
    EXPECT_NO_FATAL_FAILURE(a.ProcessReceivedData(VALID_FD, frame.data(), frame.size()));
    RemoveSession(VALID_FD, DEVICE_ID_1);
}


/**
 * @tc.name: GetPeerDeviceId_Found_001
 * @tc.desc: GetPeerDeviceIdBySocket when session exists
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, GetPeerDeviceId_Found_001, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_EQ(a.GetPeerDeviceIdBySocket(VALID_FD), DEVICE_ID_1);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: GetSocketFd_NotFound_002
 * @tc.desc: GetPeerDeviceIdBySocket when session not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, GetPeerDeviceId_Found_002, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_EQ(a.GetPeerDeviceIdBySocket(VALID_FD), "");
}

/**
 * @tc.name: UpdateSessionActivity_Found_001
 * @tc.desc: UpdateSessionActivity updates lastActivityTime
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, UpdateSessionActivity_Found_001, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    a.sessions_[VALID_FD]->lastActivityTime = std::chrono::steady_clock::time_point{};
    a.UpdateSessionActivity(VALID_FD);
    auto now = std::chrono::steady_clock::now();
    auto diff = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - a.sessions_[VALID_FD]->lastActivityTime).count();
    EXPECT_LT(diff, 5000);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: CleanupIdleSessions_ExpiredClientSession_002
 * @tc.desc: CleanupIdleSessions removes expired Client session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, CleanupIdleSessions_ExpiredClientSession_002, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    auto session = std::make_shared<IntentSocketSession>();
    a.UpdateSessionActivity(VALID_FD);
    a.sessions_[VALID_FD] = nullptr;
    a.CleanupIdleSessions();
    a.sessions_.erase(VALID_FD);
    session->peerDeviceId = DEVICE_ID_1;
    session->socketFd = VALID_FD;
    session->isConnected = true;
    session->isServer = false;
    session->refCount = 1;
    session->lastActivityTime = std::chrono::steady_clock::now() -
        std::chrono::milliseconds(SESSION_IDLE_TIMEOUT_MS + 1000);
    a.sessions_[VALID_FD] = session;

    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    a.CleanupIdleSessions();

    EXPECT_EQ(a.sessions_.find(VALID_FD), a.sessions_.end());
}

/**
 * @tc.name: CleanupIdleSessions_SkipServerSession_003
 * @tc.desc: CleanupIdleSessions skips Server session even if expired
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, CleanupIdleSessions_SkipServerSession_003, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    auto session = std::make_shared<IntentSocketSession>();
    session->peerDeviceId = DEVICE_ID_1;
    session->socketFd = SERVER_FD;
    session->isConnected = true;
    session->isServer = true;
    session->refCount = 0;
    session->lastActivityTime = std::chrono::steady_clock::now() -
        std::chrono::milliseconds(SESSION_IDLE_TIMEOUT_MS + 1000);
    a.sessions_[SERVER_FD] = session;

    a.CleanupIdleSessions();
    EXPECT_NE(a.sessions_.find(SERVER_FD), a.sessions_.end());
    a.sessions_.erase(SERVER_FD);
}

/**
 * @tc.name: CleanupIdleSessions_DeviceMapFdMismatch_004
 * @tc.desc: CleanupIdleSessions
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, CleanupIdleSessions_DeviceMapFdMismatch_004, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    auto session = std::make_shared<IntentSocketSession>();
    session->peerDeviceId = DEVICE_ID_1;
    session->socketFd = VALID_FD;
    session->isConnected = true;
    session->isServer = false;
    session->refCount = 1;
    session->lastActivityTime = std::chrono::steady_clock::now() -
        std::chrono::milliseconds(SESSION_IDLE_TIMEOUT_MS + 1000);
    a.sessions_[VALID_FD] = session;

    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    a.CleanupIdleSessions();

    EXPECT_EQ(a.sessions_.find(VALID_FD), a.sessions_.end());
}

/**
 * @tc.name: CleanupIdleSessions_ActiveSessionNotCleaned_005
 * @tc.desc: CleanupIdleSessions does not remove active session (not expired)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, CleanupIdleSessions_ActiveSessionNotCleaned_005, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    a.CleanupIdleSessions();
    EXPECT_NE(a.sessions_.find(VALID_FD), a.sessions_.end());
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: CleanupSocketIfNeeded_DeviceNotInMap_002
 * @tc.desc: CleanupSocketIfNeeded removes session from sessions_ map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, CleanupSocketIfNeeded_DeviceNotInMap_002, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    a.CleanupSocketIfNeeded(VALID_FD);
    EXPECT_EQ(a.sessions_.find(VALID_FD), a.sessions_.end());
}

/**
 * @tc.name: CleanupSocketIfNeeded_IsServerTrue_004
 * @tc.desc: CleanupSocketIfNeeded when isServer=true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, CleanupSocketIfNeeded_IsServerTrue_004, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(SERVER_FD, DEVICE_ID_1, true, true, 0);
    a.CleanupSocketIfNeeded(SERVER_FD);
    EXPECT_EQ(a.sessions_.find(SERVER_FD), a.sessions_.end());
}

/**
 * @tc.name: OnIntentBytes_ProcessReceivedData_003
 * @tc.desc: OnIntentBytes with valid execute intent data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentBytes_ProcessReceivedData_003, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    uint32_t typeValue = static_cast<uint32_t>(IntentDataType::INTENT_DATA_TYPE_EXECUTE);
    std::string payload = "{\"requestCode\":100}";
    std::vector<uint8_t> frame(sizeof(uint32_t) + sizeof(uint32_t) + payload.size());
    ASSERT_EQ(memcpy_s(frame.data(), sizeof(uint32_t), &typeValue, sizeof(uint32_t)), 0);
    uint32_t payloadLen = static_cast<uint32_t>(payload.size());
    ASSERT_EQ(memcpy_s(frame.data() + sizeof(uint32_t), sizeof(uint32_t), &payloadLen, sizeof(uint32_t)), 0);
    ASSERT_EQ(memcpy_s(frame.data() + sizeof(uint32_t) + sizeof(uint32_t), payload.size(),
        payload.data(), payload.size()), 0);
    EXPECT_NO_FATAL_FAILURE(a.OnIntentBytes(VALID_FD, frame.data(), frame.size()));
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: OnIntentBytes_UnknownDataType_006
 * @tc.desc: OnIntentBytes with unknown IntentDataType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentBytes_UnknownDataType_006, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    uint32_t typeValue = 999;
    std::string payload = "test";
    std::vector<uint8_t> frame(sizeof(uint32_t) + sizeof(uint32_t) + payload.size());
    ASSERT_EQ(memcpy_s(frame.data(), sizeof(uint32_t), &typeValue, sizeof(uint32_t)), 0);
    uint32_t payloadLen = static_cast<uint32_t>(payload.size());
    ASSERT_EQ(memcpy_s(frame.data() + sizeof(uint32_t), sizeof(uint32_t),
        &payloadLen, sizeof(uint32_t)), 0);
    ASSERT_EQ(memcpy_s(frame.data() + sizeof(uint32_t) + sizeof(uint32_t), frame.size(),
        payload.data(), payload.size()), 0);
    EXPECT_NO_FATAL_FAILURE(a.OnIntentBytes(VALID_FD, frame.data(), frame.size()));
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: OnIntentBindCallback_NetworkIdNull_001
 * @tc.desc: OnIntentBindCallback when networkId is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentBindCallback_NetworkIdNull_001, TestSize.Level3)
{
    PeerSocketInfo info;
    info.networkId = nullptr;
    EXPECT_NO_FATAL_FAILURE(OnIntentBindCallback(VALID_FD, info));
}

/**
 * @tc.name: OnIntentBindCallback_NetworkIdValid_002
 * @tc.desc: OnIntentBindCallback with valid networkId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentBindCallback_NetworkIdValid_002, TestSize.Level3)
{
    PeerSocketInfo info;
    char networkId[] = "test_network_id_12345";
    info.networkId = networkId;
    EXPECT_NO_FATAL_FAILURE(OnIntentBindCallback(VALID_FD, info));
    RemoveSession(VALID_FD, networkId);
}


/**
 * @tc.name: OnIntentShutdownCallback_001
 * @tc.desc: OnIntentShutdownCallback invokes OnIntentShutdown
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentShutdownCallback_001, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    EXPECT_NO_FATAL_FAILURE(OnIntentShutdownCallback(VALID_FD, SHUTDOWN_REASON_UNKNOWN));
}


/**
 * @tc.name: OnIntentBytesCallback_001
 * @tc.desc: OnIntentBytesCallback invokes OnIntentBytes
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentBytesCallback_001, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    EXPECT_NO_FATAL_FAILURE(OnIntentBytesCallback(VALID_FD, data, 4));
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: OnIntentBytesCallback_NullData_002
 * @tc.desc: OnIntentBytesCallback with null data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentBytesCallback_NullData_002, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_NO_FATAL_FAILURE(OnIntentBytesCallback(VALID_FD, nullptr, 0));
    RemoveSession(VALID_FD, DEVICE_ID_1);
}


/**
 * @tc.name: StopSessionCleanupThread_NotRunning_001
 * @tc.desc: StopSessionCleanupThread when cleanup thread is not running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, StopSessionCleanupThread_NotRunning_001, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.sessionCleanupRunning_.store(false);
    EXPECT_NO_FATAL_FAILURE(a.StopSessionCleanupThread());
}

/**
 * @tc.name: StopSessionCleanupThread_Running_002
 * @tc.desc: StopSessionCleanupThread when cleanup thread is running
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, StopSessionCleanupThread_Running_002, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.StartSessionCleanupThread();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    EXPECT_NO_FATAL_FAILURE(a.StopSessionCleanupThread());
}

/**
 * @tc.name: ForceCleanupDeviceSessions_NoSession_001
 * @tc.desc: Test ForceCleanupDeviceSessions with no sessions returns empty closed sockets
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ForceCleanupDeviceSessions_NoSession, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    std::vector<int32_t> closedSockets;
    a.ForceCleanupDeviceSessions(DEVICE_ID_1, closedSockets);
    EXPECT_TRUE(closedSockets.empty());
}

/**
 * @tc.name: ForceCleanupDeviceSessions_HasSessions_001
 * @tc.desc: Test ForceCleanupDeviceSessions closes all sessions for the given device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ForceCleanupDeviceSessions_HasSessions, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    InsertSession(ANOTHER_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    EXPECT_CALL(*softbusMock_, Shutdown(ANOTHER_FD)).Times(1);
    std::vector<int32_t> closedSockets;
    a.ForceCleanupDeviceSessions(DEVICE_ID_1, closedSockets);
    EXPECT_EQ(closedSockets.size(), 2u);
    EXPECT_TRUE(a.sessions_.empty());
}

/**
 * @tc.name: ForceCleanupDeviceSessions_MixedDevices_001
 * @tc.desc: Test ForceCleanupDeviceSessions only closes sessions for the target device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ForceCleanupDeviceSessions_MixedDevices, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    InsertSession(ANOTHER_FD, DEVICE_ID_2, true, false, 1);
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    std::vector<int32_t> closedSockets;
    a.ForceCleanupDeviceSessions(DEVICE_ID_1, closedSockets);
    EXPECT_EQ(closedSockets.size(), 1u);
    EXPECT_EQ(closedSockets[0], VALID_FD);
    EXPECT_NE(a.sessions_.find(ANOTHER_FD), a.sessions_.end());
    RemoveSession(ANOTHER_FD, DEVICE_ID_2);
}

/**
 * @tc.name: OnIntentBind_WhenStopped_001
 * @tc.desc: Test OnIntentBind does not create session when adapter is stopped
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentBind_WhenStopped, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.stopped_.store(true);
    a.OnIntentBind(SERVER_FD, DEVICE_ID_1);
    EXPECT_EQ(a.sessions_.find(SERVER_FD), a.sessions_.end());
    a.stopped_.store(false);
}

/**
 * @tc.name: OnIntentShutdown_WhenStopped_001
 * @tc.desc: Test OnIntentShutdown does not remove session when adapter is stopped
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentShutdown_WhenStopped, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    a.stopped_.store(true);
    a.OnIntentShutdown(VALID_FD);
    EXPECT_NE(a.sessions_.find(VALID_FD), a.sessions_.end());
    a.stopped_.store(false);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: OnIntentBytes_WhenStopped_001
 * @tc.desc: Test OnIntentBytes does not deliver data when adapter is stopped
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentBytes_WhenStopped, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    a.stopped_.store(true);
    auto& mock = RemoteIntentManager::GetInstance();
    EXPECT_CALL(mock, OnIntentDataReceived(_, _, _, _)).Times(AtLeast(0));
    uint8_t data[] = {0x01, 0x02, 0x03, 0x04};
    a.OnIntentBytes(VALID_FD, data, sizeof(data));
    a.stopped_.store(false);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: DeliverIntentData_NoSession_001
 * @tc.desc: Test DeliverIntentData with no session does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, DeliverIntentData_NoSession, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    EXPECT_NO_FATAL_FAILURE(a.DeliverIntentData(VALID_FD,
        IntentDataType::INTENT_DATA_TYPE_EXECUTE, TEST_DATA));
}

/**
 * @tc.name: DeliverIntentData_Success_001
 * @tc.desc: Test DeliverIntentData delivers data to RemoteIntentManager for valid session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, DeliverIntentData_Success, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    auto& mock = RemoteIntentManager::GetInstance();
    EXPECT_CALL(mock, OnIntentDataReceived(DEVICE_ID_1,
        IntentDataType::INTENT_DATA_TYPE_EXECUTE, TEST_DATA, VALID_FD)).Times(1);
    a.DeliverIntentData(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, TEST_DATA);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: FindClientSession_ServerSession_001
 * @tc.desc: FindClientSession skips server session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, FindClientSession_ServerSession, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(SERVER_FD, DEVICE_ID_1, true, true, 0);
    EXPECT_EQ(a.FindClientSession(DEVICE_ID_1), nullptr);
    RemoveSession(SERVER_FD, DEVICE_ID_1);
}

/**
 * @tc.name: FindClientSession_NotConnected_002
 * @tc.desc: FindClientSession skips disconnected client session
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, FindClientSession_NotConnected, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, false, false, 1);
    EXPECT_EQ(a.FindClientSession(DEVICE_ID_1), nullptr);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: FindClientSession_DeviceIdMismatch_003
 * @tc.desc: FindClientSession skips session with different deviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, FindClientSession_DeviceIdMismatch, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_2, true, false, 1);
    EXPECT_EQ(a.FindClientSession(DEVICE_ID_1), nullptr);
    RemoveSession(VALID_FD, DEVICE_ID_2);
}

/**
 * @tc.name: FindClientSession_NullSession_004
 * @tc.desc: FindClientSession skips null session entry
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, FindClientSession_NullSession, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.sessions_[VALID_FD] = nullptr;
    EXPECT_EQ(a.FindClientSession(DEVICE_ID_1), nullptr);
    a.sessions_.erase(VALID_FD);
}

/**
 * @tc.name: GetDeviceMutex_Existing_001
 * @tc.desc: GetDeviceMutex returns existing mutex when deviceId already in map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, GetDeviceMutex_Existing, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    auto mutex1 = a.GetDeviceMutex(DEVICE_ID_1);
    auto mutex2 = a.GetDeviceMutex(DEVICE_ID_1);
    EXPECT_EQ(mutex1, mutex2);
    a.RemoveDeviceMutex(DEVICE_ID_1);
}

/**
 * @tc.name: GetDeviceMutex_New_002
 * @tc.desc: GetDeviceMutex creates new mutex when deviceId not in map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, GetDeviceMutex_New, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.RemoveDeviceMutex(DEVICE_ID_1);
    auto mutex1 = a.GetDeviceMutex(DEVICE_ID_1);
    EXPECT_NE(mutex1, nullptr);
    a.RemoveDeviceMutex(DEVICE_ID_1);
}

/**
 * @tc.name: UnbindIntentSession_ShouldStopThread_001
 * @tc.desc: UnbindIntentSession triggers StopSessionCleanupThread when sessions empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, UnbindIntentSession_ShouldStopThread, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.StartSessionCleanupThread();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    a.UnbindIntentSession(VALID_FD);
    EXPECT_EQ(a.sessions_.find(VALID_FD), a.sessions_.end());
}

/**
 * @tc.name: ForceCleanupDeviceSessions_EmptySessionsStopThread_001
 * @tc.desc: ForceCleanupDeviceSessions triggers StopSessionCleanupThread when all sessions removed
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ForceCleanupDeviceSessions_EmptySessionsStopThread, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.StartSessionCleanupThread();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    std::vector<int32_t> closedSockets;
    a.ForceCleanupDeviceSessions(DEVICE_ID_1, closedSockets);
    EXPECT_EQ(closedSockets.size(), 1u);
    EXPECT_TRUE(a.sessions_.empty());
}

/**
 * @tc.name: ShutdownDeviceSession_MixedDevices_001
 * @tc.desc: ShutdownDeviceSession only shuts down sessions matching deviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ShutdownDeviceSession_MixedDevices, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    InsertSession(ANOTHER_FD, DEVICE_ID_2, true, false, 1);
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    a.ShutdownDeviceSession(DEVICE_ID_1);
    EXPECT_NE(a.sessions_.find(VALID_FD), a.sessions_.end());
    EXPECT_NE(a.sessions_.find(ANOTHER_FD), a.sessions_.end());
    RemoveSession(VALID_FD, DEVICE_ID_1);
    RemoveSession(ANOTHER_FD, DEVICE_ID_2);
}

/**
 * @tc.name: SendIntentData_FragPath_001
 * @tc.desc: SendIntentDataBySession uses SendFrag when data exceeds maxSendSize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendIntentData_FragPath, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, GetSessionOption(_, _, _, _))
        .WillRepeatedly(Invoke([](int32_t, SessionOption, void*, uint32_t) { return -1; }));
    EXPECT_CALL(*softbusMock_, SendBytes(VALID_FD, _, _))
        .WillRepeatedly(Return(0));
    std::string bigData(SEND_DATA_MAX_LEN + 1, 'x');
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, bigData),
        ERR_DI_INVALID_PARAMETER);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: OnIntentShutdown_EmptySessions_001
 * @tc.desc: OnIntentShutdown triggers StopSessionCleanupThread when sessions become empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, OnIntentShutdown_EmptySessions, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.StartSessionCleanupThread();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    a.OnIntentShutdown(VALID_FD);
    EXPECT_TRUE(a.sessions_.empty());
}

/**
 * @tc.name: FindClientSession_SkipThenFind_001
 * @tc.desc: FindClientSession skips non-matching sessions then finds matching one
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, FindClientSession_SkipThenFind, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(SERVER_FD, DEVICE_ID_1, true, true, 0);
    InsertSession(ANOTHER_FD, DEVICE_ID_2, true, false, 1);
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    auto result = a.FindClientSession(DEVICE_ID_1);
    EXPECT_NE(result, nullptr);
    EXPECT_EQ(result->socketFd, VALID_FD);
    RemoveSession(SERVER_FD, DEVICE_ID_1);
    RemoveSession(ANOTHER_FD, DEVICE_ID_2);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: ShutdownDeviceSession_NullSession_001
 * @tc.desc: ShutdownDeviceSession skips null session in loop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ShutdownDeviceSession_NullSession, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.sessions_[ANOTHER_FD] = nullptr;
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    a.ShutdownDeviceSession(DEVICE_ID_1);
    EXPECT_NE(a.sessions_.find(VALID_FD), a.sessions_.end());
    a.sessions_.erase(ANOTHER_FD);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: ForceCleanupDeviceSessions_NullSession_001
 * @tc.desc: ForceCleanupDeviceSessions skips null session in loop (++it, not erase)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ForceCleanupDeviceSessions_NullSession, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.sessions_[ANOTHER_FD] = nullptr;
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, Shutdown(VALID_FD)).Times(1);
    std::vector<int32_t> closedSockets;
    a.ForceCleanupDeviceSessions(DEVICE_ID_1, closedSockets);
    EXPECT_EQ(closedSockets.size(), 1u);
    EXPECT_NE(a.sessions_.find(ANOTHER_FD), a.sessions_.end());
    a.sessions_.erase(ANOTHER_FD);
}

/**
 * @tc.name: CleanupIdleSessions_NullSession_001
 * @tc.desc: CleanupIdleSessions skips null session in loop
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, CleanupIdleSessions_NullSession, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    a.sessions_[ANOTHER_FD] = nullptr;
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    a.CleanupIdleSessions();
    EXPECT_NE(a.sessions_.find(VALID_FD), a.sessions_.end());
    a.sessions_.erase(ANOTHER_FD);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: SendFrag_MultiFragment_001
 * @tc.desc: SendFrag sends data with FRAG_START, FRAG_MID, FRAG_END sequence
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendFrag_MultiFragment, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, GetSessionOption(_, _, _, _))
        .WillRepeatedly(Invoke([](int32_t, SessionOption, void* value, uint32_t valueLen) -> int32_t {
            if (value && valueLen >= sizeof(uint32_t)) {
                uint32_t* ptr = static_cast<uint32_t*>(value);
                *ptr = 64;
            }
            return 0;
        }));
    EXPECT_CALL(*softbusMock_, SendBytes(VALID_FD, _, _))
        .WillRepeatedly(Return(0));
    std::string data(200, 'x');
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, data),
        ERR_DI_OK);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: SendFrag_SendBytesFail_002
 * @tc.desc: SendFrag returns error when SendBytes fails on first fragment
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendFrag_SendBytesFail, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, GetSessionOption(_, _, _, _))
        .WillRepeatedly(Invoke([](int32_t, SessionOption, void* value, uint32_t valueLen) -> int32_t {
            if (value && valueLen >= sizeof(uint32_t)) {
                uint32_t* ptr = static_cast<uint32_t*>(value);
                *ptr = 64;
            }
            return 0;
        }));
    EXPECT_CALL(*softbusMock_, SendBytes(VALID_FD, _, _))
        .WillOnce(Return(-1));
    std::string data(200, 'x');
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, data),
        ERR_DI_DATA_SEND_FAILED);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: SendNoFrag_EmptyPayload_001
 * @tc.desc: SendNoFrag with zero-length payload (totalLen=0)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, SendNoFrag_EmptyPayload, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    EXPECT_CALL(*softbusMock_, SendBytes(VALID_FD, _, _))
        .WillOnce(Return(0));
    std::string headerOnlyData("x");
    EXPECT_EQ(a.SendIntentDataBySession(VALID_FD, IntentDataType::INTENT_DATA_TYPE_EXECUTE, headerOnlyData),
        ERR_DI_OK);
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: ProcessFragFrame_FragStart_001
 * @tc.desc: ProcessFragFrame with FRAG_START creates new frag buffer
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ProcessFragFrame_FragStart, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    a.fragBuffers_.clear();
    uint32_t typeValue = static_cast<uint32_t>(IntentDataType::INTENT_DATA_TYPE_EXECUTE);
    uint32_t totalLen = 100;
    uint16_t seq = 0;
    uint8_t flag = FRAG_START;
    std::string payload = "start_payload";
    a.ProcessFragFrame(VALID_FD, typeValue, totalLen, seq, flag, payload);
    EXPECT_NE(a.fragBuffers_.find(VALID_FD), a.fragBuffers_.end());
    RemoveSession(VALID_FD, DEVICE_ID_1);
    a.fragBuffers_.erase(VALID_FD);
}

/**
 * @tc.name: ProcessFragFrame_SeqMismatch_002
 * @tc.desc: ProcessFragFrame discards buffer when seq mismatches expected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ProcessFragFrame_SeqMismatch, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    a.fragBuffers_.clear();
    auto fragBuf = std::make_shared<IntentFragBuffer>();
    fragBuf->dataType = static_cast<uint32_t>(IntentDataType::INTENT_DATA_TYPE_EXECUTE);
    fragBuf->totalLen = 100;
    fragBuf->expectedSeq = 5;
    a.fragBuffers_[VALID_FD] = fragBuf;
    uint32_t typeValue = static_cast<uint32_t>(IntentDataType::INTENT_DATA_TYPE_EXECUTE);
    a.ProcessFragFrame(VALID_FD, typeValue, 100, 2, FRAG_MID, "wrong_seq_payload");
    EXPECT_EQ(a.fragBuffers_.find(VALID_FD), a.fragBuffers_.end());
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

/**
 * @tc.name: ProcessFragFrame_FragEnd_003
 * @tc.desc: ProcessFragFrame with FRAG_END assembles and delivers data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ProcessFragFrame_FragEnd, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    a.fragBuffers_.clear();
    auto fragBuf = std::make_shared<IntentFragBuffer>();
    fragBuf->dataType = static_cast<uint32_t>(IntentDataType::INTENT_DATA_TYPE_DMS_RESULT);
    fragBuf->totalLen = 20;
    fragBuf->expectedSeq = 1;
    fragBuf->fragments[0] = "start_data";
    a.fragBuffers_[VALID_FD] = fragBuf;
    uint32_t typeValue = static_cast<uint32_t>(IntentDataType::INTENT_DATA_TYPE_DMS_RESULT);
    auto& mock = RemoteIntentManager::GetInstance();
    EXPECT_CALL(mock, OnIntentDataReceived(DEVICE_ID_1,
        IntentDataType::INTENT_DATA_TYPE_DMS_RESULT, _, VALID_FD)).Times(1);
    a.ProcessFragFrame(VALID_FD, typeValue, 20, 1, FRAG_END, "end_data");
    RemoveSession(VALID_FD, DEVICE_ID_1);
    a.fragBuffers_.erase(VALID_FD);
}

/**
 * @tc.name: ProcessFragFrame_NoBufferForMid_004
 * @tc.desc: ProcessFragFrame with FRAG_MID but no existing buffer returns early
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, ProcessFragFrame_NoBufferForMid, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    InsertSession(VALID_FD, DEVICE_ID_1, true, false, 1);
    a.fragBuffers_.clear();
    uint32_t typeValue = static_cast<uint32_t>(IntentDataType::INTENT_DATA_TYPE_EXECUTE);
    a.ProcessFragFrame(VALID_FD, typeValue, 100, 1, FRAG_MID, "mid_payload");
    EXPECT_EQ(a.fragBuffers_.find(VALID_FD), a.fragBuffers_.end());
    RemoveSession(VALID_FD, DEVICE_ID_1);
}

#ifdef DMSFWK_ALL_CONNECT_MGR
/**
 * @tc.name: BindIntentSession_AllConnectApplyFail_006
 * @tc.desc: BindIntentSession returns error when AllConnect ApplyResource fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, BindIntentSession_AllConnectApplyFail, TestSize.Level3)
{
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    MockIntentProvider mockProvider;
    a.provider_ = &mockProvider;
    EXPECT_CALL(mockProvider, IsWifiActive()).WillOnce(Return(true));
    
    auto mock = std::make_shared<IntentAllConnectManagerMock>();
    IIntentAllConnectManager::allConnectMock = mock;
    EXPECT_CALL(*mock, IsAllConnectAvailable()).WillOnce(Return(true));
    EXPECT_CALL(*mock, ApplyResource(DEVICE_ID_1)).WillOnce(Return(ERR_DI_SOCKET_BIND_FAILED));

    int32_t fd = -1;
    EXPECT_EQ(a.BindIntentSession(DEVICE_ID_1, fd), ERR_DI_SOCKET_BIND_FAILED);
    IIntentAllConnectManager::allConnectMock = nullptr;
}

/**
 * @tc.name: BindIntentSession_AllConnectSuccess_007
 * @tc.desc: BindIntentSession with AllConnect success calls PublishServiceState(CONNECTED)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentDsoftbusAdapterTest, BindIntentSession_AllConnectSuccess, TestSize.Level3)
{
    EXPECT_CALL(*softbusMock_, Socket(_)).WillOnce(Return(VALID_FD));
    EXPECT_CALL(*softbusMock_, Bind(_, _, _, _)).WillOnce(Return(0));
    
    auto& a = DistributedIntentDsoftbusAdapter::GetInstance();
    MockIntentProvider mockProvider;
    a.provider_ = &mockProvider;
    EXPECT_CALL(mockProvider, IsWifiActive()).WillOnce(Return(true));
    
    auto mock = std::make_shared<IntentAllConnectManagerMock>();
    IIntentAllConnectManager::allConnectMock = mock;
    EXPECT_CALL(*mock, IsAllConnectAvailable()).WillOnce(Return(true));
    EXPECT_CALL(*mock, ApplyResource(DEVICE_ID_1)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*mock, PublishServiceState(DEVICE_ID_1, SCM_CONNECTED)).Times(1);

    int32_t fd = -1;
    EXPECT_EQ(a.BindIntentSession(DEVICE_ID_1, fd), ERR_DI_OK);
    EXPECT_EQ(fd, VALID_FD);
    IIntentAllConnectManager::allConnectMock = nullptr;
}
#endif

} // namespace DistributedSchedule
} // namespace OHOS