/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "softbus_adapter_test.h"

#include "mock_softbus_adapter.h"
#include "softbus_error_code.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

static int32_t g_mockRet = 0;
namespace {
const std::string NETWORKID_01 = "networkId01";
constexpr int32_t RETRY_SENT_EVENT_MAX_TIME = 3;
const int32_t WAITTIME = 2000;
}

std::shared_ptr<AccountSA::OhosAccountKitsMock> SoftbusAdapterTest::ohosAccountMock_;
std::shared_ptr<AccountSA::OsAccountManagerMock> SoftbusAdapterTest::osAccountMock_;

void SoftbusAdapterTest::SetUpTestCase()
{
    DTEST_LOG << "SoftbusAdapterTest::SetUpTestCase" << std::endl;
    ohosAccountMock_ = std::make_shared<AccountSA::OhosAccountKitsMock>();
    AccountSA::IOhosAccountKits::ohosAccountMock = ohosAccountMock_;
    osAccountMock_ = std::make_shared<AccountSA::OsAccountManagerMock>();
    AccountSA::IOsAccountManager::osAccountMock = osAccountMock_;
}

void SoftbusAdapterTest::TearDownTestCase()
{
    DTEST_LOG << "SoftbusAdapterTest::TearDownTestCase" << std::endl;
    AccountSA::IOhosAccountKits::ohosAccountMock = nullptr;
    ohosAccountMock_ = nullptr;
    AccountSA::IOsAccountManager::osAccountMock = nullptr;
    osAccountMock_ = nullptr;
}

void SoftbusAdapterTest::TearDown()
{
    DTEST_LOG << "SoftbusAdapterTest::TearDown" << std::endl;
}

void SoftbusAdapterTest::SetUp()
{
    DTEST_LOG << "SoftbusAdapterTest::SetUp" << std::endl;
    ASSERT_NE(ohosAccountMock_, nullptr);
    ::testing::Mock::VerifyAndClearExpectations(ohosAccountMock_.get());
    ON_CALL(*ohosAccountMock_, GetOsAccountDistributedInfo(_, _))
        .WillByDefault(Invoke([](int32_t localId, AccountSA::OhosAccountInfo& info) {
            if (localId < 0) {
                return static_cast<ErrCode>(-1);
            }
            info.uid_ = "test_uid";
            return 0;
        }));
    ASSERT_NE(osAccountMock_, nullptr);
    ::testing::Mock::VerifyAndClearExpectations(osAccountMock_.get());
    ON_CALL(*osAccountMock_, GetForegroundOsAccountLocalId(_))
        .WillByDefault(Invoke([](int32_t& localId) {
            localId = 100;
            return ERR_OK;
        }));
    ON_CALL(*osAccountMock_, GetOsAccountLocalIdFromUid(_, _))
        .WillByDefault(Invoke([](const int uid, int& id) {
            if (uid < 0) {
                return static_cast<ErrCode>(-1);
            }
            id = uid / 200000;
            return 0;
        }));
}

static int32_t SendEvent(bool screenOff, uint8_t *data, size_t dataLen, std::string accountId)
{
    return g_mockRet;
}

static int32_t StopEvent()
{
    return g_mockRet;
}

static int32_t RegisterEventListener(bool deduplicate, void *onBroadCastRecvFunc)
{
    return g_mockRet;
}

#ifdef DMSFWK_ENABLE_MULTI_DISTRIBUTED_ACCOUNTS
static int32_t RegisterEventListenerForMultiAccount(bool deduplicate, void *onBroadCastRecvFunc, std::string accountId)
{
    return g_mockRet;
}
#endif

static int32_t UnregisterEventListener(bool deduplicate, void *onBroadCastRecvFunc)
{
    return g_mockRet;
}

#ifdef DMSFWK_ENABLE_MULTI_DISTRIBUTED_ACCOUNTS
static int32_t UnregisterEventListenerForMultiAccount(bool deduplicate,
    void *onBroadCastRecvFunc, std::string accountId)
{
    return g_mockRet;
}
#endif

/**
 * @tc.name: SendSoftbusEvent_001
 * @tc.desc: call SendSoftbusEvent from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, SendSoftbusEvent_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest SendSoftbusEvent_001 begin" << std::endl;
    size_t sendDataLen = 1;
    std::string accountId = "testAccountId";
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(sendDataLen);
    SoftbusAdapter::GetInstance().eventHandler_ = nullptr;
    int32_t result = SoftbusAdapter::GetInstance().SendSoftbusEvent(buffer, accountId);
    EXPECT_EQ(result, SOFTBUS_OK);

    SoftbusAdapter::GetInstance().Init();
    usleep(WAITTIME);
    result = SoftbusAdapter::GetInstance().SendSoftbusEvent(buffer, accountId);
    EXPECT_EQ(result, SOFTBUS_OK);
    SoftbusAdapter::GetInstance().UnInit();
    DTEST_LOG << "SoftbusAdapterTest SendSoftbusEvent_001 end" << std::endl;
}

/**
 * @tc.name: DealSendSoftbusEvent_001
 * @tc.desc: call DealSendSoftbusEvent
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, DealSendSoftbusEvent_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest DealSendSoftbusEvent_001 begin" << std::endl;
    size_t sendDataLen = 1;
    int32_t retry = 0;
    std::string accountId = "testAccountId";
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(sendDataLen);
    SoftbusAdapter::GetInstance().eventHandler_ = nullptr;
    int32_t result = SoftbusAdapter::GetInstance().DealSendSoftbusEvent(nullptr, accountId, retry);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    SoftbusAdapter::GetInstance().Init();
    usleep(WAITTIME);
    result = SoftbusAdapter::GetInstance().DealSendSoftbusEvent(nullptr, accountId, retry);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    result = SoftbusAdapter::GetInstance().DealSendSoftbusEvent(buffer, accountId, retry);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    SoftbusAdapter::GetInstance().UnInit();
    DTEST_LOG << "SoftbusAdapterTest DealSendSoftbusEvent_001 end" << std::endl;
}

/**
 * @tc.name: RetrySendSoftbusEvent_001
 * @tc.desc: call RetrySendSoftbusEvent
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, RetrySendSoftbusEvent_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest RetrySendSoftbusEvent_001 begin" << std::endl;
    size_t sendDataLen = 1;
    int32_t retry = RETRY_SENT_EVENT_MAX_TIME;
    std::string accountId = "testAccountId";
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(sendDataLen);
    SoftbusAdapter::GetInstance().eventHandler_ = nullptr;
    int32_t result = SoftbusAdapter::GetInstance().RetrySendSoftbusEvent(nullptr, accountId, retry);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    retry = 0;
    SoftbusAdapter::GetInstance().eventHandler_ = nullptr;
    result = SoftbusAdapter::GetInstance().RetrySendSoftbusEvent(buffer, accountId, retry);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    SoftbusAdapter::GetInstance().Init();
    usleep(WAITTIME);
    result = SoftbusAdapter::GetInstance().RetrySendSoftbusEvent(buffer, accountId, retry);
    EXPECT_EQ(result, ERR_OK);
    SoftbusAdapter::GetInstance().UnInit();
    DTEST_LOG << "SoftbusAdapterTest RetrySendSoftbusEvent_001 end" << std::endl;
}

/**
 * @tc.name: StopSoftbusEvent_001
 * @tc.desc: call StopSoftbusEvent from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, StopSoftbusEvent_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest StopSoftbusEvent_001 begin" << std::endl;
    int32_t result = SoftbusAdapter::GetInstance().StopSoftbusEvent();
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "SoftbusAdapterTest StopSoftbusEvent_001 end" << std::endl;
}

/**
 * @tc.name: RegisterSoftbusEventListener_001
 * @tc.desc: call RegisterSoftbusEventListener from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, RegisterSoftbusEventListener_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest OnBroadCastRecv_001 begin" << std::endl;
    std::string networkId = NETWORKID_01;
    std::string accountIdTrunc = "testAccountId";
    uint8_t* sendData = nullptr;
    uint32_t sendDataLen = 1;
    SoftbusAdapter::GetInstance().OnBroadCastRecv(networkId, sendData, sendDataLen, accountIdTrunc);
    DTEST_LOG << "SoftbusAdapterTest OnBroadCastRecv_001 end" << std::endl;

    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_001 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener = std::make_shared<SubSoftbusAdapterListener>();
    int32_t result = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_001 end" << std::endl;
}

/**
 * @tc.name: UnregisterSoftbusEventListener_001
 * @tc.desc: call UnregisterSoftbusEventListener from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, UnregisterSoftbusEventListener_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest UnregisterSoftbusEventListener_001 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener = std::make_shared<SubSoftbusAdapterListener>();
    int32_t result = SoftbusAdapter::GetInstance().UnregisterSoftbusEventListener(listener);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "SoftbusAdapterTest UnregisterSoftbusEventListener_001 end" << std::endl;
}

/**
 * @tc.name: RegisterSoftbusEventListener_002
 * @tc.desc: call RegisterSoftbusEventListener from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, RegisterSoftbusEventListener_002, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_002 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener = nullptr;
    int32_t result = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_002 end" << std::endl;
}

/**
 * @tc.name: RegisterSoftbusEventListener_003
 * @tc.desc: call RegisterSoftbusEventListener from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, RegisterSoftbusEventListener_003, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_003 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener;
    int32_t result = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_003 end" << std::endl;
}

/**
 * @tc.name: RegisterSoftbusEventListener_004
 * @tc.desc: call RegisterSoftbusEventListener from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, RegisterSoftbusEventListener_004, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_004 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener;
    SoftbusAdapter::GetInstance().pkgName_ = "oh";
    int32_t result = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_004 end" << std::endl;
}

/**
 * @tc.name: UnregisterSoftbusEventListener_002
 * @tc.desc: call UnregisterSoftbusEventListener from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, UnregisterSoftbusEventListener_002, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest UnregisterSoftbusEventListener_002 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener;
    int32_t result = SoftbusAdapter::GetInstance().UnregisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
    DTEST_LOG << "SoftbusAdapterTest UnregisterSoftbusEventListener_002 end" << std::endl;
}

#ifdef DMSFWK_INTERACTIVE_ADAPTER
/**
 * @tc.name: UnregisterSoftbusEventListener_003
 * @tc.desc: call UnregisterSoftbusEventListener
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, UnregisterSoftbusEventListener_003, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest UnregisterSoftbusEventListener_003 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener = std::make_shared<SubSoftbusAdapterListener>();
    SoftbusAdapter::GetInstance().pkgName_ = "oh";
    std::string accountId = "testAccountId";
    SoftbusAdapter::GetInstance().dmsAdapetr_.SendSoftbusEvent = SendEvent;
    result = SoftbusAdapter::GetInstance().DealSendSoftbusEvent(buffer, accountId, retry);
    EXPECT_EQ(result, ERR_OK);

    SoftbusAdapter::GetInstance().dmsAdapetr_.StopSoftbusEvent = StopEvent;
    result = SoftbusAdapter::GetInstance().StopSoftbusEvent();
    EXPECT_EQ(result, SOFTBUS_OK);

    SoftbusAdapter::GetInstance().dmsAdapetr_.RegisterSoftbusEventListener = RegisterEventListener;
#ifdef DMSFWK_ENABLE_MULTI_DISTRIBUTED_ACCOUNTS
    SoftbusAdapter::GetInstance().dmsAdapetr_.RegisterSoftbusEventListenerForMultiAccount =
        RegisterEventListenerForMultiAccount;
#endif
    result = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_OK);

    SoftbusAdapter::GetInstance().dmsAdapetr_.UnregisterSoftbusEventListener = UnregisterEventListener;
#ifdef DMSFWK_ENABLE_MULTI_DISTRIBUTED_ACCOUNTS
    SoftbusAdapter::GetInstance().dmsAdapetr_.UnregisterSoftbusEventListenerForMultiAccount =
        UnregisterEventListenerForMultiAccount;
#endif
    int32_t result = SoftbusAdapter::GetInstance().UnregisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_OK);
    DTEST_LOG << "SoftbusAdapterTest UnregisterSoftbusEventListener_003 end" << std::endl;
}

static void* g_capturedCallback = nullptr;

static int32_t RegisterEventListenerCapture(bool deduplicate, void *onBroadCastRecvFunc)
{
    g_capturedCallback = onBroadCastRecvFunc;
    return SOFTBUS_OK;
}

#ifdef DMSFWK_ENABLE_MULTI_DISTRIBUTED_ACCOUNTS
static int32_t RegisterEventListenerForMultiAccountCapture(
    bool deduplicate, void *onBroadCastRecvFunc, std::string accountId)
{
    g_capturedCallback = onBroadCastRecvFunc;
    return SOFTBUS_OK;
}
#endif

/**
 * @tc.name: OnBroadCastRecvAdapt_001
 * @tc.desc: test OnBroadCastRecvAdapt callback and OnBroadCastRecv with listener
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, OnBroadCastRecvAdapt_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest OnBroadCastRecvAdapt_001 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener = std::make_shared<SubSoftbusAdapterListener>();
    SoftbusAdapter::GetInstance().pkgName_ = "oh";
    g_mockRet = SOFTBUS_OK;
#ifdef DMSFWK_ENABLE_MULTI_DISTRIBUTED_ACCOUNTS
    SoftbusAdapter::GetInstance().dmsAdapetr_.RegisterSoftbusEventListenerForMultiAccount =
        RegisterEventListenerForMultiAccountCapture;
#else
    SoftbusAdapter::GetInstance().dmsAdapetr_.RegisterSoftbusEventListener = RegisterEventListenerCapture;
#endif
    int32_t result = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_OK);

    // Call the captured callback to cover OnBroadCastRecvAdapt (line 38)
    ASSERT_NE(g_capturedCallback, nullptr);
    using BroadcastRecvFunc = void(*)(std::string&, uint8_t*, uint32_t, std::string);
    auto callback = reinterpret_cast<BroadcastRecvFunc>(g_capturedCallback);
    std::string networkId = "test_network";
    uint8_t data[] = {0x01, 0x02};
    std::string accountIdTrunc = "te";
    EXPECT_NO_FATAL_FAILURE(callback(networkId, data, 2, accountIdTrunc));
    DTEST_LOG << "SoftbusAdapterTest OnBroadCastRecvAdapt_001 end" << std::endl;
}

/**
 * @tc.name: OnBroadCastRecv_WithListener_001
 * @tc.desc: test OnBroadCastRecv with listener set, covering line 173
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, OnBroadCastRecv_WithListener_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest OnBroadCastRecv_WithListener_001 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener = std::make_shared<SubSoftbusAdapterListener>();
    SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
    std::string networkId = "test_network";
    uint8_t data[] = {0x01, 0x02};
    std::string accountIdTrunc = "te";
    EXPECT_NO_FATAL_FAILURE(
        SoftbusAdapter::GetInstance().OnBroadCastRecv(networkId, data, 2, accountIdTrunc));
    DTEST_LOG << "SoftbusAdapterTest OnBroadCastRecv_WithListener_001 end" << std::endl;
}

static int32_t g_sendEventRetVal = SOFTBUS_OK;

static int32_t SendEventWithRetVal(bool screenOff, uint8_t *data, size_t dataLen, std::string accountId)
{
    return g_sendEventRetVal;
}

/**
 * @tc.name: DealSendSoftbusEvent_SendSuccess_001
 * @tc.desc: test DealSendSoftbusEvent with SendSoftbusEvent success, covering line 123
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, DealSendSoftbusEvent_SendSuccess_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest DealSendSoftbusEvent_SendSuccess_001 begin" << std::endl;
    SoftbusAdapter::GetInstance().Init();
    usleep(WAITTIME);
    size_t sendDataLen = 4;
    std::string accountId = "testAccountId";
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(sendDataLen);
    g_sendEventRetVal = SOFTBUS_OK;
    SoftbusAdapter::GetInstance().dmsAdapetr_.SendSoftbusEvent = SendEventWithRetVal;
    int32_t retry = 0;
    int32_t result = SoftbusAdapter::GetInstance().DealSendSoftbusEvent(buffer, accountId, retry);
    EXPECT_EQ(result, SOFTBUS_OK);
    SoftbusAdapter::GetInstance().UnInit();
    DTEST_LOG << "SoftbusAdapterTest DealSendSoftbusEvent_SendSuccess_001 end" << std::endl;
}

/**
 * @tc.name: DealSendSoftbusEvent_SendFailed_001
 * @tc.desc: test DealSendSoftbusEvent with SendSoftbusEvent failed, covering line 126
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, DealSendSoftbusEvent_SendFailed_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest DealSendSoftbusEvent_SendFailed_001 begin" << std::endl;
    SoftbusAdapter::GetInstance().Init();
    usleep(WAITTIME);
    size_t sendDataLen = 4;
    std::string accountId = "testAccountId";
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(sendDataLen);
    g_sendEventRetVal = SOFTBUS_OK - 1;
    SoftbusAdapter::GetInstance().dmsAdapetr_.SendSoftbusEvent = SendEventWithRetVal;
    int32_t retry = 0;
    int32_t result = SoftbusAdapter::GetInstance().DealSendSoftbusEvent(buffer, accountId, retry);
    EXPECT_EQ(result, ERR_OK);
    SoftbusAdapter::GetInstance().UnInit();
    DTEST_LOG << "SoftbusAdapterTest DealSendSoftbusEvent_SendFailed_001 end" << std::endl;
}
#endif
}
}
