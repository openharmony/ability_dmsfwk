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

#include "softbus_adapter_test.h"

#include "mock_softbus_adapter.h"
#include "softbus_error_code.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string NETWORKID_01 = "networkId01";
constexpr int32_t RETRY_SENT_EVENT_MAX_TIME = 3;
}

void SoftbusAdapterTest::SetUpTestCase()
{
    DTEST_LOG << "SoftbusAdapterTest::SetUpTestCase" << std::endl;
}

void SoftbusAdapterTest::TearDownTestCase()
{
    DTEST_LOG << "SoftbusAdapterTest::TearDownTestCase" << std::endl;
}

void SoftbusAdapterTest::TearDown()
{
    DTEST_LOG << "SoftbusAdapterTest::TearDown" << std::endl;
}

void SoftbusAdapterTest::SetUp()
{
    DTEST_LOG << "SoftbusAdapterTest::SetUp" << std::endl;
}

/**
 * @tc.name: SendSoftbusEvent_001
 * @tc.desc: call SendSoftbusEvent from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, SendSoftbusEvent_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest SendSoftbusEvent_001 begin" << std::endl;
    size_t sendDataLen = 1;
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(sendDataLen);
    SoftbusAdapter::GetInstance().eventHandler_ = nullptr;
    int32_t result = SoftbusAdapter::GetInstance().SendSoftbusEvent(buffer);
    EXPECT_EQ(result, SOFTBUS_OK);

    SoftbusMock sortbusMock;
    SoftbusAdapter::GetInstance().Init();
    result = SoftbusAdapter::GetInstance().SendSoftbusEvent(buffer);
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
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(sendDataLen);
    SoftbusAdapter::GetInstance().eventHandler_ = nullptr;
    int32_t result = SoftbusAdapter::GetInstance().DealSendSoftbusEvent(nullptr, retry);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    SoftbusAdapter::GetInstance().Init();
    result = SoftbusAdapter::GetInstance().DealSendSoftbusEvent(nullptr, retry);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    SoftbusMock sortbusMock;
    EXPECT_CALL(sortbusMock, SendEvent(_, _, _)).WillOnce(Return(SOFTBUS_OK));
    result = SoftbusAdapter::GetInstance().DealSendSoftbusEvent(buffer, retry);
    EXPECT_EQ(result, SOFTBUS_OK);

    EXPECT_CALL(sortbusMock, SendEvent(_, _, _)).WillOnce(Return(INVALID_PARAMETERS_ERR));
    result = SoftbusAdapter::GetInstance().DealSendSoftbusEvent(buffer, retry);
    EXPECT_EQ(result, ERR_OK);
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
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(sendDataLen);
    SoftbusAdapter::GetInstance().eventHandler_ = nullptr;
    int32_t result = SoftbusAdapter::GetInstance().RetrySendSoftbusEvent(nullptr, retry);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    retry = 0;
    SoftbusAdapter::GetInstance().eventHandler_ = nullptr;
    result = SoftbusAdapter::GetInstance().RetrySendSoftbusEvent(buffer, retry);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    SoftbusAdapter::GetInstance().Init();
    result = SoftbusAdapter::GetInstance().RetrySendSoftbusEvent(buffer, retry);
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
    SoftbusMock sortbusMock;
    EXPECT_CALL(sortbusMock, StopEvent(_, _, _)).WillOnce(Return(SOFTBUS_OK));
    int32_t result = SoftbusAdapter::GetInstance().StopSoftbusEvent();
    EXPECT_EQ(result, SOFTBUS_OK);

    EXPECT_CALL(sortbusMock, StopEvent(_, _, _)).WillOnce(Return(INVALID_PARAMETERS_ERR));
    result = SoftbusAdapter::GetInstance().StopSoftbusEvent();
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
    uint8_t* sendData = nullptr;
    uint32_t sendDataLen = 1;
    SoftbusAdapter::GetInstance().OnBroadCastRecv(networkId, sendData, sendDataLen);
    DTEST_LOG << "SoftbusAdapterTest OnBroadCastRecv_001 end" << std::endl;
    
    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_001 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener = std::make_shared<SubSoftbusAdapterListener>();
    SoftbusMock sortbusMock;
    EXPECT_CALL(sortbusMock, RegisterEventListener(_, _)).WillOnce(Return(SOFTBUS_OK));
    int32_t result = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_OK);
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
    SoftbusMock sortbusMock;
    EXPECT_CALL(sortbusMock, UnregisterEventListener(_, _)).WillOnce(Return(SOFTBUS_OK));
    int32_t result = SoftbusAdapter::GetInstance().UnregisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_OK);
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

/**
 * @tc.name: UnregisterSoftbusEventListener_003
 * @tc.desc: call UnregisterSoftbusEventListener from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, UnregisterSoftbusEventListener_003, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest UnregisterSoftbusEventListener_003 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener = std::make_shared<SubSoftbusAdapterListener>();
    SoftbusAdapter::GetInstance().pkgName_ = "oh";
    SoftbusMock sortbusMock;
    EXPECT_CALL(sortbusMock, UnregisterEventListener(_, _)).WillOnce(Return(INVALID_PARAMETERS_ERR));
    int32_t result = SoftbusAdapter::GetInstance().UnregisterSoftbusEventListener(listener);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "SoftbusAdapterTest UnregisterSoftbusEventListener_003 end" << std::endl;
}
}
}
