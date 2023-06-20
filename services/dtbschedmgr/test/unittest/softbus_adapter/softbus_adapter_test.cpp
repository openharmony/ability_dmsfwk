/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "softbus_error_code.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
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
    uint8_t* sendData = nullptr;
    uint32_t sendDataLen = 1;
    uint32_t result = SoftbusAdapter::GetInstance().SendSoftbusEvent(sendData, sendDataLen);
    EXPECT_EQ(result, SOFTBUS_OK);
    DTEST_LOG << "SoftbusAdapterTest SendSoftbusEvent_001 end" << std::endl;
}

/**
 * @tc.name: StopSoftbusEvent_001
 * @tc.desc: call StopSoftbusEvent from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, StopSoftbusEvent_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest StopSoftbusEvent_001 begin" << std::endl;
    uint32_t result = SoftbusAdapter::GetInstance().StopSoftbusEvent();
    EXPECT_EQ(result, SOFTBUS_OK);
    DTEST_LOG << "SoftbusAdapterTest StopSoftbusEvent_001 end" << std::endl;
}

/**
 * @tc.name: RegisterSoftbusEventListener_001
 * @tc.desc: call RegisterSoftbusEventListener from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, RegisterSoftbusEventListener_001, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_001 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener = std::make_shared<SubSoftbusAdapterListener>();
    uint32_t result = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
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
    uint32_t result = SoftbusAdapter::GetInstance().UnregisterSoftbusEventListener(listener);
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
    uint32_t result = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_OK);
    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_002 end" << std::endl;
}

/**
 * @tc.name: StopSoftbusEvent_002
 * @tc.desc: call StopSoftbusEvent from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, StopSoftbusEvent_002, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest StopSoftbusEvent_002 begin" << std::endl;
    SoftbusAdapter::GetInstance().pkgName_ = "oh";
    uint32_t result = SoftbusAdapter::GetInstance().StopSoftbusEvent();
    EXPECT_EQ(result, SOFTBUS_OK);
    DTEST_LOG << "SoftbusAdapterTest StopSoftbusEvent_002 end" << std::endl;
}

/**
 * @tc.name: RegisterSoftbusEventListener_003
 * @tc.desc: call RegisterSoftbusEventListener from distributedsched
 * @tc.type: FUNC
 */
HWTEST_F(SoftbusAdapterTest, RegisterSoftbusEventListener_003, TestSize.Level3)
{
    DTEST_LOG << "SoftbusAdapterTest RegisterSoftbusEventListener_003 begin" << std::endl;
    std::shared_ptr<SubSoftbusAdapterListener> listener ;
    uint32_t result = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_OK);
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
    std::shared_ptr<SubSoftbusAdapterListener> listener ;
    SoftbusAdapter::GetInstance().pkgName_ = "oh";
    uint32_t result = SoftbusAdapter::GetInstance().RegisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_OK);
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
    uint32_t result = SoftbusAdapter::GetInstance().UnregisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_OK);
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
    uint32_t result = SoftbusAdapter::GetInstance().UnregisterSoftbusEventListener(listener);
    EXPECT_EQ(result, SOFTBUS_OK);
    DTEST_LOG << "SoftbusAdapterTest UnregisterSoftbusEventListener_003 end" << std::endl;
}
}
}