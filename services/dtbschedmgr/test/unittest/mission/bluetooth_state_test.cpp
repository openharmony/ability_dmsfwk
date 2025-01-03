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

#include "bluetooth_state_test.h"

#define private public
#include "mission/snapshot.h"
#undef private
#include "bluetooth_state_listener.h"
#include "bluetooth_state_adapter.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "BluetoothState";
constexpr size_t TEST_PARCEL_WRITE_VALUE = 1;
}
void BluetoothStateTest::SetUpTestCase()
{
}

void BluetoothStateTest::TearDownTestCase()
{
}

void BluetoothStateTest::SetUp()
{
}

void BluetoothStateTest::TearDown()
{
}


/**
 * @tc.name: testBluetoothStateInit001
 * @tc.desc: test get bluetooth state from bluetooth service
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(BluetoothStateTest, testBluetoothStateInit001, TestSize.Level1)
{
    DTEST_LOG << "BluetoothStateTest testBluetoothStateInit001 start" << std::endl;
    std::shared_ptr<BluetoothStateListener> bluetoothStateListener = BluetoothStateListener::GetInstance();
    bluetoothStateListener->InitBluetoothState();
    DTEST_LOG << "luetoothStateTest testBluetoothStateInit001 end" << std::endl;
}

/**
 * @tc.name: testBluetoothStateChange001
 * @tc.desc: test get bluetooth state from bluetooth service
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
    HWTEST_F(BluetoothStateTest, testBluetoothStateChange001, TestSize.Level1)
{
    DTEST_LOG << "BluetoothStateTest testBluetoothStateChange001 start" << std::endl;
    BluetoothStateAdapter::GetInstance().UpdateBTState(true);
    BluetoothStateAdapter::GetInstance().UpdateBLEState(true);
    EXPECT_TRUE(BluetoothStateAdapter::GetInstance().IsBluetoothActive());

    BluetoothStateAdapter::GetInstance().UpdateBTState(true);
    BluetoothStateAdapter::GetInstance().UpdateBLEState(false);
    EXPECT_TRUE(BluetoothStateAdapter::GetInstance().IsBluetoothActive());

    BluetoothStateAdapter::GetInstance().UpdateBTState(false);
    BluetoothStateAdapter::GetInstance().UpdateBLEState(true);
    EXPECT_TRUE(BluetoothStateAdapter::GetInstance().IsBluetoothActive());

    BluetoothStateAdapter::GetInstance().UpdateBTState(false);
    BluetoothStateAdapter::GetInstance().UpdateBLEState(false);
    EXPECT_FALSE(BluetoothStateAdapter::GetInstance().IsBluetoothActive());
    DTEST_LOG << "luetoothStateTest testBluetoothStateChange001 end" << std::endl;
}

} // DistributedSchedule
} // namespace OHOS