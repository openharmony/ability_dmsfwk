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

#include "distributed_device_node_listener_test.h"

#include "distributed_device_node_listener.h"
#include "device_manager.h"
#include "deviceManager/dms_device_info.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedHardware;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string DEVICE_ID = "test_device_id";
    const std::string DEVICE_NAME = "TestDevice";
    const std::string NETWORK_ID = "test_network_id_12345";
    const int32_t DEVICE_TYPE_ID = 1;
    const std::string EXTRADATA_DEFAULT = "";

    template<size_t N>
    void SafeCopy(char (&dest)[N], const std::string& src)
    {
        if (N > 0) {
            size_t len = src.copy(dest, N-1, 0);
            dest[N - 1] = '\0';
        }
    }

    // For cases where DmDeviceInfo members are std::string
    inline void SafeCopy(std::string& dest, const std::string& src)
    {
        dest = src;
    }
}

DistributedDeviceNodeListenerTest::DistributedDeviceNodeListenerTest()
{}

DistributedDeviceNodeListenerTest::~DistributedDeviceNodeListenerTest()
{}

void DistributedDeviceNodeListenerTest::SetUpTestCase()
{}

void DistributedDeviceNodeListenerTest::TearDownTestCase()
{}

void DistributedDeviceNodeListenerTest::SetUp()
{}

void DistributedDeviceNodeListenerTest::TearDown()
{}

/**
 * @tc.name: testConstructor_001
 * @tc.desc: test default constructor
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testConstructor_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testConstructor_001 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);
    // Test that default constructor creates object without crashing
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testConstructor_001 end" << std::endl;
}

/**
 * @tc.name: testDestructor_001
 * @tc.desc: test destructor
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testDestructor_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testDestructor_001 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);
    delete listener;
    // Test that destructor works correctly
    DTEST_LOG << "DistributedDeviceNodeListenerTest testDestructor_001 end" << std::endl;
}

/**
 * @tc.name: testOnDeviceOnline_001
 * @tc.desc: test OnDeviceOnline with valid device info
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testOnDeviceOnline_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOnline_001 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, DEVICE_NAME);
    SafeCopy(deviceInfo.networkId, NETWORK_ID);
    deviceInfo.deviceTypeId = DEVICE_TYPE_ID;
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with valid device info - should not crash
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOnline(deviceInfo));
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOnline_001 end" << std::endl;
}

/**
 * @tc.name: testOnDeviceOnline_002
 * @tc.desc: test OnDeviceOnline with empty device name
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testOnDeviceOnline_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOnline_002 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, "");  // Empty device name
    SafeCopy(deviceInfo.networkId, NETWORK_ID);
    deviceInfo.deviceTypeId = DEVICE_TYPE_ID;
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with empty device name - should not crash
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOnline(deviceInfo));
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOnline_002 end" << std::endl;
}

/**
 * @tc.name: testOnDeviceOnline_003
 * @tc.desc: test OnDeviceOnline with empty networkId
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testOnDeviceOnline_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOnline_003 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, DEVICE_NAME);
    SafeCopy(deviceInfo.networkId, "");  // Empty networkId
    deviceInfo.deviceTypeId = DEVICE_TYPE_ID;
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with empty networkId - should not crash
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOnline(deviceInfo));
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOnline_003 end" << std::endl;
}

/**
 * @tc.name: testOnDeviceOnline_004
 * @tc.desc: test OnDeviceOnline with various device types
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testOnDeviceOnline_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOnline_004 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    // Test with different device type IDs
    for (int32_t deviceType = 0; deviceType <= 5; deviceType++) {
        DmDeviceInfo deviceInfo;
        SafeCopy(deviceInfo.deviceId, DEVICE_ID);
        SafeCopy(deviceInfo.deviceName, DEVICE_NAME + std::to_string(deviceType));
        SafeCopy(deviceInfo.networkId, NETWORK_ID + std::to_string(deviceType));
        deviceInfo.deviceTypeId = deviceType;
        SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

        EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOnline(deviceInfo));
    }
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOnline_004 end" << std::endl;
}

/**
 * @tc.name: testOnDeviceOffline_001
 * @tc.desc: test OnDeviceOffline with valid device info
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testOnDeviceOffline_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOffline_001 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, DEVICE_NAME);
    SafeCopy(deviceInfo.networkId, NETWORK_ID);
    deviceInfo.deviceTypeId = DEVICE_TYPE_ID;
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with valid device info - should not crash
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOffline(deviceInfo));
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOffline_001 end" << std::endl;
}

/**
 * @tc.name: testOnDeviceOffline_002
 * @tc.desc: test OnDeviceOffline with empty networkId
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testOnDeviceOffline_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOffline_002 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, DEVICE_NAME);
    SafeCopy(deviceInfo.networkId, "");  // Empty networkId
    deviceInfo.deviceTypeId = DEVICE_TYPE_ID;
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with empty networkId - should not crash
    listener->OnDeviceOffline(deviceInfo);
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceOffline_002 end" << std::endl;
}

/**
 * @tc.name: testOnDeviceInfoChanged_001
 * @tc.desc: test OnDeviceInfoChanged with valid device info
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testOnDeviceInfoChanged_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceInfoChanged_001 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, DEVICE_NAME);
    SafeCopy(deviceInfo.networkId, NETWORK_ID);
    deviceInfo.deviceTypeId = DEVICE_TYPE_ID;
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with valid device info - should not crash
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceInfoChanged(deviceInfo));
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceInfoChanged_001 end" << std::endl;
}

/**
 * @tc.name: testOnDeviceInfoChanged_002
 * @tc.desc: test OnDeviceInfoChanged with empty networkId
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testOnDeviceInfoChanged_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceInfoChanged_002 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, DEVICE_NAME);
    SafeCopy(deviceInfo.networkId, "");  // Empty networkId
    deviceInfo.deviceTypeId = DEVICE_TYPE_ID;
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with empty networkId - should not crash
    listener->OnDeviceInfoChanged(deviceInfo);
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testOnDeviceInfoChanged_002 end" << std::endl;
}

/**
 * @tc.name: testDeviceLifecycle_001
 * @tc.desc: test complete device lifecycle: online -> changed -> offline
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testDeviceLifecycle_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testDeviceLifecycle_001 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, DEVICE_NAME);
    SafeCopy(deviceInfo.networkId, NETWORK_ID);
    deviceInfo.deviceTypeId = DEVICE_TYPE_ID;
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test complete lifecycle
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOnline(deviceInfo));
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceInfoChanged(deviceInfo));
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOffline(deviceInfo));
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testDeviceLifecycle_001 end" << std::endl;
}

/**
 * @tc.name: testMultipleDevices_001
 * @tc.desc: test handling multiple devices
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testMultipleDevices_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testMultipleDevices_001 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    // Create multiple devices
    const int deviceCount = 5;
    for (int i = 0; i < deviceCount; i++) {
        DmDeviceInfo deviceInfo;
        SafeCopy(deviceInfo.deviceId, DEVICE_ID + std::to_string(i));
        SafeCopy(deviceInfo.deviceName, DEVICE_NAME + std::to_string(i));
        SafeCopy(deviceInfo.networkId, NETWORK_ID + std::to_string(i));
        deviceInfo.deviceTypeId = DEVICE_TYPE_ID + i;
        SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

        EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOnline(deviceInfo));
    }

    // Test offline for all devices
    for (int i = 0; i < deviceCount; i++) {
        DmDeviceInfo deviceInfo;
        SafeCopy(deviceInfo.networkId, NETWORK_ID + std::to_string(i));
        EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOffline(deviceInfo));
    }
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testMultipleDevices_001 end" << std::endl;
}

/**
 * @tc.name: testSpecialCharactersInDeviceName_001
 * @tc.desc: test with special characters in device name
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testSpecialCharactersInDeviceName_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testSpecialCharactersInDeviceName_001 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, "Test@#$%^&*Device");
    SafeCopy(deviceInfo.networkId, NETWORK_ID);
    deviceInfo.deviceTypeId = DEVICE_TYPE_ID;
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with special characters - should not crash
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOnline(deviceInfo));
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceInfoChanged(deviceInfo));
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOffline(deviceInfo));
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testSpecialCharactersInDeviceName_001 end" << std::endl;
}

/**
 * @tc.name: testLongNetworkId_001
 * @tc.desc: test with very long networkId
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testLongNetworkId_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testLongNetworkId_001 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    // Create a very long networkId (1000 characters)
    std::string longNetworkId(1000, 'a');

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, DEVICE_NAME);
    SafeCopy(deviceInfo.networkId, longNetworkId);
    deviceInfo.deviceTypeId = DEVICE_TYPE_ID;
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with long networkId - should not crash
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOnline(deviceInfo));
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOffline(deviceInfo));
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testLongNetworkId_001 end" << std::endl;
}

/**
 * @tc.name: testZeroDeviceTypeId_001
 * @tc.desc: test with zero deviceTypeId
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testZeroDeviceTypeId_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testZeroDeviceTypeId_001 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, DEVICE_NAME);
    SafeCopy(deviceInfo.networkId, NETWORK_ID);
    deviceInfo.deviceTypeId = 0;  // Zero device type
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with zero device type - should not crash
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOnline(deviceInfo));
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOffline(deviceInfo));
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testZeroDeviceTypeId_001 end" << std::endl;
}

/**
 * @tc.name: testNegativeDeviceTypeId_001
 * @tc.desc: test with negative deviceTypeId
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testNegativeDeviceTypeId_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testNegativeDeviceTypeId_001 begin" << std::endl;
    auto* listener = new DistributedDeviceNodeListener();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, DEVICE_NAME);
    SafeCopy(deviceInfo.networkId, NETWORK_ID);
    deviceInfo.deviceTypeId = -1;  // Negative device type
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with negative device type - should not crash
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOnline(deviceInfo));
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOffline(deviceInfo));
    delete listener;
    DTEST_LOG << "DistributedDeviceNodeListenerTest testNegativeDeviceTypeId_001 end" << std::endl;
}

/**
 * @tc.name: testSharedPtrUsage_001
 * @tc.desc: test using shared_ptr for listener
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(DistributedDeviceNodeListenerTest, testSharedPtrUsage_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedDeviceNodeListenerTest testSharedPtrUsage_001 begin" << std::endl;

    auto listener = std::make_shared<DistributedDeviceNodeListener>();
    ASSERT_NE(listener, nullptr);

    DmDeviceInfo deviceInfo;
    SafeCopy(deviceInfo.deviceId, DEVICE_ID);
    SafeCopy(deviceInfo.deviceName, DEVICE_NAME);
    SafeCopy(deviceInfo.networkId, NETWORK_ID);
    deviceInfo.deviceTypeId = DEVICE_TYPE_ID;
    SafeCopy(deviceInfo.extraData, EXTRADATA_DEFAULT);

    // Test with shared_ptr - should not crash
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOnline(deviceInfo));
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceInfoChanged(deviceInfo));
    EXPECT_NO_FATAL_FAILURE(listener->OnDeviceOffline(deviceInfo));
    DTEST_LOG << "DistributedDeviceNodeListenerTest testSharedPtrUsage_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
