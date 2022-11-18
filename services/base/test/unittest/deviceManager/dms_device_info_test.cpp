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

#include "dms_device_info_test.h"

#include "deviceManager/dms_device_info.h"
#include "parcel_helper.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsDeviceInfo";
}
void DmsDeviceInfoTest::SetUpTestCase()
{
}

void DmsDeviceInfoTest::TearDownTestCase()
{
}

void DmsDeviceInfoTest::SetUp()
{
}

void DmsDeviceInfoTest::TearDown()
{
}

/**
 * @tc.name: testGet_001
 * @tc.desc: test Get functions.
 * @tc.type: FUNC
 */
HWTEST_F(DmsDeviceInfoTest, testGet_001, TestSize.Level1)
{
    DTEST_LOG << "DmsDeviceInfoTest testGet_001 begin" << std::endl;
    DmsDeviceInfo dmsDeviceInfo("invalid deviceName", 1, "invalid deivceId");
    /**
     * @tc.steps: step1. test GetDeviceName;
     */
    EXPECT_EQ("invalid deviceName", dmsDeviceInfo.GetDeviceName());
    /**
     * @tc.steps: step2. test GetDeviceId;
     */
    EXPECT_EQ("invalid deivceId", dmsDeviceInfo.GetDeviceId());
    /**
     * @tc.steps: step3. test GetDeviceType;
     */
    EXPECT_EQ(1, dmsDeviceInfo.GetDeviceType());
    /**
     * @tc.steps: step4. test GetDeviceState;
     */
    EXPECT_EQ(1, dmsDeviceInfo.GetDeviceState());
    /**
     * @tc.steps: step5. test Marshalling;
     */
    Parcel parcel;
    std::u16string deviceId;
    std::u16string deviceName;
    int32_t deviceType;
    int32_t deviceState;
    EXPECT_TRUE(dmsDeviceInfo.Marshalling(parcel));
    PARCEL_READ_HELPER_NORET(parcel, String16, deviceId);
    PARCEL_READ_HELPER_NORET(parcel, String16, deviceName);
    PARCEL_READ_HELPER_NORET(parcel, Int32, deviceType);
    PARCEL_READ_HELPER_NORET(parcel, Int32, deviceState);
    EXPECT_FALSE(deviceId.empty());
    EXPECT_FALSE(deviceName.empty());
    EXPECT_EQ(1, deviceType);
    EXPECT_EQ(1, deviceState);
    DTEST_LOG << "DmsDeviceInfoTest testGet_001 end" << std::endl;
}
} // DistributedSchedule
} // namespace OHOS