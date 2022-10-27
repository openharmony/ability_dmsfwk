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

#include "mission_info_converter_test.h"

#include "mission/distributed_mission_info.h"
#include "mission/mission_info_converter.h"
#include "parcel_helper.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedAbilityManagerService";
}

void MissionInfoConverterTest::SetUpTestCase()
{
}

void MissionInfoConverterTest::TearDownTestCase()
{
}

void MissionInfoConverterTest::SetUp()
{
}

void MissionInfoConverterTest::TearDown()
{
}

/**
 * @tc.name: testConvertToDstbMissionInfos_001
 * @tc.desc: test ConvertToDstbMissionInfos when missionInfos is empty
 * @tc.type: FUNC
 */
HWTEST_F(MissionInfoConverterTest, testConvertToDstbMissionInfos_001, TestSize.Level1)
{
    DTEST_LOG << "MissionInfoConverterTest testConvertToDstbMissionInfos_001 begin" << std::endl;
    std::vector<AAFwk::MissionInfo> missionInfos;
    std::vector<DstbMissionInfo> dstbMissionInfos;
    int32_t result = MissionInfoConverter::ConvertToDstbMissionInfos(missionInfos, dstbMissionInfos);
    EXPECT_EQ(ERR_OK, result);
    DTEST_LOG << "MissionInfoConverterTest testConvertToDstbMissionInfos_001 end" << std::endl;
}

/**
 * @tc.name: testConvertToMissionInfos_001
 * @tc.desc: test ConvertToMissionInfos when missionInfos is empty
 * @tc.type: FUNC
 */
HWTEST_F(MissionInfoConverterTest, testConvertToMissionInfos_001, TestSize.Level1)
{
    DTEST_LOG << "MissionInfoConverterTest testConvertToMissionInfos_001 begin" << std::endl;
    std::vector<AAFwk::MissionInfo> missionInfos;
    std::vector<DstbMissionInfo> dstbMissionInfos;
    int32_t result = MissionInfoConverter::ConvertToMissionInfos(dstbMissionInfos, missionInfos);
    EXPECT_EQ(ERR_OK, result);
    DTEST_LOG << "MissionInfoConverterTest testConvertToMissionInfos_001 end" << std::endl;
}

/**
 * @tc.name: testWriteMissionInfosToParcel_001
 * @tc.desc: test WriteMissionInfosToParcel when missionInfos is empty
 * @tc.type: FUNC
 */
HWTEST_F(MissionInfoConverterTest, testWriteMissionInfosToParcel_001, TestSize.Level1)
{
    DTEST_LOG << "MissionInfoConverterTest testWriteMissionInfosToParcel_001 begin" << std::endl;
    Parcel parcel;
    std::vector<AAFwk::MissionInfo> missionInfos;
    /**
     * @tc.steps: step1. test WriteMissionInfosToParcel when missionInfos.size is 0;
     */
    bool result = MissionInfoConverter::WriteMissionInfosToParcel(parcel, missionInfos);
    EXPECT_TRUE(result);
    /**
     * @tc.steps: step2. test ReadMissionInfosFromParcel when empty is not VALUE_OBJECT;
     */
    result = MissionInfoConverter::ReadMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_TRUE(result);
}

/**
 * @tc.name: ReadMissionInfosFromParcel_001
 * @tc.desc: test ReadMissionInfosFromParcel when missionInfos is empty
 * @tc.type: FUNC
 */
HWTEST_F(MissionInfoConverterTest, ReadMissionInfosFromParcel_001, TestSize.Level1)
{
    DTEST_LOG << "MissionInfoConverterTest ReadMissionInfosFromParcel_001 begin" << std::endl;
    MessageParcel parcel;
    std::vector<AAFwk::MissionInfo> missionInfos;
    /**
     * @tc.steps: step1. test ReadMissionInfosFromParcel when len is less than 0;
     */
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, 1);
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, -1);
    bool result = MissionInfoConverter::ReadMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(result);
    EXPECT_TRUE(missionInfos.empty());
    /**
     * @tc.steps: step2. test ReadMissionInfosFromParcel when len = parcel.GetReadableBytes() + 1;
     */
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, 1);
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, parcel.GetReadableBytes() + 1);
    result = MissionInfoConverter::ReadMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(result);
    EXPECT_TRUE(missionInfos.empty());
    /**
     * @tc.steps: step3. test ReadMissionInfosFromParcel when len = missionInfos.max_size() + 1;
     */
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, 1);
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, missionInfos.max_size() + 1);
    result = MissionInfoConverter::ReadMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(result);
    EXPECT_TRUE(missionInfos.empty());
    /**
     * @tc.steps: step4. test ReadMissionInfosFromParcel when len = missionInfos.max_size() - 1;
     */
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, 1);
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, missionInfos.max_size() - 1);
    result = MissionInfoConverter::ReadMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(result);
    EXPECT_TRUE(missionInfos.empty());
    DTEST_LOG << "MissionInfoConverterTest ReadMissionInfosFromParcel_001 end" << std::endl;
}
} // DistributedSchedule
} // namespace OHOS