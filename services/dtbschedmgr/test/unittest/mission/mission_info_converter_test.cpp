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
#include "mission/mission_constant.h"
#include "mission/mission_info_converter.h"
#include "parcel_helper.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "MissionInfoConverter";
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
 * @tc.name: testConvertToDstbMissionInfos_002
 * @tc.desc: test ConvertToDstbMissionInfos when missionInfos is not empty
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(MissionInfoConverterTest, testConvertToDstbMissionInfos_002, TestSize.Level3)
{
    DTEST_LOG << "MissionInfoConverterTest testConvertToDstbMissionInfos_002 begin" << std::endl;
    std::vector<AAFwk::MissionInfo> missionInfos;
    std::vector<DstbMissionInfo> dstbMissionInfos;
    AAFwk::MissionInfo missionInfo;
    missionInfo.want = AAFwk::Want();
    missionInfos.emplace_back(missionInfo);
    int32_t result = MissionInfoConverter::ConvertToDstbMissionInfos(missionInfos, dstbMissionInfos);
    EXPECT_EQ(ERR_OK, result);
    EXPECT_FALSE(dstbMissionInfos.empty());
    DTEST_LOG << "MissionInfoConverterTest testConvertToDstbMissionInfos_002 end" << std::endl;
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
 * @tc.name: testConvertToMissionInfos_002
 * @tc.desc: test ConvertToMissionInfos when missionInfos is not empty
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(MissionInfoConverterTest, testConvertToMissionInfos_002, TestSize.Level3)
{
    DTEST_LOG << "MissionInfoConverterTest testConvertToMissionInfos_002 begin" << std::endl;
    std::vector<AAFwk::MissionInfo> missionInfos;
    std::vector<DstbMissionInfo> dstbMissionInfos;
    DstbMissionInfo dstbMissionInfo;
    std::shared_ptr<AAFwk::Want> spWant = std::make_shared<AAFwk::Want>();
    dstbMissionInfo.baseWant = spWant;
    dstbMissionInfos.emplace_back(dstbMissionInfo);
    int32_t result = MissionInfoConverter::ConvertToMissionInfos(dstbMissionInfos, missionInfos);
    EXPECT_EQ(ERR_OK, result);
    DTEST_LOG << "MissionInfoConverterTest testConvertToMissionInfos_002 end" << std::endl;
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
    /**
     * @tc.steps: step3. test WriteMissionInfosToParcel when missionInfos is not empty;
     */
    AAFwk::MissionInfo missionInfo;
    missionInfos.emplace_back(missionInfo);
    result = MissionInfoConverter::WriteMissionInfosToParcel(parcel, missionInfos);
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
     * @tc.steps: step3. test ReadMissionInfosFromParcel when len = GET_MAX_MISSIONS + 1;
     */
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, 1);
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, Constants::Mission::GET_MAX_MISSIONS + 1);
    result = MissionInfoConverter::ReadMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(result);
    EXPECT_TRUE(missionInfos.empty());
    /**
     * @tc.steps: step4. test ReadMissionInfosFromParcel when len = GET_MAX_MISSIONS - 1;
     */
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, 1);
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, Constants::Mission::GET_MAX_MISSIONS - 1);
    result = MissionInfoConverter::ReadMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(result);
    EXPECT_TRUE(missionInfos.empty());
    /**
     * @tc.steps: step5. test ReadMissionInfosFromParcel when missionInfo is not nullptr;
     */
    AAFwk::MissionInfo missionInfo;
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, 1);
    PARCEL_WRITE_HELPER_NORET(parcel, Int32, 1);
    PARCEL_WRITE_HELPER_NORET(parcel, Parcelable, &missionInfo);
    result = MissionInfoConverter::ReadMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_TRUE(result);
    EXPECT_FALSE(missionInfos.empty());
    DTEST_LOG << "MissionInfoConverterTest ReadMissionInfosFromParcel_001 end" << std::endl;
}
} // DistributedSchedule
} // namespace OHOS