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

#include "distributed_mission_info_test.h"
#include <memory>
#define private public
#include "mission/distributed_mission_info.h"
#undef private
#include "parcel_helper.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t TEST_INVALID_VALUE = -1;
constexpr int32_t TEST_PARCEL_WRITE_VALUE = 1;
constexpr size_t TEST_PARCEL_WRITE_LEN = 5;
}
void DistributedMissionInfoTest::SetUpTestCase()
{
}

void DistributedMissionInfoTest::TearDownTestCase()
{
}

void DistributedMissionInfoTest::SetUp()
{
}

void DistributedMissionInfoTest::TearDown()
{
}

/**
 * @tc.name: testReadFromParcel001
 * @tc.desc: test ReadFromParcel
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testReadFromParcel001, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testReadFromParcel001 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    bool ret = dstbMissionInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
    ret = dstbMissionInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedMissionInfoTest testReadFromParcel001 end" << std::endl;
}

/**
 * @tc.name: testReadFromParcel002
 * @tc.desc: test ReadFromParcel when combinedMissionIds read failed
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testReadFromParcel002, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testReadFromParcel002 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    for (size_t i = 0; i < TEST_PARCEL_WRITE_LEN; i++) {
        parcel.WriteInt32(TEST_PARCEL_WRITE_VALUE);
    }
    bool ret = dstbMissionInfo.ReadFromParcel(parcel);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedMissionInfoTest testReadFromParcel002 end" << std::endl;
}

/**
 * @tc.name: testUnmarshalling001
 * @tc.desc: test Unmarshalling
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testUnmarshalling001, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testUnmarshalling001 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    bool ret = dstbMissionInfo.Marshalling(parcel);
    EXPECT_TRUE(ret);
    DstbMissionInfo*  dstbMissionInfoReturn = dstbMissionInfo.Unmarshalling(parcel);
    EXPECT_NE(nullptr, dstbMissionInfoReturn);
    DTEST_LOG << "DistributedMissionInfoTest testUnmarshalling001 end" << std::endl;
}

/**
 * @tc.name: testUnmarshalling002
 * @tc.desc: test Unmarshalling when combinedMissionIds read failed
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testUnmarshalling002, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testUnmarshalling002 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    for (size_t i = 0; i < TEST_PARCEL_WRITE_LEN; i++) {
        parcel.WriteInt32(TEST_PARCEL_WRITE_VALUE);
    }
    DstbMissionInfo*  dstbMissionInfoReturn = dstbMissionInfo.Unmarshalling(parcel);
    EXPECT_EQ(nullptr, dstbMissionInfoReturn);
    DTEST_LOG << "DistributedMissionInfoTest testUnmarshalling002 end" << std::endl;
}

/**
 * @tc.name: testMarshalling001
 * @tc.desc: write data to parcel
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testMarshalling001, TestSize.Level3)
{
    DstbMissionInfo dstbMissionInfo;
    Parcel data;
    auto ret = dstbMissionInfo.Marshalling(data);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: testReadDstbMissionInfosFromParcel001
 * @tc.desc: test ReadDstbMissionInfosFromParcel
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testReadDstbMissionInfosFromParcel001, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel001 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    std::vector<DstbMissionInfo> missionInfos;
    bool ret = dstbMissionInfo.ReadDstbMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_TRUE(ret);
    EXPECT_EQ(0, missionInfos.size());
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel001 end" << std::endl;
}

/**
 * @tc.name: testReadDstbMissionInfosFromParcel002
 * @tc.desc: test ReadDstbMissionInfosFromParcel when len < 0
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testReadDstbMissionInfosFromParcel002, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel002 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    std::vector<DstbMissionInfo> missionInfos;
    parcel.WriteInt32(TEST_PARCEL_WRITE_VALUE);
    parcel.WriteInt32(TEST_INVALID_VALUE);
    bool ret = dstbMissionInfo.ReadDstbMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel002 end" << std::endl;
}

/**
 * @tc.name: testReadDstbMissionInfosFromParcel003
 * @tc.desc: test ReadDstbMissionInfosFromParcel when size > parcel.GetReadableBytes()
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testReadDstbMissionInfosFromParcel003, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel003 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    std::vector<DstbMissionInfo> missionInfos;
    parcel.WriteInt32(TEST_PARCEL_WRITE_VALUE);
    parcel.WriteInt32(parcel.GetReadableBytes() + 1);
    bool ret = dstbMissionInfo.ReadDstbMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel003 end" << std::endl;
}

/**
 * @tc.name: testReadDstbMissionInfosFromParcel004
 * @tc.desc: test ReadDstbMissionInfosFromParcel when missionInfos.max_size() < size
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testReadDstbMissionInfosFromParcel004, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel004 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    std::vector<DstbMissionInfo> missionInfos;
    parcel.WriteInt32(TEST_PARCEL_WRITE_VALUE);
    parcel.WriteInt32(missionInfos.max_size() + 1);
    bool ret = dstbMissionInfo.ReadDstbMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel004 end" << std::endl;
}

/**
 * @tc.name: testReadDstbMissionInfosFromParcel005
 * @tc.desc: test ReadDstbMissionInfosFromParcel when size = missionInfos.max_size() - 1
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testReadDstbMissionInfosFromParcel005, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel005 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    std::vector<DstbMissionInfo> missionInfos;
    parcel.WriteInt32(TEST_PARCEL_WRITE_VALUE);
    parcel.WriteInt32(missionInfos.max_size() - 1);
    bool ret = dstbMissionInfo.ReadDstbMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel005 end" << std::endl;
}

/**
 * @tc.name: testReadDstbMissionInfosFromParcel006
 * @tc.desc: test ReadDstbMissionInfosFromParcel when ptr is nullptr
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testReadDstbMissionInfosFromParcel006, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel006 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    std::vector<DstbMissionInfo> missionInfos;
    parcel.WriteInt32(TEST_PARCEL_WRITE_VALUE);
    parcel.WriteInt32(TEST_PARCEL_WRITE_VALUE);
    parcel.WriteParcelable(nullptr);
    bool ret = dstbMissionInfo.ReadDstbMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel006 end" << std::endl;
}

/**
 * @tc.name: testReadDstbMissionInfosFromParcel007
 * @tc.desc: test ReadDstbMissionInfosFromParcel when ptr is not nullptr
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testReadDstbMissionInfosFromParcel007, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel007 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    std::vector<DstbMissionInfo> missionInfos;
    parcel.WriteInt32(TEST_PARCEL_WRITE_VALUE);
    parcel.WriteInt32(TEST_PARCEL_WRITE_VALUE);
    parcel.WriteParcelable(&dstbMissionInfo);
    bool ret = dstbMissionInfo.ReadDstbMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_TRUE(ret);
    EXPECT_EQ(1, missionInfos.size());
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel007 end" << std::endl;
}

/**
 * @tc.name: testWriteDstbMissionInfosToParcel001
 * @tc.desc: test WriteDstbMissionInfosToParcel when missionInfos is empty
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testWriteDstbMissionInfosToParcel001, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testWriteDstbMissionInfosToParcel001 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    std::vector<DstbMissionInfo> missionInfos;
    bool ret = dstbMissionInfo.WriteDstbMissionInfosToParcel(parcel, missionInfos);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedMissionInfoTest testWriteDstbMissionInfosToParcel001 end" << std::endl;
}

/**
 * @tc.name: testWriteDstbMissionInfosToParcel002
 * @tc.desc: test WriteDstbMissionInfosToParcel
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testWriteDstbMissionInfosToParcel002, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testWriteDstbMissionInfosToParcel002 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    std::vector<DstbMissionInfo> missionInfos;
    missionInfos.emplace_back(dstbMissionInfo);
    bool ret = dstbMissionInfo.WriteDstbMissionInfosToParcel(parcel, missionInfos);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedMissionInfoTest testWriteDstbMissionInfosToParcel002 end" << std::endl;
}

/**
 * @tc.name: testToString001
 * @tc.desc: print a missionInfo
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testToString001, TestSize.Level3)
{
    DstbMissionInfo dstbMissionInfo;
    auto ret = dstbMissionInfo.ToString();
    EXPECT_NE(ret, "");
}

/**
 * @tc.name: testToString002
 * @tc.desc: test ToString
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testToString002, TestSize.Level3)
{
    DTEST_LOG << "DistributedMissionInfoTest testToString002 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    dstbMissionInfo.baseWant = std::make_shared<AAFwk::Want>();
    dstbMissionInfo.topAbility = std::make_shared<AppExecFwk::ElementName>();
    dstbMissionInfo.baseAbility = std::make_shared<AppExecFwk::ElementName>();
    dstbMissionInfo.reservedAbility = std::make_shared<AppExecFwk::ElementName>();
    std::string ret = dstbMissionInfo.ToString();
    EXPECT_FALSE(ret.empty());
    DTEST_LOG << "DistributedMissionInfoTest testToString002 end" << std::endl;
}
} // DistributedSchedule
} // namespace OHOS