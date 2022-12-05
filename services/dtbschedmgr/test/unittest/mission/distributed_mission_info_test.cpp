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
#include "change_notification.h"
#define private public
#include "mission/distributed_data_change_listener.h"
#include "mission/distributed_mission_info.h"
#include "mission/mission_changed_notify.h"
#undef private
#include "mission/mission_constant.h"
#include "mock_remote_stub.h"
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
const std::string TEST_DEVICE_ID = "test deviceId";
const std::u16string TEST_DEVICEID = u"invalid deviceId";
const std::u16string TEST_DEVICEID_TO_RETURN_FALSE = u"deviceId to return false";
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
    /**
     * @tc.steps: step1. test Marshalling.
     */
    DstbMissionInfo dstbMissionInfo;
    Parcel data;
    auto ret = dstbMissionInfo.Marshalling(data);
    EXPECT_EQ(ret, true);
    /**
     * @tc.steps: step2. test OnChange when insertEntries is not empty.
     */
    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;
    DistributedKv::Entry entry;
    entry.key = "key";
    entry.value = "value";
    insertEntries.emplace_back(entry);
    updateEntries.emplace_back(entry);
    deleteEntries.emplace_back(entry);
    std::string deviceId = "device";
    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries), std::move(updateEntries),
        std::move(deleteEntries), deviceId, false);
    DistributedDataChangeListener distributedDataChangeListener;
    distributedDataChangeListener.OnChange(changeNotification);
    /**
     * @tc.steps: step3. test KeyInfo when strVector.size() == MAX_SPLIT_VARS.
     */
    insertEntries.clear();
    updateEntries.clear();
    deleteEntries.clear();
    entry.key = "key_0";
    insertEntries.emplace_back(entry);
    updateEntries.emplace_back(entry);
    deleteEntries.emplace_back(entry);
    DistributedKv::ChangeNotification changeNotification1(std::move(insertEntries), std::move(updateEntries),
        std::move(deleteEntries), deviceId, false);
    distributedDataChangeListener.OnChange(changeNotification);
}

/**
 * @tc.name: testReadDstbMissionInfosFromParcel001
 * @tc.desc: test ReadDstbMissionInfosFromParcel
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testReadDstbMissionInfosFromParcel001, TestSize.Level3)
{
     /**
     * @tc.steps: step1. test ReadDstbMissionInfosFromParcel.
     */
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel001 start" << std::endl;
    DstbMissionInfo dstbMissionInfo;
    Parcel parcel;
    std::vector<DstbMissionInfo> missionInfos;
    bool ret = dstbMissionInfo.ReadDstbMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_TRUE(ret);
    EXPECT_EQ(0, missionInfos.size());
    /**
     * @tc.steps: step2. test KeyInfo when StrToInt failed.
     */
    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;
    DistributedKv::Entry entry;
    entry.key = "invalid_key";
    entry.value = "value";
    insertEntries.emplace_back(entry);
    updateEntries.emplace_back(entry);
    deleteEntries.emplace_back(entry);
    std::string deviceId = "device";
    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries), std::move(updateEntries),
        std::move(deleteEntries), deviceId, false);
    DistributedDataChangeListener distributedDataChangeListener;
    distributedDataChangeListener.OnChange(changeNotification);
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
 * @tc.desc: test ReadDstbMissionInfosFromParcel when size > GET_MAX_MISSIONS
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
    parcel.WriteInt32(Constants::Mission::GET_MAX_MISSIONS + 1);
    bool ret = dstbMissionInfo.ReadDstbMissionInfosFromParcel(parcel, missionInfos);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedMissionInfoTest testReadDstbMissionInfosFromParcel004 end" << std::endl;
}

/**
 * @tc.name: testReadDstbMissionInfosFromParcel005
 * @tc.desc: test ReadDstbMissionInfosFromParcel when size = GET_MAX_MISSIONS - 1
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
    parcel.WriteInt32(Constants::Mission::GET_MAX_MISSIONS - 1);
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
    /**
     * @tc.steps: step1. test NotifyMissionsChanged when remoteObject is nullptr
     */
    sptr<IRemoteObject> remoteObject = nullptr;
    MissionChangedNotify::NotifyMissionsChanged(remoteObject, TEST_DEVICEID);
    /**
     * @tc.steps: step2. test NotifyMissionsChanged when remoteObject is not nullptr
     */
    remoteObject = new MockRemoteStub();
    MissionChangedNotify::NotifyMissionsChanged(remoteObject, TEST_DEVICEID);
    /**
     * @tc.steps: step3. test NotifyMissionsChanged when remoteObject return false
     */
    MissionChangedNotify::NotifyMissionsChanged(remoteObject, TEST_DEVICEID_TO_RETURN_FALSE);
    /**
     * @tc.steps: step4. test WriteDstbMissionInfosToParcel when missionInfos is empty
     */
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
    int32_t missionId = 0;
    /**
     * @tc.steps: step1. test NotifySnapshot when remoteObject is nullptr
     */
    sptr<IRemoteObject> remoteObject = nullptr;
    MissionChangedNotify::NotifySnapshot(remoteObject, TEST_DEVICEID, missionId);
    /**
     * @tc.steps: step2. test NotifySnapshot when remoteObject is not nullptr
     */
    remoteObject = new MockRemoteStub();
    MissionChangedNotify::NotifySnapshot(remoteObject, TEST_DEVICEID, missionId);
    /**
     * @tc.steps: step3. test NotifySnapshot when remoteObject return false
     */
    MissionChangedNotify::NotifySnapshot(remoteObject, TEST_DEVICEID_TO_RETURN_FALSE, missionId);
    /**
     * @tc.steps: step4. test WriteDstbMissionInfosToParcel
     */
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
    int32_t state = 0;
    /**
     * @tc.steps: step1. test NotifyNetDisconnect when remoteObject is nullptr
     */
    sptr<IRemoteObject> remoteObject = nullptr;
    MissionChangedNotify::NotifyNetDisconnect(remoteObject, TEST_DEVICEID, state);
    /**
     * @tc.steps: step2. test NotifyNetDisconnect when remoteObject is not nullptr
     */
    remoteObject = new MockRemoteStub();
    MissionChangedNotify::NotifyNetDisconnect(remoteObject, TEST_DEVICEID, state);
    /**
     * @tc.steps: step3. test NotifyNetDisconnect when remoteObject is not nullptr
     */
    MissionChangedNotify::NotifyNetDisconnect(remoteObject, TEST_DEVICEID_TO_RETURN_FALSE, state);
    /**
     * @tc.steps: step4. test ToString print a missionInfo.
     */
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
    /**
     * @tc.steps: step1. test ToString.
     */
    DstbMissionInfo dstbMissionInfo;
    dstbMissionInfo.baseWant = std::make_shared<AAFwk::Want>();
    dstbMissionInfo.topAbility = std::make_shared<AppExecFwk::ElementName>();
    dstbMissionInfo.baseAbility = std::make_shared<AppExecFwk::ElementName>();
    dstbMissionInfo.reservedAbility = std::make_shared<AppExecFwk::ElementName>();
    std::string ret = dstbMissionInfo.ToString();
    EXPECT_FALSE(ret.empty());
    /**
     * @tc.steps: step2. test OnChange when insertEntries is empty.
     */
    DistributedDataChangeListener distributedDataChangeListener;
    std::vector<DistributedKv::Entry> insertEntries;
    std::vector<DistributedKv::Entry> updateEntries;
    std::vector<DistributedKv::Entry> deleteEntries;
    DistributedKv::ChangeNotification changeNotification(std::move(insertEntries),
        std::move(updateEntries), std::move(deleteEntries), TEST_DEVICE_ID, false);
    distributedDataChangeListener.OnChange(changeNotification);
    DTEST_LOG << "DistributedMissionInfoTest testToString002 end" << std::endl;
}
} // DistributedSchedule
} // namespace OHOS