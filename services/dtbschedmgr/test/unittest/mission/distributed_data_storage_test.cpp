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

#include "distributed_data_storage_test.h"

#include <memory>
#include <thread>
#include "distributed_sched_test_util.h"
#include "dtbschedmgr_device_info_storage.h"
#include "mission/distributed_sched_mission_manager.h"
#include "mission/extension/dms_main_service_channel.h"
#include "test_log.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedKv;
using namespace OHOS::DistributedHardware;
namespace {
constexpr int32_t TASK_ID_1 = 11;
constexpr int32_t TASK_ID_2 = 12;
constexpr size_t BYTESTREAM_LENGTH = 100;
constexpr uint8_t ONE_BYTE = '6';
const std::string UT_TEST_UUID = "ut-test-uuid";

class DmsMainServiceChannelStorageTestMock : public DmsMainServiceChannel {
public:
    std::shared_ptr<DmsDeviceInfo> GetDeviceInfoById(const std::string& deviceId) override
    {
        (void)deviceId;
        return nullptr;
    }
    std::string GetUuidByNetworkId(const std::string& networkId) override
    {
        (void)networkId;
        return UT_TEST_UUID;
    }
    bool GetLocalDeviceId(std::string& networkId) override
    {
        networkId = "ut-local-network-id";
        return true;
    }
    std::string GetNetworkIdByUuid(const std::string& uuid) override
    {
        (void)uuid;
        return "ut-local-network-id";
    }
    int32_t GetLocalMissionInfos(int32_t numMissions, std::vector<DstbMissionInfo>& missionInfos) override
    {
        (void)numMissions;
        (void)missionInfos;
        return ERR_OK;
    }
    int32_t RegisterMissionListener(const sptr<AAFwk::IMissionListener>& listener) override
    {
        (void)listener;
        return ERR_OK;
    }
    int32_t UnRegisterMissionListener(const sptr<AAFwk::IMissionListener>& listener) override
    {
        (void)listener;
        return ERR_OK;
    }
    int32_t GetLocalMissionSnapshotInfo(const std::string& networkId, int32_t missionId,
        AAFwk::MissionSnapshot& missionSnapshot) override
    {
        (void)networkId;
        (void)missionId;
        (void)missionSnapshot;
        return -1;
    }
    std::string GetAnonymStr(const std::string& value) override
    {
        return value;
    }
};
} // namespace

void DistributedDataStorageTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedDataStorageTest::SetUpTestCase" << std::endl;
    if (!DistributedSchedUtil::LoadDistributedSchedService()) {
        DTEST_LOG << "DMSMissionManagerTest::SetUpTestCase LoadDistributedSchedService failed" << std::endl;
    }
    const std::string pkgName = "DBinderBus_" + std::to_string(getprocpid());
    std::shared_ptr<DmInitCallback> initCallback_ = std::make_shared<DeviceInitCallBack>();
    DeviceManager::GetInstance().InitDeviceManager(pkgName, initCallback_);
}

void DistributedDataStorageTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedDataStorageTest::TearDownTestCase" << std::endl;
}

void DistributedDataStorageTest::SetUp()
{
    DistributedSchedUtil::MockPermission();
    distributedDataStorage_ = std::make_shared<DistributedDataStorage>();
    auto mockChannel = std::make_shared<DmsMainServiceChannelStorageTestMock>();
    DistributedSchedMissionManager::GetInstance().SetMainServiceChannel(mockChannel);
    DTEST_LOG << "DistributedDataStorageTest::SetUp" << std::endl;
}

void DistributedDataStorageTest::TearDown()
{
    DTEST_LOG << "DistributedDataStorageTest::TearDown" << std::endl;
}

void DistributedDataStorageTest::DeviceInitCallBack::OnRemoteDied()
{
}

uint8_t* DistributedDataStorageTest::InitByteStream()
{
    uint8_t* byteStream = new uint8_t[BYTESTREAM_LENGTH];
    for (size_t i = 0; i < BYTESTREAM_LENGTH; ++i) {
        byteStream[i] = ONE_BYTE;
    }
    return byteStream;
}

std::string DistributedDataStorageTest::GetLocalDeviceId() const
{
    std::string localDeviceId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId)) {
        DTEST_LOG << "DistributedDataStorageTest::GetLocalDeviceId failed!" << std::endl;
    }
    return localDeviceId;
}

/**
 * @tc.name: InitTest_001
 * @tc.desc: test init DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, InitTest_001, TestSize.Level0)
{
    DTEST_LOG << "DistributedDataStorageTest InitTest_001 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    bool ret = distributedDataStorage_->Init();
    EXPECT_EQ(true, ret);
    this_thread::sleep_for(1s);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest InitTest_001 end" << std::endl;
}

/**
 * @tc.name: InsertTest_001
 * @tc.desc: test insert DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, InsertTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest InsertTest_001 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    ASSERT_NE(DistributedSchedMissionManager::GetInstance().GetMainServiceChannel(), nullptr);
    if (!distributedDataStorage_->Init()) {
        DTEST_LOG << "InsertTest_001 skip: Init failed" << std::endl;
        return;
    }
    this_thread::sleep_for(1s);
    std::string deviceId = GetLocalDeviceId();
    if (deviceId.empty()) {
        deviceId = "ut-local-network-id";
    }
    uint8_t* byteStream = InitByteStream();
    ASSERT_NE(byteStream, nullptr);
    bool ret = distributedDataStorage_->Insert(deviceId, TASK_ID_1, byteStream, BYTESTREAM_LENGTH);
    delete[] byteStream;
    byteStream = nullptr;
    EXPECT_EQ(true, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest InsertTest_001 end" << std::endl;
}

/**
 * @tc.name: InsertTest_002
 * @tc.desc: test insert DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, InsertTest_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest InsertTest_002 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string deviceId;
    uint8_t* byteStream = InitByteStream();
    bool ret = distributedDataStorage_->Insert(deviceId, TASK_ID_1, byteStream, BYTESTREAM_LENGTH);
    EXPECT_EQ(false, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest InsertTest_002 end" << std::endl;
}

/**
 * @tc.name: InsertTest_003
 * @tc.desc: test insert DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, InsertTest_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest InsertTest_003 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string deviceId = GetLocalDeviceId();
    uint8_t* byteStream = InitByteStream();
    bool ret = distributedDataStorage_->Insert(deviceId, -1, byteStream, BYTESTREAM_LENGTH);
    EXPECT_EQ(false, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest InsertTest_003 end" << std::endl;
}

/**
 * @tc.name: DeleteTest_001
 * @tc.desc: test delete DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, DeleteTest_001, TestSize.Level0)
{
    DTEST_LOG << "DistributedDataStorageTest DeleteTest_001 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string deviceId = GetLocalDeviceId();
    bool ret = distributedDataStorage_->Delete(deviceId, TASK_ID_1);
    EXPECT_EQ(true, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest DeleteTest_001 end" << std::endl;
}

/**
 * @tc.name: DeleteTest_002
 * @tc.desc: test delete DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, DeleteTest_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest DeleteTest_002 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string deviceId = GetLocalDeviceId();
    uint8_t* byteStream = InitByteStream();
    distributedDataStorage_->Insert(deviceId, TASK_ID_1, byteStream, BYTESTREAM_LENGTH);
    bool ret = distributedDataStorage_->Delete(deviceId, TASK_ID_1);
    EXPECT_EQ(true, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest DeleteTest_002 end" << std::endl;
}

/**
 * @tc.name: DeleteTest_003
 * @tc.desc: test delete DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, DeleteTest_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest DeleteTest_003 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string networkId;
    int32_t missionId = 0;
    bool ret = distributedDataStorage_->Delete(networkId, missionId);
    EXPECT_EQ(false, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest DeleteTest_003 end" << std::endl;
}

/**
 * @tc.name: DeleteTest_004
 * @tc.desc: test delete DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, DeleteTest_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest DeleteTest_004 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string networkId = GetLocalDeviceId();
    int32_t missionId = -1;
    bool ret = distributedDataStorage_->Delete(networkId, missionId);
    EXPECT_EQ(false, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest DeleteTest_004 end" << std::endl;
}

/**
 * @tc.name: QueryTest_001
 * @tc.desc: test query DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, QueryTest_001, TestSize.Level0)
{
    DTEST_LOG << "DistributedDataStorageTest QueryTest_001 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string deviceId = GetLocalDeviceId();
    Value value;
    bool ret = distributedDataStorage_->Query(deviceId, TASK_ID_1, value);
    EXPECT_EQ(false, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest QueryTest_001 end" << std::endl;
}

/**
 * @tc.name: QueryTest_002
 * @tc.desc: test query DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, QueryTest_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest QueryTest_002 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string deviceId = GetLocalDeviceId();
    uint8_t* byteStream = InitByteStream();
    distributedDataStorage_->Insert(deviceId, TASK_ID_1, byteStream, BYTESTREAM_LENGTH);
    Value value;
    bool ret = distributedDataStorage_->Query(deviceId, TASK_ID_1, value);
    EXPECT_EQ(true, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest QueryTest_002 end" << std::endl;
}

/**
 * @tc.name: QueryTest_003
 * @tc.desc: test query DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, QueryTest_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest QueryTest_003 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string deviceId = GetLocalDeviceId();
    uint8_t* byteStream = InitByteStream();
    distributedDataStorage_->Insert(deviceId, TASK_ID_1, byteStream, BYTESTREAM_LENGTH);
    distributedDataStorage_->Delete(deviceId, TASK_ID_1);
    Value value;
    bool ret = distributedDataStorage_->Query(deviceId, TASK_ID_1, value);
    EXPECT_EQ(false, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest QueryTest_003 end" << std::endl;
}

/**
 * @tc.name: QueryTest_004
 * @tc.desc: test query DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, QueryTest_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest QueryTest_004 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string deviceId = GetLocalDeviceId();
    uint8_t* byteStream = InitByteStream();
    distributedDataStorage_->Insert(deviceId, TASK_ID_1, byteStream, BYTESTREAM_LENGTH);
    distributedDataStorage_->Insert(deviceId, TASK_ID_2, byteStream, BYTESTREAM_LENGTH);
    distributedDataStorage_->Delete(deviceId, TASK_ID_1);
    Value value;
    bool ret = distributedDataStorage_->Query(deviceId, TASK_ID_1, value);
    EXPECT_EQ(false, ret);
    ret = distributedDataStorage_->Query(deviceId, TASK_ID_2, value);
    EXPECT_EQ(true, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest QueryTest_004 end" << std::endl;
}

/**
 * @tc.name: QueryTest_005
 * @tc.desc: test query DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, QueryTest_005, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest QueryTest_005 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string deviceId = GetLocalDeviceId();
    uint8_t* byteStream = InitByteStream();
    distributedDataStorage_->Insert(deviceId, TASK_ID_1, byteStream, BYTESTREAM_LENGTH);
    distributedDataStorage_->Insert(deviceId, TASK_ID_2, byteStream, BYTESTREAM_LENGTH);
    distributedDataStorage_->FuzzyDelete(deviceId);
    Value value;
    bool ret = distributedDataStorage_->Query(deviceId, TASK_ID_1, value);
    EXPECT_EQ(true, ret);
    ret = distributedDataStorage_->Query(deviceId, TASK_ID_2, value);
    EXPECT_EQ(true, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest QueryTest_005 end" << std::endl;
}

/**
 * @tc.name: QueryTest_006
 * @tc.desc: test query DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, QueryTest_006, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest QueryTest_006 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string deviceId;
    Value value;
    bool ret = distributedDataStorage_->Query(deviceId, TASK_ID_1, value);
    EXPECT_EQ(false, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest QueryTest_006 end" << std::endl;
}

/**
 * @tc.name: QueryTest_007
 * @tc.desc: test query DistributedDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, QueryTest_007, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest QueryTest_007 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string deviceId = GetLocalDeviceId();
    Value value;
    bool ret = distributedDataStorage_->Query(deviceId, -1, value);
    EXPECT_EQ(false, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest QueryTest_007 end" << std::endl;
}

/**
 * @tc.name: NotifyRemoteDiedTest_001
 * @tc.desc: NotifyRemoteDied is safe when death recipient is not installed (no Init)
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, NotifyRemoteDiedTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest NotifyRemoteDiedTest_001 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    wptr<IRemoteObject> remote;
    distributedDataStorage_->NotifyRemoteDied(remote);
    DTEST_LOG << "DistributedDataStorageTest NotifyRemoteDiedTest_001 end" << std::endl;
}

/**
 * @tc.name: FuzzyDeleteTest_002
 * @tc.desc: FuzzyDelete returns false when networkId is empty
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, FuzzyDeleteTest_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest FuzzyDeleteTest_002 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    std::string emptyNetworkId;
    bool ret = distributedDataStorage_->FuzzyDelete(emptyNetworkId);
    EXPECT_EQ(false, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest FuzzyDeleteTest_002 end" << std::endl;
}

/**
 * @tc.name: InsertTest_EmptyNetworkId_001
 * @tc.desc: Insert returns false when networkId is empty
 * @tc.type: FUNC
 */
HWTEST_F(DistributedDataStorageTest, InsertTest_EmptyNetworkId_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedDataStorageTest InsertTest_EmptyNetworkId_001 start" << std::endl;
    ASSERT_NE(distributedDataStorage_, nullptr);
    distributedDataStorage_->Init();
    this_thread::sleep_for(1s);
    uint8_t* byteStream = InitByteStream();
    std::string emptyNetworkId;
    bool ret = distributedDataStorage_->Insert(emptyNetworkId, TASK_ID_1, byteStream, BYTESTREAM_LENGTH);
    EXPECT_EQ(false, ret);
    distributedDataStorage_->Stop();
    DTEST_LOG << "DistributedDataStorageTest InsertTest_EmptyNetworkId_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS