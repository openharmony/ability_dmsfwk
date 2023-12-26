/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "dtbschedmgr_device_info_storage_test.h"

#include "distributed_sched_util.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"
#include <cstddef>

namespace OHOS {
namespace DistributedSchedule {
using namespace std;
using namespace testing;
using namespace testing::ext;
namespace {
constexpr int32_t MAX_WAIT_TIME = 10000;
}

int32_t DtbschedmgrDeviceInfoStorageTest::startTaskNum_ = 2;
std::mutex DtbschedmgrDeviceInfoStorageTest::caseDoneLock_;
std::condition_variable DtbschedmgrDeviceInfoStorageTest::caseDoneCondition_;

void DtbschedmgrDeviceInfoStorageTest::SetUpTestCase()
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest::SetUpTestCase" << std::endl;
    if (!DistributedSchedUtil::LoadDistributedSchedService()) {
        DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest::SetUpTestCase load dms SA failed" << std::endl;
    }
}

void DtbschedmgrDeviceInfoStorageTest::TearDownTestCase()
{
    // Wait until all async tasks are completed before exiting the test suite
    auto caseDoneNotifyTask = []() {
        std::lock_guard<std::mutex> autoLock(caseDoneLock_);
        --startTaskNum_;
        caseDoneCondition_.notify_all();
    };
    if (DtbschedmgrDeviceInfoStorage::GetInstance().networkIdMgrHandler_ != nullptr) {
        DtbschedmgrDeviceInfoStorage::GetInstance().networkIdMgrHandler_->PostTask(caseDoneNotifyTask);
    }
    if (DtbschedmgrDeviceInfoStorage::GetInstance().initHandler_ != nullptr) {
        DtbschedmgrDeviceInfoStorage::GetInstance().initHandler_->PostTask(caseDoneNotifyTask);
    }
    std::unique_lock<std::mutex> lock(caseDoneLock_);
    caseDoneCondition_.wait_for(lock, std::chrono::milliseconds(MAX_WAIT_TIME),
        [&] () { return startTaskNum_ == 0; });
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest::TearDownTestCase" << std::endl;
}

void DtbschedmgrDeviceInfoStorageTest::SetUp()
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest::SetUp" << std::endl;
}

void DtbschedmgrDeviceInfoStorageTest::TearDown()
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest::TearDown" << std::endl;
}

/**
 * @tc.name: InitTest_001
 * @tc.desc: test Init
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, InitTest_001, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest InitTest_001 start" << std::endl;
    /**
     * @tc.steps: step1. test Init with listener when initHandler_ is nullptr;
     */
    DtbschedmgrDeviceInfoStorage::GetInstance().initHandler_ = nullptr;
    bool result = DtbschedmgrDeviceInfoStorage::GetInstance().Init();
    EXPECT_TRUE(result);
    /**
     * @tc.steps: step2. test Init when initHandler_ is not nullptr;
     */
    result = DtbschedmgrDeviceInfoStorage::GetInstance().Init();
    EXPECT_TRUE(result);
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest InitTest_001 end" << std::endl;
}

/**
 * @tc.name: ConnectSoftbusTest_001
 * @tc.desc: test ConnectSoftbus
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, ConnectSoftbusTest_001, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest ConnectSoftbusTest_001 start" << std::endl;
    /**
     * @tc.steps: step1. test ConnectSoftbus;
     */
    bool result = DtbschedmgrDeviceInfoStorage::GetInstance().ConnectSoftbus();
    EXPECT_TRUE(result);
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest ConnectSoftbusTest_001 end" << std::endl;
}

/**
 * @tc.name: InitNetworkIdManagerTest_001
 * @tc.desc: test InitNetworkIdManager
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, InitNetworkIdManagerTest_001, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest InitNetworkIdManagerTest_001 start" << std::endl;
    std::shared_ptr<DnetworkAdapter> dnetworkAdapter = DnetworkAdapter::GetInstance();
    DtbschedmgrDeviceInfoStorage::GetInstance().networkIdMgrHandler_ = nullptr;
    /**
     * @tc.steps: step1. test InitNetworkIdManager when networkIdMgrHandler_ is nullptr;
     */
    bool result = DtbschedmgrDeviceInfoStorage::GetInstance().InitNetworkIdManager(dnetworkAdapter);
    EXPECT_TRUE(result);

    /**
     * @tc.steps: step2. test InitNetworkIdManager when networkIdMgrHandler_ is not nullptr;
     */
    result = DtbschedmgrDeviceInfoStorage::GetInstance().InitNetworkIdManager(dnetworkAdapter);
    EXPECT_TRUE(result);
    /**
     * @tc.steps: step3. test Stop when deviceNodeListener_ is nullptr;
     */
    DtbschedmgrDeviceInfoStorage::GetInstance().deviceNodeListener_ = nullptr;
    DtbschedmgrDeviceInfoStorage::GetInstance().Stop();
    /**
     * @tc.steps: step4. test Stop when deviceNodeListener_ is not nullptr;
     */
    DtbschedmgrDeviceInfoStorage::GetInstance().deviceNodeListener_ = std::make_shared<DistributedDeviceNodeListener>();
    DtbschedmgrDeviceInfoStorage::GetInstance().Stop();
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest InitNetworkIdManagerTest_001 end" << std::endl;
}

/**
 * @tc.name: WaitForDnetworkReadyTest_001
 * @tc.desc: test WaitForDnetworkReady
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, WaitForDnetworkReadyTest_001, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest WaitForDnetworkReadyTest_001 start" << std::endl;
    /**
     * @tc.steps: step1. test WaitForDnetworkReady;
     */
    bool result = DtbschedmgrDeviceInfoStorage::GetInstance().WaitForDnetworkReady();
    EXPECT_TRUE(result);
    /**
     * @tc.steps: step2. test RegisterUuidNetworkIdMap;
     */
    std::string networkId = "";
    DtbschedmgrDeviceInfoStorage::GetInstance().RegisterUuidNetworkIdMap(networkId);
    /**
     * @tc.steps: step3. test UnregisterUuidNetworkIdMap;
     */
    DtbschedmgrDeviceInfoStorage::GetInstance().UnregisterUuidNetworkIdMap(networkId);
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest WaitForDnetworkReadyTest_001 end" << std::endl;
}

/**
 * @tc.name: GetDeviceIdSetTest_001
 * @tc.desc: test GetDeviceIdSet
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, GetDeviceIdSetTest_001, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest GetDeviceIdSetTest_001 start" << std::endl;
    /**
     * @tc.steps: step1. test GetDeviceIdSet;
     */
    set<std::string> deviceIdSet;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceIdSet(deviceIdSet);
    EXPECT_TRUE(deviceIdSet.empty());
    /**
     * @tc.steps: step2. test GetDeviceIdSet when remoteDevices_ is not empty;
     */
    std::string networkId = "invalid networkId for DeviceOnlineNotify";
    std::string deviceName = "invalid deviceName for DeviceOnlineNotify";
    int32_t deviceType = 0;
    std::shared_ptr<DmsDeviceInfo> devInfo = make_shared<DmsDeviceInfo>(deviceName, deviceType, networkId);
    DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[networkId] = devInfo;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceIdSet(deviceIdSet);
    EXPECT_FALSE(deviceIdSet.empty());
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest GetDeviceIdSetTest_001 end" << std::endl;
}

/**
 * @tc.name: GetLocalDeviceFromDnetTest_001
 * @tc.desc: test GetLocalDeviceFromDnet
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, GetLocalDeviceFromDnetTest_001, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest GetLocalDeviceFromDnetTest_001 start" << std::endl;
    DistributedSchedUtil::MockBundlePermission();
    std::string deviceId;
    /**
     * @tc.steps: step1. test GetLocalDeviceFromDnet;
     */
    bool result = DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(deviceId);
    EXPECT_TRUE(result);
    /**
     * @tc.steps: step2. test DeviceOnlineNotify when devInfo is nullptr;
     */
    std::shared_ptr<DmsDeviceInfo> devInfo = nullptr;
    DtbschedmgrDeviceInfoStorage::GetInstance().DeviceOnlineNotify(devInfo);
    /**
     * @tc.steps: step3. test DeviceOnlineNotify when networkIdMgrHandler_ is nullptr;
     */
    std::string networkId = "invalid networkId for DeviceOnlineNotify";
    std::string deviceName = "invalid deviceName for DeviceOnlineNotify";
    int32_t deviceType = 0;
    devInfo = make_shared<DmsDeviceInfo>(deviceName, deviceType, networkId);
    DtbschedmgrDeviceInfoStorage::GetInstance().networkIdMgrHandler_ = nullptr;
    DtbschedmgrDeviceInfoStorage::GetInstance().DeviceOnlineNotify(devInfo);
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest GetLocalDeviceFromDnetTest_001 end" << std::endl;
}

/**
 * @tc.name: ClearAllDevicesTest_001
 * @tc.desc: test ClearAllDevices
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, ClearAllDevicesTest_001, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest ClearAllDevicesTest_001 start" << std::endl;
    /**
     * @tc.steps: step1. test ClearAllDevices;
     */
    DtbschedmgrDeviceInfoStorage::GetInstance().ClearAllDevices();
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        EXPECT_TRUE(DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.empty());
    }
    /**
     * @tc.steps: step2. test DeviceOfflineNotify when deviceId is empty;
     */
    std::string deviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().DeviceOfflineNotify(deviceId);
    /**
     * @tc.steps: step3. test DeviceOfflineNotify when networkIdMgrHandler_ is nullptr;
     */
    deviceId = "invalid deviceId for DeviceOnlineNotify";
    DtbschedmgrDeviceInfoStorage::GetInstance().networkIdMgrHandler_ = nullptr;
    DtbschedmgrDeviceInfoStorage::GetInstance().DeviceOfflineNotify(deviceId);
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest ClearAllDevicesTest_001 end" << std::endl;
}

/**
 * @tc.name: GetDeviceInfoByIdTest_001
 * @tc.desc: test GetDeviceInfoById
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, GetDeviceInfoByIdTest_001, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest GetDeviceInfoByIdTest_001 start" << std::endl;
    /**
     * @tc.steps: step1. test GetDeviceInfoById when networkId is not in map;
     */
    std::string networkId = "invalid networkId for GetDeviceInfoById";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    }
    std::shared_ptr<DmsDeviceInfo> dmsDeviceInfo =
        DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(networkId);
    EXPECT_EQ(dmsDeviceInfo, nullptr);
    /**
     * @tc.steps: step2. test GetDeviceInfoById when networkId is in map;
     */
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        std::string deviceName = "invalid deviceName for GetDeviceInfoById";
        int32_t deviceType = 0;
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[networkId] =
            make_shared<DmsDeviceInfo>(deviceName, deviceType, networkId);
    }
    dmsDeviceInfo = DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(networkId);
    EXPECT_NE(dmsDeviceInfo, nullptr);
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest GetDeviceInfoByIdTest_001 end" << std::endl;
}

/**
 * @tc.name: GetUuidByNetworkIdTest_001
 * @tc.desc: test GetUuidByNetworkId
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, GetUuidByNetworkIdTest_001, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest GetUuidByNetworkIdTest_001 start" << std::endl;
    /**
     * @tc.steps: step1. test GetUuidByNetworkId when networkId is empty;
     */
    std::string networkId;
    std::string result = DtbschedmgrDeviceInfoStorage::GetInstance().GetUuidByNetworkId(networkId);
    EXPECT_TRUE(result.empty());
    /**
     * @tc.steps: step2. test GetUuidByNetworkId when networkId is not in map;
     */
    networkId = "invalid networkId for GetUuidByNetworkId";
    result = DtbschedmgrDeviceInfoStorage::GetInstance().GetUuidByNetworkId(networkId);
    EXPECT_TRUE(result.empty());
    /**
     * @tc.steps: step3. test GetUuidByNetworkId when networkId is in map;
     */
    std::string uuid = "invalid uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = networkId;
    }
    result = DtbschedmgrDeviceInfoStorage::GetInstance().GetUuidByNetworkId(networkId);
    EXPECT_EQ(result, uuid);
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest GetUuidByNetworkIdTest_001 end" << std::endl;
}

/**
 * @tc.name: GetNetworkIdByUuidTest_001
 * @tc.desc: test GetNetworkIdByUuid
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, GetNetworkIdByUuidTest_001, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest GetNetworkIdByUuidTest_001 start" << std::endl;
    /**
     * @tc.steps: step1. test GetNetworkIdByUuid when uuid is null;
     */
    std::string uuid;
    std::string result = DtbschedmgrDeviceInfoStorage::GetInstance().GetNetworkIdByUuid(uuid);
    EXPECT_TRUE(result.empty());
    /**
     * @tc.steps: step2. test GetNetworkIdByUuid when uuid is invalid;
     */
    uuid = "invalid uuid for GetNetworkIdByUuid";
    result = DtbschedmgrDeviceInfoStorage::GetInstance().GetNetworkIdByUuid(uuid);
    EXPECT_TRUE(result.empty());
    /**
     * @tc.steps: step3. test GetNetworkIdByUuid;
     */
    std::string networkId = "invalid networkId for GetNetworkIdByUuid";
    {
        std::lock_guard<std::mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = networkId;
    }
    result = DtbschedmgrDeviceInfoStorage::GetInstance().GetNetworkIdByUuid(uuid);
    EXPECT_EQ(result, networkId);
    /**
     * @tc.steps: step4. test OnDeviceInfoChanged;
     */
    std::string deviceId = "invalid deviceId for OnDeviceInfoChanged";
    DtbschedmgrDeviceInfoStorage::GetInstance().OnDeviceInfoChanged(deviceId);
    
    /**
     * @tc.steps: step5. test OnRemoteDied;
     */
    wptr<IRemoteObject> remote = nullptr;
    sptr<DnetServiceDeathRecipient> dnetServiceDeathRecipient = new DnetServiceDeathRecipient();
    dnetServiceDeathRecipient->OnRemoteDied(remote);
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest GetNetworkIdByUuidTest_001 end" << std::endl;
}

/**
 * @tc.name: UpdateDeviceInfoStorageTest_001
 * @tc.desc: test UpdateDeviceInfoStorage
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, UpdateDeviceInfoStorageTest_001, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest UpdateDeviceInfoStorageTest_001 start" << std::endl;
    std::vector<DistributedHardware::DmDeviceInfo> dmDeviceInfoList;
    dmDeviceInfoList.clear();
    DtbschedmgrDeviceInfoStorage::GetInstance().UpdateDeviceInfoStorage(dmDeviceInfoList);
    EXPECT_EQ(dmDeviceInfoList.empty(), true);
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest UpdateDeviceInfoStorageTest_001 end" << std::endl;
}

/**
 * @tc.name: UpdateDeviceInfoStorageTest_002
 * @tc.desc: test UpdateDeviceInfoStorage
 * @tc.type: FUNC
 */
HWTEST_F(DtbschedmgrDeviceInfoStorageTest, UpdateDeviceInfoStorageTest_002, TestSize.Level3)
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest UpdateDeviceInfoStorageTest_002 start" << std::endl;
    std::vector<DistributedHardware::DmDeviceInfo> dmDeviceInfoList;
    DistributedHardware::DmDeviceInfo dmDeviceInfo;
    dmDeviceInfoList.emplace_back(dmDeviceInfo);
    DtbschedmgrDeviceInfoStorage::GetInstance().UpdateDeviceInfoStorage(dmDeviceInfoList);
    EXPECT_EQ(!dmDeviceInfoList.empty(), true);
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest UpdateDeviceInfoStorageTest_002 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
