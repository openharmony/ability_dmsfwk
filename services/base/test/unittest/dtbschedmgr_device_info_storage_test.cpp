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

#include "dtbschedmgr_device_info_storage_test.h"

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

class MockDmsNotifier : public DmsNotifier {
public:
    MockDmsNotifier() = default;
    ~MockDmsNotifier() = default;

    void DeviceOnlineNotify(const std::string& deviceId) override;
    void DeviceOfflineNotify(const std::string& deviceId) override;
    void ProcessNotifierDied(const sptr<IRemoteObject>& notifier) override;
    void ScheduleStartDeviceManager(const sptr<IRemoteObject>& appProxy, int32_t token,
        const std::shared_ptr<ContinuationExtraParams>& continuationExtraParams = nullptr) override;
    int32_t OnDeviceConnect(int32_t token, const std::vector<ContinuationResult>& continuationResults) override;
    int32_t OnDeviceDisconnect(int32_t token, const std::vector<std::string>& deviceIds) override;
    int32_t OnDeviceCancel() override;
};

void MockDmsNotifier::DeviceOnlineNotify(const std::string& deviceId)
{
}

void MockDmsNotifier::DeviceOfflineNotify(const std::string& deviceId)
{
}

void MockDmsNotifier::ProcessNotifierDied(const sptr<IRemoteObject>& notifier)
{
}

void MockDmsNotifier::ScheduleStartDeviceManager(const sptr<IRemoteObject>& appProxy, int32_t token,
    const std::shared_ptr<ContinuationExtraParams>& continuationExtraParams)
{
}

int32_t MockDmsNotifier::OnDeviceConnect(int32_t token, const std::vector<ContinuationResult>& continuationResults)
{
    return 0;
}

int32_t MockDmsNotifier::OnDeviceDisconnect(int32_t token, const std::vector<std::string>& deviceIds)
{
    return 0;
}

int32_t MockDmsNotifier::OnDeviceCancel()
{
    return 0;
}

void DtbschedmgrDeviceInfoStorageTest::SetUpTestCase()
{
    DTEST_LOG << "DtbschedmgrDeviceInfoStorageTest::SetUpTestCase" << std::endl;
}

bool DtbschedmgrDeviceInfoStorageTest::isCaseDone_ = false;
std::mutex DtbschedmgrDeviceInfoStorageTest::caseDoneLock_;
std::condition_variable DtbschedmgrDeviceInfoStorageTest::caseDoneCondition_;

void DtbschedmgrDeviceInfoStorageTest::TearDownTestCase()
{
    // Wait until all asyn tasks are completed before exiting the test suite
    auto caseDoneNotifyTask = []() {
        std::lock_guard<std::mutex> autoLock(caseDoneLock_);
        isCaseDone_ = true;
        caseDoneCondition_.notify_all();
    };
    if (DtbschedmgrDeviceInfoStorage::GetInstance().networkIdMgrHandler_ != nullptr) {
        DtbschedmgrDeviceInfoStorage::GetInstance().networkIdMgrHandler_->PostTask(caseDoneNotifyTask);
    }

    std::unique_lock<std::mutex> lock(caseDoneLock_);
    caseDoneCondition_.wait_for(lock, std::chrono::milliseconds(MAX_WAIT_TIME),
        [&] () { return isCaseDone_; });
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
    sptr<DmsNotifier> listener = nullptr;
    DtbschedmgrDeviceInfoStorage::GetInstance().initHandler_ = nullptr;
    bool result = DtbschedmgrDeviceInfoStorage::GetInstance().Init(listener);
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
    auto runner = AppExecFwk::EventRunner::Create("DmsNetworkIdManager");
    DtbschedmgrDeviceInfoStorage::GetInstance().networkIdMgrHandler_ =
        std::make_shared<AppExecFwk::EventHandler>(runner);
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
    deviceId = "invalid deviceId for DeviceOnlineNotify";
    std::string deviceName = "invalid deviceName for DeviceOnlineNotify";
    int32_t deviceType = 0;
    devInfo = make_shared<DmsDeviceInfo>(deviceName, deviceType, deviceId);
    DtbschedmgrDeviceInfoStorage::GetInstance().networkIdMgrHandler_ = nullptr;
    DtbschedmgrDeviceInfoStorage::GetInstance().DeviceOnlineNotify(devInfo);
    /**
     * @tc.steps: step4. test DeviceOnlineNotify when listener_ is nullptr;
     */
    auto runner = AppExecFwk::EventRunner::Create("DmsNetworkIdManager");
    DtbschedmgrDeviceInfoStorage::GetInstance().networkIdMgrHandler_ =
        std::make_shared<AppExecFwk::EventHandler>(runner);
    DtbschedmgrDeviceInfoStorage::GetInstance().listener_ = nullptr;
    DtbschedmgrDeviceInfoStorage::GetInstance().DeviceOnlineNotify(devInfo);
    /**
     * @tc.steps: step5. test DeviceOnlineNotify when listener_ is not nullptr;
     */
    DtbschedmgrDeviceInfoStorage::GetInstance().listener_ = new MockDmsNotifier();
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
    /**
     * @tc.steps: step4. test DeviceOfflineNotify when listener_ is nullptr;
     */
    auto runner = AppExecFwk::EventRunner::Create("DmsNetworkIdManager");
    DtbschedmgrDeviceInfoStorage::GetInstance().networkIdMgrHandler_ =
        std::make_shared<AppExecFwk::EventHandler>(runner);
    DtbschedmgrDeviceInfoStorage::GetInstance().listener_ = nullptr;
    DtbschedmgrDeviceInfoStorage::GetInstance().DeviceOfflineNotify(deviceId);
    /**
     * @tc.steps: step5. test DeviceOfflineNotify when listener_ is not nullptr;
     */
    DtbschedmgrDeviceInfoStorage::GetInstance().listener_ = new MockDmsNotifier();
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
     * @tc.steps: step1. test GetDeviceInfoById when deviceId is not in map;
     */
    std::string deviceId = "invalid deviceId for GetDeviceInfoById";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    }
    std::shared_ptr<DmsDeviceInfo> dmsDeviceInfo =
        DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(deviceId);
    EXPECT_EQ(dmsDeviceInfo, nullptr);
    /**
     * @tc.steps: step2. test GetDeviceInfoById when deviceId is in map;
     */
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        std::string deviceName = "invalid deviceName for GetDeviceInfoById";
        int32_t deviceType = 0;
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[deviceId] =
            make_shared<DmsDeviceInfo>(deviceName, deviceType, deviceId);
    }
    dmsDeviceInfo = DtbschedmgrDeviceInfoStorage::GetInstance().GetDeviceInfoById(deviceId);
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

} // namespace DistributedSchedule
} // namespace OHOS
