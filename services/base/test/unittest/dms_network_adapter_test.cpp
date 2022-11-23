/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include <condition_variable>
#include <shared_mutex>
#include <thread>
#define private public
#include "adapter/dnetwork_adapter.h"
#undef private
#include "dtbschedmgr_device_info_storage.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace {
const std::string NETWORKID = "1234567";
constexpr int32_t SLEEP_TIME = 2000;
constexpr int32_t MAX_WAIT_TIME = 10000;
}

namespace OHOS {
namespace DistributedSchedule {
class MockDeviceListener : public DeviceListener {
public:
    MockDeviceListener() = default;
    ~MockDeviceListener() = default;

    void OnDeviceOnline(const DistributedHardware::DmDeviceInfo& deviceInfo) override {}
    void OnDeviceOffline(const DistributedHardware::DmDeviceInfo& deviceInfo) override {}
    void OnDeviceInfoChanged(const DistributedHardware::DmDeviceInfo& deviceInfo) override {}
};

class DMSNetworkAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static bool isCaseDone_;
    static std::mutex caseDoneLock_;
    static std::condition_variable caseDoneCondition_;
};

bool DMSNetworkAdapterTest::isCaseDone_ = false;
std::mutex DMSNetworkAdapterTest::caseDoneLock_;
std::condition_variable DMSNetworkAdapterTest::caseDoneCondition_;

void DMSNetworkAdapterTest::SetUpTestCase()
{
}

void DMSNetworkAdapterTest::TearDownTestCase()
{
    // Wait until all asyn tasks are completed before exiting the test suite
    auto caseDoneNotifyTask = []() {
        std::lock_guard<std::mutex> autoLock(caseDoneLock_);
        isCaseDone_ = true;
        caseDoneCondition_.notify_all();
    };
    if (DnetworkAdapter::GetInstance()->dnetworkHandler_ != nullptr) {
        DnetworkAdapter::GetInstance()->dnetworkHandler_->PostTask(caseDoneNotifyTask);
    }

    std::unique_lock<std::mutex> lock(caseDoneLock_);
    caseDoneCondition_.wait_for(lock, std::chrono::milliseconds(MAX_WAIT_TIME),
        [&] () { return isCaseDone_; });
}

void DMSNetworkAdapterTest::SetUp()
{
}

void DMSNetworkAdapterTest::TearDown()
{
}

/**
 * @tc.name: testGetUdidByNetworkId001
 * @tc.desc: testGetUdidByNetworkId empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUdidByNetworkId001, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUdidByNetworkId("");
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: testGetUdidByNetworkId002
 * @tc.desc: testGetUdidByNetworkId not empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUdidByNetworkId002, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(NETWORKID);
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: testGetUuidByNetworkId001
 * @tc.desc: testGetUuidByNetworkId empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUuidByNetworkId001, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUuidByNetworkId("");
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: testGetUuidByNetworkId001
 * @tc.desc: testGetUuidByNetworkId not empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUuidByNetworkId002, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUuidByNetworkId(NETWORKID);
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: Init
 * @tc.desc: testInit
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testInit001, TestSize.Level3)
{
    DnetworkAdapter::GetInstance()->Init();
    bool res = DtbschedmgrDeviceInfoStorage::GetInstance().Init();
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: testGetUdidByNetworkId003
 * @tc.desc: testGetUdidByNetworkId not empty with init
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUdidByNetworkId003, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(NETWORKID);
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: testGetUuidByNetworkId003
 * @tc.desc: testGetUuidByNetworkId not empty with init
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUuidByNetworkId003, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUuidByNetworkId(NETWORKID);
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: OnDeviceOnline_001
 * @tc.desc: listenerSet_ is empty
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DMSNetworkAdapterTest, OnDeviceOnline_001, TestSize.Level3)
{
    DistributedHardware::DmDeviceInfo deviceInfo;
    DnetworkAdapter::listenerSet_.clear();
    DnetworkAdapter::GetInstance()->stateCallback_->OnDeviceOnline(deviceInfo);
    EXPECT_EQ(DnetworkAdapter::listenerSet_.size(), 0);
}

/**
 * @tc.name: OnDeviceOnline_002
 * @tc.desc: listenerSet_ is not empty
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DMSNetworkAdapterTest, OnDeviceOnline_002, TestSize.Level3)
{
    DistributedHardware::DmDeviceInfo deviceInfo;
    DnetworkAdapter::listenerSet_.clear();
    std::shared_ptr<DeviceListener> deviceNodeListener = std::make_shared<MockDeviceListener>();
    DnetworkAdapter::listenerSet_.insert(deviceNodeListener);
    DnetworkAdapter::GetInstance()->stateCallback_->OnDeviceOnline(deviceInfo);
    EXPECT_EQ(DnetworkAdapter::listenerSet_.size(), 1);
}

/**
 * @tc.name: OnDeviceOffline_001
 * @tc.desc: listenerSet_ is empty
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DMSNetworkAdapterTest, OnDeviceOffline_001, TestSize.Level3)
{
    DistributedHardware::DmDeviceInfo deviceInfo;
    DnetworkAdapter::listenerSet_.clear();
    DnetworkAdapter::GetInstance()->stateCallback_->OnDeviceOffline(deviceInfo);
    EXPECT_EQ(DnetworkAdapter::listenerSet_.size(), 0);
}

/**
 * @tc.name: OnDeviceOffline_002
 * @tc.desc: listenerSet_ is not empty
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DMSNetworkAdapterTest, OnDeviceOffline_002, TestSize.Level3)
{
    DistributedHardware::DmDeviceInfo deviceInfo;
    DnetworkAdapter::listenerSet_.clear();
    std::shared_ptr<DeviceListener> deviceNodeListener = std::make_shared<MockDeviceListener>();
    DnetworkAdapter::listenerSet_.insert(deviceNodeListener);
    DnetworkAdapter::GetInstance()->stateCallback_->OnDeviceOffline(deviceInfo);
    EXPECT_EQ(DnetworkAdapter::listenerSet_.size(), 1);
}

/**
 * @tc.name: AddDeviceChangeListener_001
 * @tc.desc: dnetworkHandler_ is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DMSNetworkAdapterTest, AddDeviceChangeListener_001, TestSize.Level3)
{
    DnetworkAdapter::listenerSet_.clear();
    std::shared_ptr<AppExecFwk::EventHandler> dnetworkHandler = DnetworkAdapter::GetInstance()->dnetworkHandler_;
    DnetworkAdapter::GetInstance()->dnetworkHandler_ = nullptr;
    std::shared_ptr<DeviceListener> deviceNodeListener = std::make_shared<MockDeviceListener>();
    bool res = DnetworkAdapter::GetInstance()->AddDeviceChangeListener(deviceNodeListener);
    DnetworkAdapter::GetInstance()->dnetworkHandler_ = dnetworkHandler;
    EXPECT_EQ(res, false);
}

/**
 * @tc.name: AddDeviceChangeListener_002
 * @tc.desc: deviceNodeListener is not exist
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DMSNetworkAdapterTest, AddDeviceChangeListener_002, TestSize.Level3)
{
    DnetworkAdapter::listenerSet_.clear();
    std::shared_ptr<DeviceListener> oldDeviceNodeListener = std::make_shared<MockDeviceListener>();
    DnetworkAdapter::listenerSet_.insert(oldDeviceNodeListener);
    std::shared_ptr<DeviceListener> deviceNodeListener = std::make_shared<MockDeviceListener>();
    bool res = DnetworkAdapter::GetInstance()->AddDeviceChangeListener(deviceNodeListener);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: AddDeviceChangeListener_003
 * @tc.desc: deviceNodeListener is not exist
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DMSNetworkAdapterTest, AddDeviceChangeListener_003, TestSize.Level3)
{
    DnetworkAdapter::listenerSet_.clear();
    std::shared_ptr<DeviceListener> deviceNodeListener = std::make_shared<MockDeviceListener>();
    bool res = DnetworkAdapter::GetInstance()->AddDeviceChangeListener(deviceNodeListener);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: AddDeviceChangeListener_004
 * @tc.desc: deviceNodeListener is exist
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DMSNetworkAdapterTest, AddDeviceChangeListener_004, TestSize.Level3)
{
    DnetworkAdapter::listenerSet_.clear();
    std::shared_ptr<DeviceListener> deviceNodeListener = std::make_shared<MockDeviceListener>();
    DnetworkAdapter::listenerSet_.insert(deviceNodeListener);
    bool res = DnetworkAdapter::GetInstance()->AddDeviceChangeListener(deviceNodeListener);
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: AddDeviceChangeListener_005
 * @tc.desc: test AddDeviceChangeListener when initCallback_ is nullptr
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(DMSNetworkAdapterTest, AddDeviceChangeListener_005, TestSize.Level3)
{
    std::shared_ptr<DeviceListener> deviceNodeListener = std::make_shared<MockDeviceListener>();
    DnetworkAdapter::listenerSet_.clear();
    DnetworkAdapter::listenerSet_.insert(deviceNodeListener);
    DnetworkAdapter::GetInstance()->initCallback_ = nullptr;
    bool ret = DnetworkAdapter::GetInstance()->AddDeviceChangeListener(deviceNodeListener);
    EXPECT_TRUE(ret);
    DnetworkAdapter::GetInstance()->initCallback_ = std::make_shared<DnetworkAdapter::DeviceInitCallBack>();
}

/**
 * @tc.name: AddDeviceChangeListener_006
 * @tc.desc: test AddDeviceChangeListener when stateCallback_ is nullptr
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(DMSNetworkAdapterTest, AddDeviceChangeListener_006, TestSize.Level3)
{
    DistributedHardware::DmDeviceInfo deviceInfo;
    /**
     * @tc.steps: step1. OnDeviceChanged
     */
    DnetworkAdapter::GetInstance()->stateCallback_->OnDeviceChanged(deviceInfo);
    /**
     * @tc.steps: step2. OnDeviceReady
     */
    DnetworkAdapter::GetInstance()->stateCallback_->OnDeviceReady(deviceInfo);
    /**
     * @tc.steps: step3. AddDeviceChangeListener when stateCallback_ is nullptr
     */
    std::shared_ptr<DeviceListener> deviceNodeListener = std::make_shared<MockDeviceListener>();
    DnetworkAdapter::listenerSet_.clear();
    DnetworkAdapter::listenerSet_.insert(deviceNodeListener);
    DnetworkAdapter::GetInstance()->stateCallback_ = nullptr;
    bool res = DnetworkAdapter::GetInstance()->AddDeviceChangeListener(deviceNodeListener);
    EXPECT_EQ(res, true);
    DnetworkAdapter::GetInstance()->stateCallback_ =
        std::make_shared<DnetworkAdapter::DmsDeviceStateCallback>();
}

/**
 * @tc.name: RemoveDeviceChangeListener_001
 * @tc.desc: listenerSet_ size is 0
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DMSNetworkAdapterTest, RemoveDeviceChangeListener_001, TestSize.Level3)
{
    DnetworkAdapter::listenerSet_.clear();
    std::shared_ptr<DeviceListener> deviceNodeListener = std::make_shared<MockDeviceListener>();
    DnetworkAdapter::GetInstance()->RemoveDeviceChangeListener(deviceNodeListener);
    EXPECT_EQ(DnetworkAdapter::listenerSet_.size(), 0);
}

/**
 * @tc.name: RemoveDeviceChangeListener_002
 * @tc.desc: listenerSet_ size is 1
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DMSNetworkAdapterTest, RemoveDeviceChangeListener_002, TestSize.Level3)
{
    /**
     * @tc.steps: step1. test RemoveDeviceChangeListener when listenerSet_ size is 1
     */
    DnetworkAdapter::listenerSet_.clear();
    std::shared_ptr<DeviceListener> oldDeviceNodeListener = std::make_shared<MockDeviceListener>();
    DnetworkAdapter::listenerSet_.insert(oldDeviceNodeListener);
    std::shared_ptr<DeviceListener> deviceNodeListener = std::make_shared<MockDeviceListener>();
    DnetworkAdapter::GetInstance()->RemoveDeviceChangeListener(deviceNodeListener);
    EXPECT_EQ(DnetworkAdapter::listenerSet_.size(), 1);
    /**
     * @tc.steps: step2. OnRemoteDied
     */
    DnetworkAdapter::GetInstance()->initCallback_->OnRemoteDied();
}
} // namespace DistributedSchedule
} // namespace OHOS