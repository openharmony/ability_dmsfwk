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
#include "distributed_ability_manager_service_test.h"

#include <thread>
#include "distributed_sched_util.h"
#include "dms_notifier.h"
#include "dtbschedmgr_log.h"
#define private public
#include "mission/distributed_sched_mission_manager.h"
#undef private
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t DISTRIBUTED_SCHED_SA_ID = 1401;
constexpr int32_t GET_DISTRIBUTED_COMPONENT_LIST_REQUEST_CODE = 161;
constexpr int32_t UPDATE_CONNECT_STATUS = 504;
constexpr int32_t INVALID_CODE = -1;
constexpr int32_t MAX_WAIT_TIME = 10000;
const std::u16string DMS_STUB_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
const std::string DEVICE_ID = "testDeviceId";
}

sptr<DistributedAbilityManagerService>  DistributedAbilityManagerServiceTest::dtbabilitymgrService_;
int32_t DistributedAbilityManagerServiceTest::startTaskNum_ = 2;
std::mutex DistributedAbilityManagerServiceTest::caseDoneLock_;
std::condition_variable DistributedAbilityManagerServiceTest::caseDoneCondition_;

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

int32_t MockDmsNotifier::OnDeviceConnect(int32_t token,
    const std::vector<ContinuationResult>& continuationResults)
{
    return 0;
}

int32_t MockDmsNotifier::OnDeviceDisconnect(int32_t token,
    const std::vector<std::string>& deviceIds)
{
    return 0;
}

int32_t MockDmsNotifier::OnDeviceCancel()
{
    return 0;
}

void DistributedAbilityManagerServiceTest::SetUpTestCase()
{
    dtbabilitymgrService_ = new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    DTEST_LOG << "DistributedAbilityManagerServiceTest::SetUpTestCase" << std::endl;
}

void DistributedAbilityManagerServiceTest::TearDownTestCase()
{
    // Wait until all asyn tasks are completed before exiting the test suite
    auto caseDoneNotifyTask = []() {
        std::lock_guard<std::mutex> autoLock(caseDoneLock_);
        --startTaskNum_;
        caseDoneCondition_.notify_one();
    };
    if (DistributedSchedMissionManager::GetInstance().distributedDataStorage_ != nullptr) {
        std::shared_ptr<AppExecFwk::EventHandler> dmsDataStorageHandler =
        DistributedSchedMissionManager::GetInstance().distributedDataStorage_->dmsDataStorageHandler_;
        if (dmsDataStorageHandler != nullptr) {
            dmsDataStorageHandler->PostTask(caseDoneNotifyTask);
        }
    }
    if (dtbabilitymgrService_->continuationHandler_ != nullptr) {
        dtbabilitymgrService_->continuationHandler_->PostTask(caseDoneNotifyTask);
    }
    std::unique_lock<std::mutex> lock(caseDoneLock_);
    caseDoneCondition_.wait_for(lock, std::chrono::milliseconds(MAX_WAIT_TIME),
        [&] () { return startTaskNum_ == 0; });
    DTEST_LOG << "DistributedAbilityManagerServiceTest::TearDownTestCase" << std::endl;
}

void DistributedAbilityManagerServiceTest::SetUp()
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest::SetUp" << std::endl;
}

void DistributedAbilityManagerServiceTest::TearDown()
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest::TearDown" << std::endl;
}

/**
 * @tc.name: IsDistributedSchedLoaded_001
 * @tc.desc: test IsDistributedSchedLoaded
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, IsDistributedSchedLoaded_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest IsDistributedSchedLoaded_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    int32_t result = dtbabilitymgrService_->IsDistributedSchedLoaded();
    EXPECT_EQ(false, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest IsDistributedSchedLoaded_001 end" << std::endl;
}
/**
 * @tc.name: GetDistributedComponentListInner_001
 * @tc.desc: test GetDistributedComponentListInner when dms not start
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, GetDistributedComponentListInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = dtbabilitymgrService_->GetDistributedComponentListInner(data, reply, option);
    EXPECT_EQ(ERR_NONE, result);
    result = reply.ReadInt32();
    EXPECT_EQ(ERR_NONE, result);
    std::vector<std::string> distributedComponents;
    reply.ReadStringVector(&distributedComponents);
    EXPECT_EQ(true, distributedComponents.empty());
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_001 end" << std::endl;
}

/**
 * @tc.name: GetDistributedComponentListInner_002
 * @tc.desc: test GetDistributedComponentListInner when isLoaded_ true
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, GetDistributedComponentListInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    bool result1 = dtbabilitymgrService_->InitDmsImplFunc();
    EXPECT_EQ(true, result1);
    int32_t result2 = dtbabilitymgrService_->GetDistributedComponentListInner(data, reply, option);
    EXPECT_EQ(ERR_NONE, result2);
    result2 = reply.ReadInt32();
    EXPECT_EQ(ERR_NONE, result2);
    std::vector<std::string> distributedComponents;
    reply.ReadStringVector(&distributedComponents);
    EXPECT_EQ(true, distributedComponents.empty());
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_002 end" << std::endl;
}

/**
 * @tc.name: GetDistributedComponentListInner_003
 * @tc.desc: test GetDistributedComponentListInner with invalid token
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, GetDistributedComponentListInner_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_003 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t result = dtbabilitymgrService_->GetDistributedComponentListInner(data, reply, option);
    EXPECT_EQ(DMS_PERMISSION_DENIED, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_003 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: test OnRemoteRequest to start GetDistributedComponentListInner
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, OnRemoteRequest_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = dtbabilitymgrService_->OnRemoteRequest(
        GET_DISTRIBUTED_COMPONENT_LIST_REQUEST_CODE, data, reply, option);
    EXPECT_EQ(ERR_NONE, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_001 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: test OnRemoteRequest with invalid code
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, OnRemoteRequest_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = dtbabilitymgrService_->OnRemoteRequest(INVALID_CODE, data, reply, option);
    EXPECT_NE(ERR_NONE, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_002 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_003
 * @tc.desc: test OnRemoteRequest to start funcsMap_ without token
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, OnRemoteRequest_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_003 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t result = dtbabilitymgrService_->OnRemoteRequest(UPDATE_CONNECT_STATUS, data, reply, option);
    EXPECT_EQ(DMS_PERMISSION_DENIED, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_003 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_004
 * @tc.desc: test OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, OnRemoteRequest_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_004 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
	MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = dtbabilitymgrService_->OnRemoteRequest(UPDATE_CONNECT_STATUS, data, reply, option);
    EXPECT_NE(ERR_NONE, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_004 end" << std::endl;
}

/**
 * @tc.name: DeviceOnlineNotify
 * @tc.desc: test DeviceOnlineNotify
 * @tc.type: FUNC
 */
HWTEST_F(DistributedAbilityManagerServiceTest, DeviceOnlineNotify_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest DeviceOnlineNotify_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    dtbabilitymgrService_->InitDmsImplFunc();
    EXPECT_EQ(dtbabilitymgrService_->isLoaded_, true);
    dtbabilitymgrService_->DeviceOnlineNotify(DEVICE_ID);
    DTEST_LOG << "DistributedAbilityManagerServiceTest DeviceOnlineNotify_001 end" << std::endl;
}

/**
 * @tc.name: DeviceOfflineNotify
 * @tc.desc: test DeviceOfflineNotify
 * @tc.type: FUNC
 */
HWTEST_F(DistributedAbilityManagerServiceTest, DeviceOfflineNotify_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest DeviceOfflineNotify_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    dtbabilitymgrService_->DeviceOfflineNotify(DEVICE_ID);
    DTEST_LOG << "DistributedAbilityManagerServiceTest DeviceOfflineNotify_001 end" << std::endl;
}

/**
 * @tc.name: ConnectAbility
 * @tc.desc: test ConnectAbility
 * @tc.type: FUNC
 */
HWTEST_F(DistributedAbilityManagerServiceTest, ConnectAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest ConnectAbility_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    EXPECT_EQ(dtbabilitymgrService_->isLoaded_, true);
    sptr<DmsNotifier> dmsNotifier(new MockDmsNotifier());
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    int32_t ret = dtbabilitymgrService_->ConnectAbility(dmsNotifier, 1, continuationExtraParams);
    EXPECT_NE(ret, true);
    DTEST_LOG << "DistributedAbilityManagerServiceTest ConnectAbility_001 end" << std::endl;
}


/**
 * @tc.name: HandleDeviceDisconnect
 * @tc.desc: test HandleDeviceDisconnect
 * @tc.type: FUNC
 */
HWTEST_F(DistributedAbilityManagerServiceTest, HandleDeviceDisconnect_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleDeviceDisconnect_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::vector<std::string> deviceIds;
    bool ret = dtbabilitymgrService_->HandleDeviceDisconnect(dtbabilitymgrService_, deviceIds);
    EXPECT_NE(ret, true);
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    dtbabilitymgrService_->ScheduleStartDeviceManager(nullptr, 1, continuationExtraParams);
    dtbabilitymgrService_->ScheduleStartDeviceManager(dtbabilitymgrService_, 1, continuationExtraParams);
    dtbabilitymgrService_->HandleStartDeviceManager(1, continuationExtraParams);
    dtbabilitymgrService_->HandleStartDeviceManager(1, nullptr);
    if (dtbabilitymgrService_->continuationHandler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("continuation_manager");
        dtbabilitymgrService_->continuationHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    std::vector<ContinuationResult> continuationResults;
    bool result = dtbabilitymgrService_->HandleDeviceConnect(dtbabilitymgrService_, continuationResults);
    dtbabilitymgrService_->HandleStartDeviceManager(1, continuationExtraParams);
    dtbabilitymgrService_->HandleStartDeviceManager(1, nullptr);
    EXPECT_EQ(result, true);
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleDeviceDisconnect_001 end" << std::endl;
}

/**
 * @tc.name: HandleDeviceConnect
 * @tc.desc: test HandleDeviceConnect
 * @tc.type: FUNC
 */
HWTEST_F(DistributedAbilityManagerServiceTest, HandleDeviceConnect_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleDeviceConnect_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::vector<ContinuationResult> continuationResults;
    int32_t ret = dtbabilitymgrService_->HandleDeviceConnect(dtbabilitymgrService_, continuationResults);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleDeviceConnect_001 end" << std::endl;
}

/**
 * @tc.name: HandleNotifierDied
 * @tc.desc: test HandleNotifierDied
 * @tc.type: FUNC
 */
HWTEST_F(DistributedAbilityManagerServiceTest, HandleNotifierDied_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleNotifierDied_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::vector<ContinuationResult> continuationResults;
    dtbabilitymgrService_->HandleNotifierDied(dtbabilitymgrService_);
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleNotifierDied_001 end" << std::endl;
}

/**
 * @tc.name: HandleNotifierDied
 * @tc.desc: test HandleNotifierDied
 * @tc.type: FUNC
 */
HWTEST_F(DistributedAbilityManagerServiceTest, OnDeviceCancel_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnDeviceCancel_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    int32_t ret = dtbabilitymgrService_->OnDeviceCancel();
    EXPECT_NE(ret, true);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnDeviceCancel_001 end" << std::endl;
}

/**
 * @tc.name: HandleUpdateConnectStatus
 * @tc.desc: test HandleUpdateConnectStatus
 * @tc.type: FUNC
 */
HWTEST_F(DistributedAbilityManagerServiceTest, HandleUpdateConnectStatus_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleUpdateConnectStatus_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    DeviceConnectStatus deviceConnectStatus = DeviceConnectStatus::CONNECTING;
    dtbabilitymgrService_->HandleUpdateConnectStatus(1, DEVICE_ID, deviceConnectStatus);
    if (dtbabilitymgrService_->continuationHandler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("continuation_manager");
        dtbabilitymgrService_->continuationHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    dtbabilitymgrService_->HandleUpdateConnectStatus(1, DEVICE_ID, deviceConnectStatus);
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleUpdateConnectStatus_001 end" << std::endl;
}
}
}
