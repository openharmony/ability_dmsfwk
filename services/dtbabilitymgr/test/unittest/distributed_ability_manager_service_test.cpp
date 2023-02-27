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
#include "distributed_ability_manager_service_test.h"

#include <thread>
#include "distributed_sched_util.h"
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
constexpr int32_t REGISTER = 500;
constexpr int32_t UPDATE_CONNECT_STATUS = 504;
constexpr int32_t INVALID_CODE = -1;
constexpr int32_t MAX_WAIT_TIME = 10000;
const std::u16string DMS_STUB_INTERFACE_TOKEN = u"OHOS.DistributedSchedule.IDistributedAbilityManager";
const std::string DEVICE_ID = "testDeviceId";
}

sptr<DistributedAbilityManagerService>  DistributedAbilityManagerServiceTest::dtbabilitymgrService_;
int32_t DistributedAbilityManagerServiceTest::startTaskNum_ = 1;
std::mutex DistributedAbilityManagerServiceTest::caseDoneLock_;
std::condition_variable DistributedAbilityManagerServiceTest::caseDoneCondition_;

void DistributedAbilityManagerServiceTest::SetUpTestCase()
{
    dtbabilitymgrService_ = new DistributedAbilityManagerService();
    DTEST_LOG << "DistributedAbilityManagerServiceTest::SetUpTestCase" << std::endl;
}

void DistributedAbilityManagerServiceTest::TearDownTestCase()
{
    // Wait until all async tasks are completed before exiting the test suite
    auto caseDoneNotifyTask = []() {
        std::lock_guard<std::mutex> autoLock(caseDoneLock_);
        --startTaskNum_;
        caseDoneCondition_.notify_one();
    };
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
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: test OnRemoteRequest to start Register
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
    int32_t result = dtbabilitymgrService_->OnRemoteRequest(REGISTER, data, reply, option);
    EXPECT_EQ(DMS_PERMISSION_DENIED, result);
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
 * @tc.desc: test OnRemoteRequest to start funcsMap_ without DATASYNC permission
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
    EXPECT_EQ(DMS_PERMISSION_DENIED, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_004 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_005
 * @tc.desc: test OnRemoteRequest to start funcsMap_ with DATASYNC permission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedAbilityManagerServiceTest, OnRemoteRequest_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_005 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    DistributedSchedUtil::MockPermission();
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = dtbabilitymgrService_->OnRemoteRequest(UPDATE_CONNECT_STATUS, data, reply, option);
    EXPECT_NE(ERR_NONE, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_005 end" << std::endl;
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
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    int32_t ret = dtbabilitymgrService_->ConnectAbility(1, continuationExtraParams);
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

    std::vector<ContinuationResult> continuationResults;
    bool ret = dtbabilitymgrService_->HandleDeviceDisconnect(dtbabilitymgrService_, continuationResults);
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