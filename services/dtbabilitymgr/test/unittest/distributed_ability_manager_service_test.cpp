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
#include "continuation_extra_params.h"
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
constexpr int32_t MAX_REGISTER_NUM = 600;
constexpr int32_t MAX_WAIT_TIME = 10000;
constexpr uint32_t TEST_UINT32_T = 0;
const std::u16string DMS_STUB_INTERFACE_TOKEN = u"OHOS.DistributedSchedule.IDistributedAbilityManager";
const std::u16string TEST_U16STRING = u"test u16string";
const std::string DEVICE_ID = "testDeviceId";
}

sptr<DistributedAbilityManagerService>  DistributedAbilityManagerServiceTest::dtbabilitymgrService_;
int32_t DistributedAbilityManagerServiceTest::startTaskNum_ = 1;
std::mutex DistributedAbilityManagerServiceTest::caseDoneLock_;
std::condition_variable DistributedAbilityManagerServiceTest::caseDoneCondition_;

void DeviceSelectionNotifierTest::OnDeviceConnect(const std::vector<ContinuationResult>& continuationResults)
{
}

void DeviceSelectionNotifierTest::OnDeviceDisconnect(const std::vector<ContinuationResult>& continuationResults)
{
}

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
 * @tc.name: Dump_001
 * @tc.desc: test Dump when args is not empty.
 * @tc.type: FUNC
 * @tc.require: I6NMR8
 */
HWTEST_F(DistributedAbilityManagerServiceTest, Dump_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest Dump_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test OnStart.
     */
    dtbabilitymgrService_->OnStart();
    /**
     * @tc.steps: step2. test OnStop.
     */
    dtbabilitymgrService_->OnStop();
    /**
     * @tc.steps: step3. test Dump when args is not empty.
     */
    std::vector<std::u16string> args;
    args.push_back(TEST_U16STRING);
    int32_t result = dtbabilitymgrService_->Dump(INVALID_CODE, args);
    EXPECT_EQ(result, DMS_WRITE_FILE_FAILED_ERR);
    /**
     * @tc.steps: step4. test DumpAppRegisterInfo when tokenMap_ is not empty.
     */
    std::string info;
    std::vector<int32_t> tokenMapValue;
    {
        std::lock_guard<std::mutex> autoLock(dtbabilitymgrService_->tokenMapMutex_);
        dtbabilitymgrService_->tokenMap_.clear();
        tokenMapValue.push_back(INVALID_CODE);
        dtbabilitymgrService_->tokenMap_[TEST_UINT32_T] = tokenMapValue;
    }
    dtbabilitymgrService_->DumpAppRegisterInfo(info);
    {
        std::lock_guard<std::mutex> autoLock(dtbabilitymgrService_->tokenMapMutex_);
        dtbabilitymgrService_->tokenMap_.clear();
    }
    DTEST_LOG << "DistributedAbilityManagerServiceTest Dump_001 end" << std::endl;
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
 * @tc.name: Register_001
 * @tc.desc: test Register when continuationExtraParams != nullptr.
 * @tc.type: FUNC
 * @tc.require: I6NMR8
 */
HWTEST_F(DistributedAbilityManagerServiceTest, Register_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest Register_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test DumpNotifierLocked when callbackMap_ is not empty.
     */
    std::vector<int32_t> tokenVec;
    std::string info;
    std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
    {
        std::lock_guard<std::mutex> autoLock(dtbabilitymgrService_->callbackMapMutex_);
        dtbabilitymgrService_->callbackMap_.clear();
        dtbabilitymgrService_->callbackMap_[INVALID_CODE] = std::move(notifierInfo);;
    }
    tokenVec.push_back(INVALID_CODE);
    dtbabilitymgrService_->DumpNotifierLocked(tokenVec, info);
    /**
     * @tc.steps: step2. test Register when register max num.
     */
    int32_t token = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    for (int32_t i = 0; i < MAX_REGISTER_NUM; i++) {
        dtbabilitymgrService_->Register(continuationExtraParams, token);
    }
    int32_t ret = dtbabilitymgrService_->Register(continuationExtraParams, token);
    EXPECT_EQ(ret, REGISTER_EXCEED_MAX_TIMES);
    {
        std::lock_guard<std::mutex> tokenLock(dtbabilitymgrService_->tokenMutex_);
        dtbabilitymgrService_->tokenMap_.clear();
    }
    DTEST_LOG << "DistributedAbilityManagerServiceTest Register_001 end" << std::endl;
}

/**
 * @tc.name: Unregister_001
 * @tc.desc: test Unregister
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, Unregister_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest Unregister_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test Unregister when token is not registered.
     */
    int32_t ret = dtbabilitymgrService_->Unregister(INVALID_CODE);
    EXPECT_EQ(ret, TOKEN_HAS_NOT_REGISTERED);
    /**
     * @tc.steps: step2. test Unregister when notifier is not registered.
     */
    {
        std::lock_guard<std::mutex> callbackMapLock(dtbabilitymgrService_->callbackMapMutex_);
        dtbabilitymgrService_->callbackMap_.clear();
    }
    int32_t token = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    ret = dtbabilitymgrService_->Register(continuationExtraParams, token);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->Unregister(token);
    EXPECT_EQ(ret, ERR_OK);
    /**
     * @tc.steps: step3. test Unregister when notifier is registered.
     */
    ret = dtbabilitymgrService_->Register(continuationExtraParams, token);
    EXPECT_EQ(ret, ERR_OK);
    {
        std::lock_guard<std::mutex> callbackMapLock(dtbabilitymgrService_->callbackMapMutex_);
        std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
        dtbabilitymgrService_->callbackMap_[token] = std::move(notifierInfo);;
    }
    ret = dtbabilitymgrService_->Unregister(token);
    EXPECT_EQ(ret, ERR_OK);
    {
        std::lock_guard<std::mutex> callbackMapLock(dtbabilitymgrService_->callbackMapMutex_);
        dtbabilitymgrService_->callbackMap_.clear();
    }
    DTEST_LOG << "DistributedAbilityManagerServiceTest Unregister_001 end" << std::endl;
}

/**
 * @tc.name: Unregister_002
 * @tc.desc: test Unregister when iter->second is not empty.
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, Unregister_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest Unregister_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test Unregister when iter->second is not empty.
     */
    int32_t token = 0;
    int32_t tokenBackup = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    int32_t ret = dtbabilitymgrService_->Register(continuationExtraParams, token);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->Register(continuationExtraParams, tokenBackup);
    EXPECT_EQ(ret, ERR_OK);
    {
        std::lock_guard<std::mutex> callbackMapLock(dtbabilitymgrService_->callbackMapMutex_);
        std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
        dtbabilitymgrService_->callbackMap_[token] = std::move(notifierInfo);;
    }
    ret = dtbabilitymgrService_->Unregister(token);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->Unregister(tokenBackup);
    EXPECT_EQ(ret, ERR_OK);
    {
        std::lock_guard<std::mutex> callbackMapLock(dtbabilitymgrService_->callbackMapMutex_);
        dtbabilitymgrService_->callbackMap_.clear();
    }
    DTEST_LOG << "DistributedAbilityManagerServiceTest Unregister_002 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallback_001
 * @tc.desc: test RegisterDeviceSelectionCallback
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, RegisterDeviceSelectionCallback_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest RegisterDeviceSelectionCallback_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test RegisterDeviceSelectionCallback when cbType is invalid.
     */
    int32_t ret = dtbabilitymgrService_->RegisterDeviceSelectionCallback(INVALID_CODE, "", nullptr);
    EXPECT_EQ(ret, UNKNOWN_CALLBACK_TYPE);
    /**
     * @tc.steps: step2. test RegisterDeviceSelectionCallback when cbType has registered.
     */
    int32_t token = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    ret = dtbabilitymgrService_->Register(continuationExtraParams, token);
    EXPECT_EQ(ret, ERR_OK);
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    ret = dtbabilitymgrService_->RegisterDeviceSelectionCallback(token, EVENT_CONNECT, notifier);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->RegisterDeviceSelectionCallback(token, EVENT_CONNECT, notifier);
    EXPECT_EQ(ret, CALLBACK_HAS_REGISTERED);
    
    ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(token, EVENT_CONNECT);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->Unregister(token);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedAbilityManagerServiceTest RegisterDeviceSelectionCallback_001 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallback_002
 * @tc.desc: test RegisterDeviceSelectionCallback
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, RegisterDeviceSelectionCallback_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest RegisterDeviceSelectionCallback_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test RegisterDeviceSelectionCallback when iter->second != nullptr.
     */
    int32_t token = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    int32_t ret = dtbabilitymgrService_->Register(continuationExtraParams, token);
    EXPECT_EQ(ret, ERR_OK);
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    ret = dtbabilitymgrService_->RegisterDeviceSelectionCallback(token, EVENT_CONNECT, notifier);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->RegisterDeviceSelectionCallback(token, EVENT_DISCONNECT, notifier);
    EXPECT_EQ(ret, ERR_OK);
    
    ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(token, EVENT_CONNECT);
    ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(token, EVENT_DISCONNECT);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->Unregister(token);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedAbilityManagerServiceTest RegisterDeviceSelectionCallback_002 end" << std::endl;
}

/**
 * @tc.name: UnregisterDeviceSelectionCallback_001
 * @tc.desc: test UnregisterDeviceSelectionCallback
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, UnregisterDeviceSelectionCallback_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest UnregisterDeviceSelectionCallback_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test UnregisterDeviceSelectionCallback when cbType is invalid.
     */
    int32_t ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(INVALID_CODE, "");
    EXPECT_EQ(ret, UNKNOWN_CALLBACK_TYPE);
    /**
     * @tc.steps: step2. test UnregisterDeviceSelectionCallback when cbType == EVENT_CONNECT.
     */
    ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(INVALID_CODE, EVENT_CONNECT);
    EXPECT_EQ(ret, TOKEN_HAS_NOT_REGISTERED);
    /**
     * @tc.steps: step3. test UnregisterDeviceSelectionCallback when cbType == EVENT_DISCONNECT.
     */
    ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(INVALID_CODE, EVENT_DISCONNECT);
    EXPECT_EQ(ret, TOKEN_HAS_NOT_REGISTERED);
    /**
     * @tc.steps: step4. test UnregisterDeviceSelectionCallback when token is registered.
     */
    int32_t token = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    ret = dtbabilitymgrService_->Register(continuationExtraParams, token);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(token, EVENT_CONNECT);
    EXPECT_EQ(ret, CALLBACK_HAS_NOT_REGISTERED);
    /**
     * @tc.steps: step5. test UnregisterDeviceSelectionCallback when callback is registered.
     */
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    ret = dtbabilitymgrService_->RegisterDeviceSelectionCallback(token, EVENT_CONNECT, notifier);
    EXPECT_EQ(ret, ERR_OK);

    ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(token, EVENT_CONNECT);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->Unregister(token);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedAbilityManagerServiceTest UnregisterDeviceSelectionCallback_001 end" << std::endl;
}

/**
 * @tc.name: UnregisterDeviceSelectionCallback_002
 * @tc.desc: test UnregisterDeviceSelectionCallback when callback is registered.
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, UnregisterDeviceSelectionCallback_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest UnregisterDeviceSelectionCallback_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test UnregisterDeviceSelectionCallback when callback is registered.
     */
    int32_t token = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    int32_t ret = dtbabilitymgrService_->Register(continuationExtraParams, token);
    EXPECT_EQ(ret, ERR_OK);
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    ret = dtbabilitymgrService_->RegisterDeviceSelectionCallback(token, EVENT_CONNECT, notifier);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->RegisterDeviceSelectionCallback(token, EVENT_DISCONNECT, notifier);
    EXPECT_EQ(ret, ERR_OK);

    ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(token, EVENT_CONNECT);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(token, EVENT_DISCONNECT);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->Unregister(token);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedAbilityManagerServiceTest UnregisterDeviceSelectionCallback_002 end" << std::endl;
}

/**
 * @tc.name: UpdateConnectStatus_001
 * @tc.desc: test UpdateConnectStatus
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, UpdateConnectStatus_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest UpdateConnectStatus_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test UpdateConnectStatus when deviceId is empty.
     */
    int32_t ret = dtbabilitymgrService_->UpdateConnectStatus(INVALID_CODE, "", DeviceConnectStatus::IDLE);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    /**
     * @tc.steps: step2. test UpdateConnectStatus when token is not registered.
     */
    ret = dtbabilitymgrService_->UpdateConnectStatus(INVALID_CODE, DEVICE_ID, DeviceConnectStatus::IDLE);
    EXPECT_EQ(ret, TOKEN_HAS_NOT_REGISTERED);
    /**
     * @tc.steps: step3. test UpdateConnectStatus when callback is not registered.
     */
    int32_t token = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    ret = dtbabilitymgrService_->Register(continuationExtraParams, token);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->UpdateConnectStatus(token, DEVICE_ID, DeviceConnectStatus::IDLE);
    EXPECT_EQ(ret, CALLBACK_HAS_NOT_REGISTERED);
    /**
     * @tc.steps: step4. test UpdateConnectStatus when callback is registered.
     */
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    ret = dtbabilitymgrService_->RegisterDeviceSelectionCallback(token, EVENT_CONNECT, notifier);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->UpdateConnectStatus(token, DEVICE_ID, DeviceConnectStatus::IDLE);
    EXPECT_EQ(ret, ERR_OK);
    /**
     * @tc.steps: step5. test UpdateConnectStatus when appProxy_ is nullptr.
     */
    {
        std::lock_guard<std::mutex> appProxyLock(dtbabilitymgrService_->appProxyMutex_);
        dtbabilitymgrService_->appProxy_ = nullptr;
    }
    ret = dtbabilitymgrService_->UpdateConnectStatus(token, DEVICE_ID, DeviceConnectStatus::IDLE);
    EXPECT_EQ(ret, ERR_OK);

    ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(token, EVENT_CONNECT);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->Unregister(token);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedAbilityManagerServiceTest UpdateConnectStatus_001 end" << std::endl;
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
 * @tc.name: OnDeviceDisconnect_001
 * @tc.desc: test OnDeviceDisconnect
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, OnDeviceDisconnect_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnDeviceDisconnect_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test OnDeviceDisconnect when callback has not registered.
     */
    if (dtbabilitymgrService_->continuationHandler_ == nullptr) {
        auto runner = AppExecFwk::EventRunner::Create("continuation_manager");
        dtbabilitymgrService_->continuationHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    std::vector<ContinuationResult> continuationResults;
    int32_t ret = dtbabilitymgrService_->OnDeviceDisconnect(INVALID_CODE, continuationResults);
    EXPECT_EQ(ret, CALLBACK_HAS_NOT_REGISTERED);
    /**
     * @tc.steps: step2. test OnDeviceDisconnect when callback has registered.
     */
    int32_t token = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    ret = dtbabilitymgrService_->Register(continuationExtraParams, token);
    EXPECT_EQ(ret, ERR_OK);
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    ret = dtbabilitymgrService_->RegisterDeviceSelectionCallback(token, EVENT_DISCONNECT, notifier);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->OnDeviceDisconnect(token, continuationResults);
    EXPECT_EQ(ret, ERR_OK);

    ret = dtbabilitymgrService_->UnregisterDeviceSelectionCallback(token, EVENT_DISCONNECT);
    EXPECT_EQ(ret, ERR_OK);
    ret = dtbabilitymgrService_->Unregister(token);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnDeviceDisconnect_001 end" << std::endl;
}

/**
 * @tc.name: IsExceededRegisterMaxNum_001
 * @tc.desc: test IsExceededRegisterMaxNum when IsExceededRegisterMaxNum returns true.
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, IsExceededRegisterMaxNum_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest IsExceededRegisterMaxNum_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    {
        std::lock_guard<std::mutex> tokenMapLock(dtbabilitymgrService_->tokenMapMutex_);
        dtbabilitymgrService_->tokenMap_.clear();
        std::vector<int32_t> vec;
        for (int32_t i = 0; i < MAX_REGISTER_NUM; ++i) {
            vec.push_back(INVALID_CODE);
        }
        dtbabilitymgrService_->tokenMap_[TEST_UINT32_T] = vec;
    }
    bool ret = dtbabilitymgrService_->IsExceededRegisterMaxNum(TEST_UINT32_T);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedAbilityManagerServiceTest IsExceededRegisterMaxNum_001 end" << std::endl;
}

/**
 * @tc.name: IsNotifierRegistered_001
 * @tc.desc: test IsNotifierRegistered when callbackMap_[token] = nullptr.
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, IsNotifierRegistered_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest IsNotifierRegistered_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    {
        std::lock_guard<std::mutex> callbackMapLock(dtbabilitymgrService_->callbackMapMutex_);
        dtbabilitymgrService_->callbackMap_[INVALID_CODE] = nullptr;
    }
    bool ret = dtbabilitymgrService_->IsNotifierRegistered(INVALID_CODE);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedAbilityManagerServiceTest IsNotifierRegistered_001 end" << std::endl;
}

/**
 * @tc.name: HandleDeviceConnect_002
 * @tc.desc: test HandleDeviceConnect when continuationHandler_ == nullptr.
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, HandleDeviceConnect_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleDeviceConnect_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    dtbabilitymgrService_->continuationHandler_ = nullptr;
    std::vector<ContinuationResult> continuationResults;
    bool ret = dtbabilitymgrService_->HandleDeviceConnect(nullptr, continuationResults);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleDeviceConnect_002 end" << std::endl;
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
 * @tc.name: HandleDeviceDisconnect_002
 * @tc.desc: test HandleDeviceDisconnect when continuationHandler_ != nullptr.
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, HandleDeviceDisconnect_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleDeviceDisconnect_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test HandleUpdateConnectStatus when continuationHandler_ is nullptr.
     */
    dtbabilitymgrService_->continuationHandler_ = nullptr;
    dtbabilitymgrService_->HandleUpdateConnectStatus(INVALID_CODE, DEVICE_ID, DeviceConnectStatus::CONNECTED);
    /**
     * @tc.steps: step2. test HandleDeviceConnect when continuationHandler_ is not nullptr.
     */
    auto runner = AppExecFwk::EventRunner::Create("continuation_manager");
    dtbabilitymgrService_->continuationHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    std::vector<ContinuationResult> continuationResults;
    bool ret = dtbabilitymgrService_->HandleDeviceDisconnect(notifier, continuationResults);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleDeviceDisconnect_002 end" << std::endl;
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
 * @tc.name: QueryTokenByNotifier_001
 * @tc.desc: test QueryTokenByNotifier when iter->second == nullptr.
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, QueryTokenByNotifier_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest QueryTokenByNotifier_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    /**
     * @tc.steps: step1. test QueryTokenByNotifier when iter->second == nullptr.
     */
    {
        std::lock_guard<std::mutex> callbackMapLock(dtbabilitymgrService_->callbackMapMutex_);
        dtbabilitymgrService_->callbackMap_.clear();
        dtbabilitymgrService_->callbackMap_[INVALID_CODE] = nullptr;
    }
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    int32_t token;
    bool ret = dtbabilitymgrService_->QueryTokenByNotifier(notifier, token);
    EXPECT_FALSE(ret);
    {
        std::lock_guard<std::mutex> callbackMapLock(dtbabilitymgrService_->callbackMapMutex_);
        dtbabilitymgrService_->callbackMap_.clear();
    }
    /**
     * @tc.steps: step2. test ProcessNotifierDied when notifier != nullptr.
     */
    dtbabilitymgrService_->ProcessNotifierDied(notifier);
    /**
     * @tc.steps: step3. test HandleNotifierDied when continuationHandler_ == nullptr.
     */
    dtbabilitymgrService_->continuationHandler_ = nullptr;
    dtbabilitymgrService_->HandleNotifierDied(nullptr);
    /**
     * @tc.steps: step4. test HandleNotifierDied when QueryTokenByNotifier returns true.
     */
    auto runner = AppExecFwk::EventRunner::Create("continuation_manager");
    dtbabilitymgrService_->continuationHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
    notifierInfo->SetNotifier(EVENT_CONNECT, notifier);
    {
        std::lock_guard<std::mutex> callbackMapLock(dtbabilitymgrService_->callbackMapMutex_);
        dtbabilitymgrService_->callbackMap_[INVALID_CODE] = std::move(notifierInfo);;
    }
    dtbabilitymgrService_->HandleNotifierDied(notifier);
    DTEST_LOG << "DistributedAbilityManagerServiceTest QueryTokenByNotifier_001 end" << std::endl;
}

/**
 * @tc.name: HandleNotifierDied_001
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
    /**
     * @tc.steps: step1. test HandleNotifierDied.
     */
    std::vector<ContinuationResult> continuationResults;
    dtbabilitymgrService_->HandleNotifierDied(dtbabilitymgrService_);
    /**
     * @tc.steps: step2. test HandleNotifierDied when IsNotifierRegistered returns true.
     */
    int32_t token = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    int32_t res = dtbabilitymgrService_->Register(continuationExtraParams, token);
    EXPECT_EQ(res, ERR_OK);
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
    notifierInfo->SetNotifier(EVENT_CONNECT, notifier);
    {
        std::lock_guard<std::mutex> callbackMapLock(dtbabilitymgrService_->callbackMapMutex_);
        dtbabilitymgrService_->callbackMap_.clear();
        dtbabilitymgrService_->callbackMap_[token] = std::move(notifierInfo);;
    }
    dtbabilitymgrService_->HandleNotifierDied(notifier);
    DTEST_LOG << "DistributedAbilityManagerServiceTest HandleNotifierDied_001 end" << std::endl;
}

/**
 * @tc.name: OnDeviceCancel_001
 * @tc.desc: test OnDeviceCancel
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