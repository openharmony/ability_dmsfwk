/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "dms_continue_manager_test.h"

#include "datetime_ex.h"
#include "distributed_sched_test_util.h"
#include "dtbschedmgr_log.h"
#define private public
#include "mission/dms_continue_send_manager.h"
#include "mission/dms_continue_recv_manager.h"
#undef private
#include "multi_user_manager.h"
#include "softbus_adapter/softbus_adapter.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TYPE = "type";
const std::string BUNDLENAME_01 = "bundleName01";
const std::string BUNDLENAME_02 = "bundleName02";
const std::string NETWORKID_01 = "networkId01";
const std::string NETWORKID_02 = "networkId02";
const std::string ABILITY_NAME_01 = "abilityName01";
const std::string CANCEL_FOCUSED_TASK = "cancel_mission_focused_task";
const int32_t WAITTIME = 2000;
constexpr static int32_t DMS_SEND_LEN = 5;
constexpr static uint8_t DMS_0X0F = 0x0f;
constexpr int32_t MISSIONID_01 = 1;
constexpr int32_t MISSIONID_02 = 2;
constexpr int32_t ACTIVE = 0;
constexpr int32_t INACTIVE = 1;
constexpr int32_t CANCEL_FOCUSED_DELAYED = 10000;
constexpr int32_t DBMS_RETRY_MAX_TIME = 5;
constexpr uint8_t DMS_FOCUSED_TYPE = 0x00;
}

int32_t SoftbusAdapter::SendSoftbusEvent(std::shared_ptr<DSchedDataBuffer> buffer)
{
    return CAN_NOT_FOUND_ABILITY_ERR;
}

void DMSContinueManagerTest::SetUpTestCase()
{
}

void DMSContinueManagerTest::TearDownTestCase()
{
}

void DMSContinueManagerTest::SetUp()
{
    MultiUserManager::GetInstance().Init();
}

void DMSContinueManagerTest::TearDown()
{
}

void RemoteOnListenerStubTest::OnCallback(const uint32_t ContinueState, const std::string& srcDeviceId,
    const std::string &bundleName, const std::string &continueType, const std::string &srcBundleName)
{
}

/**
 * @tc.name: testUnInit001
 * @tc.desc: test UnInit
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DMSContinueManagerTest, testUnInit001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testUnInit001 begin" << std::endl;

    DistributedSchedUtil::MockManageMissions();
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t accountId = 100;
    sendMgr->Init(accountId);
    EXPECT_NE(sendMgr->eventHandler_, nullptr);

    /**
     * @tc.steps: step1. test UnInit when eventHandler is not nullptr;
     */
    usleep(WAITTIME);
    sendMgr->UnInit();
    EXPECT_EQ(sendMgr->eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test UnInit when eventHandler is nullptr;
     */
    sendMgr->UnInit();
    EXPECT_EQ(sendMgr->eventHandler_, nullptr);

    DTEST_LOG << "DMSContinueManagerTest testUnInit001 end" << std::endl;
}

/**
 * @tc.name: testUnInit002
 * @tc.desc: test UnInit
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DMSContinueManagerTest, testUnInit002, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testUnInit002 begin" << std::endl;

    DistributedSchedUtil::MockManageMissions();
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t accountId = 100;
    sendMgr->Init(accountId);
    EXPECT_NE(sendMgr->eventHandler_, nullptr);

    usleep(WAITTIME);
    sendMgr->UnInit();
    EXPECT_EQ(sendMgr->eventHandler_, nullptr);
    DTEST_LOG << "DMSContinueManagerTest testUnInit002 end" << std::endl;
}

/**
 * @tc.name: testPostUnfocusedTaskWithDelay001
 * @tc.desc: test PostUnfocusedTaskWithDelay
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testPostUnfocusedTaskWithDelay001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testPostUnfocusedTaskWithDelay001 begin" << std::endl;

    DistributedSchedUtil::MockManageMissions();
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t accountId = 100;
    sendMgr->Init(accountId);

    /**
     * @tc.steps: step1. test PostUnfocusedTaskWithDelay when eventHandler is not nullptr;
     */
    sendMgr->PostUnfocusedTaskWithDelay(0, UnfocusedReason::TIMEOUT);
    sendMgr->PostUnfocusedTaskWithDelay(0, UnfocusedReason::SCREENOFF);
    EXPECT_NE(sendMgr->eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test PostUnfocusedTaskWithDelay when eventHandler is nullptr;
     */
    usleep(WAITTIME);
    sendMgr->UnInit();
    sendMgr->PostUnfocusedTaskWithDelay(0, UnfocusedReason::TIMEOUT);
    EXPECT_EQ(sendMgr->eventHandler_, nullptr);
    DTEST_LOG << "DMSContinueManagerTest testPostUnfocusedTaskWithDelay001 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionFocused001
 * @tc.desc: test NotifyMissionFocused
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DMSContinueManagerTest, testNotifyMissionFocused001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyMissionFocused001 begin" << std::endl;

    DistributedSchedUtil::MockManageMissions();
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t accountId = 100;
    sendMgr->Init(accountId);

    /**
     * @tc.steps: step1. test NotifyMissionFocused when eventHandler is not nullptr;
     */
    sendMgr->NotifyMissionFocused(0, FocusedReason::NORMAL);
    sendMgr->NotifyMissionFocused(0, FocusedReason::SCREENOFF);
    EXPECT_NE(sendMgr->eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test NotifyMissionFocused when eventHandler is nullptr;
     */
    usleep(WAITTIME);
    sendMgr->UnInit();
    sendMgr->NotifyMissionFocused(0, FocusedReason::NORMAL);
    EXPECT_EQ(sendMgr->eventHandler_, nullptr);
    DTEST_LOG << "DMSContinueManagerTest testNotifyMissionFocused001 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionUnfocused001
 * @tc.desc: test NotifyMissionUnfocused
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DMSContinueManagerTest, testNotifyMissionUnfocused001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyMissionUnfocused001 begin" << std::endl;

    DistributedSchedUtil::MockManageMissions();
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t accountId = 100;
    sendMgr->Init(accountId);
    /**
     * @tc.steps: step1. test NotifyMissionUnfocused when eventHandler is not nullptr;
     */
    sendMgr->NotifyMissionUnfocused(0, UnfocusedReason::NORMAL);
    EXPECT_NE(sendMgr->eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test NotifyMissionUnfocused when eventHandler is nullptr;
     */
    usleep(WAITTIME);
    sendMgr->UnInit();
    sendMgr->NotifyMissionUnfocused(0, UnfocusedReason::NORMAL);
    EXPECT_EQ(sendMgr->eventHandler_, nullptr);
    DTEST_LOG << "DMSContinueManagerTest testNotifyMissionUnfocused001 end" << std::endl;
}

/**
 * @tc.name: testRegisterOnListener001
 * @tc.desc: test RegisterOnListener
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testRegisterOnListener001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testRegisterOnListener001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t accountId = 100;
    recvMgr->Init(accountId);
    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    int32_t ret = recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(ret, ERR_OK);

    ret = recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(ret, NO_MISSION_INFO_FOR_MISSION_ID);

    sptr<IRemoteObject> obj02(new RemoteOnListenerStubTest());
    ret = recvMgr->RegisterOnListener(TYPE, obj02);
    EXPECT_EQ(ret, ERR_OK);
    recvMgr->UnInit();
    DTEST_LOG << "DMSContinueManagerTest testRegisterOnListener001 end" << std::endl;
}

/**
 * @tc.name: testRegisterOffListener001
 * @tc.desc: test RegisterOffListener
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testRegisterOffListener001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testRegisterOffListener001 start" << std::endl;
    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->RegisterOnListener(TYPE, obj01);
    ret = recvMgr->RegisterOffListener(TYPE, obj01);
    EXPECT_EQ(ret, ERR_OK);

    ret = recvMgr->RegisterOffListener(TYPE, nullptr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueManagerTest testRegisterOffListener001 end" << std::endl;
}

/**
 * @tc.name: testRegisterOffListener002
 * @tc.desc: test RegisterOffListener when iterItem->second is empty.
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DMSContinueManagerTest, testRegisterOffListener002, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testRegisterOffListener002 start" << std::endl;
    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(ret, ERR_OK);

    {
        std::lock_guard<std::mutex> registerOnListenerMapLock(recvMgr->eventMutex_);
        recvMgr->registerOnListener_[TYPE].clear();
    }
    ret = recvMgr->RegisterOffListener(TYPE, obj01);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DMSContinueManagerTest testRegisterOffListener002 end" << std::endl;
}

/**
 * @tc.name: testGetMissionId001
 * @tc.desc: test GetMissionId
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testGetMissionId001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetMissionId001 start" << std::endl;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->focusedMission_[BUNDLENAME_01] = MISSIONID_01;
    int32_t missionId;
    int32_t ret = sendMgr->GetMissionIdByBundleName(BUNDLENAME_01, missionId);
    EXPECT_EQ(missionId, MISSIONID_01);
    EXPECT_EQ(ret, ERR_OK);

    ret = sendMgr->GetMissionIdByBundleName(BUNDLENAME_02, missionId);
    EXPECT_EQ(ret, MISSION_NOT_FOCUSED);
    DTEST_LOG << "DMSContinueManagerTest testGetMissionId001 end" << std::endl;
}

/**
 * @tc.name: testDealFocusedBusiness001
 * @tc.desc: test DealFocusedBusiness.
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DMSContinueManagerTest, testDealFocusedBusiness001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testDealFocusedBusiness001 start" << std::endl;

    /**
     * @tc.steps: step1. test DealFocusedBusiness when missionId is invalid;
     */
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t ret = sendMgr->DealFocusedBusiness(-1, FocusedReason::MIN);
    EXPECT_NE(ret, ERR_OK);

    DTEST_LOG << "DMSContinueManagerTest testDealFocusedBusiness001 end" << std::endl;
}

/**
 * @tc.name: testDealUnfocusedBusiness001
 * @tc.desc: test DealUnfocusedBusiness.
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DMSContinueManagerTest, testDealUnfocusedBusiness001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testDealUnfocusedBusiness001 start" << std::endl;

    /**
     * @tc.steps: step1. test DealUnfocusedBusiness when missionId is invalid;
     */
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t ret = sendMgr->DealUnfocusedBusiness(-1, UnfocusedReason::NORMAL);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    /**
     * @tc.steps: step2. test DealUnfocusedBusiness when missionId is not invalid;
     */
    sendMgr->focusedMission_[BUNDLENAME_01] = MISSIONID_01;
    sendMgr->focusedMissionAbility_[MISSIONID_01] = ABILITY_NAME_01;
    ret = sendMgr->DealUnfocusedBusiness(MISSIONID_01, UnfocusedReason::NORMAL);
    EXPECT_EQ(ret, CAN_NOT_FOUND_ABILITY_ERR);

    /**
     * @tc.steps: step3. test NotifyDied when obj is nullptr;
     */
    sptr<IRemoteObject> obj01 = nullptr;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->NotifyDied(obj01);

    /**
     * @tc.steps: step4. test NotifyDied when iterItem->second is empty;
     */
    std::vector<sptr<IRemoteObject>> objs;
    {
        std::lock_guard<std::mutex> registerOnListenerMapLock(recvMgr->eventMutex_);
        recvMgr->registerOnListener_[TYPE] = objs;
    }
    obj01 = new RemoteOnListenerStubTest();
    recvMgr->NotifyDied(obj01);

    DTEST_LOG << "DMSContinueManagerTest testDealUnfocusedBusiness001 end" << std::endl;
}

/**
 * @tc.name: testVerifyBroadcastSource001
 * @tc.desc: test testVerifyBroadcastSource001.
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testVerifyBroadcastSource001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testVerifyBroadcastSource001 start" << std::endl;

    int32_t state = ACTIVE;
    std::string networkId = "test networkId";
    std::string sourceBundleName = "test sourceBundleName";
    std::string sinkBundleName = "test sinkBundleName";
    std::string continueType = "test continueType";
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->VerifyBroadcastSource(networkId,
        sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, ERR_OK);

    state = INACTIVE;
    ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: testVerifyBroadcastSource002
 * @tc.desc: test testVerifyBroadcastSource002.
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testVerifyBroadcastSource002, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testVerifyBroadcastSource002 start" << std::endl;

    int32_t state = ACTIVE;
    std::string networkId = "test networkId";
    std::string sourceBundleName = "test sourceBundleName";
    std::string sinkBundleName = "test sinkBundleName";
    std::string continueType = "test continueType";
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, ERR_OK);

    state = INACTIVE;
    networkId = "invalid networkId";
    ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
}

/**
 * @tc.name: testVerifyBroadcastSource003
 * @tc.desc: test testVerifyBroadcastSource003.
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testVerifyBroadcastSource003, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testVerifyBroadcastSource003 start" << std::endl;

    int32_t state = ACTIVE;
    std::string networkId = "test networkId";
    std::string sourceBundleName = "test sourceBundleName";
    std::string sinkBundleName = "test sinkBundleName";
    std::string continueType = "test continueType";
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, ERR_OK);

    state = INACTIVE;
    sourceBundleName = "invalid sourceBundleName";
    sinkBundleName = "invalid sinkBundleName";
    ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
}

/**
 * @tc.name: testDealOnBroadcastBusiness001
 * @tc.desc: test DealOnBroadcastBusiness.
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DMSContinueManagerTest, testDealOnBroadcastBusiness001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testDealOnBroadcastBusiness001 start" << std::endl;

    /**
     * @tc.steps: step1. test DealOnBroadcastBusiness when senderNetworkId is invalid;
     */
    std::string senderNetworkId = "invalid senderNetworkId";
    uint16_t bundleNameId = 0;
    uint8_t continueTypeId = 0;
    int32_t state = 0;

    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->PostOnBroadcastBusiness(senderNetworkId, bundleNameId, continueTypeId, state);

    int32_t ret = recvMgr->DealOnBroadcastBusiness(senderNetworkId, bundleNameId, continueTypeId, state, 0);
    EXPECT_EQ(ret, ERR_OK);

    ret = recvMgr->DealOnBroadcastBusiness(senderNetworkId, bundleNameId, continueTypeId, state, DBMS_RETRY_MAX_TIME);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    /**
     * @tc.steps: step2. test NotifyRecvBroadcast when obj is nullptr;
     */
    sptr<IRemoteObject> obj = nullptr;
    std::string networkId = "invalid networkId";
    std::string sourceBundleName = "invalid sourceBundleName";
    std::string sinkBundleName = "invalid sinkBundleName";
    std::string continueType = "invalid continueType";
    recvMgr->NotifyRecvBroadcast(obj,
        currentIconInfo(networkId, sourceBundleName, sinkBundleName, continueType), state);

    /**
     * @tc.steps: step3. test NotifyRecvBroadcast when missionId is invalid;
     */
    obj =  new RemoteOnListenerStubTest();
    recvMgr->NotifyRecvBroadcast(obj,
        currentIconInfo(networkId, sourceBundleName, sinkBundleName, continueType), state);

    DTEST_LOG << "DMSContinueManagerTest testDealOnBroadcastBusiness001 end" << std::endl;
}

/**
 * @tc.name: testGetBundleName001
 * @tc.desc: test GetBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testGetBundleName001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetBundleName001 start" << std::endl;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->focusedMission_[BUNDLENAME_01] = MISSIONID_01;
    std::string bundleName;
    int32_t ret = sendMgr->GetBundleNameByMissionId(MISSIONID_01, bundleName);
    EXPECT_EQ(bundleName, BUNDLENAME_01);
    EXPECT_EQ(ret, ERR_OK);

    ret = sendMgr->GetBundleNameByMissionId(MISSIONID_02, bundleName);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueManagerTest testGetBundleName001 end" << std::endl;
}

/**
 * @tc.name: testIsContinue001
 * @tc.desc: test IsContinue
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testIsContinue001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsContinue001 start" << std::endl;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->focusedMission_[BUNDLENAME_02] = MISSIONID_02;
    sendMgr->info_.currentMissionId = MISSIONID_01;
    sendMgr->info_.currentIsContinuable = true;
    bool ret = sendMgr->IsContinue(MISSIONID_02, BUNDLENAME_02);
    EXPECT_EQ(ret, false);

    ret = sendMgr->IsContinue(MISSIONID_01, BUNDLENAME_01);
    EXPECT_EQ(ret, true);

    sendMgr->info_.currentIsContinuable = false;
    sendMgr->IsContinue(MISSIONID_01, BUNDLENAME_01);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DMSContinueManagerTest testIsContinue001 end" << std::endl;
}

/**
 * @tc.name: testNotifyDied001
 * @tc.desc: test NotifyDied
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyDied001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyDied001 start" << std::endl;
    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(false, recvMgr->registerOnListener_.empty());
    recvMgr->NotifyDied(obj01);
    DTEST_LOG << "DMSContinueManagerTest testNotifyDied001 end" << std::endl;
}

/**
 * @tc.name: testSetMissionContinueState001
 * @tc.desc: test SetMissionContinueState
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testSetMissionContinueState001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testSetMissionContinueState001 start" << std::endl;
    DistributedSchedUtil::MockManageMissions();
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t accountId = 100;
    sendMgr->Init(accountId);
    OHOS::AAFwk::ContinueState state = OHOS::AAFwk::ContinueState::CONTINUESTATE_ACTIVE;

     /**
     * @tc.steps: step1. test SetMissionContinueState when eventHandler is not nullptr;
     */
    sendMgr->SetMissionContinueState(0, state);
    EXPECT_NE(sendMgr->eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test SetMissionContinueState when eventHandler is nullptr;
     */
    usleep(WAITTIME);
    sendMgr->UnInit();
    sendMgr->SetMissionContinueState(0, state);
    EXPECT_EQ(sendMgr->eventHandler_, nullptr);
    DTEST_LOG << "DMSContinueManagerTest testSetMissionContinueState001 end" << std::endl;
}

/**
 * @tc.name: testSetMissionContinueState002
 * @tc.desc: test SetMissionContinueState
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testSetMissionContinueState002, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testSetMissionContinueState002 start" << std::endl;
    DistributedSchedUtil::MockManageMissions();
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t accountId = 100;
    sendMgr->Init(accountId);
    OHOS::AAFwk::ContinueState state = OHOS::AAFwk::ContinueState::CONTINUESTATE_INACTIVE;

     /**
     * @tc.steps: step1. test SetMissionContinueState when eventHandler is not nullptr;
     */
    sendMgr->SetMissionContinueState(0, state);
    EXPECT_NE(sendMgr->eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test SetMissionContinueState when eventHandler is nullptr;
     */
    usleep(WAITTIME);
    sendMgr->UnInit();
    sendMgr->SetMissionContinueState(0, state);
    EXPECT_EQ(sendMgr->eventHandler_, nullptr);
    DTEST_LOG << "DMSContinueManagerTest testSetMissionContinueState002 end" << std::endl;
}

/**
 * @tc.name: testDealSetMissionContinueStateBusiness001
 * @tc.desc: test DealSetMissionContinueStateBusiness.
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testDealSetMissionContinueStateBusiness001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testDealSetMissionContinueStateBusiness001 start" << std::endl;
    OHOS::AAFwk::ContinueState state = OHOS::AAFwk::ContinueState::CONTINUESTATE_ACTIVE;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->info_.currentMissionId = MISSIONID_01;

    /**
     * @tc.steps: step1. test DealSetMissionContinueStateBusiness when missionId is invalid;
     */
    int32_t ret = sendMgr->DealSetMissionContinueStateBusiness(MISSIONID_02, state);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    /**
     * @tc.steps: step2. test DealUnfocusedBusiness when mission is not continueable;
     */
    sendMgr->info_.currentIsContinuable = false;
    ret = sendMgr->DealSetMissionContinueStateBusiness(MISSIONID_01, state);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DMSContinueManagerTest testDealSetMissionContinueStateBusiness001 end" << std::endl;
}

/**
 * @tc.name: testDealSetMissionContinueStateBusiness002
 * @tc.desc: test DealSetMissionContinueStateBusiness.
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testDealSetMissionContinueStateBusiness002, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testDealSetMissionContinueStateBusiness002 start" << std::endl;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->info_.currentIsContinuable = true;
    OHOS::AAFwk::ContinueState state = OHOS::AAFwk::ContinueState::CONTINUESTATE_ACTIVE;
    int32_t ret = sendMgr->DealSetMissionContinueStateBusiness(MISSIONID_01, state);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DMSContinueManagerTest testDealSetMissionContinueStateBusiness002 end" << std::endl;
}

#ifdef SUPPORT_COMMON_EVENT_SERVICE
/**
 * @tc.name: testOnDeviceScreenOff001
 * @tc.desc: test OnDeviceScreenOff normal
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testOnDeviceScreenOff001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testOnDeviceScreenOff001 start" << std::endl;

    DistributedSchedUtil::MockManageMissions();
     /**
     * @tc.steps: step1. test OnDeviceScreenOff when eventHandler is not nullptr;
     */
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t accountId = 100;
    sendMgr->Init(accountId);
    sendMgr->OnDeviceScreenOff();
    EXPECT_NE(sendMgr->eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test OnDeviceScreenOff when eventHandler is nullptr;
     */
    usleep(WAITTIME);
    sendMgr->UnInit();
    sendMgr->OnDeviceScreenOff();
    EXPECT_EQ(sendMgr->eventHandler_, nullptr);
    DTEST_LOG << "DMSContinueManagerTest testOnDeviceScreenOff001 end" << std::endl;
}
#endif

/**
 * @tc.name: testNotifyDeviceOffline001
 * @tc.desc: test NotifyDeviceOffline normal
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyDeviceOffline001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.senderNetworkId = NETWORKID_01;
    recvMgr->NotifyDeviceOffline(NETWORKID_01);

    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_NE(recvMgr->registerOnListener_.size(), 0);
    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline001 end" << std::endl;
}

/**
 * @tc.name: testNotifyDeviceOffline002
 * @tc.desc: test NotifyDeviceOffline networkId empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyDeviceOffline002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline002 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.senderNetworkId = NETWORKID_01;
    recvMgr->NotifyDeviceOffline("");
    EXPECT_EQ(recvMgr->iconInfo_.senderNetworkId, NETWORKID_01);

    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline002 end" << std::endl;
}

/**
 * @tc.name: testNotifyDeviceOffline003
 * @tc.desc: test NotifyDeviceOffline networkId not match
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyDeviceOffline003, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline003 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.senderNetworkId = NETWORKID_01;
    recvMgr->NotifyDeviceOffline(NETWORKID_02);
    EXPECT_EQ(recvMgr->iconInfo_.senderNetworkId, NETWORKID_01);

    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline003 end" << std::endl;
}

/**
 * @tc.name: NotifyPackageRemoved001
 * @tc.desc: test NotifyPackageRemoved normal
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, notifyPackageRemoved001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved001 start" << std::endl;
    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_NE(recvMgr->registerOnListener_.size(), 0);

    recvMgr->iconInfo_.bundleName = BUNDLENAME_01;
    recvMgr->NotifyPackageRemoved(BUNDLENAME_01);
    EXPECT_EQ(recvMgr->iconInfo_.bundleName, "");

    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved001 end" << std::endl;
}

/**
 * @tc.name: NotifyPackageRemoved002
 * @tc.desc: test NotifyPackageRemoved bundleName empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, notifyPackageRemoved002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved002 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.bundleName = BUNDLENAME_01;
    recvMgr->NotifyPackageRemoved("");
    EXPECT_EQ(recvMgr->iconInfo_.bundleName, BUNDLENAME_01);

    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved002 end" << std::endl;
}

/**
 * @tc.name: NotifyPackageRemoved003
 * @tc.desc: test NotifyPackageRemoved bundleName not match
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, notifyPackageRemoved003, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved003 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.bundleName = BUNDLENAME_01;
    recvMgr->NotifyPackageRemoved(BUNDLENAME_02);
    EXPECT_EQ(recvMgr->iconInfo_.bundleName, BUNDLENAME_01);

    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved003 end" << std::endl;
}

/**
 * @tc.name: testNotifyDataRecv001
 * @tc.desc: NotifyDataRecv
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyDataRecv001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyDataRecv001 start" << std::endl;
    std::string senderNetworkId = NETWORKID_01;
    uint8_t payload[] = {0xf0};
    uint32_t dataLen1 = DMS_SEND_LEN - 1;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->NotifyDataRecv(senderNetworkId, payload, dataLen1);

    uint32_t dataLen2 = DMS_SEND_LEN;
    recvMgr->NotifyDataRecv(senderNetworkId, payload, dataLen2);
    EXPECT_NE(payload[0] & DMS_0X0F, sizeof(uint32_t));
    DTEST_LOG << "DMSContinueManagerTest testNotifyDataRecv001 end" << std::endl;
}

/**
 * @tc.name: testSendSoftbusEvent001
 * @tc.desc: SendSoftbusEvent
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testSendSoftbusEvent001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testSendSoftbusEvent001 start" << std::endl;
    uint16_t bundleNameId = 0;
    uint8_t continueType = 1;
    uint8_t type = 0;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    bool ret = sendMgr->SendSoftbusEvent(bundleNameId, continueType, type);
    EXPECT_NE(ret, CAN_NOT_FOUND_ABILITY_ERR);
    DTEST_LOG << "DMSContinueManagerTest testSendSoftbusEvent001 end" << std::endl;
}

/**
 * @tc.name: testNotifyDeviceOnline001
 * @tc.desc: NotifyDeviceOnline
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyDeviceOnline001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOnline001 start" << std::endl;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t ret = sendMgr->NotifyDeviceOnline();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOnline001 end" << std::endl;
}

/**
 * @tc.name: testGetAbilityNameByMissionId_001
 * @tc.desc: test GetAbilityNameByMissionId
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testGetAbilityNameByMissionId_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetAbilityNameByMissionId_001 start" << std::endl;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->focusedMissionAbility_[MISSIONID_01] = ABILITY_NAME_01;
    std::string abilityName;
    int32_t ret = sendMgr->GetAbilityNameByMissionId(MISSIONID_01, abilityName);
    EXPECT_EQ(abilityName, ABILITY_NAME_01);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DMSContinueManagerTest testGetAbilityNameByMissionId_001 end" << std::endl;
}

/**
 * @tc.name: testFocusedBusinessSendEvent_001
 * @tc.desc: test FocusedBusinessSendEvent
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testFocusedBusinessSendEvent_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testFocusedBusinessSendEvent_001 start" << std::endl;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t ret = sendMgr->FocusedBusinessSendEvent(BUNDLENAME_01, ABILITY_NAME_01);

    EXPECT_EQ(ret, CAN_NOT_FOUND_ABILITY_ERR);
    DTEST_LOG << "DMSContinueManagerTest testFocusedBusinessSendEvent_001 end" << std::endl;
}

/**
 * @tc.name: testGetBundleNameIdAndContinueTypeId_001
 * @tc.desc: test GetBundleNameIdAndContinueTypeId
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testGetBundleNameIdAndContinueTypeId_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetBundleNameIdAndContinueTypeId_001 start" << std::endl;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->focusedMission_[BUNDLENAME_01] = MISSIONID_01;
    sendMgr->focusedMissionAbility_[MISSIONID_01] = ABILITY_NAME_01;
    uint16_t bundleNameId = 0;
    uint8_t continueTypeId = 0;
    OHOS::AAFwk::ContinueState state = OHOS::AAFwk::ContinueState::CONTINUESTATE_ACTIVE;
    int32_t ret = sendMgr->GetBundleNameIdAndContinueTypeId(MISSIONID_01, state, bundleNameId, continueTypeId);

    EXPECT_EQ(ret, CAN_NOT_FOUND_ABILITY_ERR);
    DTEST_LOG << "DMSContinueManagerTest testGetBundleNameIdAndContinueTypeId_001 end" << std::endl;
}

/**
 * @tc.name: testGetContinueType_001
 * @tc.desc: test GetContinueType
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testGetContinueType_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetContinueType_001 start" << std::endl;
    int32_t state = ACTIVE;
    std::string networkId = "test networkId";
    std::string sourceBundleName = "test sourceBundleName";
    std::string sinkBundleName = "test sinkBundleName";
    std::string continueType = "test continueType";
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, ERR_OK);

    EXPECT_FALSE(recvMgr->GetContinueType(sinkBundleName).empty());
    DTEST_LOG << "DMSContinueManagerTest testGetContinueType_001 end" << std::endl;
}

/**
 * @tc.name: testSetScreenOffInfo_001
 * @tc.desc: test SetScreenOffInfo
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testSetScreenOffInfo_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testSetScreenOffInfo_001 start" << std::endl;
    int32_t missionId = 0;
    std::string bundleName = "bundleName";
    uint16_t bundleNameId = 0;
    std::string abilityName = "abilityName";
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->screenOffHandler_ =
        std::make_shared<DMSContinueSendMgr::ScreenOffHandler>();
    sendMgr->screenOffHandler_->SetScreenOffInfo(missionId, bundleName,
        bundleNameId, abilityName);
    EXPECT_EQ(sendMgr->screenOffHandler_->unfoInfo_.abilityName.empty(), false);
    
    sendMgr->screenOffHandler_->ClearScreenOffInfo();
    EXPECT_EQ(sendMgr->screenOffHandler_->unfoInfo_.abilityName.empty(), true);
    DTEST_LOG << "DMSContinueManagerTest testSetScreenOffInfo_001 end" << std::endl;
}

/**
 * @tc.name: testSetStateSendEvent_001
 * @tc.desc: test SetStateSendEvent
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testSetStateSendEvent_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testSetStateSendEvent_001 start" << std::endl;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t ret = sendMgr->SetStateSendEvent(0, 0, AAFwk::ContinueState::CONTINUESTATE_INACTIVE);
    EXPECT_NE(ret, DMS_PERMISSION_DENIED);

    ret = sendMgr->SetStateSendEvent(0, 0, AAFwk::ContinueState::CONTINUESTATE_ACTIVE);
    EXPECT_NE(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DMSContinueManagerTest testSetStateSendEvent_001 end" << std::endl;
}

/**
 * @tc.name: testGetContinueLaunchMissionInfo_001
 * @tc.desc: test GetContinueLaunchMissionInfo
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testGetContinueLaunchMissionInfo_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetContinueLaunchMissionInfo_001 start" << std::endl;
    ContinueLaunchMissionInfo missionInfo = {"com.test.missionInfo", "MainAbility"};
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->continueLaunchMission_.clear();
    int32_t ret = sendMgr->GetContinueLaunchMissionInfo(MISSIONID_01, missionInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    sendMgr->continueLaunchMission_[missionInfo] = MISSIONID_01;
    ret = sendMgr->GetContinueLaunchMissionInfo(MISSIONID_01, missionInfo);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DMSContinueManagerTest testGetContinueLaunchMissionInfo_001 end" << std::endl;
}

/**
 * @tc.name: testUpdateContinueLaunchMission_001
 * @tc.desc: test UpdateContinueLaunchMission
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testUpdateContinueLaunchMission_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testUpdateContinueLaunchMission_001 start" << std::endl;
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.test.demo", "MainAbility", "");
    want.SetElement(element);

    AAFwk::MissionInfo info;
    info.id = MISSIONID_01;
    info.want = want;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    EXPECT_FALSE(sendMgr->UpdateContinueLaunchMission(info));

    info.want.SetFlags(AAFwk::Want::FLAG_ABILITY_CONTINUATION);
    EXPECT_TRUE(sendMgr->UpdateContinueLaunchMission(info));

    info.id = MISSIONID_02;
    EXPECT_TRUE(sendMgr->UpdateContinueLaunchMission(info));
    DTEST_LOG << "DMSContinueManagerTest testUpdateContinueLaunchMission_001 end" << std::endl;
}

/**
 * @tc.name: testGetFinalBundleName_001
 * @tc.desc: test GetFinalBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testGetFinalBundleName_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetFinalBundleName_001 start" << std::endl;
    DmsBundleInfo info;
    std::string finalBundleName;
    AppExecFwk::BundleInfo localBundleInfo;
    std::string continueType;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->GetFinalBundleName(info, finalBundleName, localBundleInfo, continueType);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DMSContinueManagerTest testGetFinalBundleName_001 end" << std::endl;
}

/**
 * @tc.name: testIsBundleContinuable_001
 * @tc.desc: all continuable = false  => res = false
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testIsBundleContinuable_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_001 start" << std::endl;
    std::string srcAbilityName = "abilityName";
    std::string srcContinueType = "continueType";
    bool isSameBundle = true;

    AppExecFwk::BundleInfo localBundleInfo;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<std::string> continueTypes;
    continueTypes.push_back(srcContinueType);
    abilityInfo.continueType = continueTypes;
    abilityInfo.continuable = false;
    abilityInfo.name = srcAbilityName;
    abilityInfos.push_back(abilityInfo);

    localBundleInfo.abilityInfos = abilityInfos;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName,
                                            srcContinueType, isSameBundle);
    EXPECT_EQ(ret, false);

    isSameBundle = false;
    ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName,
                                       srcContinueType, isSameBundle);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_001 end" << std::endl;
}

/**
 * @tc.name: testIsBundleContinuable_002
 * @tc.desc: continuable = true; same continueType  => res = true
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testIsBundleContinuable_002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_002 start" << std::endl;
    std::string srcAbilityName = "abilityName";
    std::string srcContinueType = "continueType";
    bool isSameBundle = true;

    AppExecFwk::BundleInfo localBundleInfo;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<std::string> continueTypes;
    continueTypes.push_back(srcContinueType + "_ContinueQuickStart");
    abilityInfo.continueType = continueTypes;
    abilityInfo.continuable = true;
    abilityInfo.name = srcAbilityName;
    abilityInfos.push_back(abilityInfo);

    localBundleInfo.abilityInfos = abilityInfos;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName,
                                            srcContinueType, isSameBundle);
    EXPECT_EQ(ret, true);

    isSameBundle = false;
    ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName,
                                   srcContinueType, isSameBundle);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_002 end" << std::endl;
}

/**
 * @tc.name: testIsBundleContinuable_003
 * @tc.desc: continuable = true; diff continueType; diff BundleName  => res = false;
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testIsBundleContinuable_003, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_003 start" << std::endl;
    std::string srcAbilityName = "srcAbilityName";
    std::string sinkAbilityName = "sinkAbilityName";
    std::string srcContinueType = "srcContinueType";
    std::string sinkContinueType = "sinkContinueType";
    bool isSameBundle = false;

    AppExecFwk::BundleInfo localBundleInfo;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<std::string> continueTypes;
    continueTypes.push_back(sinkContinueType + "_ContinueQuickStart");
    abilityInfo.continueType = continueTypes;
    abilityInfo.continuable = true;
    abilityInfo.name = sinkAbilityName;
    abilityInfos.push_back(abilityInfo);

    localBundleInfo.abilityInfos = abilityInfos;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName,
                                            srcContinueType, isSameBundle);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_003 end" << std::endl;
}

/**
 * @tc.name: testIsBundleContinuable_004
 * @tc.desc: continuable = true; diff continueType; same BundleName  => res = false;
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testIsBundleContinuable_004, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_004 start" << std::endl;
    std::string srcAbilityName = "srcAbilityName";
    std::string sinkAbilityName = "sinkAbilityName";
    std::string srcContinueType = srcAbilityName;
    std::string sinkContinueType = "sinkContinueType";
    bool isSameBundle = true;

    AppExecFwk::BundleInfo localBundleInfo;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<std::string> continueTypes;
    continueTypes.push_back(sinkContinueType + "_ContinueQuickStart");
    abilityInfo.continueType = continueTypes;
    abilityInfo.continuable = true;
    abilityInfo.name = sinkAbilityName;
    abilityInfos.push_back(abilityInfo);

    localBundleInfo.abilityInfos = abilityInfos;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName,
                                            srcContinueType, isSameBundle);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_004 end" << std::endl;
}

/**
 * @tc.name: testIsBundleContinuable_005
 * @tc.desc: continuable = true; no src continueType; same BundleName  => res = false;
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testIsBundleContinuable_005, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_005 start" << std::endl;
    std::string srcAbilityName = "srcAbilityName";
    std::string sinkAbilityName = "sinkAbilityName";
    std::string srcContinueType = srcAbilityName;
    std::string sinkContinueType = "sinkContinueType";
    bool isSameBundle = true;

    AppExecFwk::BundleInfo localBundleInfo;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<std::string> continueTypes;
    continueTypes.push_back(sinkContinueType + "_ContinueQuickStart");
    abilityInfo.continueType = continueTypes;
    abilityInfo.continuable = true;
    abilityInfo.name = srcAbilityName;
    abilityInfos.push_back(abilityInfo);

    localBundleInfo.abilityInfos = abilityInfos;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName,
                                            srcContinueType, isSameBundle);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_005 end" << std::endl;
}

/**
 * @tc.name: GetBundleNameByScreenOffInfo_001
 * @tc.desc: test GetBundleNameByScreenOffInfo
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, GetBundleNameByScreenOffInfo_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest GetBundleNameByScreenOffInfo_001 start" << std::endl;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->screenOffHandler_ = nullptr;
    int32_t missionId = 0;
    std::string bundleName;
    int32_t ret = sendMgr->GetBundleNameByScreenOffInfo(missionId, bundleName);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    sendMgr->screenOffHandler_ = std::make_shared<DMSContinueSendMgr::ScreenOffHandler>();
    ret = sendMgr->GetBundleNameByScreenOffInfo(missionId, bundleName);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    sendMgr->screenOffHandler_->SetScreenOffInfo(0, "", 0, "");
    ret = sendMgr->GetBundleNameByScreenOffInfo(missionId, bundleName);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    sendMgr->screenOffHandler_->SetScreenOffInfo(0, "bundleName", 0, "");
    ret = sendMgr->GetBundleNameByScreenOffInfo(missionId, bundleName);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DMSContinueManagerTest GetBundleNameByScreenOffInfo_001 end" << std::endl;
}

/**
 * @tc.name: SendScreenOffEvent_001
 * @tc.desc: test SendScreenOffEvent
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, SendScreenOffEvent_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest SendScreenOffEvent_001 start" << std::endl;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->screenOffHandler_ = nullptr;
    int32_t ret = sendMgr->SendScreenOffEvent(DMS_FOCUSED_TYPE);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    sendMgr->screenOffHandler_ = std::make_shared<DMSContinueSendMgr::ScreenOffHandler>();
    ret = sendMgr->SendScreenOffEvent(DMS_FOCUSED_TYPE);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DMSContinueManagerTest SendScreenOffEvent_001 end" << std::endl;
}

/**
 * @tc.name: DeleteContinueLaunchMissionInfo_001
 * @tc.desc: test DeleteContinueLaunchMissionInfo
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, DeleteContinueLaunchMissionInfo_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest DeleteContinueLaunchMissionInfo_001 start" << std::endl;
    int32_t missionId = 0;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    sendMgr->continueLaunchMission_.clear();
    sendMgr->DeleteContinueLaunchMissionInfo(missionId);

    ContinueLaunchMissionInfo info { "bundleName", "abilityName" };
    sendMgr->continueLaunchMission_[info] = 0;
    sendMgr->DeleteContinueLaunchMissionInfo(missionId);
    EXPECT_EQ(sendMgr->continueLaunchMission_.empty(), true);
    DTEST_LOG << "DMSContinueManagerTest DeleteContinueLaunchMissionInfo_001 end" << std::endl;
}

/**
 * @tc.name: CheckContinueState_001
 * @tc.desc: test CheckContinueState
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, CheckContinueState_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest CheckContinueState_001 start" << std::endl;
    int32_t missionId = 0;
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
    ASSERT_NE(nullptr, sendMgr);
    int32_t ret = sendMgr->CheckContinueState(missionId);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueManagerTest CheckContinueState_001 end" << std::endl;
}

/**
 * @tc.name: OnContinueSwitchOff_001
 * @tc.desc: test OnContinueSwitchOff
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, OnContinueSwitchOff_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest OnContinueSwitchOff_001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.senderNetworkId = "";
    recvMgr->iconInfo_.bundleName = "";
    recvMgr->iconInfo_.continueType = "";
    recvMgr->OnContinueSwitchOff();
    EXPECT_EQ(recvMgr->iconInfo_.isEmpty(), true);

    recvMgr->iconInfo_.senderNetworkId = "senderNetworkId";
    recvMgr->iconInfo_.bundleName = "bundleName";
    recvMgr->iconInfo_.continueType = "continueType";
    recvMgr->registerOnListener_.clear();
    recvMgr->OnContinueSwitchOff();
    EXPECT_EQ(recvMgr->registerOnListener_.empty(), true);
    DTEST_LOG << "DMSContinueManagerTest OnContinueSwitchOff_001 end" << std::endl;
}

/**
 * @tc.name: OnUserSwitch_001
 * @tc.desc: test OnUserSwitch
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, OnUserSwitch_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest OnUserSwitch_001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.senderNetworkId = "";
    recvMgr->iconInfo_.bundleName = "";
    recvMgr->iconInfo_.continueType = "";
    recvMgr->OnUserSwitch();
    EXPECT_EQ(recvMgr->iconInfo_.isEmpty(), true);

    recvMgr->iconInfo_.senderNetworkId = "senderNetworkId";
    recvMgr->iconInfo_.bundleName = "bundleName";
    recvMgr->iconInfo_.continueType = "continueType";
    recvMgr->registerOnListener_.clear();
    recvMgr->OnUserSwitch();
    EXPECT_EQ(recvMgr->registerOnListener_.empty(), true);
    DTEST_LOG << "DMSContinueManagerTest OnUserSwitch_001 end" << std::endl;
}

/**
 * @tc.name: FindToNotifyRecvBroadcast_001
 * @tc.desc: test FindToNotifyRecvBroadcast
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, FindToNotifyRecvBroadcast_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest FindToNotifyRecvBroadcast_001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    std::string senderNetworkId = "senderNetworkId";
    std::string bundleName = "bundleName";
    std::string continueType = "senderNetworkId";
    recvMgr->iconInfo_.senderNetworkId = senderNetworkId;
    recvMgr->iconInfo_.bundleName = bundleName;
    recvMgr->iconInfo_.continueType = continueType;
    recvMgr->registerOnListener_.clear();
    recvMgr->FindToNotifyRecvBroadcast(senderNetworkId, bundleName, continueType);
    EXPECT_EQ(recvMgr->registerOnListener_.empty(), true);
    DTEST_LOG << "DMSContinueManagerTest FindToNotifyRecvBroadcast_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
