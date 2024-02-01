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
#include "distributed_sched_util.h"
#include "dtbschedmgr_log.h"
#define private public
#include "mission/dms_continue_send_manager.h"
#include "mission/dms_continue_recv_manager.h"
#undef private
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
const std::string CANCEL_FOCUSED_TASK = "cancel_mission_focused_task";
constexpr static int32_t DMS_SEND_LEN = 5;
constexpr static uint8_t DMS_0X0F = 0x0f;
constexpr int32_t MISSIONID_01 = 1;
constexpr int32_t MISSIONID_02 = 2;
constexpr int32_t ACTIVE = 0;
constexpr int32_t INACTIVE = 1;
constexpr int32_t CANCEL_FOCUSED_DELAYED = 10000;
constexpr int32_t DBMS_RETRY_MAX_TIME = 5;
}

void DMSContinueManagerTest::SetUpTestCase()
{
}

void DMSContinueManagerTest::TearDownTestCase()
{
}

void DMSContinueManagerTest::SetUp()
{
}

void DMSContinueManagerTest::TearDown()
{
}

void RemoteOnListenerStubTest::OnCallback(const uint32_t ContinueState, const std::string& srcDeviceId,
    const std::string& bundleName)
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
    DMSContinueSendMgr::GetInstance().Init();
    EXPECT_NE(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);

    /**
     * @tc.steps: step1. test UnInit when eventHandler is not nullptr;
     */
    DMSContinueSendMgr::GetInstance().UnInit();
    EXPECT_EQ(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test UnInit when eventHandler is nullptr;
     */
    DMSContinueSendMgr::GetInstance().UnInit();
    EXPECT_EQ(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);

    DTEST_LOG << "DMSContinueManagerTest testUnInit001 end" << std::endl;
}

/**
 * @tc.name: testAddCancelMissionFocusedTimer001
 * @tc.desc: test AddCancelMissionFocusedTimer
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testAddCancelMissionFocusedTimer001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testAddCancelMissionFocusedTimer001 begin" << std::endl;

    DistributedSchedUtil::MockManageMissions();
    DMSContinueSendMgr::GetInstance().Init();

    /**
     * @tc.steps: step1. test AddCancelMissionFocusedTimer when eventHandler is not nullptr;
     */
    DMSContinueSendMgr::GetInstance().AddCancelMissionFocusedTimer(0,
        CANCEL_FOCUSED_TASK, CANCEL_FOCUSED_DELAYED);
    EXPECT_NE(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test AddCancelMissionFocusedTimer when eventHandler is nullptr;
     */
    DMSContinueSendMgr::GetInstance().UnInit();
    DMSContinueSendMgr::GetInstance().AddCancelMissionFocusedTimer(0,
        CANCEL_FOCUSED_TASK, CANCEL_FOCUSED_DELAYED);
    EXPECT_EQ(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);
    DTEST_LOG << "DMSContinueManagerTest testAddCancelMissionFocusedTimer001 end" << std::endl;
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
    DMSContinueSendMgr::GetInstance().Init();

    /**
     * @tc.steps: step1. test NotifyMissionFocused when eventHandler is not nullptr;
     */
    DMSContinueSendMgr::GetInstance().NotifyMissionFocused(0, FocusedReason::NORMAL);
    DMSContinueSendMgr::GetInstance().NotifyMissionFocused(0, FocusedReason::SCREENOFF);
    EXPECT_NE(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test NotifyMissionFocused when eventHandler is nullptr;
     */
    DMSContinueSendMgr::GetInstance().UnInit();
    DMSContinueSendMgr::GetInstance().NotifyMissionFocused(0, FocusedReason::NORMAL);
    EXPECT_EQ(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);
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
    DMSContinueSendMgr::GetInstance().Init();
    /**
     * @tc.steps: step1. test NotifyMissionUnfocused when eventHandler is not nullptr;
     */
    DMSContinueSendMgr::GetInstance().NotifyMissionUnfocused(0);
    DMSContinueSendMgr::GetInstance().NotifyMissionUnfocused(0);
    EXPECT_NE(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test NotifyMissionUnfocused when eventHandler is nullptr;
     */
    DMSContinueSendMgr::GetInstance().UnInit();
    DMSContinueSendMgr::GetInstance().NotifyMissionUnfocused(0);
    EXPECT_EQ(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);
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
    DMSContinueRecvMgr::GetInstance().Init();
    sptr<IRemoteObject> obj01 = new RemoteOnListenerStubTest();
    int32_t ret = DMSContinueRecvMgr::GetInstance().RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(ret, ERR_OK);

    ret = DMSContinueRecvMgr::GetInstance().RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(ret, NO_MISSION_INFO_FOR_MISSION_ID);

    sptr<IRemoteObject> obj02 = new RemoteOnListenerStubTest();
    ret = DMSContinueRecvMgr::GetInstance().RegisterOnListener(TYPE, obj02);
    EXPECT_EQ(ret, ERR_OK);
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
    sptr<IRemoteObject> obj01 = new RemoteOnListenerStubTest();
    int32_t ret = DMSContinueRecvMgr::GetInstance().RegisterOnListener(TYPE, obj01);
    ret = DMSContinueRecvMgr::GetInstance().RegisterOffListener(TYPE, obj01);
    EXPECT_EQ(ret, ERR_OK);

    ret = DMSContinueRecvMgr::GetInstance().RegisterOffListener(TYPE, nullptr);
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
    sptr<IRemoteObject> obj01 = new RemoteOnListenerStubTest();
    int32_t ret = DMSContinueRecvMgr::GetInstance().RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(ret, ERR_OK);

    {
        std::lock_guard<std::mutex> registerOnListenerMapLock(
            DMSContinueRecvMgr::GetInstance().eventMutex_);
        DMSContinueRecvMgr::GetInstance().registerOnListener_[TYPE].clear();
    }
    ret = DMSContinueRecvMgr::GetInstance().RegisterOffListener(TYPE, obj01);
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
    DMSContinueSendMgr::GetInstance().focusedMission_[BUNDLENAME_01] = MISSIONID_01;
    int32_t missionId;
    int32_t ret = DMSContinueSendMgr::GetInstance().GetMissionId(BUNDLENAME_01, missionId);
    EXPECT_EQ(missionId, MISSIONID_01);
    EXPECT_EQ(ret, ERR_OK);

    ret = DMSContinueSendMgr::GetInstance().GetMissionId(BUNDLENAME_02, missionId);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
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
    int32_t ret = DMSContinueSendMgr::GetInstance().DealFocusedBusiness(-1);
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
    int32_t ret = DMSContinueSendMgr::GetInstance().DealUnfocusedBusiness(-1, true);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    /**
     * @tc.steps: step2. test DealUnfocusedBusiness when missionId is not invalid;
     */
    DMSContinueSendMgr::GetInstance().focusedMission_[BUNDLENAME_01] = MISSIONID_01;
    ret = DMSContinueSendMgr::GetInstance().DealUnfocusedBusiness(MISSIONID_01, true);
    EXPECT_EQ(ret, CAN_NOT_FOUND_ABILITY_ERR);

    /**
     * @tc.steps: step3. test NotifyDied when obj is nullptr;
     */
    sptr<IRemoteObject> obj01 = nullptr;
    DMSContinueSendMgr::GetInstance().NotifyDied(obj01);

    /**
     * @tc.steps: step4. test NotifyDied when iterItem->second is empty;
     */
    std::vector<sptr<IRemoteObject>> objs;
    {
        std::lock_guard<std::mutex> registerOnListenerMapLock(
            DMSContinueRecvMgr::GetInstance().eventMutex_);
        DMSContinueRecvMgr::GetInstance().registerOnListener_[TYPE] = objs;
    }
    obj01 = new RemoteOnListenerStubTest();
    DMSContinueSendMgr::GetInstance().NotifyDied(obj01);

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
    std::string bundleName = "test bundleName";
    int32_t ret = DMSContinueRecvMgr::GetInstance().VerifyBroadcastSource(networkId,
        bundleName, state);
    EXPECT_EQ(ret, ERR_OK);

    state = INACTIVE;
    ret = DMSContinueRecvMgr::GetInstance().VerifyBroadcastSource(networkId, bundleName, state);
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
    std::string bundleName = "test bundleName";
    int32_t ret = DMSContinueRecvMgr::GetInstance().VerifyBroadcastSource(networkId,
        bundleName, state);
    EXPECT_EQ(ret, ERR_OK);

    state = INACTIVE;
    networkId = "invalid networkId";
    ret = DMSContinueRecvMgr::GetInstance().VerifyBroadcastSource(networkId,
        bundleName, state);
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
    std::string bundleName = "test bundleName";
    int32_t ret = DMSContinueRecvMgr::GetInstance().VerifyBroadcastSource(networkId,
        bundleName, state);
    EXPECT_EQ(ret, ERR_OK);

    state = INACTIVE;
    bundleName = "invalid bundleName";
    ret = DMSContinueRecvMgr::GetInstance().VerifyBroadcastSource(networkId, bundleName, state);
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
    uint32_t accessTokenId = 0;
    int32_t state = 0;
    int32_t ret = DMSContinueRecvMgr::GetInstance().DealOnBroadcastBusiness(senderNetworkId, accessTokenId, state,
        DBMS_RETRY_MAX_TIME);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = DMSContinueRecvMgr::GetInstance().DealOnBroadcastBusiness(senderNetworkId, accessTokenId, state, 0);
    EXPECT_EQ(ret, 0);

    /**
     * @tc.steps: step2. test NotifyRecvBroadcast when obj is nullptr;
     */
    sptr<IRemoteObject> obj = nullptr;
    std::string networkId = "invalid networkId";
    std::string bundleName = "invalid bundleName";
    DMSContinueRecvMgr::GetInstance().NotifyRecvBroadcast(obj, networkId, bundleName, state);

    /**
     * @tc.steps: step3. test NotifyRecvBroadcast when missionId is invalid;
     */
    obj =  new RemoteOnListenerStubTest();
    DMSContinueRecvMgr::GetInstance().NotifyRecvBroadcast(obj, networkId, bundleName, state);

    DTEST_LOG << "DMSContinueManagerTest testDealOnBroadcastBusiness001 end" << std::endl;
}

/**
 * @tc.name: testPostOnBroadcastBusiness001
 * @tc.desc: test PostOnBroadcastBusiness
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testPostOnBroadcastBusiness001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testPostOnBroadcastBusiness001 start" << std::endl;
    std::string senderNetworkId = "invalid senderNetworkId";
    uint32_t accessTokenId = 0;
    int32_t state = 0;

    DMSContinueRecvMgr::GetInstance().PostOnBroadcastBusiness(senderNetworkId, accessTokenId, state);
    EXPECT_NE(DMSContinueRecvMgr::GetInstance().eventHandler_, nullptr);

    DTEST_LOG << "DMSContinueManagerTest testPostOnBroadcastBusiness001 end" << std::endl;
}

/**
 * @tc.name: testGetBundleName001
 * @tc.desc: test GetBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testGetBundleName001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetBundleName001 start" << std::endl;
    DMSContinueSendMgr::GetInstance().focusedMission_[BUNDLENAME_01] = MISSIONID_01;
    std::string bundleName;
    int32_t ret = DMSContinueSendMgr::GetInstance().GetBundleName(MISSIONID_01, bundleName);
    EXPECT_EQ(bundleName, BUNDLENAME_01);
    EXPECT_EQ(ret, ERR_OK);

    ret = DMSContinueSendMgr::GetInstance().GetBundleName(MISSIONID_02, bundleName);
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
    DMSContinueSendMgr::GetInstance().focusedMission_[BUNDLENAME_02] = MISSIONID_02;
    DMSContinueSendMgr::GetInstance().info_.currentMissionId = MISSIONID_01;
    DMSContinueSendMgr::GetInstance().info_.currentIsContinuable = true;
    bool ret = DMSContinueSendMgr::GetInstance().IsContinue(MISSIONID_02, BUNDLENAME_02);
    EXPECT_EQ(ret, false);

    ret = DMSContinueSendMgr::GetInstance().IsContinue(MISSIONID_01, BUNDLENAME_01);
    EXPECT_EQ(ret, true);

    DMSContinueSendMgr::GetInstance().info_.currentIsContinuable = false;
    ret = DMSContinueSendMgr::GetInstance().IsContinue(MISSIONID_01, BUNDLENAME_01);
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
    sptr<IRemoteObject> obj01 = new RemoteOnListenerStubTest();
    int32_t ret = DMSContinueRecvMgr::GetInstance().RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(false, DMSContinueRecvMgr::GetInstance().registerOnListener_.empty());
    DMSContinueSendMgr::GetInstance().NotifyDied(obj01);
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
    DMSContinueSendMgr::GetInstance().Init();
    OHOS::AAFwk::ContinueState state = OHOS::AAFwk::ContinueState::CONTINUESTATE_ACTIVE;

     /**
     * @tc.steps: step1. test SetMissionContinueState when eventHandler is not nullptr;
     */
    DMSContinueSendMgr::GetInstance().SetMissionContinueState(0, state);
    EXPECT_NE(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test SetMissionContinueState when eventHandler is nullptr;
     */
    DMSContinueSendMgr::GetInstance().UnInit();
    DMSContinueSendMgr::GetInstance().SetMissionContinueState(0, state);
    EXPECT_EQ(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);
    DTEST_LOG << "DMSContinueManagerTest testSetMissionContinueState001 end" << std::endl;
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
    DMSContinueSendMgr::GetInstance().info_.currentMissionId = MISSIONID_01;

    /**
     * @tc.steps: step1. test DealSetMissionContinueStateBusiness when missionId is invalid;
     */
    int32_t ret = DMSContinueSendMgr::GetInstance().DealSetMissionContinueStateBusiness(MISSIONID_02,
        state);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    /**
     * @tc.steps: step2. test DealUnfocusedBusiness when mission is not continueable;
     */
    DMSContinueSendMgr::GetInstance().info_.currentIsContinuable = false;
    ret = DMSContinueSendMgr::GetInstance().DealSetMissionContinueStateBusiness(MISSIONID_01, state);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DMSContinueManagerTest testDealSetMissionContinueStateBusiness001 end" << std::endl;
}

#ifdef SUPPORT_COMMON_EVENT_SERVICE
/**
 * @tc.name: testNotifyScreenOff001
 * @tc.desc: test NotifyScreenOff normal
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyScreenOff001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyScreenOff001 start" << std::endl;

    DistributedSchedUtil::MockManageMissions();
     /**
     * @tc.steps: step1. test NotifyScreenOff when eventHandler is not nullptr;
     */
    DMSContinueSendMgr::GetInstance().Init();
    DMSContinueSendMgr::GetInstance().NotifyScreenOff();
    EXPECT_NE(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);

    /**
     * @tc.steps: step2. test NotifyScreenOff when eventHandler is nullptr;
     */
    DMSContinueSendMgr::GetInstance().UnInit();
    DMSContinueSendMgr::GetInstance().NotifyScreenOff();
    EXPECT_EQ(DMSContinueSendMgr::GetInstance().eventHandler_, nullptr);
    DTEST_LOG << "DMSContinueManagerTest testNotifyScreenOff001 end" << std::endl;
}

/**
 * @tc.name: testDealScreenOff001
 * @tc.desc: test DealScreenOff normal
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, DealScreenOff001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest DealScreenOff001 start" << std::endl;
    DMSContinueSendMgr::GetInstance().info_.currentMissionId = 0;
    DMSContinueSendMgr::GetInstance().screenLockInfo_[0] = 0;
    DMSContinueSendMgr::GetInstance().DealScreenOff();
    DMSContinueSendMgr::GetInstance().info_.currentMissionId = 1;
    DMSContinueSendMgr::GetInstance().screenLockInfo_[0] = 0;
    DMSContinueSendMgr::GetInstance().DealScreenOff();
    int64_t time = GetTickCount();
    DMSContinueSendMgr::GetInstance().screenLockInfo_[0] = time;
    DMSContinueSendMgr::GetInstance().DealScreenOff();
    DMSContinueSendMgr::GetInstance().screenLockInfo_.clear();
    DMSContinueSendMgr::GetInstance().DealScreenOff();
    EXPECT_EQ(DMSContinueSendMgr::GetInstance().screenLockInfo_.size(), 1);
    DTEST_LOG << "DMSContinueManagerTest DealScreenOff001 end" << std::endl;
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
    sptr<IRemoteObject> obj01 = new RemoteOnListenerStubTest();
    DMSContinueRecvMgr::GetInstance().RegisterOnListener(TYPE, obj01);
    EXPECT_NE(DMSContinueRecvMgr::GetInstance().registerOnListener_.size(), 0);

    DMSContinueRecvMgr::GetInstance().iconInfo_.senderNetworkId = NETWORKID_01;
    DMSContinueRecvMgr::GetInstance().NotifyDeviceOffline(NETWORKID_01);
    EXPECT_EQ(DMSContinueRecvMgr::GetInstance().iconInfo_.senderNetworkId, "");

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
    DMSContinueRecvMgr::GetInstance().iconInfo_.senderNetworkId = NETWORKID_01;
    DMSContinueRecvMgr::GetInstance().NotifyDeviceOffline("");
    EXPECT_EQ(DMSContinueRecvMgr::GetInstance().iconInfo_.senderNetworkId, NETWORKID_01);

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
    DMSContinueRecvMgr::GetInstance().iconInfo_.senderNetworkId = NETWORKID_01;
    DMSContinueRecvMgr::GetInstance().NotifyDeviceOffline(NETWORKID_02);
    EXPECT_EQ(DMSContinueRecvMgr::GetInstance().iconInfo_.senderNetworkId, NETWORKID_01);

    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline003 end" << std::endl;
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
    DMSContinueRecvMgr::GetInstance().NotifyDataRecv(senderNetworkId, payload, dataLen1);

    uint32_t dataLen2 = DMS_SEND_LEN;
    DMSContinueRecvMgr::GetInstance().NotifyDataRecv(senderNetworkId, payload, dataLen2);
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
    uint32_t accessTokenId = 0;
    uint8_t type = 0;
    bool ret = DMSContinueSendMgr::GetInstance().SendSoftbusEvent(accessTokenId, type);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DMSContinueManagerTest testSendSoftbusEvent001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS