/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "dms_continue_send_manager_test.h"
#include "mission/notification/dms_continue_send_manager.h"
#include "mission/notification/dms_continue_recv_manager.h"
#include "mission/notification/dms_continue_send_strategy.h"

#include "datashare_manager.h"
#include "dtbschedmgr_log.h"
#include "mission/wifi_state_adapter.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

static bool g_mockBool = false;
static bool g_mockWifiBool = false;

namespace {
const std::string TAG = "DMSContinueMgrTest";
}
//DMSContinueSendMgrTest
void DMSContinueSendMgrTest::SetUpTestCase()
{
    bundleMgrMock_ = std::make_shared<BundleManagerInternalMock>();
    BundleManagerInternalMock::bundleMgrMock = bundleMgrMock_;
    mgrMock_ = std::make_shared<DmsContinueConditionMgrMock>();
    IDmsContinueConditionMgr::conditionMgrMock = mgrMock_;
    clientMock_ = std::make_shared<AbilityManagerClientMock>();
    AbilityManagerClientMock::clientMock = clientMock_;
}

void DMSContinueSendMgrTest::TearDownTestCase()
{
    BundleManagerInternalMock::bundleMgrMock = nullptr;
    bundleMgrMock_ = nullptr;
    IDmsContinueConditionMgr::conditionMgrMock = nullptr;
    mgrMock_ = nullptr;
    clientMock_ = nullptr;
    AbilityManagerClientMock::clientMock = nullptr;
}

void DMSContinueSendMgrTest::SetUp()
{
    ASSERT_NE(mgrMock_, nullptr);
    ::testing::Mock::VerifyAndClearExpectations(mgrMock_.get());
    ON_CALL(*mgrMock_, IsScreenLocked()).WillByDefault(Return(false));
}

void DMSContinueSendMgrTest::TearDown()
{
}

//DMSContinueRecvMgrTest
void DMSContinueRecvMgrTest::SetUpTestCase()
{
    bundleMgrMock_ = std::make_shared<BundleManagerInternalMock>();
    BundleManagerInternalMock::bundleMgrMock = bundleMgrMock_;
    dmsKvMock_ = std::make_shared<DmsKvSyncE2EMock>();
    DmsKvSyncE2EMock::dmsKvMock = dmsKvMock_;
}

void DMSContinueRecvMgrTest::TearDownTestCase()
{
    BundleManagerInternalMock::bundleMgrMock = nullptr;
    bundleMgrMock_ = nullptr;
    DmsKvSyncE2EMock::dmsKvMock = nullptr;
    dmsKvMock_ = nullptr;
}

void DMSContinueRecvMgrTest::SetUp()
{
}

void DMSContinueRecvMgrTest::TearDown()
{
}

/**
 * @tc.name: ExecuteSendStrategy_Test_001
 * @tc.desc: test ExecuteSendStrategy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategy_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategy_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    uint8_t sendType = 0;
    int32_t missionId = 0;
    EXPECT_CALL(*mgrMock_, GetMissionStatus(_, _, _)).WillOnce(Return(0));
    sendMgr->SendContinueBroadcast(missionId, MissionEventType::MISSION_EVENT_FOCUSED);

    EXPECT_CALL(*mgrMock_, GetMissionStatus(_, _, _)).WillRepeatedly(Return(1));
    sendMgr->SendContinueBroadcast(missionId, MissionEventType::MISSION_EVENT_FOCUSED);

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition(_)).WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendContinueBroadcast(status, MissionEventType::MISSION_EVENT_FOCUSED));

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition(_)).WillOnce(Return(true));
    EXPECT_CALL(*mgrMock_, CheckMissionSendCondition(_, _)).WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendContinueBroadcast(status, MissionEventType::MISSION_EVENT_FOCUSED));

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition(_)).WillOnce(Return(true));
    EXPECT_CALL(*mgrMock_, CheckMissionSendCondition(_, _)).WillOnce(Return(true));
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendContinueBroadcast(status, MissionEventType::MISSION_EVENT_FOCUSED));

    sendMgr->strategyMap_.clear();
    auto ret = sendMgr->ExecuteSendStrategy(MissionEventType::MISSION_EVENT_FOCUSED, status, sendType);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategy_Test_001 end" << std::endl;
}

/**
 * @tc.name: ExecuteSendStrategy_Test_002
 * @tc.desc: test ExecuteSendStrategy
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategy_Test_002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategy_Test_002 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    uint8_t sendType = 0;
    int32_t missionId = 0;
    EXPECT_CALL(*mgrMock_, GetMissionStatus(_, _, _)).WillOnce(Return(true));
    sendMgr->SendContinueBroadcast(missionId, MissionEventType::MISSION_EVENT_BACKGROUND);

    EXPECT_CALL(*mgrMock_, GetMissionStatus(_, _, _)).WillRepeatedly(Return(true));
    sendMgr->SendContinueBroadcast(missionId, MissionEventType::MISSION_EVENT_BACKGROUND);

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition(_)).WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendContinueBroadcast(status, MissionEventType::MISSION_EVENT_BACKGROUND));

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition(_)).WillOnce(Return(true));
    EXPECT_CALL(*mgrMock_, CheckMissionSendCondition(_, _)).WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendContinueBroadcast(status, MissionEventType::MISSION_EVENT_BACKGROUND));

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition(_)).WillOnce(Return(true));
    EXPECT_CALL(*mgrMock_, CheckMissionSendCondition(_, _)).WillOnce(Return(true));
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendContinueBroadcast(status, MissionEventType::MISSION_EVENT_BACKGROUND));

    sendMgr->strategyMap_.clear();
    auto ret = sendMgr->ExecuteSendStrategy(MissionEventType::MISSION_EVENT_BACKGROUND, status, sendType);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategy_Test_002 end" << std::endl;
}

/**
 * @tc.name: QueryBroadcastInfo_Test_001
 * @tc.desc: test QueryBroadcastInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueSendMgrTest, QueryBroadcastInfo_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest QueryBroadcastInfo_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    uint16_t bundleNameId = 0;
    uint8_t continueTypeId = 0;
    auto ret = sendMgr->QueryBroadcastInfo(status, bundleNameId, continueTypeId);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    status.bundleName = "bundleName";
    ret = sendMgr->QueryBroadcastInfo(status, bundleNameId, continueTypeId);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    status.abilityName = "abilityName";
    EXPECT_CALL(*bundleMgrMock_, GetBundleNameId(_, _)).WillOnce(Return(1));
    ret = sendMgr->QueryBroadcastInfo(status, bundleNameId, continueTypeId);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DMSContinueSendMgrTest QueryBroadcastInfo_Test_001 end" << std::endl;
}

/**
 * @tc.name: QueryBroadcastInfo_Test_002
 * @tc.desc: test QueryBroadcastInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueSendMgrTest, QueryBroadcastInfo_Test_002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest QueryBroadcastInfo_Test_002 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    uint16_t bundleNameId = 0;
    uint8_t continueTypeId = 0;
    status.bundleName = "bundleName";
    status.abilityName = "abilityName";
    EXPECT_CALL(*bundleMgrMock_, GetBundleNameId(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*bundleMgrMock_, GetContinueTypeId(_, _, _)).WillOnce(Return(1));
    auto ret = sendMgr->QueryBroadcastInfo(status, bundleNameId, continueTypeId);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DMSContinueSendMgrTest QueryBroadcastInfo_Test_002 end" << std::endl;
}

/**
 * @tc.name: QueryBroadcastInfo_Test_003
 * @tc.desc: test QueryBroadcastInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueSendMgrTest, QueryBroadcastInfo_Test_003, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest QueryBroadcastInfo_Test_003 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    uint16_t bundleNameId = 0;
    uint8_t continueTypeId = 0;
    status.bundleName = "bundleName";
    status.abilityName = "abilityName";
    EXPECT_CALL(*bundleMgrMock_, GetBundleNameId(_, _)).WillOnce(Return(0));
    EXPECT_CALL(*bundleMgrMock_, GetContinueTypeId(_, _, _)).WillOnce(Return(0));
    auto ret = sendMgr->QueryBroadcastInfo(status, bundleNameId, continueTypeId);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DMSContinueSendMgrTest QueryBroadcastInfo_Test_003 end" << std::endl;
}

/**
 * @tc.name: AddMMIListener_Test_001
 * @tc.desc: test AddMMIListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueSendMgrTest, AddMMIListener_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest AddMMIListener_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    sendMgr->mmiMonitorId_ = 0;
    sendMgr->AddMMIListener();
    sendMgr->RemoveMMIListener();

    sendMgr->mmiMonitorId_ = -1;
    sendMgr->AddMMIListener();
    EXPECT_NO_FATAL_FAILURE(sendMgr->RemoveMMIListener());
    DTEST_LOG << "DMSContinueSendMgrTest AddMMIListener_Test_001 end" << std::endl;
}

/**
 * @tc.name: AddMMIListener_Test_002
 * @tc.desc: test AddMMIListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueSendMgrTest, AddMMIListener_Test_002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest AddMMIListener_Test_002 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    sendMgr->mmiMonitorId_ = 1;
    DmsContinueConditionMgr::GetInstance().missionMap_.clear();
    sendMgr->RemoveMMIListener();

    MissionStatus missionStatus;
    std::map<int32_t, MissionStatus> missionList;
    missionStatus.isContinuable = false;
    missionList[1] = missionStatus;
    DmsContinueConditionMgr::GetInstance().missionMap_[1] = missionList;
    sendMgr->RemoveMMIListener();

    DmsContinueConditionMgr::GetInstance().missionMap_.clear();
    missionStatus.isContinuable = true;
    missionStatus.continueState = AAFwk::ContinueState::CONTINUESTATE_INACTIVE;
    missionList[1] = missionStatus;
    DmsContinueConditionMgr::GetInstance().missionMap_[1] = missionList;
    sendMgr->RemoveMMIListener();

    DmsContinueConditionMgr::GetInstance().missionMap_.clear();
    missionStatus.isContinuable = true;
    missionStatus.continueState = AAFwk::ContinueState::CONTINUESTATE_ACTIVE;
    missionList[1] = missionStatus;
    DmsContinueConditionMgr::GetInstance().missionMap_[1] = missionList;
    EXPECT_NO_FATAL_FAILURE(sendMgr->RemoveMMIListener());
    DTEST_LOG << "DMSContinueSendMgrTest AddMMIListener_Test_002 end" << std::endl;
}

/**
 * @tc.name: CheckContinueState_Test_001
 * @tc.desc: test CheckContinueState
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueSendMgrTest, CheckContinueState_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest CheckContinueState_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    clientMock_ = nullptr;
    int32_t missionId = 1;
    int32_t ret = sendMgr->CheckContinueState(missionId);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueSendMgrTest CheckContinueState_Test_001 end" << std::endl;
}

bool DataShareManager::IsCurrentContinueSwitchOn()
{
    return g_mockBool;
}

bool WifiStateAdapter::IsWifiActive()
{
    return g_mockWifiBool;
}

/**
 * @tc.name: RegisterOnListener_Test_001
 * @tc.desc: test RegisterOnListener
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecvMgrTest, RegisterOnListener_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest RegisterOnListener_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    auto ret = recvMgr->RegisterOnListener("type", nullptr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueRecvMgrTest RegisterOnListener_Test_001 end" << std::endl;
}

/**
 * @tc.name: FindContinueType_Test_001
 * @tc.desc: test FindContinueType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecvMgrTest, FindContinueType_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest FindContinueType_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    DmsAbilityInfo info;
    DmsBundleInfo distributedBundleInfo;
    distributedBundleInfo.dmsAbilityInfos.push_back(info);
    distributedBundleInfo.dmsAbilityInfos.push_back(info);
    uint8_t continueTypeId = 1;
    std::string continueType = "continueType";
    DmsAbilityInfo abilityInfo;
    EXPECT_NO_FATAL_FAILURE(recvMgr->FindContinueType(distributedBundleInfo, continueTypeId,
        continueType, abilityInfo));
    DTEST_LOG << "DMSContinueRecvMgrTest FindContinueType_Test_001 end" << std::endl;
}

/**
 * @tc.name: NotifyIconDisappear_Test_001
 * @tc.desc: test NotifyIconDisappear
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecvMgrTest, NotifyIconDisappear_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyIconDisappear_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    recvMgr->NotifyIconDisappear(1, "NetworkId", 1);

    recvMgr->iconInfo_.senderNetworkId = "senderNetworkId";
    recvMgr->NotifyIconDisappear(1, "NetworkId", 0);

    recvMgr->iconInfo_.senderNetworkId = "NetworkId";
    EXPECT_NO_FATAL_FAILURE(recvMgr->NotifyIconDisappear(1, "NetworkId", 0));
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyIconDisappear_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetContinueType_Test_001
 * @tc.desc: test GetContinueType
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecvMgrTest, GetContinueType_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest GetContinueType_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    EXPECT_NO_FATAL_FAILURE(recvMgr->NotifyDied(nullptr));

    recvMgr->iconInfo_.senderNetworkId = "";
    recvMgr->iconInfo_.bundleName = "";
    recvMgr->iconInfo_.continueType = "";
    auto ret = recvMgr->GetContinueType("bundleName");
    EXPECT_EQ(ret, "");

    recvMgr->iconInfo_.bundleName = "bundleName1";
    ret = recvMgr->GetContinueType("bundleName");
    EXPECT_EQ(ret, "");
    DTEST_LOG << "DMSContinueRecvMgrTest GetContinueType_Test_001 end" << std::endl;
}

/**
 * @tc.name: NotifyDataRecv_Test_001
 * @tc.desc: test NotifyDataRecv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecvMgrTest, NotifyDataRecv_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    std::string senderNetworkId = "NetworkId";
    uint8_t payload[] = {0xf0};
    uint32_t dataLen1 = 1;
    EXPECT_NO_FATAL_FAILURE(recvMgr->NotifyDataRecv(senderNetworkId, payload, dataLen1));
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_001 end" << std::endl;
}

/**
 * @tc.name: NotifyDataRecv_Test_002
 * @tc.desc: test NotifyDataRecv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecvMgrTest, NotifyDataRecv_Test_002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_002 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    std::string senderNetworkId = "NetworkId";
    uint8_t payload[] = {0xf0};
    uint32_t dataLen1 = 1;
    g_mockBool = false;
    EXPECT_NO_FATAL_FAILURE(recvMgr->NotifyDataRecv(senderNetworkId, payload, dataLen1));
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_002 end" << std::endl;
}

/**
 * @tc.name: NotifyDataRecv_Test_003
 * @tc.desc: test NotifyDataRecv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecvMgrTest, NotifyDataRecv_Test_003, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_003 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    std::string senderNetworkId = "NetworkId";
    uint8_t payload[] = {0xf0};
    uint32_t dataLen1 = 1;
    g_mockBool = true;
    g_mockWifiBool = false;
    EXPECT_NO_FATAL_FAILURE(recvMgr->NotifyDataRecv(senderNetworkId, payload, dataLen1));
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_003 end" << std::endl;
}

/**
 * @tc.name: NotifyDataRecv_Test_004
 * @tc.desc: test NotifyDataRecv
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecvMgrTest, NotifyDataRecv_Test_004, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_004 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    std::string senderNetworkId = "NetworkId";
    uint8_t payload[] = {0xf0};
    uint32_t dataLen1 = 1;
    g_mockBool = true;
    g_mockWifiBool = true;
    EXPECT_NO_FATAL_FAILURE(recvMgr->NotifyDataRecv(senderNetworkId, payload, dataLen1));
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_004 end" << std::endl;
}

/**
 * @tc.name: GetFinalBundleName_Test_001
 * @tc.desc: test GetFinalBundleName
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecvMgrTest, GetFinalBundleName_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest GetFinalBundleName_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    DmsBundleInfo distributedBundleInfo;
    std::string finalBundleName = "finalBundleName";
    AppExecFwk::BundleInfo localBundleInfo;
    std::string continueType = "continueType";
    EXPECT_CALL(*bundleMgrMock_, GetLocalBundleInfo(_, _)).WillOnce(Return(0));
    bool ret = recvMgr->GetFinalBundleName(distributedBundleInfo, finalBundleName, localBundleInfo, continueType);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DMSContinueRecvMgrTest GetFinalBundleName_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetSenderNetworkId_Test_001
 * @tc.desc: test GetSenderNetworkId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecvMgrTest, GetSenderNetworkId_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest GetSenderNetworkId_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    std::string ret = recvMgr->GetSenderNetworkId();
    EXPECT_EQ(ret, "");

    recvMgr->iconInfo_.senderNetworkId = "senderNetworkId";
    ret = recvMgr->GetSenderNetworkId();
    EXPECT_EQ(ret, "senderNetworkId");
    DTEST_LOG << "DMSContinueRecvMgrTest GetSenderNetworkId_Test_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategyFocused_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyFocused_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    auto strategy = std::make_shared<SendStrategyFocused>(sendMgr);
    sendMgr->strategyMap_[MISSION_EVENT_FOCUSED] = strategy;
    int32_t ret = sendMgr->ExecuteSendStrategy(MISSION_EVENT_FOCUSED, status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_APPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyFocused_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategyUnfocused_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyUnfocused_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    auto strategy = std::make_shared<SendStrategyUnfocused>(sendMgr);
    sendMgr->strategyMap_[MISSION_EVENT_UNFOCUSED] = strategy;
    int32_t ret = sendMgr->ExecuteSendStrategy(MISSION_EVENT_UNFOCUSED, status, sendType);
    EXPECT_EQ(ret, SendStrategyUnfocused::SKIP_UNFOCUSED_TYPE);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyUnfocused_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategyDestoryed_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyDestoryed_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    auto strategy = std::make_shared<SendStrategyDestoryed>(sendMgr);
    sendMgr->strategyMap_[MISSION_EVENT_DESTORYED] = strategy;
    int32_t ret = sendMgr->ExecuteSendStrategy(MISSION_EVENT_DESTORYED, status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyDestoryed_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategyBackground_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyBackground_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    auto strategy = std::make_shared<SendStrategyBackground>(sendMgr);
    sendMgr->strategyMap_[MISSION_EVENT_BACKGROUND] = strategy;
    sendMgr->screenLockedHandler_ = std::make_shared<DMSContinueSendMgr::ScreenLockedHandler>(sendMgr);
    DmsContinueConditionMgr::GetInstance().SetIsScreenLocked(false);
    int32_t ret = sendMgr->ExecuteSendStrategy(MISSION_EVENT_BACKGROUND, status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);

    DmsContinueConditionMgr::GetInstance().SetIsScreenLocked(true);
    ret = sendMgr->ExecuteSendStrategy(MISSION_EVENT_BACKGROUND, status, sendType);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyBackground_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategyActive_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyActive_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    auto strategy = std::make_shared<SendStrategyActive>(sendMgr);
    sendMgr->strategyMap_[MISSION_EVENT_ACTIVE] = strategy;
    int32_t ret = sendMgr->ExecuteSendStrategy(MISSION_EVENT_ACTIVE, status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_APPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyActive_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategyInactive_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyInactive_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    // SendStrategyInactive uses screenLockedHandler_; it is only created in Init(). Install a minimal
    // handler so the strategy does not dereference nullptr (same object graph as Init()).
    sendMgr->screenLockedHandler_ = std::make_shared<DMSContinueSendMgr::ScreenLockedHandler>(sendMgr);
    DMSContinueSendMgr::ScreenLockedHandler::LastUnfoInfo lockInfo {status.missionId, 0, {}};
    sendMgr->screenLockedHandler_->SetScreenLockedInfo(lockInfo);

    auto strategy = std::make_shared<SendStrategyInactive>(sendMgr);
    sendMgr->strategyMap_[MISSION_EVENT_INACTIVE] = strategy;
    int32_t ret = sendMgr->ExecuteSendStrategy(MISSION_EVENT_INACTIVE, status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyInactive_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategyTimeout_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyTimeout_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    auto strategy = std::make_shared<SendStrategyTimeout>(sendMgr);
    sendMgr->strategyMap_[MISSION_EVENT_TIMEOUT] = strategy;
    int32_t ret = sendMgr->ExecuteSendStrategy(MISSION_EVENT_TIMEOUT, status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyTimeout_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategyMMI_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyMMI_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    auto strategy = std::make_shared<SendStrategyMMI>(sendMgr);
    sendMgr->strategyMap_[MISSION_EVENT_MMI] = strategy;
    int32_t ret = sendMgr->ExecuteSendStrategy(MISSION_EVENT_MMI, status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_APPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategyMMI_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategySwitchOff_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategySwitchOff_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    auto strategy = std::make_shared<SendStrategyContinueSwitchOff>(sendMgr);
    sendMgr->strategyMap_[MISSION_EVENT_CONTINUE_SWITCH_OFF] = strategy;
    int32_t ret = sendMgr->ExecuteSendStrategy(MISSION_EVENT_CONTINUE_SWITCH_OFF, status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategySwitchOff_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, SendSoftbusEvent_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest SendSoftbusEvent_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    uint16_t bundleNameId = 100;
    uint8_t continueTypeId = 1;
    uint8_t type = BROADCAST_TYPE_APPEAR;
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendSoftbusEvent(bundleNameId, continueTypeId, type));
    DTEST_LOG << "DMSContinueSendMgrTest SendSoftbusEvent_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, OnMissionStatusChanged_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest OnMissionStatusChanged_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    EXPECT_CALL(*mgrMock_, GetMissionStatus(_, _, _)).WillOnce(Return(1));
    sendMgr->OnMissionStatusChanged(1, MISSION_EVENT_FOCUSED);

    EXPECT_CALL(*mgrMock_, GetMissionStatus(_, _, _)).WillOnce(Return(0));
    sendMgr->OnMissionStatusChanged(1, MISSION_EVENT_UNFOCUSED);
    DTEST_LOG << "DMSContinueSendMgrTest OnMissionStatusChanged_001 end" << std::endl;
}

HWTEST_F(DMSContinueRecvMgrTest, RegisterOffListener_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest RegisterOffListener_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    auto ret = recvMgr->RegisterOffListener("type", nullptr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueRecvMgrTest RegisterOffListener_Test_001 end" << std::endl;
}

HWTEST_F(DMSContinueRecvMgrTest, NotifyPackageRemoved_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyPackageRemoved_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    recvMgr->NotifyPackageRemoved("");
    recvMgr->NotifyPackageRemoved("testBundle");

    recvMgr->iconInfo_.bundleName = "testBundle";
    EXPECT_NO_FATAL_FAILURE(recvMgr->NotifyPackageRemoved("testBundle"));
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyPackageRemoved_Test_001 end" << std::endl;
}

HWTEST_F(DMSContinueRecvMgrTest, NotifyDeviceOffline_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDeviceOffline_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    recvMgr->NotifyDeviceOffline("");
    recvMgr->NotifyDeviceOffline("networkId");
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDeviceOffline_Test_001 end" << std::endl;
}

HWTEST_F(DMSContinueRecvMgrTest, VerifyBroadcastSource_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest VerifyBroadcastSource_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    int32_t ret = recvMgr->VerifyBroadcastSource("network1", "srcBundle", "sinkBundle", "continueType", 0);
    EXPECT_EQ(ret, ERR_OK);

    ret = recvMgr->VerifyBroadcastSource("network2", "srcBundle", "sinkBundle", "continueType", 1);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = recvMgr->VerifyBroadcastSource("network1", "srcBundle", "otherBundle", "continueType", 1);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = recvMgr->VerifyBroadcastSource("network1", "srcBundle", "sinkBundle", "continueType", 1);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DMSContinueRecvMgrTest VerifyBroadcastSource_Test_001 end" << std::endl;
}

HWTEST_F(DMSContinueRecvMgrTest, IsBundleContinuable_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest IsBundleContinuable_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    AppExecFwk::BundleInfo bundleInfo;
    bool ret = recvMgr->IsBundleContinuable(bundleInfo, "abilityName", "moduleName", "continueType");
    EXPECT_FALSE(ret);

    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.continuable = false;
    bundleInfo.abilityInfos.push_back(abilityInfo);
    ret = recvMgr->IsBundleContinuable(bundleInfo, "abilityName", "moduleName", "continueType");
    EXPECT_FALSE(ret);

    abilityInfo.continuable = true;
    abilityInfo.continueType = {"continueType"};
    abilityInfo.name = "abilityName";
    abilityInfo.moduleName = "moduleName";
    bundleInfo.abilityInfos.clear();
    bundleInfo.abilityInfos.push_back(abilityInfo);
    ret = recvMgr->IsBundleContinuable(bundleInfo, "abilityName", "moduleName", "continueType");
    EXPECT_TRUE(ret);
    DTEST_LOG << "DMSContinueRecvMgrTest IsBundleContinuable_Test_001 end" << std::endl;
}

HWTEST_F(DMSContinueRecvMgrTest, RetryPostBroadcast_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest RetryPostBroadcast_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    int32_t ret = recvMgr->RetryPostBroadcast("networkId", 1, 1, 0, 5);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = recvMgr->RetryPostBroadcast("networkId", 1, 1, 0, 0);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DMSContinueRecvMgrTest RetryPostBroadcast_Test_001 end" << std::endl;
}

HWTEST_F(DMSContinueRecvMgrTest, ContinueTypeFormat_Test_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest ContinueTypeFormat_Test_001 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();

    std::string ret = recvMgr->ContinueTypeFormat("default");
    EXPECT_EQ(ret, "default_ContinueQuickStart");

    ret = recvMgr->ContinueTypeFormat("default_ContinueQuickStart");
    EXPECT_EQ(ret, "default");

    ret = recvMgr->ContinueTypeFormat("test_ContinueQuickStart_more");
    EXPECT_EQ(ret, "test_ContinueQuickStart_more_ContinueQuickStart");

    ret = recvMgr->ContinueTypeFormat("_ContinueQuickStart");
    EXPECT_EQ(ret, "");

    ret = recvMgr->ContinueTypeFormat("");
    EXPECT_EQ(ret, "_ContinueQuickStart");
    DTEST_LOG << "DMSContinueRecvMgrTest ContinueTypeFormat_Test_001 end" << std::endl;
}

HWTEST_F(DMSContinueRecvMgrTest, IsBundleContinuable_Test_002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest IsBundleContinuable_Test_002 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    AppExecFwk::BundleInfo bundleInfo;
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.continuable = true;
    abilityInfo.continueType = {"typeA"};
    abilityInfo.name = "abilityA";
    abilityInfo.moduleName = "moduleA";
    bundleInfo.abilityInfos.push_back(abilityInfo);

    bool ret = recvMgr->IsBundleContinuable(bundleInfo, "abilityA", "moduleA", "typeB");
    EXPECT_TRUE(ret);

    ret = recvMgr->IsBundleContinuable(bundleInfo, "abilityB", "moduleB", "typeA");
    EXPECT_TRUE(ret);

    ret = recvMgr->IsBundleContinuable(bundleInfo, "abilityB", "moduleB", "typeB");
    EXPECT_FALSE(ret);

    AppExecFwk::AbilityInfo abilityInfo2;
    abilityInfo2.continuable = true;
    abilityInfo2.continueType = {"typeA_ContinueQuickStart"};
    abilityInfo2.name = "abilityC";
    abilityInfo2.moduleName = "moduleC";
    bundleInfo.abilityInfos.push_back(abilityInfo2);

    ret = recvMgr->IsBundleContinuable(bundleInfo, "abilityC", "moduleC", "typeA");
    EXPECT_TRUE(ret);
    DTEST_LOG << "DMSContinueRecvMgrTest IsBundleContinuable_Test_002 end" << std::endl;
}

HWTEST_F(DMSContinueRecvMgrTest, NotifyDataRecv_Test_005, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_005 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    std::string senderNetworkId = "NetworkId";
    g_mockBool = true;
    g_mockWifiBool = true;
    uint8_t payload[] = {0x10, 0x01, 0x02, 0x03};
    uint32_t dataLen = 4;
    EXPECT_NO_FATAL_FAILURE(recvMgr->NotifyDataRecv(senderNetworkId, payload, dataLen));

    uint8_t payload2[] = {0x00, 0x01, 0x02, 0x03};
    EXPECT_NO_FATAL_FAILURE(recvMgr->NotifyDataRecv(senderNetworkId, payload2, dataLen));
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_005 end" << std::endl;
}

HWTEST_F(DMSContinueRecvMgrTest, NotifyDataRecv_Test_006, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_006 start" << std::endl;
    std::shared_ptr<DMSContinueRecvMgr> recvMgr = std::make_shared<DMSContinueRecvMgr>();
    std::string senderNetworkId = "NetworkId";
    g_mockBool = true;
    g_mockWifiBool = true;
    uint8_t payload[] = {0x11, 0x00, 0x00, 0x00};
    uint32_t dataLen = 4;
    EXPECT_NO_FATAL_FAILURE(recvMgr->NotifyDataRecv(senderNetworkId, payload, dataLen));
    DTEST_LOG << "DMSContinueRecvMgrTest NotifyDataRecv_Test_006 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, SendStrategyFocusedNoScreenLockedHandler_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyFocusedNoScreenLockedHandler_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    auto strategy = std::make_shared<SendStrategyFocused>(sendMgr);
    int32_t ret = strategy->ExecuteSendStrategy(status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_APPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyFocusedNoScreenLockedHandler_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, SendStrategyBackgroundNoScreenLockedHandler_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyBackgroundNoScreenLockedHandler_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    auto strategy = std::make_shared<SendStrategyBackground>(sendMgr);
    int32_t ret = strategy->ExecuteSendStrategy(status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyBackgroundNoScreenLockedHandler_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ScreenLockedHandler_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ScreenLockedHandler_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    auto handler = std::make_shared<DMSContinueSendMgr::ScreenLockedHandler>(sendMgr);
    // Default and cleared mission id is INVALID_MISSION_ID (-1), not 0 (see ScreenLockedHandler::unfoInfo_ / Reset).
    EXPECT_EQ(handler->GetMissionId(), DMSContinueSendMgr::INVALID_MISSION_ID);

    auto status = handler->GetMissionStatus();
    EXPECT_EQ(status.missionId, 0);

    handler->ResetScreenLockedInfo();
    EXPECT_EQ(handler->GetMissionId(), DMSContinueSendMgr::INVALID_MISSION_ID);
    DTEST_LOG << "DMSContinueSendMgrTest ScreenLockedHandler_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ScreenLockedHandler_SetScreenLockedInfo_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueSendMgrTest ScreenLockedHandler_SetScreenLockedInfo_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    auto handler = std::make_shared<DMSContinueSendMgr::ScreenLockedHandler>(sendMgr);

    DMSContinueSendMgr::ScreenLockedHandler::LastUnfoInfo info;
    info.missionId = 42;
    info.unfoTime = 1000;
    MissionStatus status;
    status.missionId = 42;
    status.bundleName = "testBundle";
    info.status = status;
    handler->SetScreenLockedInfo(info);
    EXPECT_EQ(handler->GetMissionId(), 42);

    handler->SetMissionContinueStateInfo(status);
    handler->ResetScreenLockedInfo();
    EXPECT_EQ(handler->GetMissionId(), DMSContinueSendMgr::INVALID_MISSION_ID);
    DTEST_LOG << "DMSContinueSendMgrTest ScreenLockedHandler_SetScreenLockedInfo_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, SendStrategyInactive_WithScreenLockedHandler_001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyInactive_WithScreenLockedHandler_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    sendMgr->screenLockedHandler_ = std::make_shared<DMSContinueSendMgr::ScreenLockedHandler>(sendMgr);
    MissionStatus status;
    status.missionId = 10;
    status.continueState = AAFwk::ContinueState::CONTINUESTATE_INACTIVE;
    uint8_t sendType = 0;

    DMSContinueSendMgr::ScreenLockedHandler::LastUnfoInfo info;
    info.missionId = 10;
    info.unfoTime = 1000;
    info.status = status;
    sendMgr->screenLockedHandler_->SetScreenLockedInfo(info);

    auto strategy = std::make_shared<SendStrategyInactive>(sendMgr);
    int32_t ret = strategy->ExecuteSendStrategy(status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyInactive_WithScreenLockedHandler_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, SendStrategyInactive_WithScreenLockedHandler_Mismatch_001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyInactive_WithScreenLockedHandler_Mismatch_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    sendMgr->screenLockedHandler_ = std::make_shared<DMSContinueSendMgr::ScreenLockedHandler>(sendMgr);
    MissionStatus status;
    status.missionId = 99;
    uint8_t sendType = 0;

    DMSContinueSendMgr::ScreenLockedHandler::LastUnfoInfo info;
    info.missionId = 10;
    info.unfoTime = 1000;
    MissionStatus handlerStatus;
    handlerStatus.missionId = 10;
    info.status = handlerStatus;
    sendMgr->screenLockedHandler_->SetScreenLockedInfo(info);

    auto strategy = std::make_shared<SendStrategyInactive>(sendMgr);
    int32_t ret = strategy->ExecuteSendStrategy(status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    EXPECT_EQ(sendMgr->screenLockedHandler_->GetMissionId(), 10);
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyInactive_WithScreenLockedHandler_Mismatch_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, SendStrategyBackground_IsScreenLocked_001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyBackground_IsScreenLocked_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    sendMgr->screenLockedHandler_ = std::make_shared<DMSContinueSendMgr::ScreenLockedHandler>(sendMgr);
    MissionStatus status;
    status.missionId = 5;
    uint8_t sendType = 0;

    auto strategy = std::make_shared<SendStrategyBackground>(sendMgr);
    DmsContinueConditionMgr::GetInstance().SetIsScreenLocked(true);
    int32_t ret = strategy->ExecuteSendStrategy(status, sendType);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyBackground_IsScreenLocked_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ExecuteSendStrategy_UnknownType_001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategy_UnknownType_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    MissionEventType unknownType = static_cast<MissionEventType>(999);
    int32_t ret = sendMgr->ExecuteSendStrategy(unknownType, status, sendType);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategy_UnknownType_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, QueryBroadcastInfo_EmptyBundleName_001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest QueryBroadcastInfo_EmptyBundleName_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    MissionStatus status;
    status.bundleName = "";
    status.abilityName = "ability";
    uint16_t bundleNameId = 0;
    uint8_t continueTypeId = 0;

    int32_t ret = sendMgr->QueryBroadcastInfo(status, bundleNameId, continueTypeId);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    status.bundleName = "bundle";
    status.abilityName = "";
    ret = sendMgr->QueryBroadcastInfo(status, bundleNameId, continueTypeId);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueSendMgrTest QueryBroadcastInfo_EmptyBundleName_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, SendStrategyFocused_WithScreenLockedHandler_001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyFocused_WithScreenLockedHandler_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    sendMgr->screenLockedHandler_ = std::make_shared<DMSContinueSendMgr::ScreenLockedHandler>(sendMgr);
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;

    DMSContinueSendMgr::ScreenLockedHandler::LastUnfoInfo info;
    info.missionId = 1;
    info.unfoTime = 1000;
    info.status = status;
    sendMgr->screenLockedHandler_->SetScreenLockedInfo(info);

    auto strategy = std::make_shared<SendStrategyFocused>(sendMgr);
    int32_t ret = strategy->ExecuteSendStrategy(status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_APPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyFocused_WithScreenLockedHandler_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ScreenLockedHandler_OnDeviceScreenLocked_001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest ScreenLockedHandler_OnDeviceScreenLocked_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    auto handler = std::make_shared<DMSContinueSendMgr::ScreenLockedHandler>(sendMgr);
    EXPECT_NO_FATAL_FAILURE(handler->OnDeviceScreenLocked());
    DTEST_LOG << "DMSContinueSendMgrTest ScreenLockedHandler_OnDeviceScreenLocked_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, SendContinueBroadcastAfterDelay_NullHandler_001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest SendContinueBroadcastAfterDelay_NullHandler_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendContinueBroadcastAfterDelay(1));
    DTEST_LOG << "DMSContinueSendMgrTest SendContinueBroadcastAfterDelay_NullHandler_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ContinueSendContext_NullStrategy_001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest ContinueSendContext_NullStrategy_001 start" << std::endl;
    ContinueSendContext ctx;
    MissionStatus status;
    status.missionId = 1;
    uint8_t sendType = 0;
    int32_t ret = ctx.ExecuteSendStrategy(status, sendType);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DMSContinueSendMgrTest ContinueSendContext_NullStrategy_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, ContinueSendContext_WithStrategy_001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest ContinueSendContext_WithStrategy_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    ContinueSendContext ctx;
    ctx.SetStrategy(std::make_shared<SendStrategyTimeout>(sendMgr));
    MissionStatus status;
    status.missionId = 2;
    uint8_t sendType = 0;
    int32_t ret = ctx.ExecuteSendStrategy(status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest ContinueSendContext_WithStrategy_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, SendStrategyTimeout_SendType_001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyTimeout_SendType_001 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    SendStrategyTimeout strategy(sendMgr);
    MissionStatus status;
    uint8_t sendType = 0xFF;
    int32_t ret = strategy.ExecuteSendStrategy(status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyTimeout_SendType_001 end" << std::endl;
}

HWTEST_F(DMSContinueSendMgrTest, SendStrategyContinueSwitchOff_002, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyContinueSwitchOff_002 start" << std::endl;
    std::shared_ptr<DMSContinueSendMgr> sendMgr = std::make_shared<DMSContinueSendMgr>();
    SendStrategyContinueSwitchOff strategy(sendMgr);
    MissionStatus status;
    uint8_t sendType = 0xFF;
    int32_t ret = strategy.ExecuteSendStrategy(status, sendType);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(sendType, BROADCAST_TYPE_DISAPPEAR);
    DTEST_LOG << "DMSContinueSendMgrTest SendStrategyContinueSwitchOff_002 end" << std::endl;
}
}
}
