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

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition()).WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendContinueBroadcast(status, MissionEventType::MISSION_EVENT_FOCUSED));

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition()).WillOnce(Return(true));
    EXPECT_CALL(*mgrMock_, CheckMissionSendCondition(_, _)).WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendContinueBroadcast(status, MissionEventType::MISSION_EVENT_FOCUSED));

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition()).WillOnce(Return(true));
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

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition()).WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendContinueBroadcast(status, MissionEventType::MISSION_EVENT_BACKGROUND));

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition()).WillOnce(Return(true));
    EXPECT_CALL(*mgrMock_, CheckMissionSendCondition(_, _)).WillOnce(Return(false));
    EXPECT_NO_FATAL_FAILURE(sendMgr->SendContinueBroadcast(status, MissionEventType::MISSION_EVENT_BACKGROUND));

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition()).WillOnce(Return(true));
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
}
}
