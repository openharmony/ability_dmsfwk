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

#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DMSContinueMgrTest";
}
//DMSContinueSendMgrTest
void DMSContinueSendMgrTest::SetUpTestCase()
{
}

void DMSContinueSendMgrTest::TearDownTestCase()
{
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
}

void DMSContinueRecvMgrTest::TearDownTestCase()
{
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
    sendMgr->SendContinueBroadcast(status, MissionEventType::MISSION_EVENT_FOCUSED);

    sendMgr->strategyMap_.clear();
    auto ret = sendMgr->ExecuteSendStrategy(MissionEventType::MISSION_EVENT_FOCUSED, status, sendType);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueSendMgrTest ExecuteSendStrategy_Test_001 end" << std::endl;
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
    ret = sendMgr->QueryBroadcastInfo(status, bundleNameId, continueTypeId);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DMSContinueSendMgrTest QueryBroadcastInfo_Test_001 end" << std::endl;
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
}
}
