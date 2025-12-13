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

#include "dms_continue_recommend_manager_test.h"

#include "mission/notification/dms_continue_recommend_info.h"
#include "mission/notification/dms_continue_recommend_manager.h"

#include "multi_user_manager.h"

#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
static int32_t g_missionId = 0;
namespace {
const std::string TAG = "DMSContinueRecomMgr";
const int32_t WAITTIME = 2000;
}
void ContinueRecommendInfoTest::SetUpTestCase()
{
}

void ContinueRecommendInfoTest::TearDownTestCase()
{
}

void ContinueRecommendInfoTest::SetUp()
{
}

void ContinueRecommendInfoTest::TearDown()
{
}

/**
 * @tc.name: testMarshalCandidates001
 * @tc.desc: test MarshalCandidates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContinueRecommendInfoTest, testMarshalCandidates001, TestSize.Level1)
{
    DTEST_LOG << "ContinueRecommendInfoTest testMarshalCandidates001 start" << std::endl;
    ContinueRecommendInfo info;
    std::string ret = info.MarshalCandidates();
    EXPECT_NE(ret, "");
    DTEST_LOG << "ContinueRecommendInfoTest testMarshalCandidates001 end" << std::endl;
}

/**
 * @tc.name: testMarshalCandidates002
 * @tc.desc: test MarshalCandidates
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContinueRecommendInfoTest, testMarshalCandidates002, TestSize.Level1)
{
    DTEST_LOG << "ContinueRecommendInfoTest testMarshalCandidates002 start" << std::endl;
    ContinueRecommendInfo info;
    ContinueCandidate date;
    date.deviceId_ = "deviceId";
    date.dstBundleName_ = "dstBundleName";
    info.candidates_.push_back(date);
    date.deviceId_ = "";
    date.dstBundleName_ = "";
    info.candidates_.push_back(date);
    std::string ret = info.MarshalCandidates();
    EXPECT_NE(ret, "");
    DTEST_LOG << "ContinueRecommendInfoTest testMarshalCandidates002 end" << std::endl;
}

/**
 * @tc.name: testMarshalCandidate001
 * @tc.desc: test MarshalCandidate
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContinueRecommendInfoTest, testMarshalCandidate001, TestSize.Level1)
{
    DTEST_LOG << "ContinueRecommendInfoTest testMarshalCandidate001 start" << std::endl;
    ContinueRecommendInfo info;
    ContinueCandidate candidate;
    std::string ret = info.MarshalCandidate(candidate);
    EXPECT_NE(ret, "");
    DTEST_LOG << "ContinueRecommendInfoTest testMarshalCandidate001 end" << std::endl;
}

/**
 * @tc.name: testToString001
 * @tc.desc: test ToString
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(ContinueRecommendInfoTest, testToString001, TestSize.Level1)
{
    DTEST_LOG << "ContinueRecommendInfoTest testToString001 start" << std::endl;
    ContinueRecommendInfo info;
    std::string ret = info.ToString();
    EXPECT_NE(ret, "");
    DTEST_LOG << "ContinueRecommendInfoTest testToString001 end" << std::endl;
}

void DMSContinueRecomMgrTest::SetUpTestCase()
{
    bundleMgrMock_ = std::make_shared<BundleManagerInternalMock>();
    BundleManagerInternalMock::bundleMgrMock = bundleMgrMock_;
    mgrMock_ = std::make_shared<DmsContinueConditionMgrMock>();
    IDmsContinueConditionMgr::conditionMgrMock = mgrMock_;
    storageMock_ = std::make_shared<DtbschedmgrDeviceInfoStorageMock>();
    DtbschedmgrDeviceInfoStorageMock::storageMock = storageMock_;
}

void DMSContinueRecomMgrTest::TearDownTestCase()
{
    BundleManagerInternalMock::bundleMgrMock = nullptr;
    bundleMgrMock_ = nullptr;
    IDmsContinueConditionMgr::conditionMgrMock = nullptr;
    mgrMock_ = nullptr;
    DtbschedmgrDeviceInfoStorageMock::storageMock = nullptr;
    storageMock_ = nullptr;
}

void DMSContinueRecomMgrTest::SetUp()
{
    MultiUserManager::GetInstance().Init();
}

void DMSContinueRecomMgrTest::TearDown()
{
}

int32_t GetCurrentMissionId()
{
    return g_missionId;
}

/**
 * @tc.name: testDMSContinueRecomMgrInitUninit001
 * @tc.desc: test Init UnInit
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecomMgrTest, testDMSContinueRecomMgrInitUninit001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecomMgrTest testDMSContinueRecomMgrInitUninit001 start" << std::endl;
    auto recomMgr = MultiUserManager::GetInstance().GetCurrentRecomMgr();
    ASSERT_NE(nullptr, recomMgr);
    EXPECT_CALL(*mgrMock_, TypeEnumToString(_)).WillRepeatedly(Return("test"));
    int32_t accountId = 100;
    EXPECT_NO_FATAL_FAILURE(recomMgr->Init(accountId));
    usleep(WAITTIME);
    recomMgr->hasInit_ = false;
    EXPECT_NO_FATAL_FAILURE(recomMgr->Init(accountId));

    g_missionId = 0;
    EXPECT_NO_FATAL_FAILURE(recomMgr->OnDeviceChanged());

    g_missionId = 1;
    EXPECT_CALL(*mgrMock_, GetMissionStatus(_, _, _)).WillRepeatedly(Return(1));
    EXPECT_NO_FATAL_FAILURE(recomMgr->OnDeviceChanged());
    int32_t missionId = 0;
    MissionEventType type = MISSION_EVENT_INVALID;
    EXPECT_NO_FATAL_FAILURE(recomMgr->OnMissionStatusChanged(missionId, type));
    EXPECT_NO_FATAL_FAILURE(recomMgr->UnInit());
    DTEST_LOG << "DMSContinueRecomMgrTest testDMSContinueRecomMgrInitUninit001 end" << std::endl;
}

/**
 * @tc.name: testOnMissionStatusChanged001
 * @tc.desc: test OnMissionStatusChanged
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecomMgrTest, testOnMissionStatusChanged001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecomMgrTest testOnMissionStatusChanged001 start" << std::endl;
    auto recomMgr = MultiUserManager::GetInstance().GetCurrentRecomMgr();
    ASSERT_NE(nullptr, recomMgr);
    int32_t missionId = 0;
    MissionEventType type = MISSION_EVENT_INVALID;
    EXPECT_CALL(*mgrMock_, GetMissionStatus(_, _, _)).WillRepeatedly(Return(0));
    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition()).WillRepeatedly(Return(false));
    EXPECT_NO_FATAL_FAILURE(recomMgr->OnMissionStatusChanged(missionId, type));
    EXPECT_NO_FATAL_FAILURE(recomMgr->UnInit());
    DTEST_LOG << "DMSContinueRecomMgrTest testOnMissionStatusChanged001 end" << std::endl;
}

/**
 * @tc.name: testPublishContinueRecommend001
 * @tc.desc: test PublishContinueRecommend
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecomMgrTest, testPublishContinueRecommend001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecomMgrTest testPublishContinueRecommend start" << std::endl;
    auto recomMgr = MultiUserManager::GetInstance().GetCurrentRecomMgr();
    ASSERT_NE(nullptr, recomMgr);
    int32_t accountId = 100;
    recomMgr->Init(accountId);
    usleep(WAITTIME);

    MissionStatus status;
    MissionEventType type = MISSION_EVENT_INVALID;
    EXPECT_NO_FATAL_FAILURE(recomMgr->PublishContinueRecommend(status, type));

    EXPECT_CALL(*mgrMock_, CheckSystemSendCondition()).WillRepeatedly(Return(true));
    EXPECT_CALL(*mgrMock_, CheckMissionSendCondition(_, _)).WillRepeatedly(Return(false));
    EXPECT_NO_FATAL_FAILURE(recomMgr->PublishContinueRecommend(status, type));

    EXPECT_CALL(*mgrMock_, CheckMissionSendCondition(_, _)).WillRepeatedly(Return(true));
    EXPECT_NO_FATAL_FAILURE(recomMgr->PublishContinueRecommend(status, type));

    EXPECT_CALL(*bundleMgrMock_, GetLocalAbilityInfo(_, _, _, _)).WillOnce(Return(1));
    EXPECT_NO_FATAL_FAILURE(recomMgr->PublishContinueRecommend(status, type));
    recomMgr->UnInit();
    DTEST_LOG << "DMSContinueRecomMgrTest testPublishContinueRecommend001 end" << std::endl;
}

/**
 * @tc.name: testGetRecommendInfo001
 * @tc.desc: test GetRecommendInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DMSContinueRecomMgrTest, testGetRecommendInfo001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecomMgrTest testGetRecommendInfo start" << std::endl;
    auto recomMgr = MultiUserManager::GetInstance().GetCurrentRecomMgr();
    ASSERT_NE(nullptr, recomMgr);
    int32_t accountId = 100;
    recomMgr->Init(accountId);
    usleep(WAITTIME);

    MissionStatus status;
    MissionEventType type = MISSION_EVENT_INVALID;
    ContinueRecommendInfo info;
    EXPECT_CALL(*bundleMgrMock_, GetLocalAbilityInfo(_, _, _, _)).WillOnce(Return(1));
    bool ret = recomMgr->GetRecommendInfo(status, type, info);
    EXPECT_EQ(ret, false);

    EXPECT_CALL(*bundleMgrMock_, GetLocalAbilityInfo(_, _, _, _)).WillOnce(Return(0));
    ret = recomMgr->GetRecommendInfo(status, type, info);
    EXPECT_EQ(ret, true);
    recomMgr->UnInit();
    DTEST_LOG << "DMSContinueRecomMgrTest testGetRecommendInfo001 end" << std::endl;
}

/**
 * @tc.name: GetAvailableRecommendListInternalTest_001
 * @tc.desc: test GetAvailableRecommendListInternal
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueRecomMgrTest, GetAvailableRecommendListInternalTest_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecomMgrTest GetAvailableRecommendListInternalTest_001 start" << std::endl;
    auto recomMgr = MultiUserManager::GetInstance().GetCurrentRecomMgr();
    ASSERT_NE(nullptr, recomMgr);
    int32_t accountId = 100;
    recomMgr->Init(accountId);
    usleep(WAITTIME);

    std::map<std::string, DmsBundleInfo> result;
    std::vector<std::string> networkIdList;
    std::string bundleName = "";
    AppExecFwk::AppProvisionInfo appProvisionInfo;
    appProvisionInfo.developerId = "0";
    EXPECT_CALL(*storageMock_, GetNetworkIdList()).WillOnce(Return(networkIdList));
    bool ret = recomMgr->GetAvailableRecommendListInternal(bundleName, result, appProvisionInfo);
    EXPECT_EQ(ret, true);

    networkIdList.push_back("networkId");
    EXPECT_CALL(*storageMock_, GetNetworkIdList()).WillOnce(Return(networkIdList));
    ret = recomMgr->GetAvailableRecommendListInternal(bundleName, result, appProvisionInfo);
    EXPECT_EQ(ret, true);
    recomMgr->UnInit();
    DTEST_LOG << "DMSContinueRecomMgrTest GetAvailableRecommendListInternalTest_001 end" << std::endl;
}

/**
 * @tc.name: IsContinuableWithDiffBundleTest_001
 * @tc.desc: test IsContinuableWithDiffBundle
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueRecomMgrTest, IsContinuableWithDiffBundleTest_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecomMgrTest IsContinuableWithDiffBundleTest_001 start" << std::endl;
    auto recomMgr = MultiUserManager::GetInstance().GetCurrentRecomMgr();
    ASSERT_NE(nullptr, recomMgr);
    int32_t accountId = 100;
    recomMgr->Init(accountId);
    usleep(WAITTIME);

    DmsAbilityInfo abilityInfo;
    DmsBundleInfo info;
    std::string bundleName = "";
    info.dmsAbilityInfos.push_back(abilityInfo);
    bool ret = recomMgr->IsContinuableWithDiffBundle("bundleName", info);
    EXPECT_EQ(ret, false);

    abilityInfo.continueBundleName.push_back("bundleName");
    info.dmsAbilityInfos.clear();
    info.dmsAbilityInfos.push_back(abilityInfo);
    ret = recomMgr->IsContinuableWithDiffBundle("bundleName", info);
    EXPECT_EQ(ret, true);
    recomMgr->UnInit();
    DTEST_LOG << "DMSContinueRecomMgrTest IsContinuableWithDiffBundleTest_001 end" << std::endl;
}

/**
 * @tc.name: GetAvailableRecommendListTest_001
 * @tc.desc: test GetAvailableRecommendList
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueRecomMgrTest, GetAvailableRecommendListTest_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueRecomMgrTest GetAvailableRecommendListTest_001 start" << std::endl;
    auto recomMgr = MultiUserManager::GetInstance().GetCurrentRecomMgr();
    ASSERT_NE(nullptr, recomMgr);
    int32_t accountId = 100;
    recomMgr->Init(accountId);
    usleep(WAITTIME);

    std::map<std::string, DmsBundleInfo> result;
    std::vector<std::string> networkIdList;
    std::string bundleName = "";
    AppExecFwk::AppProvisionInfo appProvisionInfo;
    EXPECT_CALL(*bundleMgrMock_, GetAppProvisionInfo4CurrentUser(_, _)).WillOnce(Return(false));
    bool ret = recomMgr->GetAvailableRecommendList(bundleName, result);
    EXPECT_EQ(ret, false);

    networkIdList.push_back("networkId");
    bundleName = "bundleName";
    EXPECT_CALL(*storageMock_, GetNetworkIdList()).WillOnce(Return(networkIdList));
    EXPECT_CALL(*bundleMgrMock_, GetAppProvisionInfo4CurrentUser(_, _)).WillOnce(Return(true));
    ret = recomMgr->GetAvailableRecommendList(bundleName, result);
    EXPECT_EQ(ret, true);
    recomMgr->UnInit();
    DTEST_LOG << "DMSContinueRecomMgrTest GetAvailableRecommendListTest_001 end" << std::endl;
}
} // DistributedSchedule
} // namespace OHOS
