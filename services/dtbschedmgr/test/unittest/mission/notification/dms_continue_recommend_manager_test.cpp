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
}

void DMSContinueRecomMgrTest::TearDownTestCase()
{
}

void DMSContinueRecomMgrTest::SetUp()
{
    MultiUserManager::GetInstance().Init();
}

void DMSContinueRecomMgrTest::TearDown()
{
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
    int32_t accountId = 100;
    EXPECT_NO_FATAL_FAILURE(recomMgr->Init(accountId));
    usleep(WAITTIME);

    EXPECT_NO_FATAL_FAILURE(recomMgr->OnDeviceChanged());
    int32_t missionId = 0;
    MissionEventType type = MISSION_EVENT_INVALID;
    EXPECT_NO_FATAL_FAILURE(recomMgr->OnMissionStatusChanged(missionId, type));
    EXPECT_NO_FATAL_FAILURE(recomMgr->UnInit());
    DTEST_LOG << "DMSContinueRecomMgrTest testDMSContinueRecomMgrInitUninit001 end" << std::endl;
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
    bool ret = recomMgr->GetRecommendInfo(status, type, info);
    EXPECT_EQ(ret, false);
    recomMgr->UnInit();
    DTEST_LOG << "DMSContinueRecomMgrTest testGetRecommendInfo001 end" << std::endl;
}
} // DistributedSchedule
} // namespace OHOS
