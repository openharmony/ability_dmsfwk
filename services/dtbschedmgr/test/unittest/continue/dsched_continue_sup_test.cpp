/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "dsched_continue_sup_test.h"

#include "distributed_sched_service.h"
#include "dtbschedmgr_log.h"
#include "softbus_error_code.h"
#include "test_log.h"
#include "mission/distributed_bm_storage.h"
#include "continue_scene_session_handler.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

namespace {
    const std::string BASEDIR = "/data/service/el1/public/database/DistributedSchedule";
    const std::string BUNDLEMAME_1 = "bundleName";
    const std::string CONTINUE_TYPE1 = "continueType1";
    const std::string CONTINUE_TYPE2 = "continueType2";
    const std::string CONTINUE_TYPE3 = "continueType3";
    const std::string CONTINUE_TYPE1_QUICK = "continueType1_ContinueQuickStart";
    const std::string MODULE_NAME1 = "moduleName1";
    const std::string MODULE_NAME2 = "moduleName2";
    const std::string MODULE_NAME3 = "moduleName3";
    const std::string ABILITY_NAME_SAME_AS_CONTINUE_TYPE = CONTINUE_TYPE1;
    const std::string ABILITY_NAME_DIFF_AS_CONTINUE_TYPE = "ability";
    const int32_t WAITTIME = 2000;
    const uint32_t DSCHED_BUFFER_SIZE = 1024;
}
void DSchedContinueSupTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DSchedContinueSupTest::SetUpTestCase" << std::endl;
    DistributedSchedService::GetInstance().Init();

    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    OHOS::AAFwk::WantParams wantParams;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    conti_ = std::make_shared<DSchedContinue>(subType, direction, callback, info);
}

void DSchedContinueSupTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    conti_ = nullptr;
    DTEST_LOG << "DSchedContinueSupTest::TearDownTestCase" << std::endl;
}

void DSchedContinueSupTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueSupTest::TearDown" << std::endl;
}

void DSchedContinueSupTest::SetUp()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueSupTest::SetUp" << std::endl;
}

/**
 * @tc.name: DSchedContinueSupTest_001_1
 * @tc.desc: OnContinueMission and PostStartTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSupTest, DSchedContinueSupTest_001_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_001_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_EQ(conti_->eventHandler_, nullptr);
    OHOS::AAFwk::WantParams wantParams;
    int32_t ret = conti_->OnContinueMission(wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti_->PostStartTask(wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_001_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueSupTest_001_2
 * @tc.desc: DSchedContinue Constructor
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSupTest, DSchedContinueSupTest_001_2, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_001_2 begin" << std::endl;
    std::shared_ptr<DSchedContinueStartCmd> startCmd = nullptr;
    int32_t sessionId = 1;
    int32_t accountId = 1;

    auto testInfo = std::make_shared<DSchedContinue>(startCmd, sessionId, accountId);
    EXPECT_TRUE(testInfo->continueInfo_.sourceBundleName_.empty());

    startCmd = std::make_shared<DSchedContinueStartCmd>();
    auto testInfo2 = std::make_shared<DSchedContinue>(startCmd, sessionId, accountId);
    EXPECT_EQ(testInfo2->accountId_, accountId);

    startCmd->sourceMissionId_ = 1;
    auto testInfo3 = std::make_shared<DSchedContinue>(startCmd, sessionId, accountId);
    EXPECT_EQ(testInfo3->continueInfo_.missionId_, startCmd->sourceMissionId_);

    startCmd->dstBundleName_ = "sinkBundleName";
    auto testInfo4 = std::make_shared<DSchedContinue>(startCmd, sessionId, accountId);
    EXPECT_EQ(testInfo4->continueInfo_.sinkBundleName_, startCmd->dstBundleName_);

    startCmd->srcBundleName_ = "srcBundleName";
    auto testInfo5 = std::make_shared<DSchedContinue>(startCmd, sessionId, accountId);
    EXPECT_EQ(testInfo5->continueInfo_.sourceBundleName_, startCmd->srcBundleName_);
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_001_2 end" << std::endl;
}

/**
 * @tc.name: DSchedContinueSupTest_002_1
 * @tc.desc: OnStartCmd and PostCotinueAbilityTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSupTest, DSchedContinueSupTest_002_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_002_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_EQ(conti_->eventHandler_, nullptr);
    int32_t appVersion = 0;

    // eventHandler_ is null
    int32_t ret = conti_->OnStartCmd(appVersion);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti_->PostCotinueAbilityTask(appVersion);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_002_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueSupTest_003
 * @tc.desc: OnReplyCmd and PostReplyTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSupTest, DSchedContinueSupTest_003_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_003_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_EQ(conti_->eventHandler_, nullptr);
    auto cmd = std::make_shared<DSchedContinueReplyCmd>();
    // eventHandler_ is null
    cmd->replyCmd_ = DSCHED_CONTINUE_CMD_START;
    int32_t ret = conti_->OnReplyCmd(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti_->PostReplyTask(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_003_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueSupTest_004_1
 * @tc.desc: OnStartContinuation and PostContinueSendTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSupTest, DSchedContinueSupTest_004_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_004_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_EQ(conti_->eventHandler_, nullptr);
    OHOS::AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t status = ERR_OK;
    uint32_t accessToken = 0;

    // eventHandler_ is null
    int32_t ret = conti_->OnStartContinuation(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti_->PostContinueSendTask(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_004_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueSupTest_005
 * @tc.desc: OnContinueDataCmd and PostContinueDataTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSupTest, DSchedContinueSupTest_005_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_005_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_EQ(conti_->eventHandler_, nullptr);

    // eventHandler_ is null
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    int32_t ret = conti_->OnContinueDataCmd(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti_->PostContinueDataTask(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_005_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueSupTest_006_1
 * @tc.desc: OnNotifyComplete, OnContinueEndCmd and PostNotifyCompleteTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSupTest, DSchedContinueSupTest_006_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_006_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_EQ(conti_->eventHandler_, nullptr);

    int32_t missionId = 1;
    bool isSuccess = true;

    // OnNotifyComplete
    int32_t ret = conti_->OnNotifyComplete(missionId, isSuccess);
    EXPECT_EQ(ret, ERR_OK);

    missionId = 0;
    ret = conti_->OnNotifyComplete(missionId, isSuccess);
    EXPECT_EQ(ret, ERR_OK);

    isSuccess = false;
    ret = conti_->OnNotifyComplete(missionId, isSuccess);
    EXPECT_EQ(ret, ERR_OK);

    // eventHandler_ is null
    auto cmd = std::make_shared<DSchedContinueEndCmd>();
    ret = conti_->OnContinueEndCmd(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti_->PostNotifyCompleteTask(ERR_OK);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_006_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueSupTest_007_1
 * @tc.desc: OnContinueEnd and PostContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSupTest, DSchedContinueSupTest_007_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_007_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_EQ(conti_->eventHandler_, nullptr);
    int32_t result = ERR_OK;

    // eventHandler_ is null
    int32_t ret = conti_->OnContinueEnd(result);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti_->PostContinueEndTask(result);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_007_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueSupTest_0011_1
 * @tc.desc: GetMissionIdByBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSupTest, DSchedContinueSupTest_0011_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_0011_1 begin" << std::endl;
    std::string deviceId = "123";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    int32_t missionId = 1;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, deviceId, missionId);
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    int32_t ret = conti->GetMissionIdByBundleName();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueSupTest DSchedContinueSupTest_0011_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: ExecuteQuickStartFailed_037
 * @tc.desc: ExecuteQuickStartFailed
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueSupTest, OnRemoteDied_038, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueSupTest OnRemoteDied_038 begin" << std::endl;
    sptr<StateCallbackIpcDiedListener> diedListener = new StateCallbackIpcDiedListener();
    EXPECT_NO_FATAL_FAILURE(diedListener->OnRemoteDied(nullptr));
    DTEST_LOG << "DSchedContinueSupTest OnRemoteDied_038 end ret:" << std::endl;
    usleep(WAITTIME);
}
}
}
