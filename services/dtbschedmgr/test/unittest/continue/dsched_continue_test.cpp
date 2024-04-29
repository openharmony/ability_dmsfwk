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

#include "dsched_continue_test.h"

#include "distributed_sched_service.h"
#include "dsched_continue.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

void DSchedContinueTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueTest::SetUpTestCase" << std::endl;
    DistributedSchedService::GetInstance().Init();
}

void DSchedContinueTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueTest::TearDownTestCase" << std::endl;
}

void DSchedContinueTest::TearDown()
{
    DTEST_LOG << "DSchedContinueTest::TearDown" << std::endl;
}

void DSchedContinueTest::SetUp()
{
    DTEST_LOG << "DSchedContinueTest::SetUp" << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_001_1
 * @tc.desc: OnContinueMission and PostStartTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_001_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_001_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    OHOS::AAFwk::WantParams wantParams;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);

    // eventHandler_ is null
    int32_t ret = conti->OnContinueMission(wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti->PostStartTask(wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    // eventHandler_ not null
    conti->Init();
    ret = conti->PostStartTask(wantParams);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_001_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_002_1
 * @tc.desc: OnStartCmd and PostCotinueAbilityTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_002_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_002_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    int32_t appVersion = 0;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);

    // eventHandler_ is null
    int32_t ret = conti->OnStartCmd(appVersion);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti->PostCotinueAbilityTask(appVersion);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    // eventHandler_ not null
    conti->Init();
    ret = conti->PostCotinueAbilityTask(appVersion);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_002_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_003
 * @tc.desc: OnReplyCmd and PostReplyTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_003_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_003_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto cmd = std::make_shared<DSchedContinueReplyCmd>();
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);

    // eventHandler_ is null
    cmd->replyCmd_ = DSCHED_CONTINUE_CMD_START;
    int32_t ret = conti->OnReplyCmd(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti->PostReplyTask(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    // eventHandler_ not null
    conti->Init();

    cmd->replyCmd_ = DSCHED_CONTINUE_END_EVENT;
    ret = conti->OnReplyCmd(cmd);
    EXPECT_EQ(ret, ERR_OK);

    ret = conti->PostReplyTask(cmd);
    EXPECT_EQ(ret, ERR_OK);

    cmd->replyCmd_ = DSCHED_CONTINUE_INVALID_EVENT;
    ret = conti->PostReplyTask(cmd);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_003_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_004_1
 * @tc.desc: OnStartContinuation and PostContinueSendTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_004_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_004_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);

    OHOS::AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t status = ERR_OK;
    uint32_t accessToken = 0;

    // eventHandler_ is null
    int32_t ret = conti->OnStartContinuation(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti->PostContinueSendTask(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    // eventHandler_ not null
    conti->Init();

    ret = conti->OnStartContinuation(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, ERR_OK);

    ret = conti->PostContinueSendTask(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, ERR_OK);

    status = INVALID_PARAMETERS_ERR;
    ret = conti->PostContinueSendTask(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_004_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_005
 * @tc.desc: OnContinueDataCmd and PostContinueDataTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_005_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_005_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);

    // eventHandler_ is null
    int32_t ret = conti->OnContinueDataCmd(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti->PostContinueDataTask(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    // eventHandler_ not null
    conti->Init();

    ret = conti->OnContinueDataCmd(cmd);
    EXPECT_EQ(ret, ERR_OK);

    ret = conti->PostContinueDataTask(cmd);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_005_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_006_1
 * @tc.desc: OnNotifyComplete, OnContinueEndCmd and PostNotifyCompleteTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_006_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_006_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    int32_t missionId = 1;
    bool isSuccess = true;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);

    // OnNotifyComplete
    int32_t ret = conti->OnNotifyComplete(missionId, isSuccess);
    EXPECT_EQ(ret, ERR_OK);

    missionId = 0;
    ret = conti->OnNotifyComplete(missionId, isSuccess);
    EXPECT_EQ(ret, ERR_OK);

    isSuccess = false;
    ret = conti->OnNotifyComplete(missionId, isSuccess);
    EXPECT_EQ(ret, ERR_OK);

    // eventHandler_ is null
    auto cmd = std::make_shared<DSchedContinueEndCmd>();
    ret = conti->OnContinueEndCmd(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti->PostNotifyCompleteTask(ERR_OK);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    // eventHandler_ not null
    conti->Init();
    ret = conti->PostNotifyCompleteTask(ERR_OK);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_006_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_007_1
 * @tc.desc: OnContinueEnd and PostContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_007_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_007_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    int32_t result = ERR_OK;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);

    // eventHandler_ is null
    int32_t ret = conti->OnContinueEnd(result);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = conti->PostContinueEndTask(result);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    // eventHandler_ not null
    conti->Init();
    ret = conti->PostContinueEndTask(result);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_007_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_008_1
 * @tc.desc: ExecuteContinueReq
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_008_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_008_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    auto wantParams = std::make_shared<DistributedWantParams>();
    int32_t ret = conti->ExecuteContinueReq(wantParams);
    EXPECT_NE(ret, ERR_OK);

    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_008_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_009_1
 * @tc.desc: PackStartCmd
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_009_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_009_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PUSH;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    auto cmd = std::make_shared<DSchedContinueStartCmd>();
    auto wantParams = std::make_shared<DistributedWantParams>();

    int32_t ret = conti->PackStartCmd(cmd, wantParams);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_009_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0010_1
 * @tc.desc: ExecuteContinueAbility
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0010_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0010_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    int32_t missionId = 1;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, deviceId, missionId);
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    int32_t appVersion = 0;
    int32_t ret = conti->ExecuteContinueAbility(appVersion);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0010_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0011_1
 * @tc.desc: GetMissionIdByBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0011_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0011_1 begin" << std::endl;
    std::string deviceId = "123";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    int32_t missionId = 1;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, deviceId, missionId);
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    int32_t ret = conti->GetMissionIdByBundleName();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0011_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0012_1
 * @tc.desc: CheckContinueAbilityPermission
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0012_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0012_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    int32_t ret = conti->CheckContinueAbilityPermission();
    EXPECT_EQ(ret, NO_MISSION_INFO_FOR_MISSION_ID);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0012_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0013_1
 * @tc.desc: ExecuteContinueReply
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0013_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0013_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    int32_t ret = conti->ExecuteContinueReply();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0013_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0014_1
 * @tc.desc: ExecuteContinueSend
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0014_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0014_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    auto data = std::make_shared<ContinueAbilityData>();
    int32_t ret = conti->ExecuteContinueSend(data);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0014_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0015_1
 * @tc.desc: SetWantForContinuation
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0015_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0015_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    AAFwk::Want want;
    int32_t ret = conti->SetWantForContinuation(want);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0015_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0016_1
 * @tc.desc: PackDataCmd
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0016_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0016_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    OHOS::AAFwk::Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    CallerInfo callerInfo;
    AccountInfo accountInfo;

    int32_t ret = conti->PackDataCmd(cmd, want, abilityInfo, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0016_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0017_1
 * @tc.desc: ExecuteContinueData
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0017_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0017_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    auto cmd = std::make_shared<DSchedContinueDataCmd>();

    int32_t ret = conti->ExecuteContinueData(cmd);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0017_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0018_1
 * @tc.desc: ExecuteNotifyComplete
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0018_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0018_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    int32_t result = ERR_OK;
    int32_t ret = conti->ExecuteNotifyComplete(result);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0018_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0019_1
 * @tc.desc: PackReplyCmd
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0019_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0019_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    auto cmd = std::make_shared<DSchedContinueReplyCmd>();
    int32_t replyCmd = 0;
    int32_t appVersion = 0;
    int32_t result = 0;

    int32_t ret = conti->PackReplyCmd(cmd, replyCmd, appVersion, result, "");
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0019_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0020_1
 * @tc.desc: ExecuteContinueEnd
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0020_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0020_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    int32_t result = 0;

    int32_t ret = conti->ExecuteContinueEnd(result);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0020_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0021_1
 * @tc.desc: ExecuteContinueError
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0021_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0021_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    int32_t result = 0;
    int32_t ret = conti->ExecuteContinueError(result);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0021_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0022_1
 * @tc.desc: PackEndCmd
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0022_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0022_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    auto cmd = std::make_shared<DSchedContinueEndCmd>();
    int32_t result = 0;

    int32_t ret = conti->PackEndCmd(cmd, result);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0022_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0023_1
 * @tc.desc: SendCommand
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0023_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0023_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    auto cmd = std::make_shared<DSchedContinueCmdBase>();
    int32_t ret = conti->SendCommand(cmd);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0023_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0024_1
 * @tc.desc: GetLocalDeviceId
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0024_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0024_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    std::string localDeviceId;
    bool ret = conti->GetLocalDeviceId(localDeviceId);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0024_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0025_1
 * @tc.desc: CheckDeviceIdFromRemote
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0025_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0025_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();

    int32_t ret = conti->CheckDeviceIdFromRemote("", "", "");
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0025_1 end ret:" << ret << std::endl;
}
}
}
