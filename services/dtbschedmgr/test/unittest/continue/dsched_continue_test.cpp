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
void DSchedContinueTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    dmsStoreMock = std::make_shared<MockDmsMgrDeviceInfoStore>();
    DmsMgrDeviceInfoStore::dmsStore = dmsStoreMock;
    DTEST_LOG << "DSchedContinueTest::SetUpTestCase" << std::endl;
    DistributedSchedService::GetInstance().Init();
}

void DSchedContinueTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DmsMgrDeviceInfoStore::dmsStore = nullptr;
    dmsStoreMock = nullptr;
    DTEST_LOG << "DSchedContinueTest::TearDownTestCase" << std::endl;
}

void DSchedContinueTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueTest::TearDown" << std::endl;
}

void DSchedContinueTest::SetUp()
{
    usleep(WAITTIME);
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
    usleep(WAITTIME);
    ret = conti->PostStartTask(wantParams);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_001_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);
    ret = conti->PostCotinueAbilityTask(appVersion);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_002_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    cmd->replyCmd_ = DSCHED_CONTINUE_END_EVENT;
    ret = conti->OnReplyCmd(cmd);
    EXPECT_EQ(ret, ERR_OK);

    ret = conti->PostReplyTask(cmd);
    EXPECT_EQ(ret, ERR_OK);

    cmd->replyCmd_ = DSCHED_CONTINUE_INVALID_EVENT;
    ret = conti->PostReplyTask(cmd);
    EXPECT_EQ(ret, ERR_OK);

    cmd = nullptr;
    ret = conti->PostReplyTask(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_003_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    ret = conti->OnStartContinuation(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, ERR_OK);

    ret = conti->PostContinueSendTask(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, ERR_OK);

    status = ERR_NONE;
    ret = conti->PostContinueSendTask(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_004_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    ret = conti->OnContinueDataCmd(cmd);
    EXPECT_EQ(ret, ERR_OK);

    ret = conti->PostContinueDataTask(cmd);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_005_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);
    ret = conti->PostNotifyCompleteTask(ERR_OK);
    EXPECT_EQ(ret, ERR_OK);

    cmd = nullptr;
    ret = conti->OnContinueEndCmd(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_006_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);
    ret = conti->PostContinueEndTask(result);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_007_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    auto wantParams = std::make_shared<DistributedWantParams>();
    int32_t ret = conti->ExecuteContinueReq(wantParams);
    EXPECT_NE(ret, ERR_OK);

    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_008_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    auto cmd = std::make_shared<DSchedContinueStartCmd>();
    auto wantParams = std::make_shared<DistributedWantParams>();

    int32_t ret = conti->PackStartCmd(cmd, wantParams);
    EXPECT_EQ(ret, ERR_OK);

    wantParams = nullptr;
    ret = conti->PackStartCmd(cmd, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    wantParams = std::make_shared<DistributedWantParams>();
    conti->continueInfo_.missionId_ = 0;
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_009_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    int32_t appVersion = 0;
    int32_t ret = conti->ExecuteContinueAbility(appVersion);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0010_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    int32_t ret = conti->GetMissionIdByBundleName();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0011_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    int32_t ret = conti->CheckContinueAbilityPermission();
    EXPECT_EQ(ret, NO_MISSION_INFO_FOR_MISSION_ID);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0012_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    int32_t ret = conti->ExecuteContinueReply();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0013_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    auto data = std::make_shared<ContinueAbilityData>();
    int32_t ret = conti->ExecuteContinueSend(data);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);

    data = nullptr;
    ret = conti->ExecuteContinueSend(data);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0014_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    AAFwk::Want want;
    int32_t ret = conti->SetWantForContinuation(want);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0015_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    OHOS::AAFwk::Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    CallerInfo callerInfo;
    AccountInfo accountInfo;

    int32_t ret = conti->PackDataCmd(cmd, want, abilityInfo, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_OK);

    cmd = nullptr;
    ret = conti->PackDataCmd(cmd, want, abilityInfo, callerInfo, accountInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0016_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    auto cmd = std::make_shared<DSchedContinueDataCmd>();

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true)).WillOnce(Return(true));
    int32_t ret = conti->ExecuteContinueData(cmd);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);

    cmd = nullptr;
    ret = conti->ExecuteContinueData(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0017_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: DSchedContinueTest_0017_2
 * @tc.desc: UpdateElementInfo
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0017_2, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0017_2 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    // no same continueType, diff module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE3;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_SAME_AS_CONTINUE_TYPE, MODULE_NAME2);
    int32_t ret = conti->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, CAN_NOT_FOUND_MODULE_ERR);
    // no continueType, same module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE1;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_SAME_AS_CONTINUE_TYPE, MODULE_NAME1);
    ret = conti->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, ERR_OK);
    // no continueType with quick start, same module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE1_QUICK;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_SAME_AS_CONTINUE_TYPE, MODULE_NAME1);
    ret = conti->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, ERR_OK);
    // has continueType, same module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE2;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_DIFF_AS_CONTINUE_TYPE, MODULE_NAME2);
    ret = conti->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, ERR_OK);
    // has continueType, diff module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE2;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_DIFF_AS_CONTINUE_TYPE, MODULE_NAME1);
    ret = conti->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, ERR_OK);
    // has continueType, no module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE2;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_DIFF_AS_CONTINUE_TYPE, MODULE_NAME3);
    ret = conti->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0017_2 end ret:" << ret << std::endl;
    usleep(WAITTIME);
}

bool DmsBmStorage::GetDistributedBundleInfo(const std::string &networkId, const std::string &bundleName,
    DmsBundleInfo &distributeBundleInfo)
{
    DmsAbilityInfo info2;
    info2.continueType = {CONTINUE_TYPE2};
    info2.moduleName = MODULE_NAME2;
    info2.abilityName = ABILITY_NAME_DIFF_AS_CONTINUE_TYPE;
    distributeBundleInfo.dmsAbilityInfos.push_back(info2);

    DmsAbilityInfo info1;
    info1.continueType = {CONTINUE_TYPE1};
    info1.moduleName = MODULE_NAME1;
    info1.abilityName = ABILITY_NAME_SAME_AS_CONTINUE_TYPE;
    distributeBundleInfo.dmsAbilityInfos.push_back(info1);
    return true;
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
    usleep(WAITTIME);

    int32_t result = ERR_OK;
    int32_t ret = conti->ExecuteNotifyComplete(result);
    EXPECT_NE(ret, ERR_OK);

    direction = CONTINUE_SOURCE;
    ret = conti->ExecuteNotifyComplete(result);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0018_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    auto cmd = std::make_shared<DSchedContinueReplyCmd>();
    int32_t replyCmd = 0;
    int32_t appVersion = 0;
    int32_t result = 0;

    int32_t ret = conti->PackReplyCmd(cmd, replyCmd, appVersion, result, "");
    EXPECT_EQ(ret, ERR_OK);

    cmd = nullptr;
    ret = conti->PackReplyCmd(cmd, replyCmd, appVersion, result, "");
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0019_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    int32_t result = 0;

    int32_t ret = conti->ExecuteContinueEnd(result);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0020_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    int32_t result = 0;
    int32_t ret = conti->ExecuteContinueError(result);
    EXPECT_EQ(ret, ERR_OK);

    direction = CONTINUE_SOURCE;
    ret = conti->ExecuteContinueError(result);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0021_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    auto cmd = std::make_shared<DSchedContinueEndCmd>();
    int32_t result = 0;

    int32_t ret = conti->PackEndCmd(cmd, result);
    EXPECT_EQ(ret, ERR_OK);

    cmd = nullptr;
    ret = conti->PackEndCmd(cmd, result);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0022_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    auto cmd = std::make_shared<DSchedContinueCmdBase>();
    int32_t ret = conti->SendCommand(cmd);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0023_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    std::string localDeviceId;
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    bool ret = conti->GetLocalDeviceId(localDeviceId);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0024_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
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
    usleep(WAITTIME);

    bool ret = conti->CheckDeviceIdFromRemote("", "", "");
    EXPECT_FALSE(ret);

    std::string localDevId = "localDevId";
    std::string destDevId = "destDevId";
    std::string srcDevId = "srcDevId";
    ret = conti->CheckDeviceIdFromRemote(localDevId, destDevId, srcDevId);
    EXPECT_FALSE(ret);

    destDevId = "localDevId";
    srcDevId = "localDevId";
    ret = conti->CheckDeviceIdFromRemote(localDevId, destDevId, srcDevId);
    EXPECT_FALSE(ret);

    conti->continueInfo_.sourceDeviceId_ = "localDevId";
    ret = conti->CheckDeviceIdFromRemote(localDevId, destDevId, srcDevId);
    EXPECT_FALSE(ret);

    srcDevId = "srcDevId";
    conti->continueInfo_.sourceDeviceId_ = "srcDevId";
    ret = conti->CheckDeviceIdFromRemote(localDevId, destDevId, srcDevId);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0025_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: WaitAbilityStateInitialTest_0026_1
 * @tc.desc: WaitAbilityStateInitialTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, WaitAbilityStateInitialTest_0026_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest WaitAbilityStateInitialTest_0026_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    int32_t persistentId = 100;
    bool ret = conti->WaitAbilityStateInitial(persistentId);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DSchedContinueTest WaitAbilityStateInitialTest_0026_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: StartAbilityTest_0027_1
 * @tc.desc: StartAbilityTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, StartAbilityTest_0027_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest StartAbilityTest_0027_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    AAFwk::Want want;
    AppExecFwk::ElementName element("devicdId", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    int32_t ret = conti->StartAbility(want, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest StartAbilityTest_0027_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: QuerySinkAbilityNameTest_0028_1
 * @tc.desc: QuerySinkAbilityNameTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, QuerySinkAbilityNameTest_0028_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest QuerySinkAbilityNameTest_0028_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    std::string continueType = "test";
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, continueType);
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    std::string sinkBundleName = conti->QuerySinkAbilityName();
    EXPECT_TRUE(sinkBundleName.empty());
    DTEST_LOG << "DSchedContinueTest QuerySinkAbilityNameTest_0028_1 end" << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: QuickStartAbilityTest_0029_1
 * @tc.desc: QuickStartAbilityTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, QuickStartAbilityTest_0029_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest QuickStartAbilityTest_0029_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    int32_t ret = conti->QuickStartAbility();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest QuickStartAbilityTest_0029_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: UpdateWantForContinueTypeTest_0030_1
 * @tc.desc: UpdateWantForContinueTypeTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, UpdateWantForContinueTypeTest_0030_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest UpdateWantForContinueTypeTest_0030_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    AAFwk::Want want;
    AppExecFwk::ElementName element("devicdId", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    int32_t ret = conti->UpdateWantForContinueType(want);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest UpdateWantForContinueTypeTest_0030_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: DSchedContinueTest_031_1
 * @tc.desc: DSchedContinue
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_031_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_031_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    AppExecFwk::InnerEvent *event = nullptr;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
        }
    };
    conti->ProcessEvent(AppExecFwk::InnerEvent::Pointer(event, destructor));
    conti->continueInfo_.continueType_ = "";
    conti->CheckQuickStartConfiguration();
    conti->GetSessionId();
    conti->GetAbilityNameByContinueType();
    EXPECT_NE(nullptr, conti->stateMachine_);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_031_1 end" << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: OnDataRecvTest_032_1
 * @tc.desc: OnDataRecv
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, OnDataRecvTest_032_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest OnDataRecvTest_032_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    int32_t command = 0;
    std::shared_ptr<DSchedDataBuffer> dataBuffer = nullptr;
    conti->OnDataRecv(command, dataBuffer);
    EXPECT_EQ(nullptr, dataBuffer);
    command = DSCHED_CONTINUE_CMD_START;
    dataBuffer = std::make_shared<DSchedDataBuffer>(DSCHED_BUFFER_SIZE);
    conti->OnDataRecv(command, dataBuffer);
    EXPECT_NE(nullptr, dataBuffer);
    command = DSCHED_CONTINUE_CMD_DATA;
    conti->OnDataRecv(command, dataBuffer);
    EXPECT_NE(nullptr, dataBuffer);
    command = DSCHED_CONTINUE_CMD_REPLY;
    conti->OnDataRecv(command, dataBuffer);
    EXPECT_NE(nullptr, dataBuffer);
    command = DSCHED_CONTINUE_CMD_END;
    conti->OnDataRecv(command, dataBuffer);
    EXPECT_NE(nullptr, dataBuffer);
    command = DSCHED_CONTINUE_CMD_MIN;
    conti->OnDataRecv(command, dataBuffer);
    EXPECT_NE(nullptr, dataBuffer);
    DTEST_LOG << "DSchedContinueTest OnDataRecvTest_032_1 end" << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: UpdateStateTest_033_1
 * @tc.desc: UpdateState
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, UpdateStateTest_033_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest UpdateStateTest_033_1 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    DSchedContinueStateType stateType = DSCHED_CONTINUE_SINK_START_STATE;
    conti->UpdateState(stateType);
    EXPECT_NE(nullptr, conti->stateMachine_);
    DTEST_LOG << "DSchedContinueTest UpdateStateTest_033_1 end" << std::endl;
}

/**
 * @tc.name: CheckStartPermission_034_1
 * @tc.desc: CheckStartPermission
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, CheckStartPermission_034_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest CheckStartPermission_034_1 begin" << std::endl;
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    ASSERT_NE(nullptr, cmd);
    cmd->srcBundleName_ = BUNDLEMAME_1;
    cmd->dstBundleName_ = BUNDLEMAME_1;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    int32_t ret = conti->CheckStartPermission(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cmd->srcBundleName_.clear();
    ret = conti->CheckStartPermission(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest CheckStartPermission_034_1 end" << std::endl;
}

/**
 * @tc.name: ConvertToDmsSdkErr_035_1
 * @tc.desc: ConvertToDmsSdkErr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ConvertToDmsSdkErr_035_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest ConvertToDmsSdkErr_035_1 begin" << std::endl;
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    ASSERT_NE(nullptr, cmd);
    cmd->srcBundleName_ = BUNDLEMAME_1;
    cmd->dstBundleName_ = BUNDLEMAME_1;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    int32_t ret = conti->ConvertToDmsSdkErr(0);
    EXPECT_EQ(ret, ERR_OK);
    ret = conti->ConvertToDmsSdkErr(SoftBusErrNo::SOFTBUS_CONN_PASSIVE_TYPE_AP_STA_CHIP_CONFLICT);
    EXPECT_EQ(ret,  DmsInterfaceSdkErr::ERR_BIND_REMOTE_HOTSPOT_ENABLE_STATE);
    ret = conti->ConvertToDmsSdkErr(-1);
    EXPECT_EQ(ret, DmsInterfaceSdkErr::ERR_DMS_WORK_ABNORMALLY);
    DTEST_LOG << "DSchedContinueTest ConvertToDmsSdkErr_035_1 end" << std::endl;
}

int32_t ContinueSceneSessionHandler::GetPersistentId(int32_t& persistentId, std::string &continueSessionId)
{
    persistentId = 1;
    return ERR_OK;
}

/**
 * @tc.name: ExecuteQuickStartSuccess_036
 * @tc.desc: ExecuteQuickStartSuccess
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteQuickStartSuccess_036, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartSuccess_036 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    int32_t ret = conti->ExecuteQuickStartSuccess();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartSuccess_036 end ret:" << ret << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: ExecuteQuickStartFailed_037
 * @tc.desc: ExecuteQuickStartFailed
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteQuickStartFailed_037, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartFailed_037 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto conti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    conti->Init();
    usleep(WAITTIME);

    int32_t ret = conti->ExecuteQuickStartFailed(1);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartFailed_037 end ret:" << ret << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: ExecuteQuickStartFailed_037
 * @tc.desc: ExecuteQuickStartFailed
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, OnRemoteDied_038, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueTest OnRemoteDied_038 begin" << std::endl;
    sptr<StateCallbackIpcDiedListener> diedListener = new StateCallbackIpcDiedListener();
    EXPECT_NO_FATAL_FAILURE(diedListener->OnRemoteDied(nullptr));
    DTEST_LOG << "DSchedContinueTest OnRemoteDied_038 end ret:" << std::endl;
    usleep(WAITTIME);
}
}
}
