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
using namespace AAFwk;
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
    clientMock_ = std::make_shared<AbilityManagerClientMock>();
    AbilityManagerClientMock::clientMock = clientMock_;
    DTEST_LOG << "DSchedContinueTest::SetUpTestCase" << std::endl;
    DistributedSchedService::GetInstance().Init();

    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    OHOS::AAFwk::WantParams wantParams;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    conti_ = std::make_shared<DSchedContinue>(subType, direction, callback, info);

    conti_->Init();
    usleep(WAITTIME);
}

void DSchedContinueTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DmsMgrDeviceInfoStore::dmsStore = nullptr;
    dmsStoreMock = nullptr;
    AbilityManagerClientMock::clientMock = nullptr;
    clientMock_ = nullptr;
    DTEST_LOG << "DSchedContinueTest::TearDownTestCase" << std::endl;
    conti_ = nullptr;
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
HWTEST_F(DSchedContinueTest, DSchedContinueTest_001_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_001_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);

    // eventHandler_ not null
    OHOS::AAFwk::WantParams wantParams;
    auto ret = conti_->PostStartTask(wantParams);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_001_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_002_1
 * @tc.desc: OnStartCmd and PostCotinueAbilityTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_002_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_002_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);

    // eventHandler_ not null
    int32_t appVersion = 0;
    auto ret = conti_->PostCotinueAbilityTask(appVersion);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_002_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_003
 * @tc.desc: OnReplyCmd and PostReplyTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_003_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_003_1 begin" << std::endl;
    // eventHandler_ not null
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto cmd = std::make_shared<DSchedContinueReplyCmd>();
    cmd->replyCmd_ = DSCHED_CONTINUE_END_EVENT;
    auto ret = conti_->OnReplyCmd(cmd);
    EXPECT_EQ(ret, ERR_OK);

    ret = conti_->PostReplyTask(cmd);
    EXPECT_EQ(ret, ERR_OK);

    cmd->replyCmd_ = DSCHED_CONTINUE_INVALID_EVENT;
    ret = conti_->PostReplyTask(cmd);
    EXPECT_EQ(ret, ERR_OK);

    cmd = nullptr;
    ret = conti_->PostReplyTask(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_003_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_004_1
 * @tc.desc: OnStartContinuation and PostContinueSendTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_004_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_004_1 begin" << std::endl;
    OHOS::AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t status = ERR_OK;
    uint32_t accessToken = 0;

    // eventHandler_ not null
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);

    auto ret = conti_->OnStartContinuation(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, ERR_OK);

    ret = conti_->PostContinueSendTask(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, ERR_OK);

    status = ERR_NONE;
    ret = conti_->PostContinueSendTask(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_004_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_005
 * @tc.desc: OnContinueDataCmd and PostContinueDataTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_005_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_005_1 begin" << std::endl;
    // eventHandler_ not null
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    auto ret = conti_->OnContinueDataCmd(cmd);
    EXPECT_EQ(ret, ERR_OK);

    ret = conti_->PostContinueDataTask(cmd);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_005_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_006_1
 * @tc.desc: OnNotifyComplete, OnContinueEndCmd and PostNotifyCompleteTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_006_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_006_1 begin" << std::endl;
    // eventHandler_ not null
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto cmd = std::make_shared<DSchedContinueEndCmd>();
    auto ret = conti_->PostNotifyCompleteTask(ERR_OK);
    EXPECT_EQ(ret, ERR_OK);

    cmd = nullptr;
    ret = conti_->OnContinueEndCmd(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_006_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_007_1
 * @tc.desc: OnContinueEnd and PostContinueEndTask
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_007_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_007_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    int32_t result = ERR_OK;
    auto ret = conti_->PostContinueEndTask(result);
    EXPECT_EQ(ret, ERR_OK);

    // result is CONTINUE_SINK_ABILITY_TERMINATED
    result = CONTINUE_SINK_ABILITY_TERMINATED;
    conti_->UpdateState(DSCHED_CONTINUE_SINK_WAIT_END_STATE);
    ret = conti_->OnContinueEnd(result);
    EXPECT_EQ(ret, ERR_OK);
    conti_->UpdateState(DSCHED_CONTINUE_SINK_END_STATE);
    ret = conti_->OnContinueEnd(result);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_007_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_008_1
 * @tc.desc: ExecuteContinueReq
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_008_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_008_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto wantParams = std::make_shared<DistributedWantParams>();
    int32_t ret = conti_->ExecuteContinueReq(wantParams);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_008_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_009_1
 * @tc.desc: PackStartCmd
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_009_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_009_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto cmd = std::make_shared<DSchedContinueStartCmd>();
    auto wantParams = std::make_shared<DistributedWantParams>();
    
    conti_->subServiceType_ = CONTINUE_PUSH;
    int32_t ret = conti_->PackStartCmd(cmd, wantParams);
    EXPECT_EQ(ret, ERR_OK);

    wantParams = nullptr;
    ret = conti_->PackStartCmd(cmd, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    wantParams = std::make_shared<DistributedWantParams>();
    conti_->continueInfo_.missionId_ = 0;
    EXPECT_NE(ret, ERR_OK);
    conti_->subServiceType_ = CONTINUE_PULL;
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_009_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0010_1
 * @tc.desc: ExecuteContinueAbility
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0010_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0010_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    int32_t appVersion = 0;
    int32_t ret = conti_->ExecuteContinueAbility(appVersion);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0010_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0011_1
 * @tc.desc: GetMissionIdByBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0011_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0011_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    int32_t ret = conti_->GetMissionIdByBundleName();
    #ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    EXPECT_EQ(ret, MISSION_NOT_FOCUSED);
    #else
    EXPECT_EQ(ret, ERR_OK);
    #endif
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0011_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0012_1
 * @tc.desc: CheckContinueAbilityPermission
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0012_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0012_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    EXPECT_CALL(*clientMock_, GetMissionInfo(_, _, _)).WillOnce(Return(1));
    int32_t ret = conti_->CheckContinueAbilityPermission();
    EXPECT_EQ(ret, NO_MISSION_INFO_FOR_MISSION_ID);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0012_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0013_1
 * @tc.desc: ExecuteContinueReply
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0013_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0013_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    int32_t ret = conti_->ExecuteContinueReply();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0013_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0014_1
 * @tc.desc: ExecuteContinueSend
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0014_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0014_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto data = std::make_shared<ContinueAbilityData>();
    int32_t ret = conti_->ExecuteContinueSend(data);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);

    data = nullptr;
    ret = conti_->ExecuteContinueSend(data);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0014_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0015_1
 * @tc.desc: SetWantForContinuation
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0015_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0015_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    AAFwk::Want want;
    int32_t ret = conti_->SetWantForContinuation(want);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0015_1 end ret:" << ret << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: DSchedContinueTest_0016_1
 * @tc.desc: PackDataCmd
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0016_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0016_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    OHOS::AAFwk::Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    CallerInfo callerInfo;
    AccountInfo accountInfo;

    int32_t ret = conti_->PackDataCmd(cmd, want, abilityInfo, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_OK);

    cmd = nullptr;
    ret = conti_->PackDataCmd(cmd, want, abilityInfo, callerInfo, accountInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0016_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0017_1
 * @tc.desc: ExecuteContinueData
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0017_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0017_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto cmd = std::make_shared<DSchedContinueDataCmd>();

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true)).WillOnce(Return(true));
    int32_t ret = conti_->ExecuteContinueData(cmd);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);

    cmd = nullptr;
    ret = conti_->ExecuteContinueData(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0017_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0017_2
 * @tc.desc: UpdateElementInfo
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0017_2, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0017_2 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    // no same continueType, diff module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE3;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_SAME_AS_CONTINUE_TYPE, MODULE_NAME2);
    int32_t ret = conti_->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, CAN_NOT_FOUND_MODULE_ERR);
    // no continueType, same module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE1;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_SAME_AS_CONTINUE_TYPE, MODULE_NAME1);
    ret = conti_->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, ERR_OK);
    // no continueType with quick start, same module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE1_QUICK;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_SAME_AS_CONTINUE_TYPE, MODULE_NAME1);
    ret = conti_->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, ERR_OK);
    // has continueType, same module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE2;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_DIFF_AS_CONTINUE_TYPE, MODULE_NAME2);
    ret = conti_->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, ERR_OK);
    // has continueType, diff module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE2;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_DIFF_AS_CONTINUE_TYPE, MODULE_NAME1);
    ret = conti_->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, ERR_OK);
    // has continueType, no module
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    cmd->continueType_ = CONTINUE_TYPE2;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_DIFF_AS_CONTINUE_TYPE, MODULE_NAME3);
    ret = conti_->UpdateElementInfo(cmd);
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
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0018_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0018_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);

    int32_t result = ERR_OK;
    int32_t ret = conti_->ExecuteNotifyComplete(result);
    EXPECT_NE(ret, ERR_OK);

    conti_->direction_ = CONTINUE_SOURCE;
    ret = conti_->ExecuteNotifyComplete(result);
    EXPECT_NE(ret, ERR_OK);
    conti_->direction_ = CONTINUE_SINK;
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0018_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0019_1
 * @tc.desc: PackReplyCmd
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0019_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0019_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto cmd = std::make_shared<DSchedContinueReplyCmd>();
    int32_t replyCmd = 0;
    int32_t appVersion = 0;
    int32_t result = 0;

    int32_t ret = conti_->PackReplyCmd(cmd, replyCmd, appVersion, result, "");
    EXPECT_EQ(ret, ERR_OK);

    cmd = nullptr;
    ret = conti_->PackReplyCmd(cmd, replyCmd, appVersion, result, "");
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0019_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0020_1
 * @tc.desc: ExecuteContinueEnd
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0020_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0020_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    int32_t result = 0;

    int32_t ret = conti_->ExecuteContinueEnd(result);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0020_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0021_1
 * @tc.desc: ExecuteContinueError
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0021_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0021_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    int32_t result = 0;
    int32_t ret = conti_->ExecuteContinueError(result);
    EXPECT_EQ(ret, ERR_OK);
    
    conti_->direction_ = CONTINUE_SOURCE;
    ret = conti_->ExecuteContinueError(result);
    EXPECT_EQ(ret, ERR_OK);
    conti_->direction_ = CONTINUE_SINK;
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0021_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0022_1
 * @tc.desc: PackEndCmd
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0022_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0022_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto cmd = std::make_shared<DSchedContinueEndCmd>();
    int32_t result = 0;

    int32_t ret = conti_->PackEndCmd(cmd, result);
    EXPECT_EQ(ret, ERR_OK);

    cmd = nullptr;
    ret = conti_->PackEndCmd(cmd, result);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0022_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0023_1
 * @tc.desc: SendCommand
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0023_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0023_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    auto cmd = std::make_shared<DSchedContinueCmdBase>();
    int32_t ret = conti_->SendCommand(cmd);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0023_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0024_1
 * @tc.desc: GetLocalDeviceId
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0024_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0024_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    std::string localDeviceId;
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    bool ret = conti_->GetLocalDeviceId(localDeviceId);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0024_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_0025_1
 * @tc.desc: CheckDeviceIdFromRemote
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_0025_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0025_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    bool ret = conti_->CheckDeviceIdFromRemote("", "", "");
    EXPECT_FALSE(ret);

    std::string localDevId = "localDevId";
    std::string destDevId = "destDevId";
    std::string srcDevId = "srcDevId";
    ret = conti_->CheckDeviceIdFromRemote(localDevId, destDevId, srcDevId);
    EXPECT_FALSE(ret);

    destDevId = "localDevId";
    srcDevId = "localDevId";
    ret = conti_->CheckDeviceIdFromRemote(localDevId, destDevId, srcDevId);
    EXPECT_FALSE(ret);

    conti_->continueInfo_.sourceDeviceId_ = "localDevId";
    ret = conti_->CheckDeviceIdFromRemote(localDevId, destDevId, srcDevId);
    EXPECT_FALSE(ret);

    srcDevId = "srcDevId";
    conti_->continueInfo_.sourceDeviceId_ = "srcDevId";
    ret = conti_->CheckDeviceIdFromRemote(localDevId, destDevId, srcDevId);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_0025_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: WaitAbilityStateInitialTest_0026_1
 * @tc.desc: WaitAbilityStateInitialTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, WaitAbilityStateInitialTest_0026_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest WaitAbilityStateInitialTest_0026_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    int32_t persistentId = 100;
    EXPECT_CALL(*clientMock_, GetAbilityStateByPersistentId(_, _)).WillRepeatedly(Return(0));
    bool ret = conti_->WaitAbilityStateInitial(persistentId);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DSchedContinueTest WaitAbilityStateInitialTest_0026_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: StartAbilityTest_0027_1
 * @tc.desc: StartAbilityTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, StartAbilityTest_0027_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest StartAbilityTest_0027_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    AAFwk::Want want;
    AppExecFwk::ElementName element("devicdId", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    EXPECT_CALL(*clientMock_, Connect()).WillOnce(Return(0));
    EXPECT_CALL(*clientMock_, StartAbility(_, An<int>(), _, _)).WillOnce(Return(1));
    int32_t ret = conti_->StartAbility(want, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest StartAbilityTest_0027_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: QuerySinkAbilityNameTest_0028_1
 * @tc.desc: QuerySinkAbilityNameTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, QuerySinkAbilityNameTest_0028_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest QuerySinkAbilityNameTest_0028_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    std::string sinkBundleName = conti_->QuerySinkAbilityName();
    EXPECT_TRUE(sinkBundleName.empty());
    DTEST_LOG << "DSchedContinueTest QuerySinkAbilityNameTest_0028_1 end" << std::endl;
}

/**
 * @tc.name: QuickStartAbilityTest_0029_1
 * @tc.desc: QuickStartAbilityTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, QuickStartAbilityTest_0029_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest QuickStartAbilityTest_0029_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    int32_t ret = conti_->QuickStartAbility();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest QuickStartAbilityTest_0029_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UpdateWantForContinueTypeTest_0030_1
 * @tc.desc: UpdateWantForContinueTypeTest
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, UpdateWantForContinueTypeTest_0030_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest UpdateWantForContinueTypeTest_0030_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    AAFwk::Want want;
    AppExecFwk::ElementName element("devicdId", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    int32_t ret = conti_->UpdateWantForContinueType(want);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest UpdateWantForContinueTypeTest_0030_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueTest_031_1
 * @tc.desc: DSchedContinue
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueTest_031_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_031_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    AppExecFwk::InnerEvent *event = nullptr;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    conti_->ProcessEvent(AppExecFwk::InnerEvent::Pointer(event, destructor));
    conti_->continueInfo_.continueType_ = "";
    conti_->CheckQuickStartConfiguration();
    conti_->GetSessionId();
    conti_->GetAbilityNameByContinueType();
    EXPECT_NE(nullptr, conti_->stateMachine_);
    DTEST_LOG << "DSchedContinueTest DSchedContinueTest_031_1 end" << std::endl;
}

/**
 * @tc.name: OnDataRecvTest_032_1
 * @tc.desc: OnDataRecv
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, OnDataRecvTest_032_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest OnDataRecvTest_032_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    int32_t command = 0;
    std::shared_ptr<DSchedDataBuffer> dataBuffer = nullptr;
    conti_->OnDataRecv(command, dataBuffer);
    EXPECT_EQ(nullptr, dataBuffer);
    command = DSCHED_CONTINUE_CMD_START;
    dataBuffer = std::make_shared<DSchedDataBuffer>(DSCHED_BUFFER_SIZE);
    conti_->OnDataRecv(command, dataBuffer);
    EXPECT_NE(nullptr, dataBuffer);
    command = DSCHED_CONTINUE_CMD_DATA;
    conti_->OnDataRecv(command, dataBuffer);
    EXPECT_NE(nullptr, dataBuffer);
    command = DSCHED_CONTINUE_CMD_REPLY;
    conti_->OnDataRecv(command, dataBuffer);
    EXPECT_NE(nullptr, dataBuffer);
    command = DSCHED_CONTINUE_CMD_END;
    conti_->OnDataRecv(command, dataBuffer);
    EXPECT_NE(nullptr, dataBuffer);
    command = DSCHED_CONTINUE_CMD_MIN;
    conti_->OnDataRecv(command, dataBuffer);
    EXPECT_NE(nullptr, dataBuffer);
    DTEST_LOG << "DSchedContinueTest OnDataRecvTest_032_1 end" << std::endl;
}

/**
 * @tc.name: UpdateStateTest_033_1
 * @tc.desc: UpdateState
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, UpdateStateTest_033_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest UpdateStateTest_033_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    DSchedContinueStateType stateType = DSCHED_CONTINUE_SINK_START_STATE;
    conti_->UpdateState(stateType);
    EXPECT_NE(nullptr, conti_->stateMachine_);
    DTEST_LOG << "DSchedContinueTest UpdateStateTest_033_1 end" << std::endl;
}

/**
 * @tc.name: CheckStartPermission_034_1
 * @tc.desc: CheckStartPermission
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, CheckStartPermission_034_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest CheckStartPermission_034_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);

    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    ASSERT_NE(nullptr, cmd);
    cmd->srcBundleName_ = BUNDLEMAME_1;
    cmd->dstBundleName_ = BUNDLEMAME_1;

    int32_t ret = conti_->CheckStartPermission(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cmd->srcBundleName_.clear();
    ret = conti_->CheckStartPermission(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest CheckStartPermission_034_1 end" << std::endl;
}

/**
 * @tc.name: ConvertToDmsSdkErr_035_1
 * @tc.desc: ConvertToDmsSdkErr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ConvertToDmsSdkErr_035_1, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ConvertToDmsSdkErr_035_1 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);

    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    ASSERT_NE(nullptr, cmd);
    cmd->srcBundleName_ = BUNDLEMAME_1;
    cmd->dstBundleName_ = BUNDLEMAME_1;

    int32_t ret = conti_->ConvertToDmsSdkErr(0);
    EXPECT_EQ(ret, ERR_OK);
    ret = conti_->ConvertToDmsSdkErr(SoftBusErrNo::SOFTBUS_CONN_PASSIVE_TYPE_AP_STA_CHIP_CONFLICT);
    EXPECT_EQ(ret,  DmsInterfaceSdkErr::ERR_BIND_REMOTE_HOTSPOT_ENABLE_STATE);
    ret = conti_->ConvertToDmsSdkErr(-1);
    EXPECT_EQ(ret, DmsInterfaceSdkErr::ERR_DMS_WORK_ABNORMALLY);
    DTEST_LOG << "DSchedContinueTest ConvertToDmsSdkErr_035_1 end" << std::endl;
}

int32_t ContinueSceneSessionHandler::GetPersistentId(int32_t& persistentId, std::string &ContinueSessionId)
{
    persistentId = 1;
    return ERR_OK;
}

/**
 * @tc.name: ExecuteQuickStartSuccess_036
 * @tc.desc: ExecuteQuickStartSuccess
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteQuickStartSuccess_036, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartSuccess_036 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);

    int32_t ret = conti_->ExecuteQuickStartSuccess();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartSuccess_036 end ret:" << ret << std::endl;
}

/**
 * @tc.name: ExecuteQuickStartFailed_037
 * @tc.desc: ExecuteQuickStartFailed
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteQuickStartFailed_037, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartFailed_037 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);

    int32_t ret = conti_->ExecuteQuickStartFailed(1);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartFailed_037 end ret:" << ret << std::endl;
}

/**
 * @tc.name: OnRemoteDied_038
 * @tc.desc: ExecuteQuickStartFailed
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, OnRemoteDied_038, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest OnRemoteDied_038 begin" << std::endl;
    sptr<StateCallbackIpcDiedListener> diedListener = new StateCallbackIpcDiedListener();
    EXPECT_NO_FATAL_FAILURE(diedListener->OnRemoteDied(nullptr));
    DTEST_LOG << "DSchedContinueTest OnRemoteDied_038 end ret:" << std::endl;
    usleep(WAITTIME);
}

/**
 * @tc.name: DSchedContinueConstructor_039
 * @tc.desc: DSchedContinue constructor with startCmd nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueConstructor_039, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueConstructor_039 begin" << std::endl;
    std::shared_ptr<DSchedContinueStartCmd> startCmd = nullptr;
    int32_t sessionId = 1;
    int32_t accountId = 100;
    auto continueWithNullCmd = std::make_shared<DSchedContinue>(startCmd, sessionId, accountId);
    EXPECT_NE(continueWithNullCmd, nullptr);
    DTEST_LOG << "DSchedContinueTest DSchedContinueConstructor_039 end" << std::endl;
}

/**
 * @tc.name: DSchedContinueConstructor_040
 * @tc.desc: DSchedContinue constructor with missionId != 0 and empty bundleNames
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DSchedContinueConstructor_040, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DSchedContinueConstructor_040 begin" << std::endl;
    auto startCmd = std::make_shared<DSchedContinueStartCmd>();
    startCmd->subServiceType_ = CONTINUE_PULL;
    startCmd->direction_ = CONTINUE_SOURCE;
    startCmd->srcDeviceId_ = "srcDeviceId";
    startCmd->srcBundleName_ = "";
    startCmd->dstDeviceId_ = "dstDeviceId";
    startCmd->dstBundleName_ = "";
    startCmd->continueType_ = "";
    startCmd->sourceMissionId_ = 100;
    startCmd->continueByType_ = false;
    int32_t sessionId = 1;
    int32_t accountId = 100;

    EXPECT_CALL(*clientMock_, GetMissionInfo(_, _, _)).WillOnce(Return(ERR_OK));
    auto continueWithMission = std::make_shared<DSchedContinue>(startCmd, sessionId, accountId);
    EXPECT_NE(continueWithMission, nullptr);
    DTEST_LOG << "DSchedContinueTest DSchedContinueConstructor_040 end" << std::endl;
}

/**
 * @tc.name: Init_041
 * @tc.desc: Init when eventHandler_ is already initialized
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, Init_041, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest Init_041 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    // eventHandler_ already initialized, should return ERR_OK immediately
    int32_t ret = conti_->Init();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest Init_041 end" << std::endl;
}

/**
 * @tc.name: CheckQuickStartConfiguration_042
 * @tc.desc: CheckQuickStartConfiguration with suffix longer than continueType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, CheckQuickStartConfiguration_042, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest CheckQuickStartConfiguration_042 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->continueInfo_.continueType_ = "short";
    bool ret = conti_->CheckQuickStartConfiguration();
    EXPECT_FALSE(ret);
    DTEST_LOG << "DSchedContinueTest CheckQuickStartConfiguration_042 end" << std::endl;
}

/**
 * @tc.name: CheckQuickStartConfiguration_043
 * @tc.desc: CheckQuickStartConfiguration with valid suffix
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, CheckQuickStartConfiguration_043, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest CheckQuickStartConfiguration_043 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->continueInfo_.continueType_ = "type_ContinueQuickStart";
    bool ret = conti_->CheckQuickStartConfiguration();
    EXPECT_TRUE(ret);
    DTEST_LOG << "DSchedContinueTest CheckQuickStartConfiguration_043 end" << std::endl;
}

/**
 * @tc.name: ContinueTypeFormat_044
 * @tc.desc: ContinueTypeFormat with valid suffix
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ContinueTypeFormat_044, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ContinueTypeFormat_044 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    std::string continueType = "type_ContinueQuickStart";
    conti_->ContinueTypeFormat(continueType);
    EXPECT_EQ(continueType, "type");
    DTEST_LOG << "DSchedContinueTest ContinueTypeFormat_044 end" << std::endl;
}

/**
 * @tc.name: ContinueTypeFormat_045
 * @tc.desc: ContinueTypeFormat with suffix longer than continueType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ContinueTypeFormat_045, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ContinueTypeFormat_045 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    std::string continueType = "short";
    conti_->ContinueTypeFormat(continueType);
    EXPECT_EQ(continueType, "short");
    DTEST_LOG << "DSchedContinueTest ContinueTypeFormat_045 end" << std::endl;
}

/**
 * @tc.name: CheckContinueAbilityPermission_046
 * @tc.desc: CheckContinueAbilityPermission with mission continue state INACTIVE
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, CheckContinueAbilityPermission_046, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest CheckContinueAbilityPermission_046 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->continueInfo_.missionId_ = 100;
    EXPECT_CALL(*clientMock_, GetMissionInfo(_, _, _)).WillOnce(
        [](const std::string&, int32_t, MissionInfo& missionInfo) {
            missionInfo.continueState = AAFwk::ContinueState::CONTINUESTATE_INACTIVE;
            return ERR_OK;
        });
    int32_t ret = conti_->CheckContinueAbilityPermission();
    EXPECT_EQ(ret, MISSION_NOT_CONTINUE_ACTIVE);
    DTEST_LOG << "DSchedContinueTest CheckContinueAbilityPermission_046 end" << std::endl;
}

/**
 * @tc.name: OnNotifyComplete_047
 * @tc.desc: OnNotifyComplete with isSuccess false
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, OnNotifyComplete_047, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest OnNotifyComplete_047 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    int32_t missionId = 100;
    bool isSuccess = false;
    int32_t ret = conti_->OnNotifyComplete(missionId, isSuccess);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest OnNotifyComplete_047 end" << std::endl;
}

/**
 * @tc.name: OnNotifyComplete_048
 * @tc.desc: OnNotifyComplete with missionId <= 0
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, OnNotifyComplete_048, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest OnNotifyComplete_048 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    int32_t missionId = 0;
    bool isSuccess = true;
    int32_t ret = conti_->OnNotifyComplete(missionId, isSuccess);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest OnNotifyComplete_048 end" << std::endl;
}

/**
 * @tc.name: WaitAbilityStateInitial_049
 * @tc.desc: WaitAbilityStateInitial with success state
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, WaitAbilityStateInitial_049, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest WaitAbilityStateInitial_049 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    int32_t persistentId = 100;
    EXPECT_CALL(*clientMock_, GetAbilityStateByPersistentId(_, _)).WillOnce(
        [](int32_t, bool& state) {
            state = true;
            return ERR_OK;
        });
    bool ret = conti_->WaitAbilityStateInitial(persistentId);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DSchedContinueTest WaitAbilityStateInitial_049 end" << std::endl;
}

/**
 * @tc.name: StartAbility_050
 * @tc.desc: StartAbility with Connect failed
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, StartAbility_050, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest StartAbility_050 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    AAFwk::Want want;
    AppExecFwk::ElementName element("devicdId", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    EXPECT_CALL(*clientMock_, Connect()).WillOnce(Return(-1));
    int32_t ret = conti_->StartAbility(want, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest StartAbility_050 end" << std::endl;
}

/**
 * @tc.name: ExecuteNotifyComplete_051
 * @tc.desc: ExecuteNotifyComplete with CONTINUE_SOURCE direction and result ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteNotifyComplete_051, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ExecuteNotifyComplete_051 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    ASSERT_NE(conti_->eventHandler_, nullptr);
    conti_->direction_ = CONTINUE_SOURCE;
    conti_->UpdateState(DSCHED_CONTINUE_SOURCE_WAIT_END_STATE);
    int32_t result = ERR_OK;
    int32_t ret = conti_->ExecuteNotifyComplete(result);
    EXPECT_NE(ret, ERR_OK);
    conti_->direction_ = CONTINUE_SINK;
    DTEST_LOG << "DSchedContinueTest ExecuteNotifyComplete_051 end" << std::endl;
}

/**
 * @tc.name: ExecuteContinueEnd_052
 * @tc.desc: ExecuteContinueEnd with result ERR_OK and isSourceExit true
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteContinueEnd_052, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ExecuteContinueEnd_052 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->isSourceExit_ = true;
    conti_->direction_ = CONTINUE_SOURCE;
    conti_->subServiceType_ = CONTINUE_PUSH;
    conti_->continueInfo_.missionId_ = 100;
    EXPECT_CALL(*clientMock_, CleanMission(_)).WillOnce(Return(ERR_OK));
    int32_t ret = conti_->ExecuteContinueEnd(ERR_OK);
    EXPECT_EQ(ret, ERR_OK);
    conti_->isSourceExit_ = false;
    conti_->direction_ = CONTINUE_SINK;
    conti_->subServiceType_ = CONTINUE_PULL;
    DTEST_LOG << "DSchedContinueTest ExecuteContinueEnd_052 end" << std::endl;
}

/**
 * @tc.name: ExecuteContinueEnd_053
 * @tc.desc: ExecuteContinueEnd with result != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteContinueEnd_053, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ExecuteContinueEnd_053 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    int32_t ret = conti_->ExecuteContinueEnd(-1);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest ExecuteContinueEnd_053 end" << std::endl;
}

/**
 * @tc.name: NotifyContinuationCallbackResult_054
 * @tc.desc: NotifyContinuationCallbackResult with callback nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, NotifyContinuationCallbackResult_054, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest NotifyContinuationCallbackResult_054 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->callback_ = nullptr;
    conti_->NotifyContinuationCallbackResult(ERR_OK);
    EXPECT_EQ(conti_->callback_, nullptr);
    DTEST_LOG << "DSchedContinueTest NotifyContinuationCallbackResult_054 end" << std::endl;
}

/**
 * @tc.name: DurationDumperComplete_055
 * @tc.desc: DurationDumperComplete with result != ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DurationDumperComplete_055, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DurationDumperComplete_055 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->DurationDumperComplete(-1);
    DTEST_LOG << "DSchedContinueTest DurationDumperComplete_055 end" << std::endl;
}

/**
 * @tc.name: ExecuteQuickStartSuccess_056
 * @tc.desc: ExecuteQuickStartSuccess with sinkMissionId != 0
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteQuickStartSuccess_056, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartSuccess_056 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->continueInfo_.sinkMissionId_ = 100;
    int32_t ret = conti_->ExecuteQuickStartSuccess();
    EXPECT_EQ(ret, ERR_OK);
    conti_->continueInfo_.sinkMissionId_ = 0;
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartSuccess_056 end" << std::endl;
}

/**
 * @tc.name: ExecuteQuickStartFailed_057
 * @tc.desc: ExecuteQuickStartFailed with sinkMissionId != 0
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteQuickStartFailed_057, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartFailed_057 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->continueInfo_.sinkMissionId_ = 100;
    int32_t ret = conti_->ExecuteQuickStartFailed(1);
    EXPECT_EQ(ret, ERR_OK);
    conti_->continueInfo_.sinkMissionId_ = 0;
    DTEST_LOG << "DSchedContinueTest ExecuteQuickStartFailed_057 end" << std::endl;
}

/**
 * @tc.name: UpdateState_058
 * @tc.desc: UpdateState with stateMachine nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, UpdateState_058, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest UpdateState_058 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    auto originalStateMachine = conti_->stateMachine_;
    conti_->stateMachine_ = nullptr;
    DSchedContinueStateType stateType = DSCHED_CONTINUE_SINK_START_STATE;
    conti_->UpdateState(stateType);
    EXPECT_EQ(conti_->stateMachine_, nullptr);
    conti_->stateMachine_ = originalStateMachine;
    DTEST_LOG << "DSchedContinueTest UpdateState_058 end" << std::endl;
}

/**
 * @tc.name: ProcessEvent_059
 * @tc.desc: ProcessEvent with event nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ProcessEvent_059, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ProcessEvent_059 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    AppExecFwk::InnerEvent *event = nullptr;
    auto destructor = [](AppExecFwk::InnerEvent *event) {
        if (event != nullptr) {
            delete event;
            event = nullptr;
        }
    };
    conti_->ProcessEvent(AppExecFwk::InnerEvent::Pointer(event, destructor));
    DTEST_LOG << "DSchedContinueTest ProcessEvent_059 end" << std::endl;
}

/**
 * @tc.name: ProcessEvent_060
 * @tc.desc: ProcessEvent with stateMachine nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ProcessEvent_060, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ProcessEvent_060 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    auto originalStateMachine = conti_->stateMachine_;
    conti_->stateMachine_ = nullptr;
    auto event = AppExecFwk::InnerEvent::Get(0, 0);
    conti_->ProcessEvent(event);
    EXPECT_EQ(conti_->stateMachine_, nullptr);
    conti_->stateMachine_ = originalStateMachine;
    DTEST_LOG << "DSchedContinueTest ProcessEvent_060 end" << std::endl;
}

/**
 * @tc.name: SendCommand_061
 * @tc.desc: SendCommand with cmd nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, SendCommand_061, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest SendCommand_061 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    std::shared_ptr<DSchedContinueCmdBase> cmd = nullptr;
    int32_t ret = conti_->SendCommand(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest SendCommand_061 end" << std::endl;
}

/**
 * @tc.name: GetLocalDeviceId_062
 * @tc.desc: GetLocalDeviceId with GetLocalDeviceId failed
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, GetLocalDeviceId_062, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest GetLocalDeviceId_062 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    std::string localDeviceId;
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(false));
    bool ret = conti_->GetLocalDeviceId(localDeviceId);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DSchedContinueTest GetLocalDeviceId_062 end" << std::endl;
}

/**
 * @tc.name: PostStartTask_063
 * @tc.desc: PostStartTask with eventHandler nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, PostStartTask_063, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest PostStartTask_063 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    OHOS::AAFwk::WantParams wantParams;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto newConti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    // Don't call Init(), so eventHandler_ stays nullptr
    newConti->eventHandler_ = nullptr;
    OHOS::AAFwk::WantParams params;
    int32_t ret = newConti->PostStartTask(params);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest PostStartTask_063 end" << std::endl;
}

/**
 * @tc.name: PostCotinueAbilityTask_064
 * @tc.desc: PostCotinueAbilityTask with eventHandler nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, PostCotinueAbilityTask_064, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest PostCotinueAbilityTask_064 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    OHOS::AAFwk::WantParams wantParams;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto newConti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    newConti->eventHandler_ = nullptr;
    int32_t appVersion = 0;
    int32_t ret = newConti->PostCotinueAbilityTask(appVersion);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest PostCotinueAbilityTask_064 end" << std::endl;
}

/**
 * @tc.name: PostContinueDataTask_065
 * @tc.desc: PostContinueDataTask with eventHandler nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, PostContinueDataTask_065, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest PostContinueDataTask_065 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    OHOS::AAFwk::WantParams wantParams;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto newConti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    newConti->eventHandler_ = nullptr;
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    int32_t ret = newConti->PostContinueDataTask(cmd);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest PostContinueDataTask_065 end" << std::endl;
}

/**
 * @tc.name: PostNotifyCompleteTask_066
 * @tc.desc: PostNotifyCompleteTask with eventHandler nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, PostNotifyCompleteTask_066, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest PostNotifyCompleteTask_066 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    OHOS::AAFwk::WantParams wantParams;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto newConti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    newConti->eventHandler_ = nullptr;
    int32_t ret = newConti->PostNotifyCompleteTask(ERR_OK);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest PostNotifyCompleteTask_066 end" << std::endl;
}

/**
 * @tc.name: PostContinueEndTask_067
 * @tc.desc: PostContinueEndTask with eventHandler nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, PostContinueEndTask_067, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest PostContinueEndTask_067 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    OHOS::AAFwk::WantParams wantParams;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto newConti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    newConti->eventHandler_ = nullptr;
    int32_t ret = newConti->PostContinueEndTask(ERR_OK);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest PostContinueEndTask_067 end" << std::endl;
}

/**
 * @tc.name: PostContinueSendTask_068
 * @tc.desc: PostContinueSendTask with eventHandler nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, PostContinueSendTask_068, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest PostContinueSendTask_068 begin" << std::endl;
    std::string deviceId = "123";
    std::string bundleName = "test";
    int32_t subType = CONTINUE_PULL;
    int32_t direction = CONTINUE_SINK;
    sptr<IRemoteObject> callback = nullptr;
    OHOS::AAFwk::WantParams wantParams;
    auto info = DSchedContinueInfo(deviceId, bundleName, deviceId, bundleName, "");
    auto newConti = std::make_shared<DSchedContinue>(subType, direction, callback, info);
    newConti->eventHandler_ = nullptr;
    OHOS::AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t status = ERR_OK;
    uint32_t accessToken = 0;
    int32_t ret = newConti->PostContinueSendTask(want, callerUid, status, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest PostContinueSendTask_068 end" << std::endl;
}

/**
 * @tc.name: PackStartCmd_069
 * @tc.desc: PackStartCmd with cmd nullptr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, PackStartCmd_069, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest PackStartCmd_069 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    std::shared_ptr<DSchedContinueStartCmd> cmd = nullptr;
    auto wantParams = std::make_shared<DistributedWantParams>();
    int32_t ret = conti_->PackStartCmd(cmd, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest PackStartCmd_069 end" << std::endl;
}

/**
 * @tc.name: FindSinkContinueAbilityInfo_070
 * @tc.desc: FindSinkContinueAbilityInfo with continueTypeElement != srcContinueType
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, FindSinkContinueAbilityInfo_070, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest FindSinkContinueAbilityInfo_070 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    std::vector<DmsAbilityInfo> dmsAbilityInfos;
    DmsAbilityInfo info1;
    info1.continueType = {"differentType"};
    info1.moduleName = MODULE_NAME1;
    info1.abilityName = ABILITY_NAME_SAME_AS_CONTINUE_TYPE;
    dmsAbilityInfos.push_back(info1);

    std::vector<DmsAbilityInfo> result;
    conti_->FindSinkContinueAbilityInfo(MODULE_NAME1, CONTINUE_TYPE1, dmsAbilityInfos, result);
    EXPECT_TRUE(result.empty());
    DTEST_LOG << "DSchedContinueTest FindSinkContinueAbilityInfo_070 end" << std::endl;
}

/**
 * @tc.name: FindSinkContinueAbilityInfo_071
 * @tc.desc: FindSinkContinueAbilityInfo with sameModuleGot true
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, FindSinkContinueAbilityInfo_071, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest FindSinkContinueAbilityInfo_071 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    std::vector<DmsAbilityInfo> dmsAbilityInfos;
    DmsAbilityInfo info1;
    info1.continueType = {CONTINUE_TYPE1};
    info1.moduleName = MODULE_NAME1;
    info1.abilityName = ABILITY_NAME_SAME_AS_CONTINUE_TYPE;
    dmsAbilityInfos.push_back(info1);

    std::vector<DmsAbilityInfo> result;
    conti_->FindSinkContinueAbilityInfo(MODULE_NAME1, CONTINUE_TYPE1, dmsAbilityInfos, result);
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0].moduleName, MODULE_NAME1);
    DTEST_LOG << "DSchedContinueTest FindSinkContinueAbilityInfo_071 end" << std::endl;
}

/**
 * @tc.name: FindSinkContinueAbilityInfo_072
 * @tc.desc: FindSinkContinueAbilityInfo with srcModuleName != abilityInfoElement.moduleName
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, FindSinkContinueAbilityInfo_072, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest FindSinkContinueAbilityInfo_072 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    std::vector<DmsAbilityInfo> dmsAbilityInfos;
    DmsAbilityInfo info1;
    info1.continueType = {CONTINUE_TYPE1};
    info1.moduleName = MODULE_NAME2;
    info1.abilityName = ABILITY_NAME_SAME_AS_CONTINUE_TYPE;
    dmsAbilityInfos.push_back(info1);

    std::vector<DmsAbilityInfo> result;
    conti_->FindSinkContinueAbilityInfo(MODULE_NAME1, CONTINUE_TYPE1, dmsAbilityInfos, result);
    EXPECT_EQ(result.size(), 1);
    EXPECT_EQ(result[0].moduleName, MODULE_NAME2);
    DTEST_LOG << "DSchedContinueTest FindSinkContinueAbilityInfo_072 end" << std::endl;
}

/**
 * @tc.name: UpdateWantForContinueType_073
 * @tc.desc: UpdateWantForContinueType with sinkAbilityName != srcAbilityName
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, UpdateWantForContinueType_073, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest UpdateWantForContinueType_073 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    AAFwk::Want want;
    AppExecFwk::ElementName element("devicdId", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    conti_->continueInfo_.continueType_ = CONTINUE_TYPE1;
    int32_t ret = conti_->UpdateWantForContinueType(want);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest UpdateWantForContinueType_073 end" << std::endl;
}

/**
 * @tc.name: ExecuteContinueAbility_074
 * @tc.desc: ExecuteContinueAbility with ContinueAbility failed
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteContinueAbility_074, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ExecuteContinueAbility_074 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->continueInfo_.missionId_ = 100;
    EXPECT_CALL(*clientMock_, GetMissionInfo(_, _, _)).WillOnce(
        [](const std::string&, int32_t, MissionInfo& missionInfo) {
            missionInfo.continueState = AAFwk::ContinueState::CONTINUESTATE_ACTIVE;
            return ERR_OK;
        });
    EXPECT_CALL(*clientMock_, ContinueAbility(_, _, _)).WillOnce(Return(-1));
    int32_t appVersion = 0;
    int32_t ret = conti_->ExecuteContinueAbility(appVersion);
    EXPECT_EQ(ret, CONTINUE_CALL_CONTINUE_ABILITY_FAILED);
    DTEST_LOG << "DSchedContinueTest ExecuteContinueAbility_074 end" << std::endl;
}

/**
 * @tc.name: SetCleanMissionFlag_076
 * @tc.desc: SetCleanMissionFlag with SUPPORT_CONTINUE_SOURCE_EXIT_KEY true
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, SetCleanMissionFlag_076, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest SetCleanMissionFlag_076 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    AAFwk::Want want;
    want.SetParam("ohos.extra.param.key.supportContinueSourceExit", true);
    conti_->SetCleanMissionFlag(want);
    EXPECT_TRUE(conti_->isSourceExit_);
    conti_->isSourceExit_ = false;
    DTEST_LOG << "DSchedContinueTest SetCleanMissionFlag_076 end" << std::endl;
}

/**
 * @tc.name: SetWantForContinuation_077
 * @tc.desc: SetWantForContinuation with isPageStackContinue false and moduleName set
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, SetWantForContinuation_077, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest SetWantForContinuation_077 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    AAFwk::Want want;
    want.SetElementName("deviceId", "bundleName", "abilityName");
    want.SetParam("ohos.extra.param.key.supportContinuePageStack", false);
    conti_->SetWantForContinuation(want);
    DTEST_LOG << "DSchedContinueTest SetWantForContinuation_077 end" << std::endl;
}

/**
 * @tc.name: OnShutDown_078
 * @tc.desc: OnShutDown
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, OnShutDown_078, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest OnShutDown_078 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->OnShutDown();
    DTEST_LOG << "DSchedContinueTest OnShutDown_078 end" << std::endl;
}

/**
 * @tc.name: OnBind_079
 * @tc.desc: OnBind
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, OnBind_079, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest OnBind_079 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->OnBind();
    DTEST_LOG << "DSchedContinueTest OnBind_079 end" << std::endl;
}

/**
 * @tc.name: DurationDumperStart_080
 * @tc.desc: DurationDumperStart
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DurationDumperStart_080, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DurationDumperStart_080 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->subServiceType_ = CONTINUE_PULL;
    conti_->DurationDumperStart();
    conti_->subServiceType_ = CONTINUE_PUSH;
    DTEST_LOG << "DSchedContinueTest DurationDumperStart_080 end" << std::endl;
}

/**
 * @tc.name: DurationDumperBeforeStartRemoteAbility_081
 * @tc.desc: DurationDumperBeforeStartRemoteAbility
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, DurationDumperBeforeStartRemoteAbility_081, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest DurationDumperBeforeStartRemoteAbility_081 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    conti_->DurationDumperBeforeStartRemoteAbility();
    DTEST_LOG << "DSchedContinueTest DurationDumperBeforeStartRemoteAbility_081 end" << std::endl;
}

/**
 * @tc.name: GetContinueInfo_082
 * @tc.desc: GetContinueInfo
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, GetContinueInfo_082, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest GetContinueInfo_082 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    DSchedContinueInfo info = conti_->GetContinueInfo();
    EXPECT_NE(info.sourceDeviceId_, "");
    DTEST_LOG << "DSchedContinueTest GetContinueInfo_082 end" << std::endl;
}

/**
 * @tc.name: UpdateElementInfo_083
 * @tc.desc: UpdateElementInfo with srcModuleName empty
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, UpdateElementInfo_083, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest UpdateElementInfo_083 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    cmd->continueType_ = CONTINUE_TYPE1;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_SAME_AS_CONTINUE_TYPE);
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    int32_t ret = conti_->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest UpdateElementInfo_083 end" << std::endl;
}

/**
 * @tc.name: UpdateElementInfo_084
 * @tc.desc: UpdateElementInfo with GetLocalDeviceId failed
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, UpdateElementInfo_084, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest UpdateElementInfo_084 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    cmd->continueType_ = CONTINUE_TYPE1;
    cmd->want_.SetElementName("", BUNDLEMAME_1, ABILITY_NAME_SAME_AS_CONTINUE_TYPE, MODULE_NAME1);
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(false));
    int32_t ret = conti_->UpdateElementInfo(cmd);
    EXPECT_EQ(ret, CAN_NOT_FOUND_MODULE_ERR);
    DTEST_LOG << "DSchedContinueTest UpdateElementInfo_084 end" << std::endl;
}

/**
 * @tc.name: ExecuteContinueData_085
 * @tc.desc: ExecuteContinueData with CheckStartPermission failed
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteContinueData_085, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ExecuteContinueData_085 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    auto cmd = std::make_shared<DSchedContinueDataCmd>();
    cmd->srcBundleName_ = "srcBundle";
    cmd->dstBundleName_ = "dstBundle";
    cmd->want_.SetElementName("srcDeviceId", "dstBundle", "abilityName");
    cmd->callerInfo_.sourceDeviceId = "srcDeviceId";
    conti_->continueInfo_.sourceDeviceId_ = "srcDeviceId";
    conti_->continueInfo_.sinkDeviceId_ = "localDeviceId";

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true)).WillOnce(Return(true));
    int32_t ret = conti_->ExecuteContinueData(cmd);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueTest ExecuteContinueData_085 end" << std::endl;
}

/**
 * @tc.name: ExecuteContinueSend_086
 * @tc.desc: ExecuteContinueSend with flags invalid
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueTest, ExecuteContinueSend_086, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinueTest ExecuteContinueSend_086 begin" << std::endl;
    ASSERT_NE(conti_, nullptr);
    auto data = std::make_shared<ContinueAbilityData>();
    data->want.SetFlags(0); // Invalid flags - no FLAG_ABILITY_CONTINUATION
    int32_t ret = conti_->ExecuteContinueSend(data);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueTest ExecuteContinueSend_086 end" << std::endl;
}
}
}
