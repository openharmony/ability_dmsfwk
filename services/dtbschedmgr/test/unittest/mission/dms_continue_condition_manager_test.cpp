/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "dms_continue_condition_manager_test.h"

#include "ability_manager_client.h"

#include "dtbschedmgr_log.h"
#include "mission/dms_continue_condition_manager.h"
#include "mission/dsched_sync_e2e.h"
#include "test_log.h"
using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedKv;
namespace {
    constexpr int32_t CONDITION_INVALID_MISSION_ID = -1;
}

namespace OHOS {
namespace DistributedSchedule {
void DmsContinueConditionMgrTest::SetUpTestCase()
{
}

void DmsContinueConditionMgrTest::TearDownTestCase()
{
}

void DmsContinueConditionMgrTest::SetUp()
{
}

void DmsContinueConditionMgrTest::TearDown()
{
}

void DmsContinueConditionMgrTest::InitMissionMap()
{
    DmsContinueConditionMgr::GetInstance().missionMap_.clear();
    int32_t missionId = 1;
    MissionStatus status {
        .missionId = missionId, .bundleName = "bundleName", .moduleName = "moduleName",
        .abilityName = "abilityName",  .isContinuable = true, .isFocused = true};
    std::map<int32_t, MissionStatus> missionList;
    missionList[missionId] = status;

    int32_t accountId = 0;
    DmsContinueConditionMgr::GetInstance().missionMap_[accountId] = missionList;
}

/**
 * @tc.name: testUpdateMissionStatus001
 * @tc.desc: test UpdateMissionStatus
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testUpdateMissionStatus001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testUpdateMissionStatus001 start" << std::endl;
    InitMissionMap();
    int32_t missionId = 1;
    int32_t accountId = 0;
    MissionEventType type = MISSION_EVENT_UNFOCUSED;
    auto ret = DmsContinueConditionMgr::GetInstance().UpdateMissionStatus(accountId, missionId, type);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DmsContinueConditionMgr::GetInstance().missionFuncMap_[MISSION_EVENT_UNFOCUSED] =
        &DmsContinueConditionMgr::OnMissionUnfocused;
    ret = DmsContinueConditionMgr::GetInstance().UpdateMissionStatus(accountId, missionId, type);
    EXPECT_EQ(ret, ERR_OK);

    missionId = 2;
    ret = DmsContinueConditionMgr::GetInstance().UpdateMissionStatus(accountId, missionId, type);
    EXPECT_EQ(ret, CONDITION_INVALID_MISSION_ID);
    EXPECT_EQ(DmsContinueConditionMgr::GetInstance().missionMap_[accountId][missionId].isFocused,
        false);
    DmsContinueConditionMgr::GetInstance().UnInit();
    DmsContinueConditionMgr::GetInstance().missionFuncMap_.clear();
    DTEST_LOG << "DMSContinueManagerTest testUpdateMissionStatus001 end" << std::endl;
}

/**
 * @tc.name: testOnMissionBackground001
 * @tc.desc: test OnMissionBackground
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testOnMissionBackground001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testOnMissionBackground001 start" << std::endl;
    InitMissionMap();
    int32_t missionId = 1;
    int32_t accountId = 0;
    MissionEventType type = MISSION_EVENT_BACKGROUND;
    auto ret = DmsContinueConditionMgr::GetInstance().UpdateMissionStatus(accountId, missionId, type);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DmsContinueConditionMgr::GetInstance().missionFuncMap_[MISSION_EVENT_BACKGROUND] =
        &DmsContinueConditionMgr::OnMissionBackground;
    ret = DmsContinueConditionMgr::GetInstance().UpdateMissionStatus(accountId, missionId, type);
    EXPECT_EQ(ret, ERR_OK);

    missionId = 2;
    ret = DmsContinueConditionMgr::GetInstance().UpdateMissionStatus(accountId, missionId, type);
    EXPECT_EQ(ret, CONDITION_INVALID_MISSION_ID);
    EXPECT_EQ(DmsContinueConditionMgr::GetInstance().missionMap_[accountId][missionId].isFocused,
        false);
    DmsContinueConditionMgr::GetInstance().UnInit();
    DmsContinueConditionMgr::GetInstance().missionFuncMap_.clear();
    DTEST_LOG << "DMSContinueManagerTest testOnMissionBackground001 end" << std::endl;
}

/**
 * @tc.name: testOnMissionDestory001
 * @tc.desc: test OnMissionDestory
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testOnMissionDestory001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testOnMissionDestory001 start" << std::endl;
    InitMissionMap();
    int32_t missionId = 1;
    int32_t accountId = 0;
    auto ret = DmsContinueConditionMgr::GetInstance().OnMissionDestory(accountId, missionId);
    EXPECT_EQ(ret, ERR_OK);

    accountId = 2;
    ret = DmsContinueConditionMgr::GetInstance().OnMissionDestory(accountId, missionId);
    EXPECT_EQ(ret, ERR_OK);
    DmsContinueConditionMgr::GetInstance().UnInit();
    DmsContinueConditionMgr::GetInstance().missionFuncMap_.clear();
    DTEST_LOG << "DMSContinueManagerTest testOnMissionDestory001 end" << std::endl;
}

/**
 * @tc.name: testOnMissionActive001
 * @tc.desc: test OnMissionActive
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testOnMissionActive001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testOnMissionActive001 start" << std::endl;
    int32_t missionId = 1;
    int32_t accountId = 0;
    auto ret = DmsContinueConditionMgr::GetInstance().OnMissionActive(accountId, missionId);
    EXPECT_EQ(ret, ERR_OK);

    InitMissionMap();
    ret = DmsContinueConditionMgr::GetInstance().OnMissionActive(accountId, missionId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(DmsContinueConditionMgr::GetInstance().missionMap_[accountId][missionId].continueState,
        AAFwk::ContinueState::CONTINUESTATE_ACTIVE);
    DmsContinueConditionMgr::GetInstance().UnInit();
    DmsContinueConditionMgr::GetInstance().missionFuncMap_.clear();
    DTEST_LOG << "DMSContinueManagerTest testOnMissionActive001 end" << std::endl;
}

/**
 * @tc.name: testOnMissionInactive001
 * @tc.desc: test OnMissionInactive
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testOnMissionInactive001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testOnMissionInactive001 start" << std::endl;
    int32_t missionId = 1;
    int32_t accountId = 0;
    auto ret = DmsContinueConditionMgr::GetInstance().OnMissionInactive(accountId, missionId);
    EXPECT_EQ(ret, ERR_OK);

    InitMissionMap();
    ret = DmsContinueConditionMgr::GetInstance().OnMissionInactive(accountId, missionId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(DmsContinueConditionMgr::GetInstance().missionMap_[accountId][missionId].continueState,
        AAFwk::ContinueState::CONTINUESTATE_INACTIVE);
    DmsContinueConditionMgr::GetInstance().UnInit();
    DmsContinueConditionMgr::GetInstance().missionFuncMap_.clear();
    DTEST_LOG << "DMSContinueManagerTest testOnMissionInactive001 end" << std::endl;
}

/**
 * @tc.name: testCheckSystemSendCondition001
 * @tc.desc: test CheckSystemSendCondition
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testCheckSystemSendCondition001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testCheckSystemSendCondition001 start" << std::endl;
    MissionStatus status;
    status.isContinuable = false;
    status.bundleName = "bundleName";
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSystemSendCondition(status);
    EXPECT_FALSE(ret);

    DmsContinueConditionMgr::GetInstance().isSwitchOn_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSystemSendCondition(status);
    EXPECT_FALSE(ret);

    DmsContinueConditionMgr::GetInstance().isSwitchOn_ = true;
    #ifdef DMS_CHECK_WIFI
    DmsContinueConditionMgr::GetInstance().isWifiActive_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSystemSendCondition(status);
    EXPECT_FALSE(ret);

    DmsContinueConditionMgr::GetInstance().isWifiActive_ = true;
    #endif

    #ifdef DMS_CHECK_BLUETOOTH
    DmsContinueConditionMgr::GetInstance().isBtActive_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSystemSendCondition(status);
    EXPECT_FALSE(ret);

    DmsContinueConditionMgr::GetInstance().isBtActive_ = true;
    #endif

    ret = DmsContinueConditionMgr::GetInstance().CheckSystemSendCondition(status);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DMSContinueManagerTest testCheckSystemSendCondition001 end" << std::endl;
}

/**
 * @tc.name: testTypeEnumToString001
 * @tc.desc: test TypeEnumToString
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testTypeEnumToString001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testTypeEnumToString001 start" << std::endl;
    MissionEventType type = MISSION_EVENT_FOCUSED;
    std::string ret = DmsContinueConditionMgr::GetInstance().TypeEnumToString(type);
    EXPECT_EQ(ret, "FOCUSED");

    type = MISSION_EVENT_UNFOCUSED;
    ret = DmsContinueConditionMgr::GetInstance().TypeEnumToString(type);
    EXPECT_EQ(ret, "UNFOCUSED");

    type = MISSION_EVENT_DESTORYED;
    ret = DmsContinueConditionMgr::GetInstance().TypeEnumToString(type);
    EXPECT_EQ(ret, "DESTORYED");

    type = MISSION_EVENT_ACTIVE;
    ret = DmsContinueConditionMgr::GetInstance().TypeEnumToString(type);
    EXPECT_EQ(ret, "ACTIVE");

    type = MISSION_EVENT_INACTIVE;
    ret = DmsContinueConditionMgr::GetInstance().TypeEnumToString(type);
    EXPECT_EQ(ret, "INACTIVE");

    type = MISSION_EVENT_TIMEOUT;
    ret = DmsContinueConditionMgr::GetInstance().TypeEnumToString(type);
    EXPECT_EQ(ret, "TIMEOUT");

    type = MISSION_EVENT_MMI;
    ret = DmsContinueConditionMgr::GetInstance().TypeEnumToString(type);
    EXPECT_EQ(ret, "MMI");

    type = MISSION_EVENT_MAX;
    ret = DmsContinueConditionMgr::GetInstance().TypeEnumToString(type);
    EXPECT_EQ(ret, "UNDEFINED");
    DTEST_LOG << "DMSContinueManagerTest testTypeEnumToString001 end" << std::endl;
}

/**
 * @tc.name: testCheckSendFocusedCondition001
 * @tc.desc: test CheckSendFocusedCondition
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testCheckSendFocusedCondition001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testCheckSendFocusedCondition001 start" << std::endl;
    MissionStatus status;
    status.isContinuable = false;
    status.bundleName = "bundleName";
    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = true;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSendFocusedCondition(status);
    EXPECT_FALSE(ret);

    status.isContinuable = true;
    status.continueState = AAFwk::ContinueState::CONTINUESTATE_INACTIVE;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendFocusedCondition(status);
    EXPECT_FALSE(ret);

    status.continueState = AAFwk::ContinueState::CONTINUESTATE_ACTIVE;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendFocusedCondition(status);
    EXPECT_TRUE(ret);

    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendFocusedCondition(status);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DMSContinueManagerTest testCheckSendFocusedCondition001 end" << std::endl;
}

/**
 * @tc.name: testCheckSendUnfocusedCondition001
 * @tc.desc: test CheckSendUnfocusedCondition
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testCheckSendUnfocusedCondition001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testCheckSendUnfocusedCondition001 start" << std::endl;
    MissionStatus status;
    status.isFocused = false;
    status.bundleName = "bundleName";
    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = true;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSendUnfocusedCondition(status);
    EXPECT_FALSE(ret);

    status.isFocused = true;
    status.isContinuable = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendUnfocusedCondition(status);
    EXPECT_FALSE(ret);

    status.isContinuable = true;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendUnfocusedCondition(status);
    EXPECT_TRUE(ret);

    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendUnfocusedCondition(status);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DMSContinueManagerTest testCheckSendUnfocusedCondition001 end" << std::endl;
}

/**
 * @tc.name: testCheckSendActiveCondition001
 * @tc.desc: test CheckSendActiveCondition
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testCheckSendActiveCondition001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testCheckSendActiveCondition001 start" << std::endl;
    MissionStatus status;
    status.isFocused = false;
    status.bundleName = "bundleName";
    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = true;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSendActiveCondition(status);
    EXPECT_FALSE(ret);

    status.isFocused = true;
    status.isContinuable = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendActiveCondition(status);
    EXPECT_FALSE(ret);

    status.isContinuable = true;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendActiveCondition(status);
    EXPECT_TRUE(ret);

    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendActiveCondition(status);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DMSContinueManagerTest testCheckSendActiveCondition001 end" << std::endl;
}

/**
 * @tc.name: testCheckSendInactiveCondition001
 * @tc.desc: test CheckSendInactiveCondition
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testCheckSendInactiveCondition001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testCheckSendInactiveCondition001 start" << std::endl;
    MissionStatus status;
    status.isContinuable = false;
    status.bundleName = "bundleName";
    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = true;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSendInactiveCondition(status);
    EXPECT_FALSE(ret);

    status.isContinuable = true;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendInactiveCondition(status);
    EXPECT_TRUE(ret);

    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendInactiveCondition(status);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DMSContinueManagerTest testCheckSendInactiveCondition001 end" << std::endl;
}

/**
 * @tc.name: testCheckMissionSendCondition001
 * @tc.desc: test CheckMissionSendCondition
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testCheckMissionSendCondition001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testCheckMissionSendCondition001 start" << std::endl;
    DmsContinueConditionMgr::GetInstance().conditionFuncMap_.clear();
    MissionStatus status;
    MissionEventType type = MISSION_EVENT_FOCUSED;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckMissionSendCondition(status, type);
    EXPECT_FALSE(ret);

    DmsContinueConditionMgr::GetInstance().conditionFuncMap_[MISSION_EVENT_FOCUSED] =
        &DmsContinueConditionMgr::CheckSendFocusedCondition;

    ret = DmsContinueConditionMgr::GetInstance().CheckMissionSendCondition(status, type);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DMSContinueManagerTest testCheckMissionSendCondition001 end" << std::endl;
}

/**
 * @tc.name: testGetMissionIdByBundleName001
 * @tc.desc: test GetMissionIdByBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, testGetMissionIdByBundleName001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetMissionIdByBundleName001 start" << std::endl;
    int32_t accountId = 0;
    std::string bundleName = "bundleName";
    int32_t missionId = 1;
    InitMissionMap();
    auto ret = DmsContinueConditionMgr::GetInstance().GetMissionIdByBundleName(accountId, bundleName, missionId);
    EXPECT_EQ(ret, ERR_OK);

    bundleName = "bundleName2";
    ret = DmsContinueConditionMgr::GetInstance().GetMissionIdByBundleName(accountId, bundleName, missionId);
    EXPECT_EQ(ret, MISSION_NOT_FOCUSED);

    accountId = 1;
    ret = DmsContinueConditionMgr::GetInstance().GetMissionIdByBundleName(accountId, bundleName, missionId);
    EXPECT_EQ(ret, MISSION_NOT_FOCUSED);
    DTEST_LOG << "DMSContinueManagerTest testGetMissionIdByBundleName001 end" << std::endl;
}

/**
 * @tc.name: DmsContinueConditionMgr_CheckBlacklist_001
 * @tc.desc: test CheckBlacklist executes and returns a boolean result
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, DmsContinueConditionMgr_CheckBlacklist_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest DmsContinueConditionMgr_CheckBlacklist_001 start" << std::endl;

    MissionStatus status;
    status.accountId = 0;
    status.missionId = 1;
    status.bundleName = "com.example.testbundle";

    bool ret = DmsContinueConditionMgr::GetInstance().CheckBlacklist(status);

    EXPECT_FALSE(ret);
    DTEST_LOG << "DMSContinueManagerTest DmsContinueConditionMgr_CheckBlacklist_001 end" << std::endl;
}

/**
 * @tc.name: DmsContinueConditionMgr_CheckBlacklist_002
 * @tc.desc: test CheckBlacklist on default not-found kv value path
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, DmsContinueConditionMgr_CheckBlacklist_002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest DmsContinueConditionMgr_CheckBlacklist_002 start" << std::endl;

    MissionStatus status;
    status.accountId = 0;
    status.missionId = 1;
    status.bundleName = "com.example.bundle.not.exist";

    bool ret = DmsContinueConditionMgr::GetInstance().CheckBlacklist(status);

    EXPECT_FALSE(ret);
    DTEST_LOG << "DMSContinueManagerTest DmsContinueConditionMgr_CheckBlacklist_002 end" << std::endl;
}

/**
 * @tc.name: CheckVirtualScreenScenario_001
 * @tc.desc: test CheckVirtualScreenScenario with displayId >= 1000
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, CheckVirtualScreenScenario_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest CheckVirtualScreenScenario_001 start" << std::endl;

    MissionStatus status;
    status.accountId = 0;
    status.missionId = 1;
    status.bundleName = "com.example.testbundle";
    status.abilityName = "MainAbility";

    bool ret = DmsContinueConditionMgr::GetInstance().CheckVirtualScreenScenario(status);

    EXPECT_FALSE(ret);
    DTEST_LOG << "DMSContinueManagerTest CheckVirtualScreenScenario_001 end" << std::endl;
}

/**
 * @tc.name: CheckVirtualScreenScenario_002
 * @tc.desc: test CheckVirtualScreenScenario with invalid missionId
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueConditionMgrTest, CheckVirtualScreenScenario_002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest CheckVirtualScreenScenario_002 start" << std::endl;

    MissionStatus status;
    status.accountId = 0;
    status.missionId = -1;
    status.bundleName = "com.example.testbundle";
    status.abilityName = "MainAbility";

    bool ret = DmsContinueConditionMgr::GetInstance().CheckVirtualScreenScenario(status);

    EXPECT_FALSE(ret);
    DTEST_LOG << "DMSContinueManagerTest CheckVirtualScreenScenario_002 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testTypeEnumToString002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testTypeEnumToString002 start" << std::endl;
    MissionEventType type = MISSION_EVENT_BACKGROUND;
    std::string ret = DmsContinueConditionMgr::GetInstance().TypeEnumToString(type);
    EXPECT_EQ(ret, "BACKGROUND");

    type = MISSION_EVENT_CONTINUE_SWITCH_OFF;
    ret = DmsContinueConditionMgr::GetInstance().TypeEnumToString(type);
    EXPECT_EQ(ret, "CONTINUE_SWITCH_OFF");
    DTEST_LOG << "DMSContinueManagerTest testTypeEnumToString002 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testCheckSendBackgroundCondition001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testCheckSendBackgroundCondition001 start" << std::endl;
    MissionStatus status;
    status.isContinuable = false;
    status.bundleName = "bundleName";
    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = true;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSendBackgroundCondition(status);
    EXPECT_FALSE(ret);

    status.isContinuable = true;
    status.continueState = AAFwk::ContinueState::CONTINUESTATE_INACTIVE;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendBackgroundCondition(status);
    EXPECT_FALSE(ret);

    status.continueState = AAFwk::ContinueState::CONTINUESTATE_ACTIVE;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendBackgroundCondition(status);
    EXPECT_TRUE(ret);

    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendBackgroundCondition(status);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DMSContinueManagerTest testCheckSendBackgroundCondition001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testCheckSendContinueSwitchOffCondition001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testCheckSendContinueSwitchOffCondition001 start" << std::endl;
    MissionStatus status;
    status.isContinuable = false;
    status.bundleName = "bundleName";
    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = true;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSendContinueSwitchOffCondition(status);
    EXPECT_FALSE(ret);

    status.isContinuable = true;
    status.continueState = AAFwk::ContinueState::CONTINUESTATE_INACTIVE;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendContinueSwitchOffCondition(status);
    EXPECT_FALSE(ret);

    status.continueState = AAFwk::ContinueState::CONTINUESTATE_ACTIVE;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendContinueSwitchOffCondition(status);
    EXPECT_TRUE(ret);

    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendContinueSwitchOffCondition(status);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DMSContinueManagerTest testCheckSendContinueSwitchOffCondition001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testGetMissionStatus001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetMissionStatus001 start" << std::endl;
    InitMissionMap();
    int32_t missionId = 1;
    int32_t accountId = 0;
    MissionStatus status;
    auto ret = DmsContinueConditionMgr::GetInstance().GetMissionStatus(accountId, missionId, status);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(status.bundleName, "bundleName");
    EXPECT_EQ(status.isFocused, true);

    missionId = 999;
    ret = DmsContinueConditionMgr::GetInstance().GetMissionStatus(accountId, missionId, status);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    accountId = 999;
    ret = DmsContinueConditionMgr::GetInstance().GetMissionStatus(accountId, 1, status);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueManagerTest testGetMissionStatus001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testIsScreenLocked001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsScreenLocked001 start" << std::endl;
    DmsContinueConditionMgr::GetInstance().isScreenLocked_ = false;
    EXPECT_FALSE(DmsContinueConditionMgr::GetInstance().IsScreenLocked());

    DmsContinueConditionMgr::GetInstance().isScreenLocked_ = true;
    EXPECT_TRUE(DmsContinueConditionMgr::GetInstance().IsScreenLocked());

    DmsContinueConditionMgr::GetInstance().isScreenLocked_ = false;
    DTEST_LOG << "DMSContinueManagerTest testIsScreenLocked001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testGetCurrentFocusedMission001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetCurrentFocusedMission001 start" << std::endl;
    DmsContinueConditionMgr::GetInstance().missionMap_.clear();
    int32_t ret = DmsContinueConditionMgr::GetInstance().GetCurrentFocusedMission(0);
    EXPECT_EQ(ret, -1);

    InitMissionMap();
    ret = DmsContinueConditionMgr::GetInstance().GetCurrentFocusedMission(0);
    EXPECT_EQ(ret, 1);

    ret = DmsContinueConditionMgr::GetInstance().GetCurrentFocusedMission(999);
    EXPECT_EQ(ret, -1);

    DmsContinueConditionMgr::GetInstance().missionMap_[0][1].isFocused = false;
    ret = DmsContinueConditionMgr::GetInstance().GetCurrentFocusedMission(0);
    EXPECT_EQ(ret, -1);
    DTEST_LOG << "DMSContinueManagerTest testGetCurrentFocusedMission001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testGetCurrentFocusedMissionWithStatus001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetCurrentFocusedMissionWithStatus001 start" << std::endl;
    DmsContinueConditionMgr::GetInstance().missionMap_.clear();
    MissionStatus missionStatus;
    int32_t ret = DmsContinueConditionMgr::GetInstance().GetCurrentFocusedMission(0, missionStatus);
    EXPECT_EQ(ret, -1);
    EXPECT_EQ(missionStatus.missionId, -1);

    InitMissionMap();
    ret = DmsContinueConditionMgr::GetInstance().GetCurrentFocusedMission(0, missionStatus);
    EXPECT_EQ(ret, 1);
    EXPECT_EQ(missionStatus.bundleName, "bundleName");
    EXPECT_EQ(missionStatus.isFocused, true);

    ret = DmsContinueConditionMgr::GetInstance().GetCurrentFocusedMission(999, missionStatus);
    EXPECT_EQ(ret, -1);
    DTEST_LOG << "DMSContinueManagerTest testGetCurrentFocusedMissionWithStatus001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testGetLastContinuableMissionStatus001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetLastContinuableMissionStatus001 start" << std::endl;
    MissionStatus status;
    status.missionId = 5;
    status.bundleName = "testBundle";
    DmsContinueConditionMgr::GetInstance().lastContinuableMissionStatus_ = status;
    auto ret = DmsContinueConditionMgr::GetInstance().GetLastContinuableMissionStatus();
    EXPECT_EQ(ret.missionId, 5);
    EXPECT_EQ(ret.bundleName, "testBundle");

    MissionStatus emptyStatus;
    DmsContinueConditionMgr::GetInstance().lastContinuableMissionStatus_ = emptyStatus;
    ret = DmsContinueConditionMgr::GetInstance().GetLastContinuableMissionStatus();
    EXPECT_EQ(ret.missionId, 0);
    DTEST_LOG << "DMSContinueManagerTest testGetLastContinuableMissionStatus001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testOnUserRemoved001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testOnUserRemoved001 start" << std::endl;
    DmsContinueConditionMgr::GetInstance().missionMap_.clear();
    DmsContinueConditionMgr::GetInstance().OnUserRemoved(0);
    EXPECT_TRUE(DmsContinueConditionMgr::GetInstance().missionMap_.empty());

    InitMissionMap();
    EXPECT_FALSE(DmsContinueConditionMgr::GetInstance().missionMap_.empty());
    DmsContinueConditionMgr::GetInstance().OnUserRemoved(0);
    EXPECT_TRUE(DmsContinueConditionMgr::GetInstance().missionMap_.find(0) ==
        DmsContinueConditionMgr::GetInstance().missionMap_.end());

    InitMissionMap();
    DmsContinueConditionMgr::GetInstance().OnUserRemoved(999);
    EXPECT_TRUE(DmsContinueConditionMgr::GetInstance().missionMap_.find(0) !=
        DmsContinueConditionMgr::GetInstance().missionMap_.end());
    DTEST_LOG << "DMSContinueManagerTest testOnUserRemoved001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testUnInit001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testUnInit001 start" << std::endl;
    InitMissionMap();
    EXPECT_FALSE(DmsContinueConditionMgr::GetInstance().missionMap_.empty());
    DmsContinueConditionMgr::GetInstance().UnInit();
    EXPECT_TRUE(DmsContinueConditionMgr::GetInstance().missionMap_.empty());
    DTEST_LOG << "DMSContinueManagerTest testUnInit001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testUpdateSystemStatus001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testUpdateSystemStatus001 start" << std::endl;
    DmsContinueConditionMgr::GetInstance().sysFuncMap_[SYS_EVENT_CONTINUE_SWITCH] =
        &DmsContinueConditionMgr::SetIsContinueSwitchOn;
    auto ret = DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_CONTINUE_SWITCH, true);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(DmsContinueConditionMgr::GetInstance().isSwitchOn_.load());

    ret = DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_CONTINUE_SWITCH, false);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(DmsContinueConditionMgr::GetInstance().isSwitchOn_.load());

    DmsContinueConditionMgr::GetInstance().sysFuncMap_[SYS_EVENT_WIFI] =
        &DmsContinueConditionMgr::SetIsWifiActive;
    ret = DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_WIFI, true);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(DmsContinueConditionMgr::GetInstance().isWifiActive_.load());

    DmsContinueConditionMgr::GetInstance().sysFuncMap_[SYS_EVENT_BLUETOOTH] =
        &DmsContinueConditionMgr::SetIsBtActive;
    ret = DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_BLUETOOTH, true);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(DmsContinueConditionMgr::GetInstance().isBtActive_.load());

    DmsContinueConditionMgr::GetInstance().sysFuncMap_[SYS_EVENT_SCREEN_LOCK] =
        &DmsContinueConditionMgr::SetIsScreenLocked;
    ret = DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(SYS_EVENT_SCREEN_LOCK, true);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(DmsContinueConditionMgr::GetInstance().IsScreenLocked());

    ret = DmsContinueConditionMgr::GetInstance().UpdateSystemStatus(
        static_cast<SysEventType>(999), true);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueManagerTest testUpdateSystemStatus001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testConvertToMissionStatus001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testConvertToMissionStatus001 start" << std::endl;
    AAFwk::MissionInfo missionInfo;
    missionInfo.id = 10;
    missionInfo.continuable = true;
    missionInfo.continueState = AAFwk::ContinueState::CONTINUESTATE_ACTIVE;
    AAFwk::Want want;
    want.SetElementName("", "testBundle", "testAbility", "testModule");
    want.SetFlags(0x01);
    missionInfo.want = want;

    MissionStatus status;
    DmsContinueConditionMgr::GetInstance().ConvertToMissionStatus(missionInfo, 100, status);
    const auto& element = missionInfo.want.GetElement();
    EXPECT_EQ(status.accountId, 100);
    EXPECT_EQ(status.missionId, 10);
    EXPECT_EQ(status.bundleName, element.GetBundleName());
    EXPECT_EQ(status.moduleName, element.GetModuleName());
    EXPECT_EQ(status.abilityName, element.GetAbilityName());
    EXPECT_EQ(status.isContinuable, true);
    EXPECT_EQ(status.launchFlag, 0x01);
    EXPECT_EQ(status.continueState, AAFwk::ContinueState::CONTINUESTATE_ACTIVE);
    DTEST_LOG << "DMSContinueManagerTest testConvertToMissionStatus001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testCleanLastFocusedFlagLocked001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testCleanLastFocusedFlagLocked001 start" << std::endl;
    DmsContinueConditionMgr::GetInstance().missionMap_.clear();
    int32_t accountId = 0;
    std::map<int32_t, MissionStatus> missionList;
    MissionStatus status1{.missionId = 1, .bundleName = "b1", .isFocused = true};
    MissionStatus status2{.missionId = 2, .bundleName = "b2", .isFocused = true};
    missionList[1] = status1;
    missionList[2] = status2;
    DmsContinueConditionMgr::GetInstance().missionMap_[accountId] = missionList;

    DmsContinueConditionMgr::GetInstance().CleanLastFocusedFlagLocked(accountId, 1);
    EXPECT_FALSE(DmsContinueConditionMgr::GetInstance().missionMap_[accountId][2].isFocused);

    DmsContinueConditionMgr::GetInstance().missionMap_[accountId][1].isFocused = true;
    DmsContinueConditionMgr::GetInstance().CleanLastFocusedFlagLocked(accountId, 2);
    EXPECT_FALSE(DmsContinueConditionMgr::GetInstance().missionMap_[accountId][1].isFocused);
    DTEST_LOG << "DMSContinueManagerTest testCleanLastFocusedFlagLocked001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testSetMissionStatus001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testSetMissionStatus001 start" << std::endl;
    MissionStatus status;
    status.accountId = 100;
    status.missionId = 10;
    status.bundleName = "testBundle";
    status.isContinuable = true;
    status.isFocused = true;
    status.continueState = AAFwk::ContinueState::CONTINUESTATE_ACTIVE;

    DmsContinueConditionMgr::GetInstance().SetMissionStatus(status);
    EXPECT_EQ(status.accountId, 0);
    EXPECT_EQ(status.missionId, 0);
    EXPECT_EQ(status.bundleName, "");
    EXPECT_EQ(status.isContinuable, false);
    EXPECT_EQ(status.isFocused, false);
    EXPECT_EQ(status.continueState, AAFwk::ContinueState::CONTINUESTATE_UNKNOWN);
    DTEST_LOG << "DMSContinueManagerTest testSetMissionStatus001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testIsMissionStatusExistLocked001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsMissionStatusExistLocked001 start" << std::endl;
    DmsContinueConditionMgr::GetInstance().missionMap_.clear();
    EXPECT_FALSE(DmsContinueConditionMgr::GetInstance().IsMissionStatusExistLocked(0, 1));

    InitMissionMap();
    EXPECT_TRUE(DmsContinueConditionMgr::GetInstance().IsMissionStatusExistLocked(0, 1));
    EXPECT_FALSE(DmsContinueConditionMgr::GetInstance().IsMissionStatusExistLocked(0, 999));
    EXPECT_FALSE(DmsContinueConditionMgr::GetInstance().IsMissionStatusExistLocked(999, 1));
    DTEST_LOG << "DMSContinueManagerTest testIsMissionStatusExistLocked001 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testGetMissionIdByBundleName002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetMissionIdByBundleName002 start" << std::endl;
    int32_t accountId = 0;
    std::string bundleName = "bundleName";
    int32_t missionId = -1;
    InitMissionMap();

    DmsContinueConditionMgr::GetInstance().lastContinuableMissionStatus_ = {};
    auto ret = DmsContinueConditionMgr::GetInstance().GetMissionIdByBundleName(
        accountId, bundleName, missionId);
    EXPECT_EQ(ret, ERR_OK);

    DmsContinueConditionMgr::GetInstance().missionMap_[0][1].isContinuable = false;
    bundleName = "otherBundle";
    missionId = -1;
    ret = DmsContinueConditionMgr::GetInstance().GetMissionIdByBundleName(
        accountId, bundleName, missionId);
    EXPECT_EQ(ret, MISSION_NOT_FOCUSED);

    MissionStatus lastStatus;
    lastStatus.missionId = 1;
    lastStatus.bundleName = "otherBundle";
    lastStatus.isContinuable = true;
    DmsContinueConditionMgr::GetInstance().lastContinuableMissionStatus_ = lastStatus;
    // Fallback matches bundleName on the mission map entry for lastContinuableMissionStatus_.missionId.
    DmsContinueConditionMgr::GetInstance().missionMap_[0][1].bundleName = "otherBundle";
    DmsContinueConditionMgr::GetInstance().missionMap_[0][1].isContinuable = true;
    ret = DmsContinueConditionMgr::GetInstance().GetMissionIdByBundleName(
        accountId, bundleName, missionId);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(missionId, 1);
    DTEST_LOG << "DMSContinueManagerTest testGetMissionIdByBundleName002 end" << std::endl;
}

HWTEST_F(DmsContinueConditionMgrTest, testOnMissionUnfocusedNotExist, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testOnMissionUnfocusedNotExist start" << std::endl;
    DmsContinueConditionMgr::GetInstance().missionMap_.clear();
    int32_t accountId = 0;
    int32_t missionId = 999;
    auto ret = DmsContinueConditionMgr::GetInstance().OnMissionUnfocused(accountId, missionId);
    EXPECT_EQ(ret, -1);

    InitMissionMap();
    ret = DmsContinueConditionMgr::GetInstance().OnMissionUnfocused(accountId, 1);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_FALSE(DmsContinueConditionMgr::GetInstance().missionMap_[accountId][1].isFocused);
    DTEST_LOG << "DMSContinueManagerTest testOnMissionUnfocusedNotExist end" << std::endl;
}
}
}