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
    DmsContinueConditionMgr::GetInstance().isCfgDevice_ = true;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSystemSendCondition();
    EXPECT_FALSE(ret);

    DmsContinueConditionMgr::GetInstance().isCfgDevice_ = false;
    DmsContinueConditionMgr::GetInstance().isSwitchOn_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSystemSendCondition();
    EXPECT_FALSE(ret);

    DmsContinueConditionMgr::GetInstance().isSwitchOn_ = true;
    #ifdef DMS_CHECK_WIFI
    DmsContinueConditionMgr::GetInstance().isWifiActive_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSystemSendCondition();
    EXPECT_FALSE(ret);

    DmsContinueConditionMgr::GetInstance().isWifiActive_ = true;
    #endif

    #ifdef DMS_CHECK_BLUETOOTH
    DmsContinueConditionMgr::GetInstance().isBtActive_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSystemSendCondition();
    EXPECT_FALSE(ret);

    DmsContinueConditionMgr::GetInstance().isBtActive_ = true;
    #endif

    ret = DmsContinueConditionMgr::GetInstance().CheckSystemSendCondition();
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
    DmsKvSyncE2E::GetInstance()->whiteList_.clear();
    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = true;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSendFocusedCondition(status);
    EXPECT_FALSE(ret);

    status.isContinuable = true;
    status.continueState = AAFwk::ContinueState::CONTINUESTATE_INACTIVE;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendFocusedCondition(status);
    EXPECT_FALSE(ret);

    status.continueState = AAFwk::ContinueState::CONTINUESTATE_ACTIVE;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendFocusedCondition(status);
    EXPECT_FALSE(ret);

    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendFocusedCondition(status);
    EXPECT_TRUE(ret);
    DmsKvSyncE2E::GetInstance()->whiteList_.clear();
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
    DmsKvSyncE2E::GetInstance()->whiteList_.clear();
    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = true;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSendUnfocusedCondition(status);
    EXPECT_FALSE(ret);

    status.isFocused = true;
    status.isContinuable = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendUnfocusedCondition(status);
    EXPECT_FALSE(ret);

    status.isContinuable = true;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendUnfocusedCondition(status);
    EXPECT_FALSE(ret);

    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendUnfocusedCondition(status);
    EXPECT_TRUE(ret);
    DmsKvSyncE2E::GetInstance()->whiteList_.clear();
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
    DmsKvSyncE2E::GetInstance()->whiteList_.clear();
    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = true;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSendActiveCondition(status);
    EXPECT_FALSE(ret);

    status.isFocused = true;
    status.isContinuable = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendActiveCondition(status);
    EXPECT_FALSE(ret);

    status.isContinuable = true;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendActiveCondition(status);
    EXPECT_FALSE(ret);

    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendActiveCondition(status);
    EXPECT_TRUE(ret);
    DmsKvSyncE2E::GetInstance()->whiteList_.clear();
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
    DmsKvSyncE2E::GetInstance()->whiteList_.clear();
    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = true;
    auto ret = DmsContinueConditionMgr::GetInstance().CheckSendInactiveCondition(status);
    EXPECT_FALSE(ret);

    status.isContinuable = true;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendInactiveCondition(status);
    EXPECT_FALSE(ret);

    DmsKvSyncE2E::GetInstance()->isCfgDevices_ = false;
    ret = DmsContinueConditionMgr::GetInstance().CheckSendInactiveCondition(status);
    EXPECT_TRUE(ret);
    DmsKvSyncE2E::GetInstance()->whiteList_.clear();
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
    EXPECT_EQ(missionId, 1);
    EXPECT_EQ(ret, ERR_OK);

    bundleName = "bundleName2";
    ret = DmsContinueConditionMgr::GetInstance().GetMissionIdByBundleName(accountId, bundleName, missionId);
    EXPECT_EQ(ret, MISSION_NOT_FOCUSED);

    accountId = 1;
    ret = DmsContinueConditionMgr::GetInstance().GetMissionIdByBundleName(accountId, bundleName, missionId);
    EXPECT_EQ(ret, MISSION_NOT_FOCUSED);
    DTEST_LOG << "DMSContinueManagerTest testGetMissionIdByBundleName001 end" << std::endl;
}
}
}