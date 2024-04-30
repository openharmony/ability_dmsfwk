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

#include "dsched_continue_manager_test.h"

#include "datetime_ex.h"
#include "test_log.h"
#include "mock_distributed_sched.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

namespace {
    const std::string LOCAL_DEVICEID = "192.168.43.100";
    const std::string REMOTE_DEVICEID = "192.168.44.100";
    constexpr int32_t MISSION_ID = 1;
    const std::string BUNDLE_NAME = "com.ohos.permissionmanager";
}

void DSchedContinueManagerTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueManagerTest::SetUpTestCase" << std::endl;
}

void DSchedContinueManagerTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueManagerTest::TearDownTestCase" << std::endl;
}

void DSchedContinueManagerTest::TearDown()
{
    DTEST_LOG << "DSchedContinueManagerTest::TearDown" << std::endl;
}

void DSchedContinueManagerTest::SetUp()
{
    DTEST_LOG << "DSchedContinueManagerTest::SetUp" << std::endl;
}

sptr<IRemoteObject> DSchedContinueManagerTest::GetDSchedService() const
{
    sptr<IRemoteObject> dsched = new MockDistributedSched();
    return dsched;
}

/**
 * @tc.name: Init_001
 * @tc.desc: test Init func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, Init_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest Init_001 begin" << std::endl;
    DSchedContinueManager::GetInstance().Init();
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler =
        DSchedContinueManager::GetInstance().eventHandler_;
    EXPECT_NE(eventHandler, nullptr);
    DTEST_LOG << "DSchedContinueManagerTest Init_001 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_001
 * @tc.desc: test ContinueMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, ContinueMission_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_001 begin" << std::endl;
    auto callback = GetDSchedService();
    OHOS::AAFwk::WantParams wantParams;
    int32_t ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        callback, wantParams);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_001 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_002
 * @tc.desc: test ContinueMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, ContinueMission_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_002 begin" << std::endl;
    OHOS::AAFwk::WantParams wantParams;
    auto callback = GetDSchedService();
    DSchedContinueManager::GetInstance().HandleContinueMission("", REMOTE_DEVICEID, MISSION_ID, callback, wantParams);
    DSchedContinueManager::GetInstance().HandleContinueMission(LOCAL_DEVICEID, "", MISSION_ID, callback, wantParams);
    DSchedContinueManager::GetInstance().HandleContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        nullptr, wantParams);

    int32_t ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        callback, wantParams);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_002 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_003
 * @tc.desc: test ContinueMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, ContinueMission_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_003 begin" << std::endl;
    auto callback = GetDSchedService();
    OHOS::AAFwk::WantParams wantParams;
    int32_t ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, BUNDLE_NAME,
        callback, wantParams);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_003 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_004
 * @tc.desc: test ContinueMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, ContinueMission_004, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_004 begin" << std::endl;
    OHOS::AAFwk::WantParams wantParams;
    auto callback = GetDSchedService();
    DSchedContinueManager::GetInstance().HandleContinueMission("", REMOTE_DEVICEID, BUNDLE_NAME, callback, wantParams);
    DSchedContinueManager::GetInstance().HandleContinueMission(LOCAL_DEVICEID, "", BUNDLE_NAME, callback, wantParams);
    DSchedContinueManager::GetInstance().HandleContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, BUNDLE_NAME,
        nullptr, wantParams);

    int32_t ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, BUNDLE_NAME,
        callback, wantParams);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_004 end" << std::endl;
}

/**
 * @tc.name: SetTimeOut_001
 * @tc.desc: test SetTimeOut func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, SetTimeOut_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest SetTimeOut_001 begin" << std::endl;
    DSchedContinueInfo info;
    int32_t timeout = 0;
    DSchedContinueManager::GetInstance().continues_.clear();
    DSchedContinueManager::GetInstance().SetTimeOut(info, timeout);
    EXPECT_EQ(DSchedContinueManager::GetInstance().continues_.empty(), true);
    DTEST_LOG << "DSchedContinueManagerTest SetTimeOut_001 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_001
 * @tc.desc: test StartContinuation func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, StartContinuation_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest StartContinuation_001 begin" << std::endl;
    OHOS::AAFwk::Want want;
    int32_t missionId = 0;
    int32_t callerUid = 0;
    int32_t status = 0;
    uint32_t accessToken = 0;
    int32_t ret1 = DSchedContinueManager::GetInstance().StartContinuation(want, missionId,
        callerUid, status, accessToken);
    EXPECT_EQ(ret1, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest StartContinuation_001 end" << std::endl;
}

/**
 * @tc.name: CheckContinuationLimit_001
 * @tc.desc: test CheckContinuationLimit func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, CheckContinuationLimit_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest CheckContinuationLimit_001 begin" << std::endl;
    int32_t ret = DSchedContinueManager::GetInstance().CheckContinuationLimit(LOCAL_DEVICEID, REMOTE_DEVICEID);
    EXPECT_EQ(ret, GET_LOCAL_DEVICE_ERR);
    DTEST_LOG << "DSchedContinueManagerTest CheckContinuationLimit_001 end" << std::endl;
}

/**
 * @tc.name: GetLocalDeviceId_001
 * @tc.desc: test GetLocalDeviceId func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, GetLocalDeviceId_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest GetLocalDeviceId_001 begin" << std::endl;
    std::string localDeviceId = "192.168.43.100";
    int32_t ret = DSchedContinueManager::GetInstance().GetLocalDeviceId(localDeviceId);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DSchedContinueManagerTest GetLocalDeviceId_001 end" << std::endl;
}

/**
 * @tc.name: GetContinueInfo_001
 * @tc.desc: test GetContinueInfo func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, GetContinueInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest GetContinueInfo_001 begin" << std::endl;
    std::string localDeviceId = "192.168.43.100";
    std::string remoteDeviceId = "192.168.44.100";
    int32_t ret = DSchedContinueManager::GetInstance().GetContinueInfo(localDeviceId, remoteDeviceId);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest GetContinueInfo_001 end" << std::endl;
}
}
}