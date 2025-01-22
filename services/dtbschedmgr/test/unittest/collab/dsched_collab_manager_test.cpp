/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "dsched_collab_manager_test.h"

#include "dtbschedmgr_device_info_storage.h"
#include "distributed_sched_test_util.h"
#include "test_log.h"
#include "mock_distributed_sched.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedHardware;

namespace OHOS {
namespace DistributedSchedule {

static std::shared_ptr<DmsDeviceInfo> g_mockDeviceInfoPtr = nullptr;
static bool g_mockDbs = false;

namespace {
    const std::string LOCAL_DEVICEID = "localdeviceid";
    const std::string REMOTE_DEVICEID = "remotedeviceid";
    const std::string CONTINUETYPE = "continueType";
    const std::string BASEDIR = "/data/service/el1/public/database/DistributedSchedule";
    constexpr int32_t MISSION_ID = 1;
    constexpr size_t SIZE = 10;
    const int32_t WAITTIME = 2000;
    const std::string BUNDLE_NAME = "com.ohos.permissionmanager";
}

std::shared_ptr<DmsDeviceInfo> DtbschedmgrDeviceInfoStorage::GetDeviceInfoById(const std::string& networkId)
{
    return g_mockDeviceInfoPtr;
}

bool DmsBmStorage::GetDistributedBundleInfo(const std::string &networkId,
    const uint16_t &bundleNameId, DmsBundleInfo &distributeBundleInfo)
{
    return g_mockDbs;
}

void DSchedCollabManagerTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedCollabManagerTest::SetUpTestCase" << std::endl;
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DSchedCollabManager::GetInstance().Init();
}

void DSchedCollabManagerTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedCollabManagerTest::TearDownTestCase" << std::endl;
    (void)remove(BASEDIR.c_str());
}

void DSchedCollabManagerTest::TearDown()
{
    DTEST_LOG << "DSchedCollabManagerTest::TearDown" << std::endl;
    usleep(WAITTIME);
    g_mockDeviceInfoPtr = nullptr;
    g_mockDbs = false;
}

void DSchedCollabManagerTest::SetUp()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedCollabManagerTest::SetUp" << std::endl;
}

void DSchedCollabManagerTest::DeviceInitCallBack::OnRemoteDied()
{
}

sptr<IRemoteObject> DSchedCollabManagerTest::GetDSchedService() const
{
    sptr<IRemoteObject> dsched(new MockDistributedSched());
    return dsched;
}

std::shared_ptr<DSchedCollab> DSchedCollabManagerTest::CreateObject()
{
    const std::string collabToken = "";
    DSchedCollabInfo info;
    std::shared_ptr<DSchedCollab> dCollab = std::make_shared<DSchedCollab>(collabToken, info);
    dCollab->Init();
    return dCollab;
}

/**
 * @tc.name: Init_001
 * @tc.desc: test Init func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, Init_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest Init_001 begin" << std::endl;
    DSchedCollabManager::GetInstance().Init();
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler =
        DSchedCollabManager::GetInstance().eventHandler_;
    EXPECT_NE(eventHandler, nullptr);
    DTEST_LOG << "DSchedCollabManagerTest Init_001 end" << std::endl;
}

/**
 * @tc.name: CollabMission_001
 * @tc.desc: test CollabMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, CollabMission_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest CollabMission_001 begin" << std::endl;
    auto callback = GetDSchedService();
    OHOS::AAFwk::WantParams wantParams;
    DSchedCollabInfo info;
    int32_t ret = DSchedCollabManager::GetInstance().CollabMission(info);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollabManagerTest CollabMission_001 end" << std::endl;
}

/**
 * @tc.name: CollabMission_002
 * @tc.desc: test CollabMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, CollabMission_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest CollabMission_002 begin" << std::endl;
    OHOS::AAFwk::WantParams wantParams;
    auto callback = GetDSchedService();
    DSchedCollabInfo info;
    int32_t ret = DSchedCollabManager::GetInstance().CollabMission(info);
    DSchedCollabManager::GetInstance().HandleCollabMission(info);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollabManagerTest CollabMission_002 end" << std::endl;
}

/**
 * @tc.name: HandleCollabMission_001
 * @tc.desc: test HandleCollabMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, HandleCollabMission_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest HandleCollabMission_001 begin" << std::endl;
    OHOS::AAFwk::WantParams wantParams;
    auto callback = GetDSchedService();
    DSchedCollabInfo info;
    int32_t ret = DSchedCollabManager::GetInstance().CollabMission(info);
    DSchedCollabManager::GetInstance().HandleCollabMission(info);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollabManagerTest HandleCollabMission_001 end" << std::endl;
}

/**
 * @tc.name: SetTimeOut_001
 * @tc.desc: test SetTimeOut func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, SetTimeOut_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest SetTimeOut_001 begin" << std::endl;
    const std::string collabToken = "testToken";
    int32_t timeout = 0;
    DSchedCollabManager::GetInstance().collabs_.clear();
    DSchedCollabManager::GetInstance().SetTimeOut(collabToken, timeout);
    EXPECT_EQ(DSchedCollabManager::GetInstance().collabs_.empty(), true);
    DTEST_LOG << "DSchedCollabManagerTest SetTimeOut_001 end" << std::endl;
}

/**
 * @tc.name: RemoveTimeout_001
 * @tc.desc: test RemoveTimeout func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, RemoveTimeout_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest RemoveTimeout_001 begin" << std::endl;
    const std::string collabToken = "testToken";
    DSchedCollabManager::GetInstance().collabs_.clear();
    DSchedCollabManager::GetInstance().RemoveTimeout(collabToken);
    EXPECT_EQ(DSchedCollabManager::GetInstance().collabs_.empty(), true);
    DTEST_LOG << "DSchedCollabManagerTest RemoveTimeout_001 end" << std::endl;
}

/**
 * @tc.name: NotifyStartAbilityResult_001
 * @tc.desc: test NotifyStartAbilityResult func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, NotifyStartAbilityResult_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest NotifyStartAbilityResult_001 begin" << std::endl;
    const std::string collabToken = "";
    const int32_t result = 0;
    const int32_t sinkPid = 0;
    const int32_t sinkUid = 0;
    const int32_t sinkAccessTokenId = 0;
    int32_t ret1 = DSchedCollabManager::GetInstance().NotifyStartAbilityResult(collabToken, result,
        sinkPid, sinkUid, sinkAccessTokenId);
    EXPECT_EQ(ret1, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollabManagerTest NotifyStartAbilityResult_001 end" << std::endl;
}

/**
 * @tc.name: NotifySinkPrepareResult_001
 * @tc.desc: test NotifySinkPrepareResult func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, NotifySinkPrepareResult_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest NotifySinkPrepareResult_001 begin" << std::endl;
    int32_t direction = 0;
    const std::string collabToken = "";
    const int32_t result = 0;
    const int32_t collabSessionId = 0;
    const std::string socketName = "";
    const sptr<IRemoteObject> clientCB;
    int32_t ret = DSchedCollabManager::GetInstance().NotifySinkPrepareResult(collabToken, result,
        collabSessionId, socketName, clientCB);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedCollabManagerTest NotifySinkPrepareResult_001 end" << std::endl;
}

/**
 * @tc.name: NotifySinkRejectReason_001
 * @tc.desc: test NotifySinkRejectReason func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, NotifySinkRejectReason_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest NotifySinkRejectReason_001 begin" << std::endl;
    const std::string collabToken = "";
    const std::string reason = "";
    int32_t ret = DSchedCollabManager::GetInstance().NotifySinkRejectReason(collabToken, reason);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollabManagerTest NotifySinkRejectReason_001 end" << std::endl;
}

/**
 * @tc.name: NotifyAbilityDied_002
 * @tc.desc: test NotifyAbilityDied func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, NotifyAbilityDied_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest NotifyAbilityDied_002 begin" << std::endl;
    const std::string bundleName = "";
    const int32_t pid = 0;
    int32_t ret = DSchedCollabManager::GetInstance().NotifyAbilityDied(bundleName, pid);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedCollabManagerTest NotifyAbilityDied_002 end" << std::endl;
}

/**
 * @tc.name: ReleaseAbilityLink_001
 * @tc.desc: test ReleaseAbilityLink func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, ReleaseAbilityLink_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest ReleaseAbilityLink_001 begin" << std::endl;
    const std::string bundleName = "";
    const int32_t pid = 0;
    int32_t ret = DSchedCollabManager::GetInstance().ReleaseAbilityLink(bundleName, pid);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedCollabManagerTest ReleaseAbilityLink_001 end" << std::endl;
}

/**
 * @tc.name: CancleReleaseAbilityLink_001
 * @tc.desc: test CancleReleaseAbilityLink func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, CancleReleaseAbilityLink_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest CancleReleaseAbilityLink_001 begin" << std::endl;
    const std::string bundleName = "";
    const int32_t pid = 0;
    int32_t ret = DSchedCollabManager::GetInstance().CancleReleaseAbilityLink(bundleName, pid);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedCollabManagerTest CancleReleaseAbilityLink_001 end" << std::endl;
}

/**
 * @tc.name: CleanUpSession_001
 * @tc.desc: test CleanUpSession func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, CleanUpSession_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest CleanUpSession_001 begin" << std::endl;
    const std::string collabToken = "";
    int32_t ret = DSchedCollabManager::GetInstance().CleanUpSession(collabToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollabManagerTest CleanUpSession_001 end" << std::endl;
}

/**
 * @tc.name: GetDSchedCollabByTokenId_001
 * @tc.desc: test GetDSchedCollabByTokenId func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, GetDSchedCollabByTokenId_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest GetDSchedCollabByTokenId_001 begin" << std::endl;
    const std::string collabToken = "";
    auto collab = DSchedCollabManager::GetInstance().GetDSchedCollabByTokenId(collabToken);
    EXPECT_EQ(collab, nullptr);
    DTEST_LOG << "DSchedCollabManagerTest GetDSchedCollabByTokenId_001 end" << std::endl;
}

/**
 * @tc.name: OnDataRecv_001
 * @tc.desc: test OnDataRecv func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, OnDataRecv_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest OnDataRecv_001 begin" << std::endl;
    const int32_t softbusSessionId = 0;
    std::shared_ptr<DSchedDataBuffer> dataBuffer;
    DSchedCollabManager::GetInstance().OnDataRecv(softbusSessionId, dataBuffer);
    EXPECT_EQ(DSchedCollabManager::GetInstance().collabs_.empty(), true);
    DTEST_LOG << "DSchedCollabManagerTest OnDataRecv_001 end" << std::endl;
}

/**
 * @tc.name: OnDataRecv_002
 * @tc.desc: test OnDataRecv func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, OnDataRecv_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest OnDataRecv_002 begin" << std::endl;
    int32_t softbusSessionId = 0;
    size_t sizeL = 20;
    std::shared_ptr<DSchedDataBuffer> dataBuffer = std::make_shared<DSchedDataBuffer>(sizeL);
    DSchedCollabManager::GetInstance().OnDataRecv(softbusSessionId, dataBuffer);
    DTEST_LOG << "DSchedCollabManagerTest OnDataRecv_002 end" << std::endl;
}

/**
 * @tc.name: OnShutdown_001
 * @tc.desc: test OnShutdown func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerTest, OnShutdown_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerTest OnShutdown_001 begin" << std::endl;
    int32_t softbusSessionId = 0;
    DSchedCollabManager::GetInstance().OnShutdown(softbusSessionId, true);
    EXPECT_EQ(DSchedCollabManager::GetInstance().collabs_.empty(), true);
    DSchedCollabManager::GetInstance().OnShutdown(softbusSessionId, false);
    EXPECT_EQ(DSchedCollabManager::GetInstance().collabs_.empty(), true);
    DSchedCollabManager::GetInstance().collabs_.insert(std::make_pair("test1", nullptr));
    const std::string collabToken = "";
    DSchedCollabInfo info;
    auto newCollab = std::make_shared<DSchedCollab>(collabToken, info);
    DSchedCollabManager::GetInstance().collabs_.insert(std::make_pair("test2", newCollab));
    int32_t sessionId = 1;
    auto dCollab = std::make_shared<DSchedCollab>(collabToken, info);
    newCollab->softbusSessionId_ = softbusSessionId;
    DSchedCollabManager::GetInstance().collabs_.insert(std::make_pair("test3", dCollab));
    DSchedCollabManager::GetInstance().OnShutdown(softbusSessionId, false);
    EXPECT_NE(DSchedCollabManager::GetInstance().collabs_.empty(), true);
    DTEST_LOG << "DSchedCollabManagerTest OnShutdown_001 end" << std::endl;
}
}
}
