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

#include "dsched_continue_manager_test.h"

#include "datetime_ex.h"

#include "dtbschedmgr_device_info_storage.h"
#include "distributed_sched_test_util.h"
#include "mission/dsched_sync_e2e.h"
#include "test_log.h"
#include "mock_distributed_sched.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedHardware;

namespace OHOS {
namespace DistributedSchedule {

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

bool DmsBmStorage::GetDistributedBundleInfo(const std::string &networkId,
    const uint16_t &bundleNameId, DmsBundleInfo &distributeBundleInfo)
{
    return g_mockDbs;
}

void DSchedContinueManagerTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    const std::string pkgName = "DBinderBus_PermissionTest" + std::to_string(getprocpid());
    std::shared_ptr<DmInitCallback> initCallback_ = std::make_shared<DeviceInitCallBack>();
    DeviceManager::GetInstance().InitDeviceManager(pkgName, initCallback_);
    dmsStoreMock = std::make_shared<MockDmsMgrDeviceInfoStore>();
    DmsMgrDeviceInfoStore::dmsStore = dmsStoreMock;
    DTEST_LOG << "DSchedContinueManagerTest::SetUpTestCase" << std::endl;
}

void DSchedContinueManagerTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DmsMgrDeviceInfoStore::dmsStore = nullptr;
    dmsStoreMock = nullptr;
    DTEST_LOG << "DSchedContinueManagerTest::TearDownTestCase" << std::endl;
}

void DSchedContinueManagerTest::TearDown()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedContinueManagerTest::TearDown" << std::endl;
}

void DSchedContinueManagerTest::SetUp()
{
    usleep(WAITTIME);
    g_mockDbs = false;
    DTEST_LOG << "DSchedContinueManagerTest::SetUp" << std::endl;
}

void DSchedContinueManagerTest::DeviceInitCallBack::OnRemoteDied()
{
}

sptr<IRemoteObject> DSchedContinueManagerTest::GetDSchedService() const
{
    sptr<IRemoteObject> dsched(new MockDistributedSched());
    return dsched;
}

std::shared_ptr<DSchedContinue> DSchedContinueManagerTest::CreateObject()
{
    int32_t subServiceType = 0;
    int32_t direction = 0;
    sptr<IRemoteObject> callback = nullptr;
    DSchedContinueInfo continueInfo;
    std::shared_ptr<DSchedContinue> dContinue = std::make_shared<DSchedContinue>(subServiceType, direction,
        callback, continueInfo);
    dContinue->Init();
    return dContinue;
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
 * @tc.name: Init_002
 * @tc.desc: test Init func
 * @tc.type: FUNC
 */
    HWTEST_F(DSchedContinueManagerTest, Init_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest Init_002 begin" << std::endl;
    std::vector<std::thread> threads;
    for (int i = 0; i < 10; ++i) {
        threads.emplace_back(std::thread([]() {
            DSchedContinueManager::GetInstance().Init();
        }));
    }
    for (auto &item: threads) {
        if (item.joinable()) {
            item.join();
        }
    }
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler =
            DSchedContinueManager::GetInstance().eventHandler_;
    EXPECT_NE(eventHandler, nullptr);
    DTEST_LOG << "DSchedContinueManagerTest Init_002 end" << std::endl;
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
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    int32_t ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        callback, wantParams);
    EXPECT_EQ(ret, OPERATION_DEVICE_NOT_INITIATOR_OR_TARGET);
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

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true)).WillOnce(Return(true));
    DSchedContinueManager::GetInstance().HandleContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        callback, wantParams);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(false));
    DSchedContinueManager::GetInstance().HandleContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        callback, wantParams);

    int32_t ret = DSchedContinueManager::GetInstance().ContinueMission("", REMOTE_DEVICEID, MISSION_ID,
        callback, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, "", MISSION_ID,
        nullptr, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        nullptr, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
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
    DistributedSchedUtil::MockPermission();
    OHOS::AAFwk::WantParams wantParams;
    int32_t ret = DSchedContinueManager::GetInstance().ContinueMission(
        DSchedContinueInfo("", BUNDLE_NAME, "", BUNDLE_NAME, CONTINUETYPE),
        nullptr, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = DSchedContinueManager::GetInstance().ContinueMission(
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, "", BUNDLE_NAME, CONTINUETYPE),
        nullptr, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    ret = DSchedContinueManager::GetInstance().ContinueMission(
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE),
        nullptr, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    auto callback = GetDSchedService();
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    ret = DSchedContinueManager::GetInstance().ContinueMission(
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE),
        callback, wantParams);
    EXPECT_EQ(ret, OPERATION_DEVICE_NOT_INITIATOR_OR_TARGET);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(LOCAL_DEVICEID), Return(true)));
    ret = DSchedContinueManager::GetInstance().ContinueMission(
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE),
        callback, wantParams);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(REMOTE_DEVICEID), Return(true)));
    ret = DSchedContinueManager::GetInstance().ContinueMission(
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE),
        callback, wantParams);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_003 end" << std::endl;
}

/**
 * @tc.name: HandleContinueMission_001
 * @tc.desc: test HandleContinueMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, HandleContinueMission_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest HandleContinueMission_001 begin" << std::endl;
    OHOS::AAFwk::WantParams wantParams;
    auto callback = GetDSchedService();
    DSchedContinueManager::GetInstance().HandleContinueMission(
        DSchedContinueInfo("", BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE),
        callback, wantParams);
    DSchedContinueManager::GetInstance().HandleContinueMission(
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, "", BUNDLE_NAME, CONTINUETYPE),
        callback, wantParams);
    DSchedContinueManager::GetInstance().HandleContinueMission(
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE),
        nullptr, wantParams);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    DSchedContinueManager::GetInstance().HandleContinueMission(
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE),
        callback, wantParams);
    DTEST_LOG << "DSchedContinueManagerTest HandleContinueMission_001 end" << std::endl;
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
    EXPECT_EQ(ret1, INVALID_REMOTE_PARAMETERS_ERR);
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
    int32_t direction = 0;
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    int32_t ret = DSchedContinueManager::GetInstance().CheckContinuationLimit(LOCAL_DEVICEID, REMOTE_DEVICEID,
        direction);
    EXPECT_EQ(ret, OPERATION_DEVICE_NOT_INITIATOR_OR_TARGET);
    DTEST_LOG << "DSchedContinueManagerTest CheckContinuationLimit_001 end" << std::endl;
}

/**
 * @tc.name: GetContinueInfo_001
 * @tc.desc: test GetContinueInfo func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, GetContinueInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest GetContinueInfo_001 begin" << std::endl;
    std::string localDeviceId = "localdeviceid";
    std::string remoteDeviceId = "remotedeviceid";
    int32_t ret = DSchedContinueManager::GetInstance().GetContinueInfo(localDeviceId, remoteDeviceId);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest GetContinueInfo_001 end" << std::endl;
}

/**
 * @tc.name: GetContinueInfo_002
 * @tc.desc: test GetContinueInfo func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, GetContinueInfo_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest GetContinueInfo_002 begin" << std::endl;
    DSchedContinueManager::GetInstance().OnShutdown(1, true);

    DSchedContinueManager::GetInstance().OnShutdown(1, false);

    DSchedContinueManager::GetInstance().OnShutdown(1, false);

    DSchedContinueInfo info;
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    std::string localDeviceId = "localdeviceid";
    std::string remoteDeviceId = "remotedeviceid";
    DSchedContinueManager::GetInstance().continues_[info] = dContinue;
    int32_t ret = DSchedContinueManager::GetInstance().GetContinueInfo(localDeviceId, remoteDeviceId);
    EXPECT_EQ(ret, ERR_OK);

    DSchedContinueManager::GetInstance().continues_.clear();
    DSchedContinueManager::GetInstance().continues_[info] = nullptr;
    ret = DSchedContinueManager::GetInstance().GetContinueInfo(localDeviceId, remoteDeviceId);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueManagerTest GetContinueInfo_002 end" << std::endl;
}

/**
 * @tc.name: HandleNotifyCompleteContinuation_001
 * @tc.desc: test HandleNotifyCompleteContinuation func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, HandleNotifyCompleteContinuation_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest HandleNotifyCompleteContinuation_001 begin" << std::endl;
    std::u16string devId;
    int32_t missionId = 0;
    std::string callerBundleName;
    DSchedContinueManager::GetInstance().continues_.clear();
    DSchedContinueManager::GetInstance().HandleNotifyCompleteContinuation(devId, missionId, false, callerBundleName);

    DSchedContinueInfo info;
    DSchedContinueManager::GetInstance().continues_[info] = nullptr;
    DSchedContinueManager::GetInstance().HandleNotifyCompleteContinuation(devId, missionId, false, callerBundleName);
    bool ret = DSchedContinueManager::GetInstance().continues_.empty();
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DSchedContinueManagerTest HandleNotifyCompleteContinuation_001 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteContinuation_001
 * @tc.desc: test NotifyCompleteContinuation func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, NotifyCompleteContinuation_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest NotifyCompleteContinuation_001 begin" << std::endl;
    std::u16string devId;
    int32_t sessionId = 0;
    bool isSuccess = false;
    std::string callerBundleName;
    DSchedContinueManager::GetInstance().Init();
    int32_t ret = DSchedContinueManager::GetInstance().NotifyCompleteContinuation(devId,
        sessionId, isSuccess, callerBundleName);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest NotifyCompleteContinuation_001 end" << std::endl;
}

/**
 * @tc.name: OnContinueEnd_001
 * @tc.desc: test OnContinueEnd func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, OnContinueEnd_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest OnContinueEnd_001 begin" << std::endl;
    DSchedContinueInfo info(LOCAL_DEVICEID, "sourceBundleName", REMOTE_DEVICEID, "sinkBundleName",
        "continueType");
    DSchedContinueManager::GetInstance().UnInit();
    int32_t ret = DSchedContinueManager::GetInstance().OnContinueEnd(info);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DSchedContinueManager::GetInstance().Init();

    ret = DSchedContinueManager::GetInstance().OnContinueEnd(info);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest OnContinueEnd_001 end" << std::endl;
}

/**
 * @tc.name: HandleContinueEnd_001
 * @tc.desc: test HandleContinueEnd func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, HandleContinueEnd_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest HandleContinueEnd_001 begin" << std::endl;
    DSchedContinueInfo info(LOCAL_DEVICEID, "sourceBundleName", REMOTE_DEVICEID, "sinkBundleName",
        "continueType");
    DSchedContinueManager::GetInstance().RemoveTimeout(info);

    DSchedContinueManager::GetInstance().Init();
    DSchedContinueManager::GetInstance().RemoveTimeout(info);

    DSchedContinueManager::GetInstance().continues_.clear();
    DSchedContinueManager::GetInstance().HandleContinueEnd(info);
    int32_t ret = DSchedContinueManager::GetInstance().continues_.empty();
    EXPECT_EQ(ret, true);

    std::shared_ptr<DSchedContinue> ptr = nullptr;
    DSchedContinueManager::GetInstance().continues_[info] = ptr;
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(false));
    DSchedContinueManager::GetInstance().HandleContinueEnd(info);

    DSchedContinueManager::GetInstance().continues_[info] = ptr;
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    DSchedContinueManager::GetInstance().HandleContinueEnd(info);
    EXPECT_EQ(DSchedContinueManager::GetInstance().cntSource_, 0);
    DTEST_LOG << "DSchedContinueManagerTest HandleContinueEnd_001 end" << std::endl;
}

/**
 * @tc.name: GetDSchedContinueByWant_001
 * @tc.desc: test GetDSchedContinueByWant func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, GetDSchedContinueByWant_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest GetDSchedContinueByWant_001 begin" << std::endl;
    OHOS::AAFwk::Want want;
    int32_t missionId = 0;
    DSchedContinueManager::GetInstance().continues_.clear();
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    auto ret = DSchedContinueManager::GetInstance().GetDSchedContinueByWant(want, missionId);
    EXPECT_EQ(ret, nullptr);
    DTEST_LOG << "DSchedContinueManagerTest GetDSchedContinueByWant_001 end" << std::endl;
}

/**
 * @tc.name: NotifyTerminateContinuation_001
 * @tc.desc: test NotifyTerminateContinuation func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, NotifyTerminateContinuation_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest NotifyTerminateContinuation_001 begin" << std::endl;
    int32_t missionId = 0;
    int32_t sessionId = 0;
    DSchedContinueManager::GetInstance().continues_.clear();
    DSchedContinueManager::GetInstance().HandleDataRecv(sessionId, nullptr);
    DSchedContinueManager::GetInstance().NotifyTerminateContinuation(missionId);
    EXPECT_EQ(DSchedContinueManager::GetInstance().continues_.empty(), true);
    DTEST_LOG << "DSchedContinueManagerTest NotifyTerminateContinuation_001 end" << std::endl;
}

/**
 * @tc.name: GetFirstBundleName_001
 * @tc.desc: test GetFirstBundleName func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, GetFirstBundleName_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest GetFirstBundleName_001 begin" << std::endl;
    DSchedContinueInfo info;
    std::string firstBundleName;
    std::string bundleName;
    std::string deviceId;
    bool ret = DSchedContinueManager::GetInstance().GetFirstBundleName(info, firstBundleName, bundleName, deviceId);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DSchedContinueManagerTest GetFirstBundleName_001 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_004
 * @tc.desc: test ContinueMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, ContinueMission_004, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_004 begin" << std::endl;
    auto callback = GetDSchedService();
    OHOS::AAFwk::WantParams wantParams;
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(false));
    int32_t ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        callback, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(LOCAL_DEVICEID), Return(true)));
    ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        callback, wantParams);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(REMOTE_DEVICEID), Return(true)));
    ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        callback, wantParams);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_004 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_005
 * @tc.desc: test ContinueMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, ContinueMission_005, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_005 begin" << std::endl;
    auto callback = GetDSchedService();
    OHOS::AAFwk::WantParams wantParams;
    int32_t timeout = 0;
    DSchedContinueManager::GetInstance().WaitAllConnectDecision(CONTINUE_SOURCE,
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE), timeout);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(false));
    int32_t ret = DSchedContinueManager::GetInstance().ContinueMission(
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE),
        callback, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_005 end" << std::endl;
}

/**
 * @tc.name: GetDSchedContinueByWant_002
 * @tc.desc: test GetDSchedContinueByWant func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, GetDSchedContinueByWant_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest GetDSchedContinueByWant_002 begin" << std::endl;
    OHOS::AAFwk::Want want;
    int32_t missionId = 0;
    int32_t callerUid = 0;
    int32_t status = 0;
    uint32_t accessToken = 0;
    DSchedContinueInfo info(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE);
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    DSchedContinueManager::GetInstance().HandleStartContinuation(want, missionId, callerUid, status, accessToken);

    DSchedContinueManager::GetInstance().continues_.clear();
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(false));
    auto ret = DSchedContinueManager::GetInstance().GetDSchedContinueByWant(want, missionId);
    EXPECT_EQ(ret, nullptr);

    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    usleep(WAITTIME);
    DSchedContinueManager::GetInstance().continues_[info] = nullptr;
    DSchedContinueManager::GetInstance().continues_[info] = dContinue;

    DSchedContinueManager::GetInstance().NotifyTerminateContinuation(missionId);
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(true));
    ret = DSchedContinueManager::GetInstance().GetDSchedContinueByWant(want, missionId);
    EXPECT_NE(ret, nullptr);
    DTEST_LOG << "DSchedContinueManagerTest GetDSchedContinueByWant_002 end" << std::endl;
}

/**
 * @tc.name: CheckContinuationLimit_002
 * @tc.desc: test CheckContinuationLimit func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, CheckContinuationLimit_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest CheckContinuationLimit_002 begin" << std::endl;
    int32_t direction = 0;
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(false));
    int32_t ret = DSchedContinueManager::GetInstance().CheckContinuationLimit(LOCAL_DEVICEID, REMOTE_DEVICEID,
        direction);
    EXPECT_EQ(ret, GET_LOCAL_DEVICE_ERR);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(LOCAL_DEVICEID), Return(true)));
    DSchedContinueManager::GetInstance().cntSink_.store(MAX_CONCURRENT_SINK);
    ret = DSchedContinueManager::GetInstance().CheckContinuationLimit(LOCAL_DEVICEID, REMOTE_DEVICEID,
        direction);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(REMOTE_DEVICEID), Return(true)));
    DSchedContinueManager::GetInstance().cntSink_.store(0);
    ret = DSchedContinueManager::GetInstance().CheckContinuationLimit(LOCAL_DEVICEID, REMOTE_DEVICEID,
        direction);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueManagerTest CheckContinuationLimit_002 end" << std::endl;
}

/**
 * @tc.name: NotifyContinueDataRecv_001
 * @tc.desc: test NotifyContinueDataRecv func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, NotifyContinueDataRecv_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest NotifyContinueDataRecv_001 begin" << std::endl;
    int32_t sessionId = 0;
    int32_t command = 0;
    std::string jsonStr = "jsonStr";
    std::shared_ptr<DSchedDataBuffer> dataBuffer = nullptr;
    DSchedContinueManager::GetInstance().continues_.clear();
    DSchedContinueManager::GetInstance().NotifyContinueDataRecv(sessionId, command, jsonStr, dataBuffer);
    EXPECT_EQ(DSchedContinueManager::GetInstance().continues_.empty(), true);
    DTEST_LOG << "DSchedContinueManagerTest NotifyContinueDataRecv_001 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_006
 * @tc.desc: test ContinueMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, ContinueMission_006, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_006 begin" << std::endl;
    DSchedContinueManager::GetInstance(). eventHandler_ = nullptr;
    auto callback = GetDSchedService();
    OHOS::AAFwk::WantParams wantParams;
    std::shared_ptr<DmsDeviceInfo> ptr = std::make_shared<DmsDeviceInfo>("", 0, "");
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(REMOTE_DEVICEID), Return(true)));
    EXPECT_CALL(*dmsStoreMock, GetDeviceInfoById(_)).WillOnce(Return(ptr));
    int32_t ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        callback, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(REMOTE_DEVICEID), Return(true)));
    EXPECT_CALL(*dmsStoreMock, GetDeviceInfoById(_)).WillOnce(Return(ptr));
    ret = DSchedContinueManager::GetInstance().ContinueMission(
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE),
        callback, wantParams);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_006 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_007
 * @tc.desc: test ContinueMission func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, ContinueMission_007, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_007 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create(false);
    DSchedContinueManager::GetInstance().eventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    auto callback = GetDSchedService();
    OHOS::AAFwk::WantParams wantParams;
    std::shared_ptr<DmsDeviceInfo> ptr = std::make_shared<DmsDeviceInfo>("", 0, "");
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(REMOTE_DEVICEID), Return(true)));
    EXPECT_CALL(*dmsStoreMock, GetDeviceInfoById(_)).WillOnce(Return(ptr));
    int32_t ret = DSchedContinueManager::GetInstance().ContinueMission(LOCAL_DEVICEID, REMOTE_DEVICEID, MISSION_ID,
        callback, wantParams);
    EXPECT_EQ(ret, ERR_OK);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(REMOTE_DEVICEID), Return(true)));
    EXPECT_CALL(*dmsStoreMock, GetDeviceInfoById(_)).WillOnce(Return(ptr));
    ret = DSchedContinueManager::GetInstance().ContinueMission(
        DSchedContinueInfo(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE),
        callback, wantParams);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest ContinueMission_007 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_002
 * @tc.desc: test StartContinuation func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, StartContinuation_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest StartContinuation_002 begin" << std::endl;
    OHOS::AAFwk::Want want;
    int32_t missionId = 0;
    int32_t callerUid = 0;
    int32_t status = 0;
    uint32_t accessToken = 0;
    DSchedContinueInfo info(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    std::shared_ptr<DmsDeviceInfo> ptr = std::make_shared<DmsDeviceInfo>("", 0, "");
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(Return(false));
    EXPECT_CALL(*dmsStoreMock, GetDeviceInfoById(_)).WillOnce(Return(ptr));
    int32_t ret = DSchedContinueManager::GetInstance().StartContinuation(want, missionId,
        callerUid, status, accessToken);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueManagerTest StartContinuation_002 end" << std::endl;
}

/**
 * @tc.name: HandleDataRecv_001
 * @tc.desc: test HandleDataRecv func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, HandleDataRecv_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest HandleDataRecv_001 begin" << std::endl;
    std::shared_ptr<DSchedDataBuffer> dataBuffer = std::make_shared<DSchedDataBuffer>(SIZE);
    EXPECT_NO_FATAL_FAILURE(DSchedContinueManager::GetInstance().HandleDataRecv(1, dataBuffer));
    DTEST_LOG << "DSchedContinueManagerTest HandleDataRecv_001 end" << std::endl;
}

/**
 * @tc.name: NotifyContinueDataRecv_002
 * @tc.desc: test NotifyContinueDataRecv func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, NotifyContinueDataRecv_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest NotifyContinueDataRecv_002 begin" << std::endl;
    int32_t sessionId = -1;
    int32_t command = 0;
    std::string jsonStr = "jsonStr";
    DSchedContinueInfo info(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    DSchedContinueManager::GetInstance().continues_.clear();
    DSchedContinueManager::GetInstance().continues_[info] = nullptr;
    DSchedContinueManager::GetInstance().continues_[info] = dContinue;
    std::shared_ptr<DSchedDataBuffer> dataBuffer = nullptr;
    DSchedContinueManager::GetInstance().NotifyContinueDataRecv(sessionId, command, jsonStr, dataBuffer);
    EXPECT_NE(DSchedContinueManager::GetInstance().continues_.empty(), true);

    EXPECT_NO_FATAL_FAILURE(DSchedContinueManager::GetInstance().OnShutdown(1, false));
    DTEST_LOG << "DSchedContinueManagerTest NotifyContinueDataRecv_002 end" << std::endl;
}

/**
 * @tc.name: NotifyContinueDataRecv_003
 * @tc.desc: test NotifyContinueDataRecv func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, NotifyContinueDataRecv_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest NotifyContinueDataRecv_003 begin" << std::endl;
    int32_t sessionId = -1;
    int32_t command = DSCHED_CONTINUE_CMD_START;
    DmsKvSyncE2E::GetInstance()->isMDMControl_ = false;
    std::string jsonStr = "jsonStr";
    DSchedContinueInfo info(LOCAL_DEVICEID, BUNDLE_NAME, REMOTE_DEVICEID, BUNDLE_NAME, CONTINUETYPE);
    std::shared_ptr<DSchedContinue> dContinue = CreateObject();
    DSchedContinueManager::GetInstance().continues_.clear();
    DSchedContinueManager::GetInstance().continues_[info] = nullptr;
    DSchedContinueManager::GetInstance().continues_[info] = dContinue;
    std::shared_ptr<DSchedDataBuffer> dataBuffer = nullptr;
    DSchedContinueManager::GetInstance().NotifyContinueDataRecv(sessionId, command, jsonStr, dataBuffer);
    EXPECT_NE(DSchedContinueManager::GetInstance().continues_.empty(), true);
    DmsKvSyncE2E::GetInstance()->isMDMControl_ = true;
    DSchedContinueManager::GetInstance().NotifyContinueDataRecv(sessionId, command, jsonStr, dataBuffer);
    EXPECT_NE(DSchedContinueManager::GetInstance().continues_.empty(), true);
    EXPECT_NO_FATAL_FAILURE(DSchedContinueManager::GetInstance().OnShutdown(1, false));
    DTEST_LOG << "DSchedContinueManagerTest NotifyContinueDataRecv_003 end" << std::endl;
}

/**
 * @tc.name: CheckContinuationLimit_003
 * @tc.desc: test CheckContinuationLimit func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, CheckContinuationLimit_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest CheckContinuationLimit_003 begin" << std::endl;
    int32_t direction = 0;
    std::shared_ptr<DmsDeviceInfo> ptr = std::make_shared<DmsDeviceInfo>("", 0, "");
    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(LOCAL_DEVICEID), Return(true)));
    EXPECT_CALL(*dmsStoreMock, GetDeviceInfoById(_)).WillOnce(Return(ptr));
    DSchedContinueManager::GetInstance().cntSink_.store(MAX_CONCURRENT_SINK);
    int32_t ret = DSchedContinueManager::GetInstance().CheckContinuationLimit(LOCAL_DEVICEID, REMOTE_DEVICEID,
        direction);
    EXPECT_EQ(ret, ERR_OK);

    EXPECT_CALL(*dmsStoreMock, GetLocalDeviceId(_)).WillOnce(DoAll(SetArgReferee<0>(REMOTE_DEVICEID), Return(true)));
    EXPECT_CALL(*dmsStoreMock, GetDeviceInfoById(_)).WillOnce(Return(ptr));
    DSchedContinueManager::GetInstance().cntSink_.store(0);
    ret = DSchedContinueManager::GetInstance().CheckContinuationLimit(LOCAL_DEVICEID, REMOTE_DEVICEID,
        direction);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest CheckContinuationLimit_003 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteContinuation_002
 * @tc.desc: test NotifyCompleteContinuation func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, NotifyCompleteContinuation_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest NotifyCompleteContinuation_002 begin" << std::endl;
    DSchedContinueManager::GetInstance(). eventHandler_ = nullptr;
    DSchedContinueInfo info;
    DSchedContinueManager::GetInstance().SetTimeOut(info, 0);
    DSchedContinueManager::GetInstance().RemoveTimeout(info);
    DSchedContinueManager::GetInstance().OnDataRecv(0, nullptr);
    DSchedContinueManager::GetInstance().OnShutdown(1, false);

    std::u16string devId = u"testDevId";
    int32_t ret = DSchedContinueManager::GetInstance().NotifyCompleteContinuation(devId, 0, false, "");
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueManagerTest NotifyCompleteContinuation_002 end" << std::endl;
}

/**
 * @tc.name: GetFirstBundleName_002
 * @tc.desc: test GetFirstBundleName func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, GetFirstBundleName_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest GetFirstBundleName_002 begin" << std::endl;
    DSchedContinueInfo info;
    std::string firstBundleName;
    std::string bundleName;
    std::string deviceId;
    g_mockDbs = true;
    bool ret = DSchedContinueManager::GetInstance().GetFirstBundleName(info, firstBundleName, bundleName, deviceId);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DSchedContinueManagerTest GetFirstBundleName_002 end" << std::endl;
}

/**
 * @tc.name: ContinueStateCallbackRegister_001
 * @tc.desc: test ContinueStateCallbackRegister func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, ContinueStateCallbackRegister_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest ContinueStateCallbackRegister_001 begin" << std::endl;
    StateCallbackInfo stateCallbackInfo;
    stateCallbackInfo.missionId = 1;
    stateCallbackInfo.bundleName = "bundleName";
    stateCallbackInfo.moduleName = "moduleName";
    stateCallbackInfo.abilityName = "abilityName";

    auto callback = GetDSchedService();

    int32_t ret = DSchedContinueManager::GetInstance().ContinueStateCallbackRegister(
        stateCallbackInfo, callback);
    EXPECT_EQ(ret, ERR_OK);

    DSchedContinueManager::GetInstance().stateCallbackCache_[stateCallbackInfo].state = 1;
    ret = DSchedContinueManager::GetInstance().ContinueStateCallbackRegister(
        stateCallbackInfo, callback);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest ContinueStateCallbackRegister_001 end" << std::endl;
}

/**
 * @tc.name: ContinueStateCallbackUnRegister_001
 * @tc.desc: test ContinueStateCallbackUnRegister func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, ContinueStateCallbackUnRegister_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest ContinueStateCallbackUnRegister_001 begin" << std::endl;
    StateCallbackInfo stateCallbackInfo;
    stateCallbackInfo.missionId = 1;
    stateCallbackInfo.bundleName = "bundleName";
    stateCallbackInfo.moduleName = "moduleName";
    stateCallbackInfo.abilityName = "abilityName";

    int32_t ret = DSchedContinueManager::GetInstance().ContinueStateCallbackUnRegister(
        stateCallbackInfo);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueManagerTest ContinueStateCallbackUnRegister_001 end" << std::endl;
}

/**
 * @tc.name: NotifyQuickStartState_001
 * @tc.desc: test NotifyQuickStartState func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueManagerTest, NotifyQuickStartState_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinueManagerTest NotifyQuickStartState_001 begin" << std::endl;
    StateCallbackInfo stateCallbackInfo;
    stateCallbackInfo.missionId = 2;
    stateCallbackInfo.bundleName = "bundleName";
    stateCallbackInfo.moduleName = "moduleName";
    stateCallbackInfo.abilityName = "abilityName";

    std::string testMessage = "testMessage";

    int32_t ret = DSchedContinueManager::GetInstance().NotifyQuickStartState(
        stateCallbackInfo, 0, testMessage);
    EXPECT_EQ(ret, ERR_OK);

    ret = DSchedContinueManager::GetInstance().NotifyQuickStartState(
        stateCallbackInfo, 0, testMessage);
    EXPECT_EQ(ret, ERR_OK);

    DSchedContinueManager::GetInstance().stateCallbackCache_[stateCallbackInfo].remoteObject = GetDSchedService();
    ret = DSchedContinueManager::GetInstance().NotifyQuickStartState(
        stateCallbackInfo, 0, testMessage);
    EXPECT_EQ(ret, ERR_OK);

    DTEST_LOG << "DSchedContinueManagerTest NotifyQuickStartState_001 end" << std::endl;
}
}
}
