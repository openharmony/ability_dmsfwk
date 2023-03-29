/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "dms_mission_manager_test.h"
#include "distributed_sched_proxy.h"
#include "distributed_sched_service.h"
#include "distributed_sched_util.h"
#include "dtbschedmgr_device_info_storage.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "mission/distributed_sched_mission_manager.h"
#include "mission/mission_constant.h"
#include "mission/snapshot_converter.h"
#include "string_ex.h"
#include "system_ability_definition.h"
#include "test_log.h"
#undef private
#undef protected

#include <thread>
using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedHardware;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string DEVICE_NAME = "DEVICE_PHONE_001";
const std::string DEVICE_ID = "123456789ABCD";
const std::u16string U16DEVICE_ID = u"123456789ABCD";
const std::string BUNDLE_NAME = "ohos.test.test";
constexpr int32_t TASK_ID = 11;
constexpr size_t BYTESTREAM_LENGTH = 100;
constexpr uint8_t ONE_BYTE = '6';
const int32_t NUM_MISSIONS = 100;
const int32_t NORMAL_NUM_MISSIONS = 10;
constexpr int32_t REQUEST_CODE_ERR = 305;
constexpr int32_t MAX_WAIT_TIME = 1000;
}

bool DMSMissionManagerTest::isCaseDone_ = false;
std::mutex DMSMissionManagerTest::caseDoneLock_;
std::condition_variable DMSMissionManagerTest::caseDoneCondition_;

void DMSMissionManagerTest::SetUpTestCase()
{
    if (!DistributedSchedUtil::LoadDistributedSchedService()) {
        DTEST_LOG << "DMSMissionManagerTest::SetUpTestCase LoadDistributedSchedService failed" << std::endl;
    }
    const std::string pkgName = "DBinderBus_" + std::to_string(getpid());
    std::shared_ptr<DmInitCallback> initCallback_ = std::make_shared<DeviceInitCallBack>();
    DeviceManager::GetInstance().InitDeviceManager(pkgName, initCallback_);
}

void DMSMissionManagerTest::TearDownTestCase()
{
}

void DMSMissionManagerTest::SetUp()
{
    DistributedSchedUtil::MockPermission();
    string localDeviceId;
    if (!DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId)) {
        DTEST_LOG << "getLocalDevicesId failed!" << std::endl;
        return;
    }
    localDeviceId_ = localDeviceId;
    u16localDeviceId_ = Str8ToStr16(localDeviceId);
}

void DMSMissionManagerTest::TearDown()
{
}

void DMSMissionManagerTest::DeviceInitCallBack::OnRemoteDied()
{
}

sptr<IDistributedSched> DMSMissionManagerTest::GetDms()
{
    if (proxy_ != nullptr) {
        return proxy_;
    }
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_TRUE(sm != nullptr);
    if (sm == nullptr) {
        DTEST_LOG << "DMSMissionManagerTest sm is nullptr" << std::endl;
        return nullptr;
    }
    DTEST_LOG << "DMSMissionManagerTest sm is not nullptr" << std::endl;
    auto distributedObject = sm->GetSystemAbility(DISTRIBUTED_SCHED_SA_ID);
    proxy_ = iface_cast<IDistributedSched>(distributedObject);
    if (proxy_ == nullptr) {
        DTEST_LOG << "DMSMissionManagerTest DistributedSched is nullptr" << std::endl;
    } else {
        DTEST_LOG << "DMSMissionManagerTest DistributedSched is not nullptr" << std::endl;
    }
    return proxy_;
}

void RemoteMissionListenerTest::NotifyMissionsChanged(const std::string& deviceId)
{
    DTEST_LOG << "NotifyMissionsChanged" << std::endl;
}

void RemoteMissionListenerTest::NotifySnapshot(const std::string& deviceId, int32_t missionId)
{
    DTEST_LOG << "NotifySnapshot" << std::endl;
}

void RemoteMissionListenerTest::NotifyNetDisconnect(const std::string& deviceId, int32_t state)
{
    DTEST_LOG << "NotifyNetDisconnect" << std::endl;
}

/**
 * @tc.name: testGetRemoteMissionInfo001
 * @tc.desc: get remote mission info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetRemoteMissionInfo001, TestSize.Level1)
{
    std::vector<AAFwk::MissionInfo> infos;
    auto ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(DEVICE_ID, 0, infos);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(localDeviceId_, 0, infos);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos("", 0, infos);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(DEVICE_ID, -1, infos);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(localDeviceId_, -1, infos);
    EXPECT_TRUE(ret != ERR_NONE);
}

/**
 * @tc.name: testGetRemoteMissionInfo002
 * @tc.desc: get remote mission info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetRemoteMissionInfo002, TestSize.Level1)
{
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    std::vector<AAFwk::MissionInfo> infos;
    auto ret = proxy->GetMissionInfos(DEVICE_ID, 0, infos);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->GetMissionInfos(localDeviceId_, 0, infos);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->GetMissionInfos("", 0, infos);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->GetMissionInfos(DEVICE_ID, -1, infos);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->GetMissionInfos(localDeviceId_, -1, infos);
    EXPECT_TRUE(ret != ERR_NONE);
}

/**
 * @tc.name: testStartSyncRemoteMissions001
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions001, TestSize.Level1)
{
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    auto ret = proxy->StartSyncRemoteMissions(DEVICE_ID, false, 0);
    EXPECT_NE(ret, ERR_NONE);
}

/**
 * @tc.name: testStartSyncRemoteMissions002
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions002, TestSize.Level1)
{
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    auto ret = proxy->StartSyncRemoteMissions("", false, 0);
    EXPECT_NE(ret, ERR_NONE);
}

/**
 * @tc.name: testStartSyncRemoteMissions003
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions003, TestSize.Level1)
{
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    auto ret = proxy->StartSyncRemoteMissions(localDeviceId_, false, 0);
    EXPECT_NE(ret, ERR_NONE);
}

/**
 * @tc.name: testStartSyncRemoteMissions004
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions004, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions004 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions(DEVICE_ID, false, 0);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions004 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions005
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions005, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions005 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions("", false, 0);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions005 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions006
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions006, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions006 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions(localDeviceId_, false, 0);
    EXPECT_NE(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions006 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions007
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions007, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions007 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions(DEVICE_ID, true, 0);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions007 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions008
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions008, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions008 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions("", true, 0);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions008 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions009
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions009, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions009 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions(localDeviceId_, true, 0);
    EXPECT_NE(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions009 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions010
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions010, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions010 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions(DEVICE_ID, true, 1);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions010 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions011
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions011, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions011 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions("", true, 1);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions011 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions012
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions012, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions012 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions(localDeviceId_, true, 1);
    EXPECT_NE(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions012 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions013
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions013, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions013 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions(DEVICE_ID, localDeviceId_);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions013 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions014
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions014, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions014 begin" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions(DEVICE_ID, proxy);
    EXPECT_NE(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions014 end" << std::endl;
}

/**
 * @tc.name: testNeedSyncDevice001
 * @tc.desc: need sync device
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNeedSyncDevice001, TestSize.Level3)
{
    DTEST_LOG << "testCleanMissionResources001 begin" << std::endl;
    bool ret = DistributedSchedMissionManager::GetInstance().NeedSyncDevice(DEVICE_ID);
    EXPECT_FALSE(ret);
    DTEST_LOG << "testNeedSyncDevice001 end" << std::endl;
}

/**
 * @tc.name: testNeedSyncDevice002
 * @tc.desc: need sync device
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNeedSyncDevice002, TestSize.Level3)
{
    DTEST_LOG << "testNeedSyncDevice002 begin" << std::endl;
    remoteSyncDeviceSet_.emplace(DEVICE_ID);
    bool ret = DistributedSchedMissionManager::GetInstance().NeedSyncDevice(DEVICE_ID);
    EXPECT_FALSE(ret);
    DTEST_LOG << "testNeedSyncDevice002 end" << std::endl;
}

/**
 * @tc.name: testHasSyncListener001
 * @tc.desc: need sync device
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testHasSyncListener001, TestSize.Level3)
{
    DTEST_LOG << "testHasSyncListener001 begin" << std::endl;
    bool ret = DistributedSchedMissionManager::GetInstance().HasSyncListener(DEVICE_ID);
    EXPECT_FALSE(ret);
    DTEST_LOG << "testHasSyncListener001 end" << std::endl;
}

/**
 * @tc.name: testCleanMissionResources001
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testCleanMissionResources001, TestSize.Level3)
{
    DTEST_LOG << "testCleanMissionResources001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().CleanMissionResources(DEVICE_ID);
    DTEST_LOG << "testCleanMissionResources001 end" << std::endl;
}

/**
 * @tc.name: testStopSyncRemoteMissions001
 * @tc.desc: stop sync missions from remote with fake deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions001, TestSize.Level1)
{
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    auto ret = proxy->StopSyncRemoteMissions(DEVICE_ID);
    EXPECT_NE(ret, ERR_NONE);
}

/**
 * @tc.name: testStopSyncRemoteMissions002
 * @tc.desc: stop sync missions from remote with local deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions002, TestSize.Level1)
{
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    auto ret = proxy->StopSyncRemoteMissions(localDeviceId_);
    EXPECT_NE(ret, ERR_NONE);
}

/**
 * @tc.name: testStopSyncRemoteMissions003
 * @tc.desc: stop sync missions from remote with empty deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions003, TestSize.Level1)
{
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    auto ret = proxy->StopSyncRemoteMissions("");
    EXPECT_NE(ret, ERR_NONE);
}

/**
 * @tc.name: testStopSyncRemoteMissions004
 * @tc.desc: stop sync missions from remote with empty deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions004, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncRemoteMissions004 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StopSyncRemoteMissions("", false, true);
    EXPECT_NE(ret, ERR_NONE);
    DTEST_LOG << "testStopSyncRemoteMissions004 end" << std::endl;
}

/**
 * @tc.name: testStopSyncRemoteMissions005
 * @tc.desc: stop sync missions from remote with local deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions005, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncRemoteMissions005 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StopSyncRemoteMissions(localDeviceId_, false, true);
    EXPECT_NE(ret, ERR_NONE);
    DTEST_LOG << "testStopSyncRemoteMissions005 end" << std::endl;
}

/**
 * @tc.name: testStopSyncRemoteMissions006
 * @tc.desc: stop sync missions from remote with deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions006, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncRemoteMissions006 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StopSyncRemoteMissions(DEVICE_ID, false, true);
    EXPECT_NE(ret, ERR_NONE);
    DTEST_LOG << "testStopSyncRemoteMissions006 end" << std::endl;
}

/**
 * @tc.name: testStopSyncRemoteMissions007
 * @tc.desc: stop sync missions from remote with empty deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions007, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncRemoteMissions007 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StopSyncRemoteMissions("", true, true);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStopSyncRemoteMissions007 end" << std::endl;
}

/**
 * @tc.name: testStopSyncRemoteMissions008
 * @tc.desc: stop sync missions from remote with local deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions008, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncRemoteMissions008 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StopSyncRemoteMissions(localDeviceId_, true, true);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStopSyncRemoteMissions008 end" << std::endl;
}

/**
 * @tc.name: testStopSyncRemoteMissions009
 * @tc.desc: stop sync missions from remote with deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions009, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncRemoteMissions009 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StopSyncRemoteMissions(DEVICE_ID, true, true);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStopSyncRemoteMissions009 end" << std::endl;
}

/**
 * @tc.name: testStopSyncRemoteMissions010
 * @tc.desc: stop sync missions from remote with empty deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions010, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncRemoteMissions010 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StopSyncRemoteMissions("", true, false);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStopSyncRemoteMissions010 end" << std::endl;
}

/**
 * @tc.name: testStopSyncRemoteMissions011
 * @tc.desc: stop sync missions from remote with local deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions011, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncRemoteMissions011 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StopSyncRemoteMissions(localDeviceId_, true, false);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStopSyncRemoteMissions011 end" << std::endl;
}

/**
 * @tc.name: testStopSyncRemoteMissions012
 * @tc.desc: stop sync missions from remote with deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions012, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncRemoteMissions012 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StopSyncRemoteMissions(DEVICE_ID, true, false);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStopSyncRemoteMissions012 end" << std::endl;
}

/**
 * @tc.name: testRegisterMissionListener001
 * @tc.desc: register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRegisterMissionListener001, TestSize.Level1)
{
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    auto ret = proxy->RegisterMissionListener(U16DEVICE_ID, nullptr);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->RegisterMissionListener(u16localDeviceId_, nullptr);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->RegisterMissionListener(u"", nullptr);
    EXPECT_TRUE(ret != ERR_NONE);
}

/**
 * @tc.name: testRegisterMissionListener002
 * @tc.desc: register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRegisterMissionListener002, TestSize.Level1)
{
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    auto ret = proxy->RegisterMissionListener(U16DEVICE_ID, listener);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->RegisterMissionListener(u16localDeviceId_, listener);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->RegisterMissionListener(u"", listener);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->UnRegisterMissionListener(U16DEVICE_ID, listener);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->UnRegisterMissionListener(u16localDeviceId_, listener);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->UnRegisterMissionListener(u"", listener);
    EXPECT_TRUE(ret != ERR_NONE);
}

/**
 * @tc.name: testRegisterMissionListener003
 * @tc.desc: test register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRegisterMissionListener003, TestSize.Level3)
{
    DTEST_LOG << "testRegisterMissionListener003 begin" << std::endl;
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    auto ret = DistributedSchedMissionManager::GetInstance().RegisterMissionListener(u"", listener);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testRegisterMissionListener003 end" << std::endl;
}

/**
 * @tc.name: testRegisterMissionListener004
 * @tc.desc: test register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRegisterMissionListener004, TestSize.Level3)
{
    DTEST_LOG << "testRegisterMissionListener004 begin" << std::endl;
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    auto ret = DistributedSchedMissionManager::GetInstance().RegisterMissionListener(U16DEVICE_ID, listener);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testRegisterMissionListener004 end" << std::endl;
}

/**
 * @tc.name: testRegisterMissionListener005
 * @tc.desc: test register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRegisterMissionListener005, TestSize.Level3)
{
    DTEST_LOG << "testRegisterMissionListener005 begin" << std::endl;
    sptr<IRemoteObject> listener = nullptr;
    auto ret = DistributedSchedMissionManager::GetInstance().RegisterMissionListener(u"", listener);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testRegisterMissionListener005 end" << std::endl;
}

/**
 * @tc.name: testRegisterMissionListener006
 * @tc.desc: test register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRegisterMissionListener006, TestSize.Level3)
{
    DTEST_LOG << "testRegisterMissionListener006 begin" << std::endl;
    sptr<IRemoteObject> listener = nullptr;
    auto ret = DistributedSchedMissionManager::GetInstance().RegisterMissionListener(U16DEVICE_ID, listener);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testRegisterMissionListener006 end" << std::endl;
}

/**
 * @tc.name: testRegisterMissionListener007
 * @tc.desc: test register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRegisterMissionListener007, TestSize.Level3)
{
    DTEST_LOG << "testRegisterMissionListener007 begin" << std::endl;
    u16string deviceId = Str8ToStr16(localDeviceId_);
    sptr<IRemoteObject> listener = nullptr;
    auto ret = DistributedSchedMissionManager::GetInstance().RegisterMissionListener(deviceId, listener);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testRegisterMissionListener007 end" << std::endl;
}

/**
 * @tc.name: testRegisterMissionListener008
 * @tc.desc: test register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRegisterMissionListener008, TestSize.Level3)
{
    DTEST_LOG << "testRegisterMissionListener008 begin" << std::endl;
    u16string deviceId = Str8ToStr16(localDeviceId_);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    auto ret = DistributedSchedMissionManager::GetInstance().RegisterMissionListener(deviceId, listener);
    EXPECT_TRUE(ret == INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testRegisterMissionListener008 end" << std::endl;
}

/**
 * @tc.name: testUnRegisterMissionListener001
 * @tc.desc: register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testUnRegisterMissionListener001, TestSize.Level1)
{
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    auto ret = proxy->UnRegisterMissionListener(U16DEVICE_ID, nullptr);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->UnRegisterMissionListener(u16localDeviceId_, nullptr);
    EXPECT_TRUE(ret != ERR_NONE);

    ret = proxy->UnRegisterMissionListener(u"", nullptr);
    EXPECT_TRUE(ret != ERR_NONE);
}

/**
 * @tc.name: testUnRegisterMissionListener002
 * @tc.desc: register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testUnRegisterMissionListener002, TestSize.Level3)
{
    DTEST_LOG << "testUnRegisterMissionListener002 begin" << std::endl;
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    auto ret = DistributedSchedMissionManager::GetInstance().UnRegisterMissionListener(U16DEVICE_ID, listener);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testUnRegisterMissionListener002 end" << std::endl;
}

/**
 * @tc.name: testUnRegisterMissionListener003
 * @tc.desc: register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testUnRegisterMissionListener003, TestSize.Level3)
{
    DTEST_LOG << "testUnRegisterMissionListener003 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().UnRegisterMissionListener(U16DEVICE_ID, nullptr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testUnRegisterMissionListener003 end" << std::endl;
}

/**
 * @tc.name: testUnRegisterMissionListener004
 * @tc.desc: register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testUnRegisterMissionListener004, TestSize.Level3)
{
    DTEST_LOG << "testUnRegisterMissionListener004 begin" << std::endl;
    u16string deviceId = Str8ToStr16(localDeviceId_);
    auto ret = DistributedSchedMissionManager::GetInstance().UnRegisterMissionListener(deviceId, nullptr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testUnRegisterMissionListener004 end" << std::endl;
}

/**
 * @tc.name: testUnRegisterMissionListener005
 * @tc.desc: register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testUnRegisterMissionListener005, TestSize.Level3)
{
    DTEST_LOG << "testUnRegisterMissionListener005 begin" << std::endl;
    u16string deviceId = Str8ToStr16(localDeviceId_);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    auto ret = DistributedSchedMissionManager::GetInstance().UnRegisterMissionListener(deviceId, listener);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testUnRegisterMissionListener005 end" << std::endl;
}

/**
 * @tc.name: testIsDeviceIdValidated001
 * @tc.desc: judging whether the deviceId is valid
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testIsDeviceIdValidated001, TestSize.Level1)
{
    std::string emptyDeviceId = "";
    auto ret = DistributedSchedMissionManager::GetInstance().IsDeviceIdValidated(emptyDeviceId);
    EXPECT_FALSE(ret);

    ret = DistributedSchedMissionManager::GetInstance().IsDeviceIdValidated(DEVICE_ID);
    EXPECT_FALSE(ret);

    ret = DistributedSchedMissionManager::GetInstance().IsDeviceIdValidated(localDeviceId_);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: testGetMissionInfos001
 * @tc.desc: get missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetMissionInfos001, TestSize.Level1)
{
    std::string deviceid = DEVICE_ID;
    int32_t numMissions = NUM_MISSIONS;
    std::vector<AAFwk::MissionInfo> missionInfos;

    auto ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(deviceid, numMissions, missionInfos);
    EXPECT_TRUE(ret != ERR_NONE);
}

/**
 * @tc.name: testGetMissionInfos002
 * @tc.desc: get missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetMissionInfos002, TestSize.Level3)
{
    DTEST_LOG << "testGetMissionInfos002 begin" << std::endl;
    std::string deviceid = localDeviceId_;
    int32_t numMissions = NUM_MISSIONS;
    std::vector<AAFwk::MissionInfo> missionInfos;

    auto ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(deviceid, numMissions, missionInfos);
    EXPECT_TRUE(ret != ERR_NONE);
    DTEST_LOG << "testGetMissionInfos002 end" << std::endl;
}

/**
 * @tc.name: testGetMissionInfos003
 * @tc.desc: get missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetMissionInfos003, TestSize.Level3)
{
    DTEST_LOG << "testGetMissionInfos003 begin" << std::endl;
    std::string deviceid = "";
    int32_t numMissions = NUM_MISSIONS;
    std::vector<AAFwk::MissionInfo> missionInfos;

    auto ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(deviceid, numMissions, missionInfos);
    EXPECT_TRUE(ret != ERR_NONE);
    DTEST_LOG << "testGetMissionInfos003 end" << std::endl;
}

/**
 * @tc.name: testGetMissionInfos004
 * @tc.desc: get missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetMissionInfos004, TestSize.Level3)
{
    DTEST_LOG << "testGetMissionInfos004 begin" << std::endl;
    std::string deviceid = DEVICE_ID;
    int32_t numMissions = -1;
    std::vector<AAFwk::MissionInfo> missionInfos;
    auto ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(deviceid, numMissions, missionInfos);
    EXPECT_TRUE(ret == INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testGetMissionInfos004 end" << std::endl;
}

/**
 * @tc.name: testGetMissionInfos005
 * @tc.desc: get missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetMissionInfos005, TestSize.Level3)
{
    DTEST_LOG << "testGetMissionInfos005 begin" << std::endl;
    std::string deviceid = "";
    int32_t numMissions = NUM_MISSIONS;
    std::vector<AAFwk::MissionInfo> missionInfos;
    auto ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(deviceid, numMissions, missionInfos);
    EXPECT_TRUE(ret == INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testGetMissionInfos005 end" << std::endl;
}

/**
 * @tc.name: testGetMissionInfos006
 * @tc.desc: get missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetMissionInfos006, TestSize.Level3)
{
    DTEST_LOG << "testGetMissionInfos006 begin" << std::endl;
    std::string deviceid = "";
    int32_t numMissions = 0;
    std::vector<AAFwk::MissionInfo> missionInfos;
    auto ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(deviceid, numMissions, missionInfos);
    EXPECT_TRUE(ret == INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testGetMissionInfos006 end" << std::endl;
}

/**
 * @tc.name: testFetchCachedRemoteMissions001
 * @tc.desc: test stop fake device, return error code
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchCachedRemoteMissions001, TestSize.Level1)
{
    std::vector<DstbMissionInfo> infos;
    auto ret = DistributedSchedMissionManager::GetInstance().FetchCachedRemoteMissions(DEVICE_ID, 0, infos);
    EXPECT_TRUE(ret != ERR_NONE);
}

/**
 * @tc.name: testFetchCachedRemoteMissions002
 * @tc.desc: test empty deviceId, return error code
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchCachedRemoteMissions002, TestSize.Level3)
{
    DTEST_LOG << "testFetchCachedRemoteMissions002 begin" << std::endl;
    std::vector<DstbMissionInfo> infos;
    auto ret = DistributedSchedMissionManager::GetInstance().FetchCachedRemoteMissions("", 0, infos);
    EXPECT_TRUE(ret == INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testFetchCachedRemoteMissions002 end" << std::endl;
}

/**
 * @tc.name: testFetchCachedRemoteMissions003
 * @tc.desc: test local deviceId, return error code
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchCachedRemoteMissions003, TestSize.Level3)
{
    DTEST_LOG << "testFetchCachedRemoteMissions003 begin" << std::endl;
    std::vector<DstbMissionInfo> infos;
    auto ret = DistributedSchedMissionManager::GetInstance().FetchCachedRemoteMissions(localDeviceId_, 0, infos);
    EXPECT_TRUE(ret == ERR_NULL_OBJECT);
    DTEST_LOG << "testFetchCachedRemoteMissions003 end" << std::endl;
}

/**
 * @tc.name: testFetchCachedRemoteMissions004
 * @tc.desc: test stop fake device, return error code
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchCachedRemoteMissions004, TestSize.Level3)
{
    DTEST_LOG << "testFetchCachedRemoteMissions004 begin" << std::endl;
    std::vector<DstbMissionInfo> infos;
    auto ret = DistributedSchedMissionManager::GetInstance().FetchCachedRemoteMissions(DEVICE_ID, NUM_MISSIONS, infos);
    EXPECT_TRUE(ret != ERR_NONE);
    DTEST_LOG << "testFetchCachedRemoteMissions004 end" << std::endl;
}

/**
 * @tc.name: testFetchCachedRemoteMissions005
 * @tc.desc: test empty deviceId, return error code
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchCachedRemoteMissions005, TestSize.Level3)
{
    DTEST_LOG << "testFetchCachedRemoteMissions005 begin" << std::endl;
    std::vector<DstbMissionInfo> infos;
    auto ret = DistributedSchedMissionManager::GetInstance().FetchCachedRemoteMissions("", NUM_MISSIONS, infos);
    EXPECT_TRUE(ret == INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testFetchCachedRemoteMissions005 end" << std::endl;
}

/**
 * @tc.name: testFetchCachedRemoteMissions006
 * @tc.desc: test local deviceId, return error code
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchCachedRemoteMissions006, TestSize.Level3)
{
    DTEST_LOG << "testFetchCachedRemoteMissions006 begin" << std::endl;
    std::vector<DstbMissionInfo> infos;
    auto ret = DistributedSchedMissionManager::GetInstance().FetchCachedRemoteMissions(localDeviceId_,
        NUM_MISSIONS, infos);
    EXPECT_TRUE(ret == ERR_NULL_OBJECT);
    DTEST_LOG << "testFetchCachedRemoteMissions006 end" << std::endl;
}

/**
 * @tc.name: testFetchCachedRemoteMissions007
 * @tc.desc: test stop fake device, return error code
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchCachedRemoteMissions007, TestSize.Level3)
{
    DTEST_LOG << "testFetchCachedRemoteMissions007 begin" << std::endl;
    std::vector<DstbMissionInfo> infos;
    auto ret = DistributedSchedMissionManager::GetInstance().FetchCachedRemoteMissions(DEVICE_ID,
        NORMAL_NUM_MISSIONS, infos);
    EXPECT_TRUE(ret != ERR_NONE);
    DTEST_LOG << "testFetchCachedRemoteMissions007 end" << std::endl;
}

/**
 * @tc.name: testFetchCachedRemoteMissions008
 * @tc.desc: test empty deviceId, return error code
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchCachedRemoteMissions008, TestSize.Level3)
{
    DTEST_LOG << "testFetchCachedRemoteMissions008 begin" << std::endl;
    std::vector<DstbMissionInfo> infos;
    auto ret = DistributedSchedMissionManager::GetInstance().FetchCachedRemoteMissions("", NORMAL_NUM_MISSIONS, infos);
    EXPECT_TRUE(ret == INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testFetchCachedRemoteMissions008 end" << std::endl;
}

/**
 * @tc.name: testFetchCachedRemoteMissions009
 * @tc.desc: test local deviceId, return error code
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchCachedRemoteMissions009, TestSize.Level3)
{
    DTEST_LOG << "testFetchCachedRemoteMissions009 begin" << std::endl;
    std::vector<DstbMissionInfo> infos;
    auto ret = DistributedSchedMissionManager::GetInstance().FetchCachedRemoteMissions(localDeviceId_,
        NORMAL_NUM_MISSIONS, infos);
    EXPECT_TRUE(ret == ERR_NULL_OBJECT);
    DTEST_LOG << "testFetchCachedRemoteMissions009 end" << std::endl;
}

/**
 * @tc.name: testStopDataStorage001
 * @tc.desc: test stop data storage
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopDataStorage001, TestSize.Level3)
{
    DTEST_LOG << "testStopDataStorage001 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StopDataStorage();
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "testStopDataStorage001 end" << std::endl;
}

/**
 * @tc.name: testStoreSnapshotInfo001
 * @tc.desc: test store snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStoreSnapshotInfo001, TestSize.Level3)
{
    DTEST_LOG << "testStoreSnapshotInfo001 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StoreSnapshotInfo(DEVICE_ID, 0, 0, 0);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "testStoreSnapshotInfo001 end" << std::endl;
}

/**
 * @tc.name: testRemoveSnapshotInfo001
 * @tc.desc: test remove snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRemoveSnapshotInfo001, TestSize.Level3)
{
    DTEST_LOG << "testRemoveSnapshotInfo001 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().RemoveSnapshotInfo(DEVICE_ID, 0);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "testRemoveSnapshotInfo001 end" << std::endl;
}

/**
 * @tc.name: testInitDataStorage001
 * @tc.desc: test init data storage
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testInitDataStorage001, TestSize.Level3)
{
    DTEST_LOG << "testInitDataStorage001 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().InitDataStorage();
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testInitDataStorage001 end" << std::endl;
}

/**
 * @tc.name: testInitDataStorage002
 * @tc.desc: test init data storage
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testInitDataStorage002, TestSize.Level3)
{
    DTEST_LOG << "testInitDataStorage002 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().InitDataStorage();
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testInitDataStorage002 end" << std::endl;
}

/**
 * @tc.name: testStoreSnapshotInfo002
 * @tc.desc: test store snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStoreSnapshotInfo002, TestSize.Level3)
{
    DTEST_LOG << "testStoreSnapshotInfo002 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().StoreSnapshotInfo(DEVICE_ID, 0, 0, 0);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testStoreSnapshotInfo002 end" << std::endl;
}

/**
 * @tc.name: testRemoveSnapshotInfo002
 * @tc.desc: test remove snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRemoveSnapshotInfo002, TestSize.Level3)
{
    DTEST_LOG << "testRemoveSnapshotInfo002 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().RemoveSnapshotInfo(DEVICE_ID, 0);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testRemoveSnapshotInfo002 end" << std::endl;
}

/**
 * @tc.name: testGetRemoteMissionSnapshotInfo001
 * @tc.desc: test get remote mission snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetRemoteMissionSnapshotInfo001, TestSize.Level3)
{
    DTEST_LOG << "testGetRemoteMissionSnapshotInfo001 begin" << std::endl;
    unique_ptr<AAFwk::MissionSnapshot> missionSnapshot = nullptr;
    auto ret = DistributedSchedMissionManager::GetInstance().GetRemoteMissionSnapshotInfo("", 0, missionSnapshot);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testGetRemoteMissionSnapshotInfo001 end" << std::endl;
}

/**
 * @tc.name: testDeviceOnlineNotify003
 * @tc.desc: test device online notify
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testDeviceOnlineNotify003, TestSize.Level3)
{
    DTEST_LOG << "testDeviceOnlineNotify003 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().DeviceOnlineNotify(DEVICE_ID);
    DTEST_LOG << "testDeviceOnlineNotify003 end" << std::endl;
}

/**
 * @tc.name: testDeviceOfflineNotify001
 * @tc.desc: test device offline notify
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testDeviceOfflineNotify001, TestSize.Level3)
{
    DTEST_LOG << "testDeviceOfflineNotify001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().DeviceOfflineNotify("");
    DTEST_LOG << "testDeviceOfflineNotify001 end" << std::endl;
}

/**
 * @tc.name: testDeviceOfflineNotify002
 * @tc.desc: test device offline notify
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testDeviceOfflineNotify002, TestSize.Level3)
{
    DTEST_LOG << "testDeviceOfflineNotify002 begin" << std::endl;
    std::set<std::string> remoteSyncDeviceSet_ = set<std::string>();
    DistributedSchedMissionManager::GetInstance().DeviceOfflineNotify(DEVICE_ID);
    DTEST_LOG << "testDeviceOfflineNotify002 end" << std::endl;
}

/**
 * @tc.name: testNotifySnapshotChanged001
 * @tc.desc: test notify snapshot changed
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifySnapshotChanged001, TestSize.Level3)
{
    DTEST_LOG << "testNotifySnapshotChanged001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().NotifySnapshotChanged(DEVICE_ID, 0);
    DTEST_LOG << "testNotifySnapshotChanged001 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDied001
 * @tc.desc: test on remote died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDied001, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDied001 begin" << std::endl;
    wptr<IRemoteObject> remote = nullptr;
    DistributedSchedMissionManager::GetInstance().OnRemoteDied(remote);
    DTEST_LOG << "testOnRemoteDied001 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDied002
 * @tc.desc: test on remote died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDied002, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDied002 begin" << std::endl;
    wptr<IRemoteObject> remote = new RemoteMissionListenerTest();
    DistributedSchedMissionManager::GetInstance().OnRemoteDied(remote);
    DTEST_LOG << "testOnRemoteDied002 end" << std::endl;
}

/**
 * @tc.name: testStartSyncMissionsFromRemote001
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncMissionsFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncMissionsFromRemote001 begin" << std::endl;
    std::vector<DstbMissionInfo> missionInfos;
    CallerInfo callerInfo;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().GenerateCallerInfo(callerInfo);
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncMissionsFromRemote(callerInfo, missionInfos);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncMissionsFromRemote001 end" << std::endl;
}

/**
 * @tc.name: testStopSyncMissionsFromRemote001
 * @tc.desc: stop sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncMissionsFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncMissionsFromRemote001 begin" << std::endl;
    std::vector<DstbMissionInfo> missionInfos;
    CallerInfo callerInfo;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().StopSyncMissionsFromRemote("");
    DTEST_LOG << "testStopSyncMissionsFromRemote001 end" << std::endl;
}

/**
 * @tc.name: testStopSyncMissionsFromRemote002
 * @tc.desc: stop sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncMissionsFromRemote002, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncMissionsFromRemote002 begin" << std::endl;
    std::vector<DstbMissionInfo> missionInfos;
    CallerInfo callerInfo;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().StopSyncMissionsFromRemote(DEVICE_ID);
    DTEST_LOG << "testStopSyncMissionsFromRemote002 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionsChangedFromRemote001
 * @tc.desc: notify missions changed from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionsChangedFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionsChangedFromRemote001 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = "";
    callerInfo.uid = 0;
    callerInfo.pid = 0;
    callerInfo.dmsVersion = 0;
    std::vector<DstbMissionInfo> missionInfos;
    DistributedSchedMissionManager::GetInstance().Init();
    auto ret = DistributedSchedMissionManager::GetInstance().NotifyMissionsChangedFromRemote(callerInfo, missionInfos);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testNotifyMissionsChangedFromRemote001 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionsChangedFromRemote002
 * @tc.desc: notify missions changed from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionsChangedFromRemote002, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionsChangedFromRemote002 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = DEVICE_ID;
    callerInfo.uid = 0;
    callerInfo.pid = 0;
    callerInfo.dmsVersion = 0;
    std::vector<DstbMissionInfo> missionInfos;
    DistributedSchedMissionManager::GetInstance().Init();
    auto ret = DistributedSchedMissionManager::GetInstance().NotifyMissionsChangedFromRemote(callerInfo, missionInfos);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testNotifyMissionsChangedFromRemote002 end" << std::endl;
}

/**
 * @tc.name: testNotifyLocalMissionsChanged001
 * @tc.desc: notify local missions changed
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyLocalMissionsChanged001, TestSize.Level3)
{
    DTEST_LOG << "testNotifyLocalMissionsChanged001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().NotifyLocalMissionsChanged();
    DTEST_LOG << "testNotifyLocalMissionsChanged001 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionSnapshotCreated001
 * @tc.desc: notify mission snapshot created
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionSnapshotCreated001, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionSnapshotCreated001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().NotifyMissionSnapshotCreated(1);
    DTEST_LOG << "testNotifyMissionSnapshotCreated001 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionSnapshotChanged001
 * @tc.desc: notify mission snapshot changed
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionSnapshotChanged001, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionSnapshotChanged001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().NotifyMissionSnapshotChanged(1);
    DTEST_LOG << "testNotifyMissionSnapshotChanged001 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionSnapshotDestroyed001
 * @tc.desc: notify mission snapshot destroyed
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionSnapshotDestroyed001, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionSnapshotDestroyed001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().NotifyMissionSnapshotDestroyed(1);
    DTEST_LOG << "testNotifyMissionSnapshotDestroyed001 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionsChangedToRemote001
 * @tc.desc: notify missions changed to remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionsChangedToRemote001, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionsChangedToRemote001 begin" << std::endl;
    std::vector<DstbMissionInfo> missionInfos;
    auto ret = DistributedSchedMissionManager::GetInstance().NotifyMissionsChangedToRemote(missionInfos);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testNotifyMissionsChangedToRemote001 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionsChangedToRemoteInner001
 * @tc.desc: notify missions changed to remote inner
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionsChangedToRemoteInner001, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionsChangedToRemoteInner001 begin" << std::endl;
    CallerInfo callerInfo;
    std::vector<DstbMissionInfo> missionInfos;
    DistributedSchedMissionManager::GetInstance().NotifyMissionsChangedToRemoteInner("", missionInfos, callerInfo);
    DTEST_LOG << "testNotifyMissionsChangedToRemoteInner001 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionsChangedToRemoteInner002
 * @tc.desc: notify missions changed to remote inner
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionsChangedToRemoteInner002, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionsChangedToRemoteInner002 begin" << std::endl;
    CallerInfo callerInfo;
    std::vector<DstbMissionInfo> missionInfos;
    DistributedSchedMissionManager::GetInstance().NotifyMissionsChangedToRemoteInner(
        DEVICE_ID, missionInfos, callerInfo);
    DTEST_LOG << "testNotifyMissionsChangedToRemoteInner002 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDmsDied001
 * @tc.desc: on remote dms died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDmsDied001, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDmsDied001 begin" << std::endl;
    wptr<IRemoteObject> remote = nullptr;
    DistributedSchedMissionManager::GetInstance().OnRemoteDmsDied(remote);
    DTEST_LOG << "testOnRemoteDmsDied001 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDmsDied002
 * @tc.desc: on remote dms died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDmsDied002, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDmsDied002 begin" << std::endl;
    wptr<IRemoteObject> remote = wptr<IRemoteObject>();
    DistributedSchedMissionManager::GetInstance().OnRemoteDmsDied(remote);
    DTEST_LOG << "testOnRemoteDmsDied002 end" << std::endl;
}

/**
 * @tc.name: testRetryStartSyncRemoteMissions001
 * @tc.desc: retry start sync remote missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRetryStartSyncRemoteMissions001, TestSize.Level3)
{
    DTEST_LOG << "testRetryStartSyncRemoteMissions001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().RetryStartSyncRemoteMissions("", localDeviceId_, 1);
    DTEST_LOG << "testRetryStartSyncRemoteMissions001 end" << std::endl;
}

/**
 * @tc.name: testRetryStartSyncRemoteMissions002
 * @tc.desc: retry start sync remote missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRetryStartSyncRemoteMissions002, TestSize.Level3)
{
    DTEST_LOG << "testRetryStartSyncRemoteMissions002 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().RetryStartSyncRemoteMissions(DEVICE_ID, localDeviceId_, 1);
    DTEST_LOG << "testRetryStartSyncRemoteMissions002 end" << std::endl;
}

/**
 * @tc.name: testOnMissionListenerDied001
 * @tc.desc: on mission listener died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnMissionListenerDied001, TestSize.Level3)
{
    DTEST_LOG << "testOnMissionListenerDied001 begin" << std::endl;
    sptr<IRemoteObject> remote = nullptr;
    DistributedSchedMissionManager::GetInstance().OnMissionListenerDied(remote);
    DTEST_LOG << "testOnMissionListenerDied001 end" << std::endl;
}

/**
 * @tc.name: testOnMissionListenerDied002
 * @tc.desc: on mission listener died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnMissionListenerDied002, TestSize.Level3)
{
    DTEST_LOG << "testOnMissionListenerDied002 begin" << std::endl;
    sptr<IRemoteObject> remote = sptr<IRemoteObject>();
    DistributedSchedMissionManager::GetInstance().OnMissionListenerDied(remote);
    DTEST_LOG << "testOnMissionListenerDied002 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDmsDied003
 * @tc.desc: on remote dms died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDmsDied003, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDmsDied003 begin" << std::endl;
    sptr<IRemoteObject> remote = nullptr;
    DistributedSchedMissionManager::GetInstance().OnRemoteDmsDied(remote);
    DTEST_LOG << "testOnRemoteDmsDied003 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDmsDied004
 * @tc.desc: on remote dms died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDmsDied004, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDmsDied004 begin" << std::endl;
    sptr<IRemoteObject> remote = sptr<IRemoteObject>();
    DistributedSchedMissionManager::GetInstance().OnRemoteDmsDied(remote);
    DTEST_LOG << "testOnRemoteDmsDied004 end" << std::endl;
}

/**
 * @tc.name: testNotifyDmsProxyProcessDied001
 * @tc.desc: notify dms proxy process died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyDmsProxyProcessDied001, TestSize.Level3)
{
    DTEST_LOG << "testNotifyDmsProxyProcessDied001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().NotifyDmsProxyProcessDied();
    DTEST_LOG << "testNotifyDmsProxyProcessDied001 end" << std::endl;
}

/**
 * @tc.name: testRetryRegisterMissionChange001
 * @tc.desc: retry register mission change
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRetryRegisterMissionChange001, TestSize.Level3)
{
    DTEST_LOG << "testRetryRegisterMissionChange001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().RetryRegisterMissionChange(1);
    DTEST_LOG << "testRetryRegisterMissionChange001 end" << std::endl;
}

/**
 * @tc.name: testInitAllSnapshots001
 * @tc.desc: init all snapshots
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testInitAllSnapshots001, TestSize.Level3)
{
    DTEST_LOG << "testInitAllSnapshots001 begin" << std::endl;
    std::vector<DstbMissionInfo> missionInfos;
    DistributedSchedMissionManager::GetInstance().InitAllSnapshots(missionInfos);
    DTEST_LOG << "testInitAllSnapshots001 end" << std::endl;
}

/**
 * @tc.name: testMissionSnapshotChanged001
 * @tc.desc: mission snapshot changed
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testMissionSnapshotChanged001, TestSize.Level3)
{
    DTEST_LOG << "testMissionSnapshotChanged001 begin" << std::endl;
    auto ret = DistributedSchedMissionManager::GetInstance().MissionSnapshotChanged(NUM_MISSIONS);
    EXPECT_NE(ret, ERR_NONE);
    DTEST_LOG << "testMissionSnapshotChanged001 end" << std::endl;
}

/**
 * @tc.name: testOnDnetDied001
 * @tc.desc: on dnet died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnDnetDied001, TestSize.Level3)
{
    DTEST_LOG << "testOnDnetDied001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().OnDnetDied();
    DTEST_LOG << "testOnDnetDied001 end" << std::endl;
}

/**
 * @tc.name: ProxyCallStopSyncMissionsFromRemote001
 * @tc.desc: call dms proxy StopSyncMissionsFromRemote
 * @tc.type: FUNC
 * @tc.require: I5XDDS
 */
HWTEST_F(DMSMissionManagerTest, ProxyCallStopSyncMissionsFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStopSyncMissionsFromRemote001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    CallerInfo callerInfo;
    int32_t ret = proxy->StopSyncMissionsFromRemote(callerInfo);
    EXPECT_EQ(ret, REQUEST_CODE_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStopSyncMissionsFromRemote001 end" << std::endl;
}

/**
 * @tc.name: ProxyCallNotifyMissionsChangedFromRemote001
 * @tc.desc: call dms proxy NotifyMissionsChangedFromRemote
 * @tc.type: FUNC
 * @tc.require: I5XDDS
 */
HWTEST_F(DMSMissionManagerTest, ProxyCallNotifyMissionsChangedFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallNotifyMissionsChangedFromRemote001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    CallerInfo callerInfo;
    std::vector<DstbMissionInfo> missionInfos;
    int32_t ret = proxy->NotifyMissionsChangedFromRemote(missionInfos, callerInfo);
    EXPECT_EQ(ret, REQUEST_CODE_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallNotifyMissionsChangedFromRemote001 end" << std::endl;
}

/**
 * @tc.name: ProxyCallGetRemoteMissionSnapshotInfo001
 * @tc.desc: call dms proxy GetRemoteMissionSnapshotInfo
 * @tc.type: FUNC
 * @tc.require: I5XDDS
 */
HWTEST_F(DMSMissionManagerTest, ProxyCallGetRemoteMissionSnapshotInfo001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallGetRemoteMissionSnapshotInfo001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    unique_ptr<AAFwk::MissionSnapshot> missionSnapshot = nullptr;
    int32_t ret = proxy->GetRemoteMissionSnapshotInfo("MockDevId", 1, missionSnapshot);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallGetRemoteMissionSnapshotInfo001 end" << std::endl;
}

/**
 * @tc.name: ProxyCallGetRemoteMissionSnapshotInfo002
 * @tc.desc: call dms proxy GetRemoteMissionSnapshotInfo
 * @tc.type: FUNC
 * @tc.require: I5XDDS
 */
HWTEST_F(DMSMissionManagerTest, ProxyCallGetRemoteMissionSnapshotInfo002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallGetRemoteMissionSnapshotInfo002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    unique_ptr<AAFwk::MissionSnapshot> missionSnapshot = nullptr;
    int32_t ret = proxy->GetRemoteMissionSnapshotInfo("", 1, missionSnapshot);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallGetRemoteMissionSnapshotInfo002 end" << std::endl;
}

/**
 * @tc.name: ProxyCallGetRemoteMissionSnapshotInfo003
 * @tc.desc: call dms proxy GetRemoteMissionSnapshotInfo
 * @tc.type: FUNC
 * @tc.require: I5XDDS
 */
HWTEST_F(DMSMissionManagerTest, ProxyCallGetRemoteMissionSnapshotInfo003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallGetRemoteMissionSnapshotInfo003 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    unique_ptr<AAFwk::MissionSnapshot> missionSnapshot = nullptr;
    int32_t ret = proxy->GetRemoteMissionSnapshotInfo("MockDevId", -1, missionSnapshot);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallGetRemoteMissionSnapshotInfo003 end" << std::endl;
}

/**
 * @tc.name: testDeleteDataStorage005
 * @tc.desc: test DeleteDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testDeleteDataStorage005, TestSize.Level3)
{
    DTEST_LOG << "testDeleteDataStorage005 begin" << std::endl;
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = localDeviceId_;
    }
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_ =
        std::make_shared<DistributedDataStorage>();
    auto result = DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Init();
    auto initDoneTask = []() {
        std::lock_guard<std::mutex> autoLock(caseDoneLock_);
        isCaseDone_ = true;
        caseDoneCondition_.notify_all();
    };
    if (DistributedSchedMissionManager::GetInstance().distributedDataStorage_ != nullptr) {
        std::shared_ptr<AppExecFwk::EventHandler> dmsDataStorageHandler =
            DistributedSchedMissionManager::GetInstance().distributedDataStorage_->dmsDataStorageHandler_;
        if (dmsDataStorageHandler != nullptr) {
            dmsDataStorageHandler->PostTask(initDoneTask);
        }
    }
    std::unique_lock<std::mutex> lock(caseDoneLock_);
    caseDoneCondition_.wait_for(lock, std::chrono::milliseconds(MAX_WAIT_TIME),
        [&] () { return isCaseDone_; });
    EXPECT_TRUE(result);
    isCaseDone_ = false;
    uint8_t* byteStream = new uint8_t[BYTESTREAM_LENGTH];
    for (size_t i = 0; i < BYTESTREAM_LENGTH; ++i) {
        byteStream[i] = ONE_BYTE;
    }
    result = DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Insert(localDeviceId_,
        TASK_ID, byteStream, BYTESTREAM_LENGTH);
    EXPECT_TRUE(result);
    DistributedSchedMissionManager::GetInstance().missionHandler_ = nullptr;
    DistributedSchedMissionManager::GetInstance().DeleteDataStorage(localDeviceId_, false);
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Stop();
    DTEST_LOG << "testDeleteDataStorage005 end" << std::endl;
}

/**
 * @tc.name: testDeleteDataStorage006
 * @tc.desc: test DeleteDataStorage
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testDeleteDataStorage006, TestSize.Level3)
{
    DTEST_LOG << "testDeleteDataStorage006 begin" << std::endl;
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = localDeviceId_;
    }
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_ =
        std::make_shared<DistributedDataStorage>();
    auto result = DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Init();
    auto initDoneTask = []() {
        std::lock_guard<std::mutex> autoLock(caseDoneLock_);
        isCaseDone_ = true;
        caseDoneCondition_.notify_all();
    };
    if (DistributedSchedMissionManager::GetInstance().distributedDataStorage_ != nullptr) {
        std::shared_ptr<AppExecFwk::EventHandler> dmsDataStorageHandler =
            DistributedSchedMissionManager::GetInstance().distributedDataStorage_->dmsDataStorageHandler_;
        if (dmsDataStorageHandler != nullptr) {
            dmsDataStorageHandler->PostTask(initDoneTask);
        }
    }
    std::unique_lock<std::mutex> lock(caseDoneLock_);
    caseDoneCondition_.wait_for(lock, std::chrono::milliseconds(MAX_WAIT_TIME),
        [&] () { return isCaseDone_; });
    EXPECT_TRUE(result);
    isCaseDone_ = false;
    uint8_t* byteStream = new uint8_t[BYTESTREAM_LENGTH];
    for (size_t i = 0; i < BYTESTREAM_LENGTH; ++i) {
        byteStream[i] = ONE_BYTE;
    }
    result = DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Insert(localDeviceId_,
        TASK_ID, byteStream, BYTESTREAM_LENGTH);
    EXPECT_TRUE(result);
    DistributedSchedMissionManager::GetInstance().missionHandler_ = nullptr;
    DistributedSchedMissionManager::GetInstance().DeleteDataStorage(localDeviceId_, true);
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Stop();
    DTEST_LOG << "testDeleteDataStorage006 end" << std::endl;
}

/**
 * @tc.name: testRegisterMissionListener009
 * @tc.desc: test register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRegisterMissionListener009, TestSize.Level3)
{
    DTEST_LOG << "testRegisterMissionListener009 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    u16string deviceId = Str8ToStr16(localDeviceId_);
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = localDeviceId_;
    }
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    auto ret = DistributedSchedMissionManager::GetInstance().RegisterMissionListener(deviceId, listener);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testRegisterMissionListener009 end" << std::endl;
}

/**
 * @tc.name: testRegisterMissionListener010
 * @tc.desc: test register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRegisterMissionListener010, TestSize.Level3)
{
    DTEST_LOG << "testRegisterMissionListener010 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = DEVICE_ID;
    }
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().RegisterMissionListener(deviceId, listener);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testRegisterMissionListener010 end" << std::endl;
}

/**
 * @tc.name: testIsDeviceIdValidated002
 * @tc.desc: test IsDeviceIdValidated
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testIsDeviceIdValidated002, TestSize.Level1)
{
    DTEST_LOG << "testIsDeviceIdValidated002 begin" << std::endl;
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    }

    int32_t deviceType = 0;
    std::shared_ptr<DmsDeviceInfo> dmsDeviceInfo = make_shared<DmsDeviceInfo>(DEVICE_NAME, deviceType, localDeviceId_);
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[localDeviceId_] = dmsDeviceInfo;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().IsDeviceIdValidated(localDeviceId_);
    EXPECT_TRUE(ret);
    DTEST_LOG << "testIsDeviceIdValidated002 end" << std::endl;
}


/**
 * @tc.name: testGetMissionInfos007
 * @tc.desc: get missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetMissionInfos007, TestSize.Level3)
{
    DTEST_LOG << "testGetMissionInfos007 begin" << std::endl;
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    }

    int32_t deviceType = 0;
    std::shared_ptr<DmsDeviceInfo> dmsDeviceInfo = make_shared<DmsDeviceInfo>(DEVICE_NAME, deviceType, DEVICE_ID);
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[DEVICE_ID] = dmsDeviceInfo;
    }
    int32_t numMissions = 0;
    std::vector<AAFwk::MissionInfo> missionInfos;
    auto ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(DEVICE_ID, numMissions, missionInfos);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testGetMissionInfos007 end" << std::endl;
}

/**
 * @tc.name: testGetMissionInfos008
 * @tc.desc: get missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetMissionInfos008, TestSize.Level3)
{
    DTEST_LOG << "testGetMissionInfos008 begin" << std::endl;
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    }

    int32_t deviceType = 0;
    std::shared_ptr<DmsDeviceInfo> dmsDeviceInfo = make_shared<DmsDeviceInfo>(DEVICE_NAME, deviceType, DEVICE_ID);
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[DEVICE_ID] = dmsDeviceInfo;
    }
    int32_t numMissions = NORMAL_NUM_MISSIONS;
    std::vector<AAFwk::MissionInfo> missionInfos;
    auto ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(DEVICE_ID, numMissions, missionInfos);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "testGetMissionInfos008 end" << std::endl;
}

/**
 * @tc.name: testGetMissionInfos009
 * @tc.desc: get missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetMissionInfos009, TestSize.Level3)
{
    DTEST_LOG << "testGetMissionInfos009 begin" << std::endl;
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    }

    int32_t deviceType = 0;
    std::shared_ptr<DmsDeviceInfo> dmsDeviceInfo = make_shared<DmsDeviceInfo>(DEVICE_NAME, deviceType, DEVICE_ID);
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[localDeviceId_] = dmsDeviceInfo;
    }
    int32_t numMissions = NORMAL_NUM_MISSIONS;
    std::vector<AAFwk::MissionInfo> missionInfos;
    std::string uuid = DtbschedmgrDeviceInfoStorage::GetInstance().GetUuidByNetworkId(localDeviceId_);
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteMissionInfosLock_);
        DistributedSchedMissionManager::GetInstance().deviceMissionInfos_.erase(uuid);
    }
    std::vector<DstbMissionInfo> dstbMissionInfos;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteMissionInfosLock_);
        DistributedSchedMissionManager::GetInstance().deviceMissionInfos_[uuid] = dstbMissionInfos;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().GetMissionInfos(localDeviceId_, numMissions, missionInfos);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "testGetMissionInfos009 end" << std::endl;
}

/**
 * @tc.name: testInitDataStorage003
 * @tc.desc: test init data storage
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testInitDataStorage003, TestSize.Level3)
{
    DTEST_LOG << "testInitDataStorage003 begin" << std::endl;
    if (DistributedSchedMissionManager::GetInstance().distributedDataStorage_ == nullptr) {
        DistributedSchedMissionManager::GetInstance().distributedDataStorage_ =
            std::make_shared<DistributedDataStorage>();
    }
    auto ret = DistributedSchedMissionManager::GetInstance().InitDataStorage();
    EXPECT_EQ(ret, ERR_NONE);
    ret = DistributedSchedMissionManager::GetInstance().StopDataStorage();
    DTEST_LOG << "testInitDataStorage003 end" << std::endl;
}

/**
 * @tc.name: testStopDataStorage003
 * @tc.desc: test stop data storage
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopDataStorage003, TestSize.Level3)
{
    DTEST_LOG << "testStopDataStorage003 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_ =
        std::make_shared<DistributedDataStorage>();
    auto result = DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Init();
    auto initDoneTask = []() {
        std::lock_guard<std::mutex> autoLock(caseDoneLock_);
        isCaseDone_ = true;
        caseDoneCondition_.notify_all();
    };
    if (DistributedSchedMissionManager::GetInstance().distributedDataStorage_ != nullptr) {
        std::shared_ptr<AppExecFwk::EventHandler> dmsDataStorageHandler =
            DistributedSchedMissionManager::GetInstance().distributedDataStorage_->dmsDataStorageHandler_;
        if (dmsDataStorageHandler != nullptr) {
            dmsDataStorageHandler->PostTask(initDoneTask);
        }
    }
    std::unique_lock<std::mutex> lock(caseDoneLock_);
    caseDoneCondition_.wait_for(lock, std::chrono::milliseconds(MAX_WAIT_TIME),
        [&] () { return isCaseDone_; });
    EXPECT_TRUE(result);
    isCaseDone_ = false;
    auto ret = DistributedSchedMissionManager::GetInstance().StopDataStorage();
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStopDataStorage003 end" << std::endl;
}

/**
 * @tc.name: testStoreSnapshotInfo004
 * @tc.desc: test store snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStoreSnapshotInfo004, TestSize.Level3)
{
    DTEST_LOG << "testStoreSnapshotInfo004 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_ =
            std::make_shared<DistributedDataStorage>();
    auto ret = DistributedSchedMissionManager::GetInstance().StoreSnapshotInfo(DEVICE_ID, 0, 0, 0);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testStoreSnapshotInfo004 end" << std::endl;
}

/**
 * @tc.name: testStoreSnapshotInfo003
 * @tc.desc: test store snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStoreSnapshotInfo003, TestSize.Level3)
{
    DTEST_LOG << "testStoreSnapshotInfo003 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_ =
        std::make_shared<DistributedDataStorage>();
    auto result = DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Init();
    auto initDoneTask = []() {
        std::lock_guard<std::mutex> autoLock(caseDoneLock_);
        isCaseDone_ = true;
        caseDoneCondition_.notify_all();
    };
    if (DistributedSchedMissionManager::GetInstance().distributedDataStorage_ != nullptr) {
        std::shared_ptr<AppExecFwk::EventHandler> dmsDataStorageHandler =
            DistributedSchedMissionManager::GetInstance().distributedDataStorage_->dmsDataStorageHandler_;
        if (dmsDataStorageHandler != nullptr) {
            dmsDataStorageHandler->PostTask(initDoneTask);
        }
    }
    std::unique_lock<std::mutex> lock(caseDoneLock_);
    caseDoneCondition_.wait_for(lock, std::chrono::milliseconds(MAX_WAIT_TIME),
        [&] () { return isCaseDone_; });
    EXPECT_TRUE(result);
    isCaseDone_ = false;
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = localDeviceId_;
    }
    uint8_t* byteStream = new uint8_t[BYTESTREAM_LENGTH];
    for (size_t i = 0; i < BYTESTREAM_LENGTH; ++i) {
        byteStream[i] = ONE_BYTE;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().
        StoreSnapshotInfo(localDeviceId_, TASK_ID, byteStream, BYTESTREAM_LENGTH);
    EXPECT_EQ(ret, ERR_NONE);
    ret = DistributedSchedMissionManager::GetInstance().RemoveSnapshotInfo(localDeviceId_, TASK_ID);
    EXPECT_EQ(ret, ERR_NONE);
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Stop();
    DTEST_LOG << "testStoreSnapshotInfo003 end" << std::endl;
}

/**
 * @tc.name: testRemoveSnapshotInfo003
 * @tc.desc: test remove snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRemoveSnapshotInfo003, TestSize.Level3)
{
    DTEST_LOG << "testRemoveSnapshotInfo003 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_ =
            std::make_shared<DistributedDataStorage>();
    auto ret = DistributedSchedMissionManager::GetInstance().RemoveSnapshotInfo(DEVICE_ID, 0);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testRemoveSnapshotInfo003 end" << std::endl;
}

/**
 * @tc.name: testGetRemoteMissionSnapshotInfo002
 * @tc.desc: test get remote mission snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetRemoteMissionSnapshotInfo002, TestSize.Level3)
{
    DTEST_LOG << "testGetRemoteMissionSnapshotInfo002 begin" << std::endl;
    unique_ptr<AAFwk::MissionSnapshot> missionSnapshot = nullptr;
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_ = nullptr;
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = localDeviceId_;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().GetRemoteMissionSnapshotInfo(localDeviceId_,
        0, missionSnapshot);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "testGetRemoteMissionSnapshotInfo002 end" << std::endl;
}

/**
 * @tc.name: testGetRemoteMissionSnapshotInfo004
 * @tc.desc: test get remote mission snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetRemoteMissionSnapshotInfo004, TestSize.Level3)
{
    DTEST_LOG << "testGetRemoteMissionSnapshotInfo004 begin" << std::endl;
    unique_ptr<AAFwk::MissionSnapshot> missionSnapshot = nullptr;
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = localDeviceId_;
    }
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_ =
        std::make_shared<DistributedDataStorage>();
    auto ret = DistributedSchedMissionManager::GetInstance().GetRemoteMissionSnapshotInfo(localDeviceId_,
        TASK_ID, missionSnapshot);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testGetRemoteMissionSnapshotInfo004 end" << std::endl;
}

/**
 * @tc.name: testGetRemoteMissionSnapshotInfo005
 * @tc.desc: test get remote mission snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testGetRemoteMissionSnapshotInfo005, TestSize.Level3)
{
    DTEST_LOG << "testGetRemoteMissionSnapshotInfo005 begin" << std::endl;
    unique_ptr<AAFwk::MissionSnapshot> missionSnapshot = nullptr;
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = localDeviceId_;
    }
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_ =
        std::make_shared<DistributedDataStorage>();
    auto result = DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Init();
    auto initDoneTask = []() {
        std::lock_guard<std::mutex> autoLock(caseDoneLock_);
        isCaseDone_ = true;
        caseDoneCondition_.notify_all();
    };
    if (DistributedSchedMissionManager::GetInstance().distributedDataStorage_ != nullptr) {
        std::shared_ptr<AppExecFwk::EventHandler> dmsDataStorageHandler =
            DistributedSchedMissionManager::GetInstance().distributedDataStorage_->dmsDataStorageHandler_;
        if (dmsDataStorageHandler != nullptr) {
            dmsDataStorageHandler->PostTask(initDoneTask);
        }
    }
    std::unique_lock<std::mutex> lock(caseDoneLock_);
    caseDoneCondition_.wait_for(lock, std::chrono::milliseconds(MAX_WAIT_TIME),
        [&] () { return isCaseDone_; });
    EXPECT_TRUE(result);
    isCaseDone_ = false;
    uint8_t* byteStream = new uint8_t[BYTESTREAM_LENGTH];
    for (size_t i = 0; i < BYTESTREAM_LENGTH; ++i) {
        byteStream[i] = ONE_BYTE;
    }
    result = DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Insert(localDeviceId_,
        TASK_ID, byteStream, BYTESTREAM_LENGTH);
    EXPECT_TRUE(result);
    auto ret = DistributedSchedMissionManager::GetInstance().GetRemoteMissionSnapshotInfo(localDeviceId_,
        TASK_ID, missionSnapshot);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_->Stop();
    DTEST_LOG << "testGetRemoteMissionSnapshotInfo005 end" << std::endl;
}

/**
 * @tc.name: testDeviceOfflineNotify003
 * @tc.desc: test device offline notify
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testDeviceOfflineNotify003, TestSize.Level3)
{
    DTEST_LOG << "testDeviceOfflineNotify003 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().Init();
    DistributedSchedMissionManager::GetInstance().DeviceOnlineNotify(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    sptr<IDistributedSched> remoteDmsObj = iface_cast<IDistributedSched>(listener);
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_[DEVICE_ID] = remoteDmsObj;
    }
    DistributedSchedMissionManager::GetInstance().DeviceOfflineNotify(DEVICE_ID);
    DTEST_LOG << "testDeviceOfflineNotify003 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions015
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions015, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions015 begin" << std::endl;
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        listenerInfo.called = true;
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_[DEVICE_ID] = proxy;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions(DEVICE_ID, localDeviceId_);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions015 end" << std::endl;
}

/**
 * @tc.name: testStartSyncRemoteMissions016
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncRemoteMissions016, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncRemoteMissions016 begin" << std::endl;
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_[DEVICE_ID] = proxy;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncRemoteMissions(DEVICE_ID, localDeviceId_);
    EXPECT_NE(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncRemoteMissions016 end" << std::endl;
}

/**
 * @tc.name: testUnRegisterMissionListener006
 * @tc.desc: register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testUnRegisterMissionListener006, TestSize.Level3)
{
    DTEST_LOG << "testUnRegisterMissionListener006 begin" << std::endl;
    /**
     * @tc.steps: step1. test device online notify
     */
    DTEST_LOG << "testDeviceOnlineNotify001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().DeviceOnlineNotify("");
    DistributedSchedMissionManager::GetInstance().DeviceOnlineNotify(DEVICE_ID);
    DTEST_LOG << "testDeviceOnlineNotify001 end" << std::endl;
    
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    auto ret = DistributedSchedMissionManager::GetInstance().UnRegisterMissionListener(U16DEVICE_ID, listener);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testUnRegisterMissionListener006 end" << std::endl;
}

/**
 * @tc.name: testUnRegisterMissionListener007
 * @tc.desc: register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testUnRegisterMissionListener007, TestSize.Level3)
{
    DTEST_LOG << "testUnRegisterMissionListener007 begin" << std::endl;
    /**
     * @tc.steps: step1. test delete data storage
     */
    DTEST_LOG << "testDeleteDataStorage001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().DeleteDataStorage("", false);
    DTEST_LOG << "testDeleteDataStorage001 end" << std::endl;
    DTEST_LOG << "testDeleteDataStorage002 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().DeleteDataStorage(DEVICE_ID, false);
    DTEST_LOG << "testDeleteDataStorage002 end" << std::endl;
    DTEST_LOG << "testDeleteDataStorage003 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().DeleteDataStorage("", true);
    DTEST_LOG << "testDeleteDataStorage003 end" << std::endl;
    DTEST_LOG << "testDeleteDataStorage004 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().DeleteDataStorage(DEVICE_ID, true);
    DTEST_LOG << "testDeleteDataStorage004 end" << std::endl;

    u16string deviceId = Str8ToStr16(DEVICE_ID);
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    auto ret = DistributedSchedMissionManager::GetInstance().UnRegisterMissionListener(deviceId, listener);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testUnRegisterMissionListener007 end" << std::endl;
}

/**
 * @tc.name: testUnRegisterMissionListener008
 * @tc.desc: register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testUnRegisterMissionListener008, TestSize.Level3)
{
    DTEST_LOG << "testUnRegisterMissionListener008 begin" << std::endl;
    /**
     * @tc.steps: step1. enqueue cached snapshot info
     */
    DTEST_LOG << "testEnqueueCachedSnapshotInfo001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().EnqueueCachedSnapshotInfo("", 1, nullptr);
    DTEST_LOG << "testEnqueueCachedSnapshotInfo001 end" << std::endl;
    DTEST_LOG << "testEnqueueCachedSnapshotInfo002 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().EnqueueCachedSnapshotInfo(DEVICE_ID, 1, nullptr);
    DTEST_LOG << "testEnqueueCachedSnapshotInfo002 end" << std::endl;
    DTEST_LOG << "testEnqueueCachedSnapshotInfo003 begin" << std::endl;
    unique_ptr<Snapshot> snapshot = make_unique<Snapshot>();
    DistributedSchedMissionManager::GetInstance().EnqueueCachedSnapshotInfo("", 1, std::move(snapshot));
    DTEST_LOG << "testEnqueueCachedSnapshotInfo003 end" << std::endl;
    DTEST_LOG << "testDequeueCachedSnapshotInfo001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().DequeueCachedSnapshotInfo("", 1);
    DTEST_LOG << "testDequeueCachedSnapshotInfo001 end" << std::endl;
    DTEST_LOG << "testDequeueCachedSnapshotInfo002 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().DequeueCachedSnapshotInfo(DEVICE_ID, 1);
    DTEST_LOG << "testDequeueCachedSnapshotInfo002 end" << std::endl;
    /**
     * @tc.steps: step2. reborn mission cache
     */
    DTEST_LOG << "testRebornMissionCache001 begin" << std::endl;
    std::vector<DstbMissionInfo> missionInfos;
    DistributedSchedMissionManager::GetInstance().RebornMissionCache("", missionInfos);
    DTEST_LOG << "testRebornMissionCache001 end" << std::endl;
    DTEST_LOG << "testRebornMissionCache002 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().RebornMissionCache(DEVICE_ID, missionInfos);
    DTEST_LOG << "testRebornMissionCache002 end" << std::endl;

    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().UnRegisterMissionListener(deviceId, listener);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testUnRegisterMissionListener008 end" << std::endl;
}

/**
 * @tc.name: testUnRegisterMissionListener009
 * @tc.desc: register mission listener
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testUnRegisterMissionListener009, TestSize.Level3)
{
    DTEST_LOG << "testUnRegisterMissionListener009 begin" << std::endl;
    /**
     * @tc.steps: step1. fetch device handler
     */
    DTEST_LOG << "testFetchDeviceHandler001 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().FetchDeviceHandler("");
    DistributedSchedMissionManager::GetInstance().FetchDeviceHandler(DEVICE_ID);
    DTEST_LOG << "testFetchDeviceHandler001 end" << std::endl;

    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    sptr<IRemoteObject> nullListener = nullptr;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        listenerInfo.Emplace(nullListener);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().UnRegisterMissionListener(deviceId, listener);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testUnRegisterMissionListener009 end" << std::endl;
}

/**
 * @tc.name: testCleanMissionResources002
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testCleanMissionResources002, TestSize.Level3)
{
    DTEST_LOG << "testCleanMissionResources002 begin" << std::endl;
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> nullListener = nullptr;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(nullListener);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    DistributedSchedMissionManager::GetInstance().CleanMissionResources(DEVICE_ID);
    DTEST_LOG << "testCleanMissionResources002 end" << std::endl;
}

/**
 * @tc.name: testStopSyncRemoteMissions013
 * @tc.desc: stop sync missions from remote with deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncRemoteMissions013, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncRemoteMissions013 begin" << std::endl;
    /**
     * @tc.steps: step1. test GetRemoteDms
     */
    DTEST_LOG << "testGetRemoteDms001 begin" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_[localDeviceId_] = proxy;
    }

    DistributedSchedMissionManager::GetInstance().GetRemoteDms(localDeviceId_);
    DTEST_LOG << "testGetRemoteDms001 end" << std::endl;

    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_[DEVICE_ID] = proxy;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().StopSyncRemoteMissions(DEVICE_ID, false, false);
    EXPECT_NE(ret, ERR_NONE);
    DTEST_LOG << "testStopSyncRemoteMissions013 end" << std::endl;
}

/**
 * @tc.name: testStartSyncMissionsFromRemote002
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncMissionsFromRemote002, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncMissionsFromRemote002 begin" << std::endl;
    /**
     * @tc.steps: step1. test GetRemoteDms
     */
    DTEST_LOG << "testGetRemoteDms002 begin" << std::endl;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_[localDeviceId_] = nullptr;
    }

    DistributedSchedMissionManager::GetInstance().GetRemoteDms(localDeviceId_);
    DTEST_LOG << "testGetRemoteDms002 end" << std::endl;

    std::vector<DstbMissionInfo> missionInfos;
    CallerInfo callerInfo;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    DistributedSchedMissionManager::GetInstance().missonChangeListener_ = new DistributedMissionChangeListener();
    DistributedSchedMissionManager::GetInstance().GenerateCallerInfo(callerInfo);
    DistributedSchedMissionManager::GetInstance().isRegMissionChange_ = true;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncMissionsFromRemote(callerInfo, missionInfos);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncMissionsFromRemote002 end" << std::endl;
}

/**
 * @tc.name: testStartSyncMissionsFromRemote003
 * @tc.desc: prepare and sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStartSyncMissionsFromRemote003, TestSize.Level3)
{
    DTEST_LOG << "testStartSyncMissionsFromRemote003 begin" << std::endl;
    /**
     * @tc.steps: step1. test notify remote died
     */
    DTEST_LOG << "testNotifyRemoteDied002 begin" << std::endl;
    wptr<IRemoteObject> remote = new RemoteMissionListenerTest();
    if (DistributedSchedMissionManager::GetInstance().distributedDataStorage_ == nullptr) {
        DistributedSchedMissionManager::GetInstance().distributedDataStorage_ =
            std::make_shared<DistributedDataStorage>();
    }
    DistributedSchedMissionManager::GetInstance().NotifyRemoteDied(remote);
    DTEST_LOG << "testNotifyRemoteDied002 end" << std::endl;

    std::vector<DstbMissionInfo> missionInfos;
    CallerInfo callerInfo;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    DistributedSchedMissionManager::GetInstance().missonChangeListener_ = nullptr;
    DistributedSchedMissionManager::GetInstance().GenerateCallerInfo(callerInfo);
    DistributedSchedMissionManager::GetInstance().isRegMissionChange_ = false;
    auto ret = DistributedSchedMissionManager::GetInstance().StartSyncMissionsFromRemote(callerInfo, missionInfos);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testStartSyncMissionsFromRemote003 end" << std::endl;
}

/**
 * @tc.name: testStopSyncMissionsFromRemote003
 * @tc.desc: stop sync missions from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testStopSyncMissionsFromRemote003, TestSize.Level3)
{
    DTEST_LOG << "testStopSyncMissionsFromRemote003 begin" << std::endl;
    std::vector<DstbMissionInfo> missionInfos;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    DistributedSchedMissionManager::GetInstance().missonChangeListener_ = nullptr;
    DistributedSchedMissionManager::GetInstance().StopSyncMissionsFromRemote(DEVICE_ID);
    DTEST_LOG << "testStopSyncMissionsFromRemote003 end" << std::endl;
}

/**
 * @tc.name: testNeedSyncDevice003
 * @tc.desc: need sync device
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNeedSyncDevice003, TestSize.Level3)
{
    DTEST_LOG << "testNeedSyncDevice003 begin" << std::endl;
    /**
     * @tc.steps: step1. delete cached snapshot info
     */
    DTEST_LOG << "testDeleteCachedSnapshotInfo001 begin" << std::endl;
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_.clear();
    }
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = DEVICE_ID;
    }
    std::unique_ptr<Snapshot> snapshot = make_unique<Snapshot>();
    std::string key = DistributedSchedMissionManager::GetInstance().GenerateKeyInfo(DEVICE_ID, 1);
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().cachedSnapshotInfos_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().cachedSnapshotInfos_[key] = std::move(snapshot);
    }
    DistributedSchedMissionManager::GetInstance().DeleteCachedSnapshotInfo(DEVICE_ID);
    DTEST_LOG << "testDeleteCachedSnapshotInfo001 end" << std::endl;

    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteSyncDeviceLock_);
        DistributedSchedMissionManager::GetInstance().remoteSyncDeviceSet_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteSyncDeviceLock_);
        DistributedSchedMissionManager::GetInstance().remoteSyncDeviceSet_.emplace(DEVICE_ID);
    }
    bool ret = DistributedSchedMissionManager::GetInstance().NeedSyncDevice(DEVICE_ID);
    EXPECT_TRUE(ret);
    DTEST_LOG << "testNeedSyncDevice003 end" << std::endl;
}

/**
 * @tc.name: testHasSyncListener002
 * @tc.desc: need sync device
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testHasSyncListener002, TestSize.Level3)
{
    DTEST_LOG << "testHasSyncListener002 begin" << std::endl;
    /**
     * @tc.steps: step1. reborn mission cache
     */
    DTEST_LOG << "testRebornMissionCache003 begin" << std::endl;
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_.clear();
    }
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = DEVICE_ID;
    }
    std::vector<DstbMissionInfo> missionInfos;
    DistributedSchedMissionManager::GetInstance().RebornMissionCache(DEVICE_ID, missionInfos);
    DTEST_LOG << "testRebornMissionCache003 end" << std::endl;

    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        listenerInfo.called = true;
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    bool ret = DistributedSchedMissionManager::GetInstance().HasSyncListener(DEVICE_ID);
    EXPECT_TRUE(ret);
    DTEST_LOG << "testHasSyncListener002 end" << std::endl;
}

/**
 * @tc.name: testNotifySnapshotChanged002
 * @tc.desc: test notify snapshot changed
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifySnapshotChanged002, TestSize.Level3)
{
    DTEST_LOG << "testNotifySnapshotChanged002 begin" << std::endl;
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.called = false;
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    DistributedSchedMissionManager::GetInstance().NotifySnapshotChanged(DEVICE_ID, 0);
    DTEST_LOG << "testNotifySnapshotChanged002 end" << std::endl;
}

/**
 * @tc.name: testNotifySnapshotChanged003
 * @tc.desc: test notify snapshot changed
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifySnapshotChanged003, TestSize.Level3)
{
    DTEST_LOG << "testNotifySnapshotChanged003 begin" << std::endl;
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        listenerInfo.called = true;
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    DistributedSchedMissionManager::GetInstance().NotifySnapshotChanged(DEVICE_ID, 0);
    DTEST_LOG << "testNotifySnapshotChanged003 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDied003
 * @tc.desc: test on remote died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDied003, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDied003 begin" << std::endl;
    wptr<IRemoteObject> remote = new RemoteMissionListenerTest();
    DistributedSchedMissionManager::GetInstance().missionHandler_ = nullptr;
    DistributedSchedMissionManager::GetInstance().OnRemoteDied(remote);
    DTEST_LOG << "testOnRemoteDied003 end" << std::endl;
}

/**
 * @tc.name: testDequeueCachedSnapshotInfo003
 * @tc.desc: enqueue cached snapshot info
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testDequeueCachedSnapshotInfo003, TestSize.Level3)
{
    DTEST_LOG << "testDequeueCachedSnapshotInfo003 begin" << std::endl;
    std::unique_ptr<Snapshot> snapshot = make_unique<Snapshot>();
    std::string key = DistributedSchedMissionManager::GetInstance().GenerateKeyInfo(DEVICE_ID, 1);
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().cachedSnapshotInfos_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().cachedSnapshotInfos_[key] = std::move(snapshot);
    }
    auto ret = DistributedSchedMissionManager::GetInstance().DequeueCachedSnapshotInfo(DEVICE_ID, 1);
    EXPECT_NE(ret, nullptr);
    DTEST_LOG << "testDequeueCachedSnapshotInfo003 end" << std::endl;
}

/**
 * @tc.name: testFetchCachedRemoteMissions010
 * @tc.desc: test FetchCachedRemoteMissions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchCachedRemoteMissions010, TestSize.Level3)
{
    DTEST_LOG << "testFetchCachedRemoteMissions010 begin" << std::endl;
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_.clear();
    }
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = DEVICE_ID;
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteMissionInfosLock_);
        DistributedSchedMissionManager::GetInstance().deviceMissionInfos_.clear();
    }
    std::vector<DstbMissionInfo> dstbMissionInfos;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteMissionInfosLock_);
        DistributedSchedMissionManager::GetInstance().deviceMissionInfos_[uuid] = dstbMissionInfos;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().FetchCachedRemoteMissions(DEVICE_ID,
        0, dstbMissionInfos);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testFetchCachedRemoteMissions010 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionsChangedFromRemote003
 * @tc.desc: notify missions changed from remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionsChangedFromRemote003, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionsChangedFromRemote003 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = DEVICE_ID;
    callerInfo.uid = 0;
    callerInfo.pid = 0;
    callerInfo.dmsVersion = 0;
    std::vector<DstbMissionInfo> missionInfos;
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        listenerInfo.called = true;
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    DistributedSchedMissionManager::GetInstance().missionHandler_ = nullptr;
    auto ret = DistributedSchedMissionManager::GetInstance().NotifyMissionsChangedFromRemote(callerInfo, missionInfos);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "testNotifyMissionsChangedFromRemote003 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionSnapshotCreated002
 * @tc.desc: notify mission snapshot created
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionSnapshotCreated002, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionSnapshotCreated002 begin" << std::endl;
    auto missionChangeRunner = AppExecFwk::EventRunner::Create("DistributedMissionChange");
    DistributedSchedMissionManager::GetInstance().missionChangeHandler_ =
        std::make_shared<AppExecFwk::EventHandler>(missionChangeRunner);
    DistributedSchedMissionManager::GetInstance().NotifyMissionSnapshotCreated(1);
    DTEST_LOG << "testNotifyMissionSnapshotCreated002 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionSnapshotCreated003
 * @tc.desc: notify mission snapshot created
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionSnapshotCreated003, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionSnapshotCreated003 begin" << std::endl;
    auto missionChangeRunner = AppExecFwk::EventRunner::Create("DistributedMissionChange");
    DistributedSchedMissionManager::GetInstance().missionChangeHandler_ =
        std::make_shared<AppExecFwk::EventHandler>(missionChangeRunner);
    DistributedSchedMissionManager::GetInstance().distributedDataStorage_ = nullptr;
    DistributedSchedMissionManager::GetInstance().NotifyMissionSnapshotCreated(1);
    DTEST_LOG << "testNotifyMissionSnapshotCreated003 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionsChangedToRemote002
 * @tc.desc: notify missions changed to remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionsChangedToRemote002, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionsChangedToRemote002 begin" << std::endl;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteSyncDeviceLock_);
        DistributedSchedMissionManager::GetInstance().remoteSyncDeviceSet_.clear();
    }
    std::vector<DstbMissionInfo> missionInfos;
    auto ret = DistributedSchedMissionManager::GetInstance().NotifyMissionsChangedToRemote(missionInfos);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testNotifyMissionsChangedToRemote002 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionsChangedToRemote003
 * @tc.desc: notify missions changed to remote
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionsChangedToRemote003, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionsChangedToRemote003 begin" << std::endl;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteSyncDeviceLock_);
        DistributedSchedMissionManager::GetInstance().remoteSyncDeviceSet_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteSyncDeviceLock_);
        DistributedSchedMissionManager::GetInstance().remoteSyncDeviceSet_.emplace(localDeviceId_);
    }
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    }
    int32_t deviceType = 0;
    std::shared_ptr<DmsDeviceInfo> dmsDeviceInfo = make_shared<DmsDeviceInfo>(DEVICE_NAME, deviceType, localDeviceId_);
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[localDeviceId_] = dmsDeviceInfo;
    }
    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_.clear();
    }
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = localDeviceId_;
    }
    std::vector<DstbMissionInfo> missionInfos;
    auto ret = DistributedSchedMissionManager::GetInstance().NotifyMissionsChangedToRemote(missionInfos);
    EXPECT_EQ(ret, ERR_NONE);
    DTEST_LOG << "testNotifyMissionsChangedToRemote003 end" << std::endl;
}

/**
 * @tc.name: testNotifyMissionsChangedToRemoteInner003
 * @tc.desc: notify missions changed to remote inner
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyMissionsChangedToRemoteInner003, TestSize.Level3)
{
    DTEST_LOG << "testNotifyMissionsChangedToRemoteInner003 begin" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_[DEVICE_ID] = proxy;
    }
    CallerInfo callerInfo;
    std::vector<DstbMissionInfo> missionInfos;
    DistributedSchedMissionManager::GetInstance().NotifyMissionsChangedToRemoteInner(
        DEVICE_ID, missionInfos, callerInfo);
    DTEST_LOG << "testNotifyMissionsChangedToRemoteInner003 end" << std::endl;
}

/**
 * @tc.name: testFetchDeviceHandler003
 * @tc.desc: fetch device handler
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchDeviceHandler003, TestSize.Level3)
{
    DTEST_LOG << "testFetchDeviceHandler003 begin" << std::endl;
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    }

    int32_t deviceType = 0;
    std::shared_ptr<DmsDeviceInfo> dmsDeviceInfo = make_shared<DmsDeviceInfo>(DEVICE_NAME, deviceType, DEVICE_ID);
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[DEVICE_ID] = dmsDeviceInfo;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().FetchDeviceHandler(DEVICE_ID);
    EXPECT_EQ(ret, nullptr);
    DTEST_LOG << "testFetchDeviceHandler003 end" << std::endl;
}

/**
 * @tc.name: testFetchDeviceHandler004
 * @tc.desc: fetch device handler
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchDeviceHandler004, TestSize.Level3)
{
    DTEST_LOG << "testFetchDeviceHandler004 begin" << std::endl;
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    }
    int32_t deviceType = 0;
    std::shared_ptr<DmsDeviceInfo> dmsDeviceInfo = make_shared<DmsDeviceInfo>(DEVICE_NAME, deviceType, DEVICE_ID);
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[DEVICE_ID] = dmsDeviceInfo;
    }

    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_.clear();
    }
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = DEVICE_ID;
    }
    auto ret = DistributedSchedMissionManager::GetInstance().FetchDeviceHandler(DEVICE_ID);
    EXPECT_NE(ret, nullptr);
    DTEST_LOG << "testFetchDeviceHandler004 end" << std::endl;
}

/**
 * @tc.name: testFetchDeviceHandler005
 * @tc.desc: fetch device handler
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testFetchDeviceHandler005, TestSize.Level3)
{
    DTEST_LOG << "testFetchDeviceHandler005 begin" << std::endl;
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
    }
    int32_t deviceType = 0;
    std::shared_ptr<DmsDeviceInfo> dmsDeviceInfo = make_shared<DmsDeviceInfo>(DEVICE_NAME, deviceType, DEVICE_ID);
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().deviceLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_[DEVICE_ID] = dmsDeviceInfo;
    }

    std::string uuid = "uuid for GetUuidByNetworkId";
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_.clear();
    }
    {
        lock_guard<mutex> autoLock(DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdLock_);
        DtbschedmgrDeviceInfoStorage::GetInstance().uuidNetworkIdMap_[uuid] = DEVICE_ID;
    }
    auto anonyUuid = DnetworkAdapter::AnonymizeDeviceId(uuid);
    auto runner = AppExecFwk::EventRunner::Create(anonyUuid + "_MissionN");
    auto handler = std::make_shared<AppExecFwk::EventHandler>(runner);
    DistributedSchedMissionManager::GetInstance().deviceHandle_.emplace(uuid, handler);
    auto ret = DistributedSchedMissionManager::GetInstance().FetchDeviceHandler(DEVICE_ID);
    EXPECT_NE(ret, nullptr);
    DTEST_LOG << "testFetchDeviceHandler005 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDmsDied009
 * @tc.desc: on remote dms died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDmsDied009, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDmsDied009 begin" << std::endl;
    wptr<IRemoteObject> remote = new RemoteMissionListenerTest();
    DistributedSchedMissionManager::GetInstance().missionHandler_ = nullptr;
    DistributedSchedMissionManager::GetInstance().OnRemoteDmsDied(remote);
    DTEST_LOG << "testOnRemoteDmsDied009 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDmsDied005
 * @tc.desc: on remote dms died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDmsDied005, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDmsDied005 begin" << std::endl;
    wptr<IRemoteObject> remote = new RemoteMissionListenerTest();
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    DistributedSchedMissionManager::GetInstance().OnRemoteDmsDied(remote);
    DTEST_LOG << "testOnRemoteDmsDied005 end" << std::endl;
}

/**
 * @tc.name: testRetryStartSyncRemoteMissions003
 * @tc.desc: retry start sync remote missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRetryStartSyncRemoteMissions003, TestSize.Level3)
{
    DTEST_LOG << "testRetryStartSyncRemoteMissions003 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    DistributedSchedMissionManager::GetInstance().RetryStartSyncRemoteMissions(DEVICE_ID, localDeviceId_, 1);
    DTEST_LOG << "testRetryStartSyncRemoteMissions003 end" << std::endl;
}

/**
 * @tc.name: testRetryStartSyncRemoteMissions004
 * @tc.desc: retry start sync remote missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRetryStartSyncRemoteMissions004, TestSize.Level3)
{
    DTEST_LOG << "testRetryStartSyncRemoteMissions004 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        listenerInfo.called = true;
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    DistributedSchedMissionManager::GetInstance().RetryStartSyncRemoteMissions(DEVICE_ID, localDeviceId_, 1);
    DTEST_LOG << "testRetryStartSyncRemoteMissions004 end" << std::endl;
}

/**
 * @tc.name: testRetryStartSyncRemoteMissions005
 * @tc.desc: retry start sync remote missions
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRetryStartSyncRemoteMissions005, TestSize.Level3)
{
    DTEST_LOG << "testRetryStartSyncRemoteMissions005 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        listenerInfo.called = true;
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_[DEVICE_ID] = proxy;
    }
    DistributedSchedMissionManager::GetInstance().RetryStartSyncRemoteMissions(DEVICE_ID, localDeviceId_, 1);
    DTEST_LOG << "testRetryStartSyncRemoteMissions005 end" << std::endl;
}

/**
 * @tc.name: testOnMissionListenerDied003
 * @tc.desc: on mission listener died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnMissionListenerDied003, TestSize.Level3)
{
    DTEST_LOG << "testOnMissionListenerDied003 begin" << std::endl;
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        listenerInfo.called = true;
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    DistributedSchedMissionManager::GetInstance().OnMissionListenerDied(listener);
    DTEST_LOG << "testOnMissionListenerDied003 end" << std::endl;
}

/**
 * @tc.name: testOnMissionListenerDied004
 * @tc.desc: on mission listener died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnMissionListenerDied004, TestSize.Level3)
{
    DTEST_LOG << "testOnMissionListenerDied004 begin" << std::endl;
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    sptr<IRemoteObject> remote = sptr<IRemoteObject>();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        listenerInfo.called = true;
        listenerInfo.Emplace(remote);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    DistributedSchedMissionManager::GetInstance().OnMissionListenerDied(listener);
    DTEST_LOG << "testOnMissionListenerDied004 end" << std::endl;
}

/**
 * @tc.name: testOnMissionListenerDied005
 * @tc.desc: on mission listener died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnMissionListenerDied005, TestSize.Level3)
{
    DTEST_LOG << "testOnMissionListenerDied005 begin" << std::endl;
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    sptr<IRemoteObject> listener = new RemoteMissionListenerTest();
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(listener);
        listenerInfo.called = false;
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    DistributedSchedMissionManager::GetInstance().OnMissionListenerDied(listener);
    DTEST_LOG << "testOnMissionListenerDied005 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDmsDied006
 * @tc.desc: on remote dms died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDmsDied006, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDmsDied006 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    sptr<IRemoteObject> remote = new RemoteMissionListenerTest();
    sptr<IDistributedSched> remoteDmsObj = iface_cast<IDistributedSched>(remote);
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_[DEVICE_ID] = remoteDmsObj;
    }
    DistributedSchedMissionManager::GetInstance().OnRemoteDmsDied(remote);
    DTEST_LOG << "testOnRemoteDmsDied006 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDmsDied007
 * @tc.desc: on remote dms died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDmsDied007, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDmsDied007 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    sptr<IRemoteObject> remote = new RemoteMissionListenerTest();
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_[DEVICE_ID] = proxy;
    }
    DistributedSchedMissionManager::GetInstance().OnRemoteDmsDied(remote);
    DTEST_LOG << "testOnRemoteDmsDied007 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDmsDied008
 * @tc.desc: on remote dms died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnRemoteDmsDied008, TestSize.Level3)
{
    DTEST_LOG << "testOnRemoteDmsDied008 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    sptr<IRemoteObject> remote = new RemoteMissionListenerTest();
    sptr<IDistributedSched> remoteDmsObj = iface_cast<IDistributedSched>(remote);
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().remoteDmsLock_);
        DistributedSchedMissionManager::GetInstance().remoteDmsMap_[DEVICE_ID] = remoteDmsObj;
    }
    u16string deviceId = Str8ToStr16(DEVICE_ID);
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_.clear();
    }
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedMissionManager::GetInstance().listenDeviceLock_);
        ListenerInfo listenerInfo;
        listenerInfo.Emplace(remote);
        listenerInfo.called = true;
        DistributedSchedMissionManager::GetInstance().listenDeviceMap_[deviceId] = listenerInfo;
    }
    DistributedSchedMissionManager::GetInstance().OnRemoteDmsDied(remote);
    DTEST_LOG << "testOnRemoteDmsDied008 end" << std::endl;
}

/**
 * @tc.name: testNotifyDmsProxyProcessDied002
 * @tc.desc: notify dms proxy process died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testNotifyDmsProxyProcessDied002, TestSize.Level3)
{
    DTEST_LOG << "testNotifyDmsProxyProcessDied002 begin" << std::endl;
    DistributedSchedMissionManager::GetInstance().isRegMissionChange_ = false;
    DistributedSchedMissionManager::GetInstance().NotifyDmsProxyProcessDied();
    DTEST_LOG << "testNotifyDmsProxyProcessDied002 end" << std::endl;
}

/**
 * @tc.name: testRetryRegisterMissionChange002
 * @tc.desc: retry register mission change
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testRetryRegisterMissionChange002, TestSize.Level3)
{
    DTEST_LOG << "testRetryRegisterMissionChange002 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    DistributedSchedMissionManager::GetInstance().RetryRegisterMissionChange(1);
    DTEST_LOG << "testRetryRegisterMissionChange002 end" << std::endl;
}

/**
 * @tc.name: testOnDnetDied002
 * @tc.desc: on dnet died
 * @tc.type: FUNC
 */
HWTEST_F(DMSMissionManagerTest, testOnDnetDied002, TestSize.Level3)
{
    DTEST_LOG << "testOnDnetDied002 begin" << std::endl;
    auto runner = AppExecFwk::EventRunner::Create("MissionManagerHandler");
    DistributedSchedMissionManager::GetInstance().missionHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    DistributedSchedMissionManager::GetInstance().isRegMissionChange_ = false;
    DistributedSchedMissionManager::GetInstance().OnDnetDied();
    DTEST_LOG << "testOnDnetDied002 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS