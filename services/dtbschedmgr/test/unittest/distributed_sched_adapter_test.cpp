/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "distributed_sched_adapter_test.h"
#include "dtbschedmgr_log.h"
#include "snapshot.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
void DistributedSchedAdapterTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedSchedAdapterTest::SetUpTestCase" << std::endl;
}

void DistributedSchedAdapterTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedSchedAdapterTest::TearDownTestCase" << std::endl;
}

void DistributedSchedAdapterTest::TearDown()
{
    DTEST_LOG << "DistributedSchedAdapterTest::TearDown" << std::endl;
}

void DistributedSchedAdapterTest::SetUp()
{
    distributedSchedAdapter_ = std::make_shared<DistributedSchedAdapter>();
    distributedSchedAdapter_->Init();
    DTEST_LOG << "DistributedSchedAdapterTest::SetUp" << std::endl;
}

/**
 * @tc.name: ConnectAbility_001
 * @tc.desc: invalid params
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, ConnectAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest ConnectAbility_001 begin" << std::endl;
    const OHOS::AAFwk::Want want;
    const sptr<IRemoteObject> connect;
    const sptr<IRemoteObject> callerToken;
    int32_t result = distributedSchedAdapter_->ConnectAbility(want, connect, callerToken);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DistributedSchedAdapterTest ConnectAbility_001 end" << std::endl;
}

/**
 * @tc.name: DisconnectAbility_001
 * @tc.desc: invalid params
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, DisconnectAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest DisconnectAbility_001 begin" << std::endl;
    const sptr<IRemoteObject> connect;
    int32_t result = distributedSchedAdapter_->DisconnectAbility(connect);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DistributedSchedAdapterTest DisconnectAbility_001 end" << std::endl;
}

/**
 * @tc.name: DeviceOnline_001
 * @tc.desc: dmsAdapterHandler_ is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, DeviceOnline_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOnline_001 begin" << std::endl;
    const std::string deviceId = "";
    distributedSchedAdapter_->dmsAdapterHandler_ = nullptr;
    distributedSchedAdapter_->DeviceOnline(deviceId);
    EXPECT_EQ(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOnline_001 end" << std::endl;
}

/**
 * @tc.name: DeviceOnline_002
 * @tc.desc: deviceId is empty
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, DeviceOnline_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOnline_002 begin" << std::endl;
    const std::string deviceId = "";
    distributedSchedAdapter_->DeviceOnline(deviceId);
    EXPECT_NE(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOnline_002 end" << std::endl;
}

/**
 * @tc.name: DeviceOnline_003
 * @tc.desc: deviceId is not empty
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, DeviceOnline_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOnline_003 begin" << std::endl;
    const std::string deviceId = "mockDeviceId";
    distributedSchedAdapter_->DeviceOnline(deviceId);
    EXPECT_NE(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOnline_003 end" << std::endl;
}

/**
 * @tc.name: DeviceOffline_001
 * @tc.desc: dmsAdapterHandler_ is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, DeviceOffline_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOffline_001 begin" << std::endl;
    const std::string deviceId = "";
    distributedSchedAdapter_->dmsAdapterHandler_ = nullptr;
    distributedSchedAdapter_->DeviceOffline(deviceId);
    EXPECT_EQ(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOffline_001 end" << std::endl;
}

/**
 * @tc.name: DeviceOffline_002
 * @tc.desc: deviceId is empty
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, DeviceOffline_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOffline_002 begin" << std::endl;
    const std::string deviceId = "";
    distributedSchedAdapter_->DeviceOffline(deviceId);
    EXPECT_NE(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOffline_002 end" << std::endl;
}

/**
 * @tc.name: DeviceOffline_003
 * @tc.desc: deviceId is not empty
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, DeviceOffline_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOffline_003 begin" << std::endl;
    const std::string deviceId = "mockDeviceId";
    distributedSchedAdapter_->DeviceOffline(deviceId);
    EXPECT_NE(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest DeviceOffline_003 end" << std::endl;
}

/**
 * @tc.name: ProcessConnectDied_001
 * @tc.desc: dmsAdapterHandler_ is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, ProcessConnectDied_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest ProcessConnectDied_001 begin" << std::endl;
    const sptr<IRemoteObject> connect;
    distributedSchedAdapter_->dmsAdapterHandler_ = nullptr;
    distributedSchedAdapter_->ProcessConnectDied(connect);
    EXPECT_EQ(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest ProcessConnectDied_001 end" << std::endl;
}

/**
 * @tc.name: ProcessConnectDied_002
 * @tc.desc: connect is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, ProcessConnectDied_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest ProcessConnectDied_002 begin" << std::endl;
    const sptr<IRemoteObject> connect = nullptr;
    distributedSchedAdapter_->ProcessConnectDied(connect);
    EXPECT_NE(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest ProcessConnectDied_002 end" << std::endl;
}

/**
 * @tc.name: ProcessCalleeDied_001
 * @tc.desc: dmsAdapterHandler_ is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, ProcessCalleeDied_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest ProcessCalleeDied_001 begin" << std::endl;
    const sptr<IRemoteObject> connect;
    distributedSchedAdapter_->dmsAdapterHandler_ = nullptr;
    distributedSchedAdapter_->ProcessCalleeDied(connect);
    EXPECT_EQ(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest ProcessCalleeDied_001 end" << std::endl;
}

/**
 * @tc.name: ProcessCalleeDied_002
 * @tc.desc: connect is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, ProcessCalleeDied_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest ProcessCalleeDied_002 begin" << std::endl;
    const sptr<IRemoteObject> connect = nullptr;
    distributedSchedAdapter_->ProcessCalleeDied(connect);
    EXPECT_NE(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest ProcessCalleeDied_002 end" << std::endl;
}

/**
 * @tc.name: ProcessCallerDied_001
 * @tc.desc: dmsAdapterHandler_ is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, ProcessCallerDied_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest ProcessCallerDied_001 begin" << std::endl;
    const sptr<IRemoteObject> connect;
    int32_t deviceType = 0;
    distributedSchedAdapter_->dmsAdapterHandler_ = nullptr;
    distributedSchedAdapter_->ProcessCallerDied(connect, deviceType);
    EXPECT_EQ(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest ProcessCallerDied_001 end" << std::endl;
}

/**
 * @tc.name: ProcessCallerDied_002
 * @tc.desc: connect is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, ProcessCallerDied_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedAdapterTest ProcessCallerDied_002 begin" << std::endl;
    const sptr<IRemoteObject> connect = nullptr;
    int32_t deviceType = 0;
    distributedSchedAdapter_->ProcessCallerDied(connect, deviceType);
    EXPECT_NE(distributedSchedAdapter_->dmsAdapterHandler_, nullptr);
    DTEST_LOG << "DistributedSchedAdapterTest ProcessCallerDied_002 end" << std::endl;
}

/**
 * @tc.name: GetLocalMissionInfos_001
 * @tc.desc: numMissions is invalid
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, GetLocalMissionInfos_001, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedAdapterTest GetLocalMissionInfos_001 begin" << std::endl;
    int32_t numMissions = -1;
    std::vector<DstbMissionInfo> missionInfos;
    int32_t result = distributedSchedAdapter_->GetLocalMissionInfos(numMissions, missionInfos);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DistributedSchedAdapterTest GetLocalMissionInfos_001 end" << std::endl;
}

/**
 * @tc.name: GetLocalMissionInfos_002
 * @tc.desc: numMissions is zero
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, GetLocalMissionInfos_002, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedAdapterTest GetLocalMissionInfos_002 begin" << std::endl;
    int32_t numMissions = 0;
    std::vector<DstbMissionInfo> missionInfos;
    int32_t result = distributedSchedAdapter_->GetLocalMissionInfos(numMissions, missionInfos);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DistributedSchedAdapterTest GetLocalMissionInfos_002 end" << std::endl;
}

/**
 * @tc.name: GetLocalMissionInfos_003
 * @tc.desc: numMissions is not zero
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, GetLocalMissionInfos_003, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedAdapterTest GetLocalMissionInfos_003 begin" << std::endl;
    int32_t numMissions = 10;
    std::vector<DstbMissionInfo> missionInfos;
    int32_t result = distributedSchedAdapter_->GetLocalMissionInfos(numMissions, missionInfos);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DistributedSchedAdapterTest GetLocalMissionInfos_003 end" << std::endl;
}

/**
 * @tc.name: RegisterMissionListener_001
 * @tc.desc: listener is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, RegisterMissionListener_001, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedAdapterTest RegisterMissionListener_001 begin" << std::endl;
    const sptr<DistributedMissionChangeListener> listener = nullptr;
    int32_t result = distributedSchedAdapter_->RegisterMissionListener(listener);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedAdapterTest RegisterMissionListener_001 end" << std::endl;
}

/**
 * @tc.name: RegisterMissionListener_002
 * @tc.desc: listener is not nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, RegisterMissionListener_002, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedAdapterTest RegisterMissionListener_002 begin" << std::endl;
    const sptr<DistributedMissionChangeListener> listener = new DistributedMissionChangeListener();
    int32_t result = distributedSchedAdapter_->RegisterMissionListener(listener);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DistributedSchedAdapterTest RegisterMissionListener_002 end" << std::endl;
}

/**
 * @tc.name: UnRegisterMissionListener_001
 * @tc.desc: listener is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, UnRegisterMissionListener_001, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedAdapterTest UnRegisterMissionListener_001 begin" << std::endl;
    const sptr<DistributedMissionChangeListener> listener = nullptr;
    int32_t result = distributedSchedAdapter_->UnRegisterMissionListener(listener);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedAdapterTest UnRegisterMissionListener_001 end" << std::endl;
}

/**
 * @tc.name: UnRegisterMissionListener_002
 * @tc.desc: listener is nullptr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, UnRegisterMissionListener_002, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedAdapterTest UnRegisterMissionListener_002 begin" << std::endl;
    const sptr<DistributedMissionChangeListener> listener = new DistributedMissionChangeListener();
    int32_t result = distributedSchedAdapter_->UnRegisterMissionListener(listener);
    EXPECT_NE(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedAdapterTest UnRegisterMissionListener_002 end" << std::endl;
}

/**
 * @tc.name: GetLocalMissionSnapshotInfo_001
 * @tc.desc: networkId is invalid
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedAdapterTest, GetLocalMissionSnapshotInfo_001, TestSize.Level4)
{
    DTEST_LOG << "DistributedSchedAdapterTest GetLocalMissionSnapshotInfo_001 begin" << std::endl;
    const std::string networkId = "invalidNetworkId";
    int32_t missionId = 0;
    AAFwk::MissionSnapshot missionSnapshot;
    int32_t result = distributedSchedAdapter_->GetLocalMissionSnapshotInfo(networkId, missionId, missionSnapshot);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DistributedSchedAdapterTest GetLocalMissionSnapshotInfo_001 end" << std::endl;
}
}
}