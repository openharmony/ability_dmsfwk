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

#include "dms_callback_task_test.h"
#include "dtbschedmgr_log.h"
#include "mock_remote_stub.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
void DmsCallbackTaskTest::SetUpTestCase()
{
    DTEST_LOG << "DmsCallbackTaskTest::SetUpTestCase" << std::endl;
}

void DmsCallbackTaskTest::TearDownTestCase()
{
    DTEST_LOG << "DmsCallbackTaskTest::TearDownTestCase" << std::endl;
}

void DmsCallbackTaskTest::TearDown()
{
    DTEST_LOG << "DmsCallbackTaskTest::TearDown" << std::endl;
}

void DmsCallbackTaskTest::SetUp()
{
    DmsCallbackTaskInitCallbackFunc mockCallback = [this] (int64_t taskId) {};
    dmsCallbackTask_ = std::make_shared<DmsCallbackTask>();
    dmsCallbackTask_->Init(mockCallback);
    DTEST_LOG << "DmsCallbackTaskTest::SetUp" << std::endl;
}

void DmsCallbackTaskTest::PushMockTask(int64_t taskId, std::string& deviceId)
{
    sptr<IRemoteObject> callback = nullptr;
    LaunchType launchType = LaunchType::FREEINSTALL_CONTINUE;
    OHOS::AAFwk::Want want;
    CallbackTaskItem item {
        .callback = callback,
        .taskId = taskId,
        .launchType = launchType,
        .deviceId = deviceId,
        .want = want,
    };
    dmsCallbackTask_->callbackMap_.emplace(taskId, item);
}

/**
 * @tc.name: GenerateTaskId_001
 * @tc.desc: currTaskId_ is INT64_MAX
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, GenerateTaskId_001, TestSize.Level4)
{
    DTEST_LOG << "DmsCallbackTaskTest GenerateTaskId_001 begin" << std::endl;
    dmsCallbackTask_->currTaskId_ = INT64_MAX;
    int64_t currValue = dmsCallbackTask_->GenerateTaskId();
    EXPECT_EQ(currValue, INT64_MAX);
    EXPECT_EQ(dmsCallbackTask_->currTaskId_, 1);
    DTEST_LOG << "DmsCallbackTaskTest GenerateTaskId_001 end" << std::endl;
}

/**
 * @tc.name: GenerateTaskId_002
 * @tc.desc: currTaskId_ is greater than zero
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, GenerateTaskId_002, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest GenerateTaskId_002 begin" << std::endl;
    dmsCallbackTask_->currTaskId_ = 1;
    int64_t currValue = dmsCallbackTask_->GenerateTaskId();
    EXPECT_EQ(currValue, 1);
    EXPECT_EQ(dmsCallbackTask_->currTaskId_, 2);
    DTEST_LOG << "DmsCallbackTaskTest GenerateTaskId_002 end" << std::endl;
}

/**
 * @tc.name: PushCallback_001
 * @tc.desc: invalid taskId
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, PushCallback_001, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_001 begin" << std::endl;
    int64_t taskId = -1;
    sptr<IRemoteObject> callback = nullptr;
    std::string deviceId = "mockDeviceId";
    LaunchType launchType = LaunchType::FREEINSTALL_START;
    OHOS::AAFwk::Want want;
    int32_t result = dmsCallbackTask_->PushCallback(taskId, callback, deviceId,
        launchType, want);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_001 end" << std::endl;
}

/**
 * @tc.name: PushCallback_002
 * @tc.desc: callback is nullptr
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, PushCallback_002, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_002 begin" << std::endl;
    int64_t taskId = 1;
    sptr<IRemoteObject> callback = nullptr;
    std::string deviceId = "mockDeviceId";
    LaunchType launchType = LaunchType::FREEINSTALL_START;
    OHOS::AAFwk::Want want;
    int32_t result = dmsCallbackTask_->PushCallback(taskId, callback, deviceId,
        launchType, want);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_002 end" << std::endl;
}

/**
 * @tc.name: PushCallback_003
 * @tc.desc: dmsCallbackHandler_ is nullptr
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, PushCallback_003, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_003 begin" << std::endl;
    int64_t taskId = 1;
    sptr<IRemoteObject> callback = new MockRemoteStub();
    std::string deviceId = "mockDeviceId";
    LaunchType launchType = LaunchType::FREEINSTALL_START;
    OHOS::AAFwk::Want want;
    dmsCallbackTask_->dmsCallbackHandler_ = nullptr;
    int32_t result = dmsCallbackTask_->PushCallback(taskId, callback, deviceId,
        launchType, want);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_003 end" << std::endl;
}

/**
 * @tc.name: PushCallback_004
 * @tc.desc: launchType is FREEINSTALL_CONTINUE
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, PushCallback_004, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_004 begin" << std::endl;
    int64_t taskId = 1;
    sptr<IRemoteObject> callback = new MockRemoteStub();
    std::string deviceId = "mockDeviceId";
    LaunchType launchType = LaunchType::FREEINSTALL_CONTINUE;
    OHOS::AAFwk::Want want;
    dmsCallbackTask_->dmsCallbackHandler_ = nullptr;
    int32_t result = dmsCallbackTask_->PushCallback(taskId, callback, deviceId,
        launchType, want);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_004 end" << std::endl;
}

/**
 * @tc.name: PushCallback_005
 * @tc.desc: taskId is exist
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, PushCallback_005, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_005 begin" << std::endl;
    int64_t taskId = 1;
    sptr<IRemoteObject> callback = new MockRemoteStub();
    std::string deviceId = "mockDeviceId";
    LaunchType launchType = LaunchType::FREEINSTALL_CONTINUE;
    OHOS::AAFwk::Want want;
    PushMockTask(taskId, deviceId);
    int32_t result = dmsCallbackTask_->PushCallback(taskId, callback, deviceId,
        launchType, want);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_005 end" << std::endl;
}

/**
 * @tc.name: PushCallback_006
 * @tc.desc: PushCallback success
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, PushCallback_006, TestSize.Level1)
{
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_006 begin" << std::endl;
    int64_t taskId = 1;
    sptr<IRemoteObject> callback = new MockRemoteStub();
    std::string deviceId = "mockDeviceId";
    LaunchType launchType = LaunchType::FREEINSTALL_CONTINUE;
    OHOS::AAFwk::Want want;
    int32_t result = dmsCallbackTask_->PushCallback(taskId, callback, deviceId,
        launchType, want);
    EXPECT_EQ(result, ERR_OK);
    DTEST_LOG << "DmsCallbackTaskTest PushCallback_006 end" << std::endl;
}

/**
 * @tc.name: PopCallback_001
 * @tc.desc: taskId is not exist
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, PopCallback_001, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest PopCallback_001 begin" << std::endl;
    int64_t taskId = 1;
    CallbackTaskItem result = dmsCallbackTask_->PopCallback(taskId);
    EXPECT_EQ(result.taskId, -1);
    DTEST_LOG << "DmsCallbackTaskTest PopCallback_001 end" << std::endl;
}

/**
 * @tc.name: PopCallback_002
 * @tc.desc: taskId is exist
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, PopCallback_002, TestSize.Level1)
{
    DTEST_LOG << "DmsCallbackTaskTest PopCallback_002 begin" << std::endl;
    int64_t taskId = 1;
    std::string deviceId = "";
    PushMockTask(taskId, deviceId);
    CallbackTaskItem result = dmsCallbackTask_->PopCallback(taskId);
    EXPECT_EQ(result.taskId, 1);
    DTEST_LOG << "DmsCallbackTaskTest PopCallback_002 end" << std::endl;
}

/**
 * @tc.name: PopContinuationMissionMap_001
 * @tc.desc: taskId is exsit
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, PopContinuationMissionMap_001, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest PopContinuationMissionMap_001 begin" << std::endl;
    int64_t taskId = 1;
    int64_t mockMissionId = 2;
    dmsCallbackTask_->continuationMissionMap_.emplace(taskId, mockMissionId);
    dmsCallbackTask_->PopContinuationMissionMap(taskId);
    EXPECT_EQ(dmsCallbackTask_->continuationMissionMap_.size(), 0);
    DTEST_LOG << "DmsCallbackTaskTest PopContinuationMissionMap_001 end" << std::endl;
}

/**
 * @tc.name: PopContinuationMissionMap_002
 * @tc.desc: taskId is not exsit
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, PopContinuationMissionMap_002, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest PopContinuationMissionMap_002 begin" << std::endl;
    int64_t taskId = 1;
    int64_t mockTaskId = 2;
    int64_t mockMissionId = 2;
    dmsCallbackTask_->continuationMissionMap_.emplace(mockTaskId, mockMissionId);
    dmsCallbackTask_->PopContinuationMissionMap(taskId);
    EXPECT_EQ(dmsCallbackTask_->continuationMissionMap_.size(), 1);
    DTEST_LOG << "DmsCallbackTaskTest PopContinuationMissionMap_002 end" << std::endl;
}

/**
 * @tc.name: GetContinuaionMissionId_001
 * @tc.desc: taskId is less than zero
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, GetContinuaionMissionId_001, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest GetContinuaionMissionId_001 begin" << std::endl;
    int64_t taskId = -1;
    int32_t result = dmsCallbackTask_->GetContinuaionMissionId(taskId);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsCallbackTaskTest GetContinuaionMissionId_001 end" << std::endl;
}

/**
 * @tc.name: GetContinuaionMissionId_002
 * @tc.desc: taskId is not exsit
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, GetContinuaionMissionId_002, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest GetContinuaionMissionId_002 begin" << std::endl;
    int64_t taskId = 1;
    int64_t result = dmsCallbackTask_->GetContinuaionMissionId(taskId);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsCallbackTaskTest GetContinuaionMissionId_002 end" << std::endl;
}

/**
 * @tc.name: GetContinuaionMissionId_003
 * @tc.desc: taskId is exsit
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, GetContinuaionMissionId_003, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest GetContinuaionMissionId_003 begin" << std::endl;
    int64_t taskId = 1;
    int64_t mockMissionId = 2;
    dmsCallbackTask_->continuationMissionMap_.emplace(taskId, mockMissionId);
    int64_t result = dmsCallbackTask_->GetContinuaionMissionId(taskId);
    EXPECT_EQ(result, mockMissionId);
    DTEST_LOG << "DmsCallbackTaskTest GetContinuaionMissionId_003 end" << std::endl;
}

/**
 * @tc.name: SetContinuationMissionMap_001
 * @tc.desc: taskId is less than zero
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, SetContinuationMissionMap_001, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_001 begin" << std::endl;
    int64_t taskId = -1;
    int64_t missionId = 1;
    dmsCallbackTask_->SetContinuationMissionMap(taskId, missionId);
    EXPECT_EQ(dmsCallbackTask_->continuationMissionMap_.size(), 0);
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_001 end" << std::endl;
}

/**
 * @tc.name: SetContinuationMissionMap_002
 * @tc.desc: missionId is less than zero
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, SetContinuationMissionMap_002, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_002 begin" << std::endl;
    int64_t taskId = 1;
    int64_t missionId = -1;
    dmsCallbackTask_->SetContinuationMissionMap(taskId, missionId);
    EXPECT_EQ(dmsCallbackTask_->continuationMissionMap_.size(), 0);
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_002 end" << std::endl;
}

/**
 * @tc.name: SetContinuationMissionMap_003
 * @tc.desc: taskId is less than zero, missionId is less than zero
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, SetContinuationMissionMap_003, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_003 begin" << std::endl;
    int64_t taskId = -1;
    int64_t missionId = -1;
    dmsCallbackTask_->SetContinuationMissionMap(taskId, missionId);
    EXPECT_EQ(dmsCallbackTask_->continuationMissionMap_.size(), 0);
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_003 end" << std::endl;
}

/**
 * @tc.name: SetContinuationMissionMap_004
 * @tc.desc: taskId is less than zero, missionId is less than zero
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, SetContinuationMissionMap_004, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_004 begin" << std::endl;
    int64_t taskId = -1;
    int64_t missionId = -1;
    dmsCallbackTask_->SetContinuationMissionMap(taskId, missionId);
    EXPECT_EQ(dmsCallbackTask_->continuationMissionMap_.size(), 0);
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_004 end" << std::endl;
}

/**
 * @tc.name: SetContinuationMissionMap_005
 * @tc.desc: taskId is exsit
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, SetContinuationMissionMap_005, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_005 begin" << std::endl;
    int64_t taskId = 1;
    int64_t missionId = 1;
    dmsCallbackTask_->continuationMissionMap_.emplace(taskId, missionId);
    dmsCallbackTask_->SetContinuationMissionMap(taskId, missionId);
    EXPECT_EQ(dmsCallbackTask_->continuationMissionMap_.size(), 1);
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_005 end" << std::endl;
}

/**
 * @tc.name: SetContinuationMissionMap_006
 * @tc.desc: taskId is not exsit
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, SetContinuationMissionMap_006, TestSize.Level1)
{
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_006 begin" << std::endl;
    int64_t taskId = 1;
    int64_t missionId = 1;
    dmsCallbackTask_->SetContinuationMissionMap(taskId, missionId);
    EXPECT_EQ(dmsCallbackTask_->continuationMissionMap_.size(), 1);
    DTEST_LOG << "DmsCallbackTaskTest SetContinuationMissionMap_006 end" << std::endl;
}

/**
 * @tc.name: GetLaunchType_001
 * @tc.desc: taskId is less than zero
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, GetLaunchType_001, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest GetLaunchType_001 begin" << std::endl;
    int64_t taskId = -1;
    LaunchType launchType = dmsCallbackTask_->GetLaunchType(taskId);
    EXPECT_EQ(launchType, LaunchType::FREEINSTALL_START);
    DTEST_LOG << "DmsCallbackTaskTest GetLaunchType_001 end" << std::endl;
}

/**
 * @tc.name: GetLaunchType_002
 * @tc.desc: taskId is less than zero
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, GetLaunchType_002, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest GetLaunchType_002 begin" << std::endl;
    int64_t taskId = -1;
    LaunchType launchType = dmsCallbackTask_->GetLaunchType(taskId);
    EXPECT_EQ(launchType, LaunchType::FREEINSTALL_START);
    DTEST_LOG << "DmsCallbackTaskTest GetLaunchType_002 end" << std::endl;
}

/**
 * @tc.name: GetLaunchType_003
 * @tc.desc: taskId is not exsit
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, GetLaunchType_003, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest GetLaunchType_003 begin" << std::endl;
    int64_t taskId = 1;
    LaunchType launchType = dmsCallbackTask_->GetLaunchType(taskId);
    EXPECT_EQ(launchType, LaunchType::FREEINSTALL_START);
    DTEST_LOG << "DmsCallbackTaskTest GetLaunchType_003 end" << std::endl;
}

/**
 * @tc.name: GetLaunchType_004
 * @tc.desc: taskId is exsit
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, GetLaunchType_004, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest GetLaunchType_004 begin" << std::endl;
    int64_t taskId = 1;
    std::string deviceId = "";
    PushMockTask(taskId, deviceId);
    LaunchType launchType = dmsCallbackTask_->GetLaunchType(taskId);
    EXPECT_EQ(launchType, LaunchType::FREEINSTALL_CONTINUE);
    DTEST_LOG << "DmsCallbackTaskTest GetLaunchType_004 end" << std::endl;
}

/**
 * @tc.name: NotifyDeviceOffline_001
 * @tc.desc: taskId is exsit
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, NotifyDeviceOffline_001, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest NotifyDeviceOffline_001 begin" << std::endl;
    int64_t taskId = 1;
    std::string deviceId = "mockDeviceId";
    PushMockTask(taskId, deviceId);
    dmsCallbackTask_->NotifyDeviceOffline(deviceId);
    EXPECT_EQ(dmsCallbackTask_->callbackMap_.size(), 0);
    DTEST_LOG << "DmsCallbackTaskTest NotifyDeviceOffline_001 end" << std::endl;
}

/**
 * @tc.name: NotifyDeviceOffline_002
 * @tc.desc: taskId is not exsit
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, NotifyDeviceOffline_002, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest NotifyDeviceOffline_002 begin" << std::endl;
    int64_t mockTaskId = 1;
    std::string mockDeviceId = "mockDeviceId";
    PushMockTask(mockTaskId, mockDeviceId);
    std::string deviceId = "deviceId";
    dmsCallbackTask_->NotifyDeviceOffline(deviceId);
    EXPECT_EQ(dmsCallbackTask_->callbackMap_.size(), 1);
    DTEST_LOG << "DmsCallbackTaskTest NotifyDeviceOffline_002 end" << std::endl;
}

/**
 * @tc.name: NotifyDeviceOffline_003
 * @tc.desc: dmsCallbackHandler_ is nullptr
 * @tc.type: FUNC
 * @tc.require: I5VIZT
 */
HWTEST_F(DmsCallbackTaskTest, NotifyDeviceOffline_003, TestSize.Level3)
{
    DTEST_LOG << "DmsCallbackTaskTest NotifyDeviceOffline_003 begin" << std::endl;
    int64_t taskId = 1;
    std::string deviceId = "mockDeviceId";
    dmsCallbackTask_->dmsCallbackHandler_ = nullptr;
    PushMockTask(taskId, deviceId);
    dmsCallbackTask_->NotifyDeviceOffline(deviceId);
    EXPECT_EQ(dmsCallbackTask_->callbackMap_.size(), 0);
    DTEST_LOG << "DmsCallbackTaskTest NotifyDeviceOffline_003 end" << std::endl;
}
}
}