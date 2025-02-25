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

#include "dsched_collab_manager_sup_test.h"

#include "dtbschedmgr_device_info_storage.h"
#include "distributed_sched_test_util.h"
#include "test_log.h"
#include "mock_distributed_sched.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedHardware;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string BASEDIR = "/data/service/el1/public/database/DistributedSchedule";
    constexpr int32_t MISSION_ID = 1;
    constexpr size_t SIZE = 10;
    const int32_t WAITTIME = 2000;
}

void DSchedCollabManagerSupTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedCollabManagerSupTest::SetUpTestCase" << std::endl;
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
}

void DSchedCollabManagerSupTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedCollabManagerSupTest::TearDownTestCase" << std::endl;
    (void)remove(BASEDIR.c_str());
}

void DSchedCollabManagerSupTest::TearDown()
{
    DTEST_LOG << "DSchedCollabManagerSupTest::TearDown" << std::endl;
    usleep(WAITTIME);
}

void DSchedCollabManagerSupTest::SetUp()
{
    usleep(WAITTIME);
    DTEST_LOG << "DSchedCollabManagerSupTest::SetUp" << std::endl;
}

/**
 * @tc.name: UnInit_001
 * @tc.desc: test UnInit func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerSupTest, UnInit_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerSupTest UnInit_001 begin" << std::endl;
    ASSERT_EQ(DSchedCollabManager::GetInstance().eventHandler_, nullptr);
    DSchedCollabManager::GetInstance().UnInit();

    DSchedCollabManager::GetInstance().Init();
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler =
        DSchedCollabManager::GetInstance().eventHandler_;
    EXPECT_NE(eventHandler, nullptr);
    usleep(WAITTIME);
    DSchedCollabManager::GetInstance().UnInit();
    EXPECT_EQ(DSchedCollabManager::GetInstance().eventHandler_, nullptr);
    DTEST_LOG << "DSchedCollabManagerSupTest UnInit_001 end" << std::endl;
}

/**
 * @tc.name: SetTimeOut_001
 * @tc.desc: test SetTimeOut func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerSupTest, SetTimeOut_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerSupTest SetTimeOut_001 begin" << std::endl;
    ASSERT_EQ(DSchedCollabManager::GetInstance().eventHandler_, nullptr);
    const std::string collabToken = "testToken";
    int32_t timeout = 10;
    DSchedCollabInfo info;
    info.srcInfo_.pid_ = 100;
    info.srcCollabSessionId_ = 1;
    auto collab = std::make_shared<DSchedCollab>("test1", info);
    DSchedCollabManager::GetInstance().collabs_.insert(std::make_pair(collabToken, collab));
    DSchedCollabManager::GetInstance().SetTimeOut(collabToken, timeout);
    EXPECT_NE(DSchedCollabManager::GetInstance().collabs_.empty(), true);
    DSchedCollabManager::GetInstance().collabs_.clear();
    DTEST_LOG << "DSchedCollabManagerSupTest SetTimeOut_001 end" << std::endl;
}

/**
 * @tc.name: RemoveTimeout_001
 * @tc.desc: test RemoveTimeout func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerSupTest, RemoveTimeout_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerSupTest RemoveTimeout_001 begin" << std::endl;
    ASSERT_EQ(DSchedCollabManager::GetInstance().eventHandler_, nullptr);
    const std::string collabToken = "testToken";
    DSchedCollabManager::GetInstance().RemoveTimeout(collabToken);
    EXPECT_EQ(DSchedCollabManager::GetInstance().collabs_.empty(), true);
    DTEST_LOG << "DSchedCollabManagerSupTest RemoveTimeout_001 end" << std::endl;
}

/**
 * @tc.name: NotifySinkPrepareResult_001
 * @tc.desc: test NotifySinkPrepareResult func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerSupTest, NotifySinkPrepareResult_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerSupTest NotifySinkPrepareResult_001 begin" << std::endl;
    ASSERT_EQ(DSchedCollabManager::GetInstance().eventHandler_, nullptr);
    int32_t direction = 0;
    const std::string collabToken = "";
    const int32_t result = 0;
    const int32_t collabSessionId = 0;
    const std::string socketName = "";
    const sptr<IRemoteObject> clientCB;
    auto ret = DSchedCollabManager::GetInstance().NotifySinkPrepareResult(collabToken, result,
        collabSessionId, socketName, clientCB);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollabManagerSupTest NotifySinkPrepareResult_001 end" << std::endl;
}

/**
 * @tc.name: NotifyAbilityDied_001
 * @tc.desc: test NotifyAbilityDied func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerSupTest, NotifyAbilityDied_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerSupTest NotifyAbilityDied_001 begin" << std::endl;
    ASSERT_EQ(DSchedCollabManager::GetInstance().eventHandler_, nullptr);
    const std::string bundleName = "";
    const int32_t pid = 0;

    auto ret = DSchedCollabManager::GetInstance().NotifyAbilityDied(bundleName, pid);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollabManagerSupTest NotifyAbilityDied_001 end" << std::endl;
}

/**
 * @tc.name: ReleaseAbilityLink_001
 * @tc.desc: test ReleaseAbilityLink func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerSupTest, ReleaseAbilityLink_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerSupTest ReleaseAbilityLink_001 begin" << std::endl;
    ASSERT_EQ(DSchedCollabManager::GetInstance().eventHandler_, nullptr);
    const std::string bundleName = "";
    const int32_t pid = 0;

    auto ret = DSchedCollabManager::GetInstance().ReleaseAbilityLink(bundleName, pid);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollabManagerSupTest ReleaseAbilityLink_001 end" << std::endl;
}

/**
 * @tc.name: CancleReleaseAbilityLink_001
 * @tc.desc: test CancleReleaseAbilityLink func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerSupTest, CancleReleaseAbilityLink_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerSupTest CancleReleaseAbilityLink_001 begin" << std::endl;
    ASSERT_EQ(DSchedCollabManager::GetInstance().eventHandler_, nullptr);
    const std::string bundleName = "";
    const int32_t pid = 0;
    int32_t ret = DSchedCollabManager::GetInstance().CancleReleaseAbilityLink(bundleName, pid);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollabManagerSupTest CancleReleaseAbilityLink_001 end" << std::endl;
}

/**
 * @tc.name: OnDataRecv_001
 * @tc.desc: test OnDataRecv func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerSupTest, OnDataRecv_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerSupTest OnDataRecv_001 begin" << std::endl;
    ASSERT_EQ(DSchedCollabManager::GetInstance().eventHandler_, nullptr);
    int32_t softbusSessionId = 0;
    size_t sizeL = 20;
    std::shared_ptr<DSchedDataBuffer> dataBuffer = std::make_shared<DSchedDataBuffer>(sizeL);
    DSchedCollabManager::GetInstance().OnDataRecv(softbusSessionId, dataBuffer);
    EXPECT_EQ(DSchedCollabManager::GetInstance().collabs_.empty(), true);
    DTEST_LOG << "DSchedCollabManagerSupTest OnDataRecv_001 end" << std::endl;
}

/**
 * @tc.name: OnShutdown_001
 * @tc.desc: test OnShutdown func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerSupTest, OnShutdown_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerSupTest OnShutdown_001 begin" << std::endl;
    ASSERT_EQ(DSchedCollabManager::GetInstance().eventHandler_, nullptr);
    int32_t softbusSessionId = 0;
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
    DSchedCollabManager::GetInstance().collabs_.clear();
    DTEST_LOG << "DSchedCollabManagerSupTest OnShutdown_001 end" << std::endl;
}

/**
 * @tc.name: GenerateCollabToken_001
 * @tc.desc: test GenerateCollabToken func
 * @tc.type: FUNC
 */
HWTEST_F(DSchedCollabManagerSupTest, GenerateCollabToken_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollabManagerSupTest GenerateCollabToken_001 begin" << std::endl;
    ASSERT_EQ(DSchedCollabManager::GetInstance().eventHandler_, nullptr);
    string srcDeviceId = "test";
    auto rlt = DSchedCollabManager::GetInstance().GenerateCollabToken(srcDeviceId);
    EXPECT_FALSE(rlt.empty());
    DSchedCollabManager::GetInstance().collabs_.clear();
    DTEST_LOG << "DSchedCollabManagerSupTest GenerateCollabToken_001 end" << std::endl;
}
}
}
