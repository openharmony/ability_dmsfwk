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

#include "gtest/gtest.h"

#include "softbus_adapter/allconnectmgr/dsched_all_connect_manager.h"
#include "test_log.h"
#include "dtbschedmgr_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
class DSchedAllConnectManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DSchedAllConnectManagerTest::SetUpTestCase()
{
}

void DSchedAllConnectManagerTest::TearDownTestCase()
{
}

void DSchedAllConnectManagerTest::SetUp()
{
}

void DSchedAllConnectManagerTest::TearDown()
{
}

/**
 * @tc.name: RegistLifecycleCallback001
 * @tc.desc: call RegistLifecycleCallback
 * @tc.type: FUNC
 */
HWTEST_F(DSchedAllConnectManagerTest, RegistLifecycleCallback001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest RegistLifecycleCallback001 start" << std::endl;
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.
        ServiceCollaborationManager_RegisterLifecycleCallback = nullptr;
    int32_t ret = DSchedAllConnectManager::GetInstance().RegistLifecycleCallback();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedAllConnectManagerTest RegistLifecycleCallback001 end" << std::endl;
}

/**
 * @tc.name: UnregistLifecycleCallback001
 * @tc.desc: call UnregistLifecycleCallback
 * @tc.type: FUNC
 */
HWTEST_F(DSchedAllConnectManagerTest, UnregistLifecycleCallback001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest UnregistLifecycleCallback001 start" << std::endl;
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.
        ServiceCollaborationManager_UnRegisterLifecycleCallback = nullptr;
    int32_t ret = DSchedAllConnectManager::GetInstance().UnregistLifecycleCallback();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedAllConnectManagerTest UnregistLifecycleCallback001 end" << std::endl;
}

/**
 * @tc.name: ApplyAdvanceResource001
 * @tc.desc: call ApplyAdvanceResource
 * @tc.type: FUNC
 */
HWTEST_F(DSchedAllConnectManagerTest, ApplyAdvanceResource001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource001 start" << std::endl;
    std::string peerNetworkId = "peerNetworkId";
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.
        ServiceCollaborationManager_ApplyAdvancedResource = nullptr;
    int32_t ret = DSchedAllConnectManager::GetInstance().ApplyAdvanceResource(peerNetworkId, reqInfoSets);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource001 end" << std::endl;
}

/**
 * @tc.name: WaitAllConnectApplyCb001
 * @tc.desc: call WaitAllConnectApplyCb
 * @tc.type: FUNC
 */
HWTEST_F(DSchedAllConnectManagerTest, WaitAllConnectApplyCb001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest WaitAllConnectApplyCb001 start" << std::endl;
    std::string peerNetworkId = "peerNetworkId1";
    DSchedAllConnectManager::GetInstance().peerConnectDecision_.clear();
    DSchedAllConnectManager::GetInstance().peerConnectDecision_["peerNetworkId"] = true;
    int32_t ret = DSchedAllConnectManager::GetInstance().WaitAllConnectApplyCb(peerNetworkId);
    EXPECT_EQ(ret, DMS_CONNECT_APPLY_TIMEOUT_FAILED);

    peerNetworkId = "peerNetworkId";
    ret = DSchedAllConnectManager::GetInstance().WaitAllConnectApplyCb(peerNetworkId);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest WaitAllConnectApplyCb001 end" << std::endl;
}

/**
 * @tc.name: OnStop001
 * @tc.desc: call OnStop
 * @tc.type: FUNC
 */
HWTEST_F(DSchedAllConnectManagerTest, OnStop001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest OnStop001 start" << std::endl;
    std::string peerNetworkId = "peerNetworkId";
    int32_t ret = DSchedAllConnectManager::GetInstance().OnStop(peerNetworkId.c_str());
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest OnStop001 end" << std::endl;
}

/**
 * @tc.name: ApplyResult001
 * @tc.desc: call ApplyResult
 * @tc.type: FUNC
 */
HWTEST_F(DSchedAllConnectManagerTest, ApplyResult001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyResult001 start" << std::endl;
    int32_t errorcode = 0;
    int32_t result = 0;
    std::string reason = "reason";
    while (!DSchedAllConnectManager::GetInstance().peerConnectCbQueue_.empty()) {
        DSchedAllConnectManager::GetInstance().peerConnectCbQueue_.pop();
    }
    int32_t ret = DSchedAllConnectManager::GetInstance().ApplyResult(errorcode, result, reason.c_str());
    EXPECT_EQ(ret, ERR_OK);

    DSchedAllConnectManager::GetInstance().peerConnectCbQueue_.push(reason);
    ret = DSchedAllConnectManager::GetInstance().ApplyResult(errorcode, result, reason.c_str());
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyResult001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
