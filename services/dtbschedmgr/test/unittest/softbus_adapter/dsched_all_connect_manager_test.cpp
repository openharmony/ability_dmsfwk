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

HWTEST_F(DSchedAllConnectManagerTest, GetResourceRequest001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest GetResourceRequest001 start" << std::endl;
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    DSchedAllConnectManager::GetInstance().GetResourceRequest(reqInfoSets);
    EXPECT_EQ(reqInfoSets.remoteHardwareListSize, 1u);
    EXPECT_EQ(reqInfoSets.localHardwareListSize, 1u);
    EXPECT_NE(reqInfoSets.communicationRequest, nullptr);
    DTEST_LOG << "DSchedAllConnectManagerTest GetResourceRequest001 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, NotifyAllConnectDecision001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest NotifyAllConnectDecision001 start" << std::endl;
    std::string peerNetworkId = "testNetworkId";
    DSchedAllConnectManager::GetInstance().peerConnectDecision_.clear();
    DSchedAllConnectManager::GetInstance().NotifyAllConnectDecision(peerNetworkId, true);
    EXPECT_EQ(DSchedAllConnectManager::GetInstance().peerConnectDecision_.size(), 1u);
    DTEST_LOG << "DSchedAllConnectManagerTest NotifyAllConnectDecision001 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, PublishServiceState001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest PublishServiceState001 start" << std::endl;
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.ServiceCollaborationManager_PublishServiceState = nullptr;
    std::string peerNetworkId = "testNetworkId";
    std::string extraInfo = "testInfo";
    int32_t ret = DSchedAllConnectManager::GetInstance().PublishServiceState(
        peerNetworkId, extraInfo, ServiceCollaborationManagerBussinessStatus::SCM_CONNECTED);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedAllConnectManagerTest PublishServiceState001 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, OnStop002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest OnStop002 start" << std::endl;
    std::string peerNetworkId = "";
    int32_t ret = DSchedAllConnectManager::GetInstance().OnStop(peerNetworkId.c_str());
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest OnStop002 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, ApplyAdvanceResource002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource002 start" << std::endl;
    std::string peerNetworkId = "testNetworkId";
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.ServiceCollaborationManager_ApplyAdvancedResource =
        nullptr;
    int32_t ret = DSchedAllConnectManager::GetInstance().ApplyAdvanceResource(peerNetworkId, reqInfoSets);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource002 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, WaitAllConnectApplyCb002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest WaitAllConnectApplyCb002 start" << std::endl;
    std::string peerNetworkId = "testNetworkId";
    DSchedAllConnectManager::GetInstance().peerConnectDecision_.clear();
    DSchedAllConnectManager::GetInstance().peerConnectDecision_[peerNetworkId] = false;
    int32_t ret = DSchedAllConnectManager::GetInstance().WaitAllConnectApplyCb(peerNetworkId);
    EXPECT_EQ(ret, DMS_CONNECT_APPLY_REJECT_FAILED);
    DTEST_LOG << "DSchedAllConnectManagerTest WaitAllConnectApplyCb002 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, ApplyResult002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyResult002 start" << std::endl;
    int32_t errorcode = 100;
    int32_t result = static_cast<int32_t>(ServiceCollaborationManagerResultCode::PASS);
    std::string reason = "testReason";
    while (!DSchedAllConnectManager::GetInstance().peerConnectCbQueue_.empty()) {
        DSchedAllConnectManager::GetInstance().peerConnectCbQueue_.pop();
    }
    DSchedAllConnectManager::GetInstance().peerConnectDecision_.clear();
    DSchedAllConnectManager::GetInstance().peerConnectCbQueue_.push("network1");
    int32_t ret = DSchedAllConnectManager::GetInstance().ApplyResult(errorcode, result, reason.c_str());
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(DSchedAllConnectManager::GetInstance().peerConnectDecision_["network1"].load(), true);
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyResult002 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, ApplyResult003, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyResult003 start" << std::endl;
    int32_t errorcode = 0;
    int32_t result = static_cast<int32_t>(ServiceCollaborationManagerResultCode::REJECT);
    std::string reason = "rejectReason";
    while (!DSchedAllConnectManager::GetInstance().peerConnectCbQueue_.empty()) {
        DSchedAllConnectManager::GetInstance().peerConnectCbQueue_.pop();
    }
    DSchedAllConnectManager::GetInstance().peerConnectDecision_.clear();
    DSchedAllConnectManager::GetInstance().peerConnectCbQueue_.push("network1");
    int32_t ret = DSchedAllConnectManager::GetInstance().ApplyResult(errorcode, result, reason.c_str());
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(DSchedAllConnectManager::GetInstance().peerConnectDecision_["network1"].load(), false);
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyResult003 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, NotifyAllConnectDecision002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest NotifyAllConnectDecision002 start" << std::endl;
    std::string peerNetworkId = "testNetworkId";
    DSchedAllConnectManager::GetInstance().peerConnectDecision_.clear();
    DSchedAllConnectManager::GetInstance().NotifyAllConnectDecision(peerNetworkId, false);
    auto it = DSchedAllConnectManager::GetInstance().peerConnectDecision_.find(peerNetworkId);
    EXPECT_NE(it, DSchedAllConnectManager::GetInstance().peerConnectDecision_.end());
    EXPECT_EQ(it->second.load(), false);
    DTEST_LOG << "DSchedAllConnectManagerTest NotifyAllConnectDecision002 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, NotifyAllConnectDecision003, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest NotifyAllConnectDecision003 start" << std::endl;
    std::string peerNetworkId1 = "network1";
    std::string peerNetworkId2 = "network2";
    DSchedAllConnectManager::GetInstance().peerConnectDecision_.clear();
    DSchedAllConnectManager::GetInstance().NotifyAllConnectDecision(peerNetworkId1, true);
    DSchedAllConnectManager::GetInstance().NotifyAllConnectDecision(peerNetworkId2, false);
    EXPECT_EQ(DSchedAllConnectManager::GetInstance().peerConnectDecision_.size(), 2u);
    DTEST_LOG << "DSchedAllConnectManagerTest NotifyAllConnectDecision003 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, GetResourceRequest002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest GetResourceRequest002 start" << std::endl;
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets1;
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets2;
    DSchedAllConnectManager::GetInstance().GetResourceRequest(reqInfoSets1);
    DSchedAllConnectManager::GetInstance().GetResourceRequest(reqInfoSets2);
    EXPECT_EQ(reqInfoSets1.remoteHardwareListSize, reqInfoSets2.remoteHardwareListSize);
    EXPECT_EQ(reqInfoSets1.localHardwareListSize, reqInfoSets2.localHardwareListSize);
    EXPECT_EQ(reqInfoSets1.remoteHardwareList, reqInfoSets2.remoteHardwareList);
    DTEST_LOG << "DSchedAllConnectManagerTest GetResourceRequest002 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, QueryAllServiceStateContext001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext001 start" << std::endl;
    DSchedAllConnectManager::GetInstance().allConnectMgrV3_Api_.ServiceCollaborationManager_GetAllServiceState =
        nullptr;
    std::vector<std::string> result = DSchedAllConnectManager::GetInstance().QueryAllServiceStateContext();
    EXPECT_TRUE(result.empty());
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext001 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, RegistLifecycleCallback002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest RegistLifecycleCallback002 start" << std::endl;
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.ServiceCollaborationManager_RegisterLifecycleCallback =
        nullptr;
    int32_t ret = DSchedAllConnectManager::GetInstance().RegistLifecycleCallback();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedAllConnectManagerTest RegistLifecycleCallback002 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, UnregistLifecycleCallback002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest UnregistLifecycleCallback002 start" << std::endl;
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.ServiceCollaborationManager_UnRegisterLifecycleCallback =
        nullptr;
    int32_t ret = DSchedAllConnectManager::GetInstance().UnregistLifecycleCallback();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedAllConnectManagerTest UnregistLifecycleCallback002 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, ApplyAdvanceResource003, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource003 start" << std::endl;
    std::string peerNetworkId = "testNetworkId";
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    reqInfoSets.remoteHardwareListSize = 0;
    reqInfoSets.remoteHardwareList = nullptr;
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.ServiceCollaborationManager_ApplyAdvancedResource =
        nullptr;
    int32_t ret = DSchedAllConnectManager::GetInstance().ApplyAdvanceResource(peerNetworkId, reqInfoSets);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource003 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, NotifyAllConnectDecision004, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest NotifyAllConnectDecision004 start" << std::endl;
    std::string peerNetworkId = "testNetworkId";
    DSchedAllConnectManager::GetInstance().peerConnectDecision_.clear();
    DSchedAllConnectManager::GetInstance().NotifyAllConnectDecision(peerNetworkId, true);
    DSchedAllConnectManager::GetInstance().NotifyAllConnectDecision(peerNetworkId, false);
    auto it = DSchedAllConnectManager::GetInstance().peerConnectDecision_.find(peerNetworkId);
    EXPECT_NE(it, DSchedAllConnectManager::GetInstance().peerConnectDecision_.end());
    EXPECT_EQ(it->second.load(), false);
    DTEST_LOG << "DSchedAllConnectManagerTest NotifyAllConnectDecision004 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, WaitAllConnectApplyCb003, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest WaitAllConnectApplyCb003 start" << std::endl;
    std::string peerNetworkId1 = "network1";
    std::string peerNetworkId2 = "network2";
    DSchedAllConnectManager::GetInstance().peerConnectDecision_.clear();
    DSchedAllConnectManager::GetInstance().peerConnectDecision_[peerNetworkId1] = true;
    DSchedAllConnectManager::GetInstance().peerConnectDecision_[peerNetworkId2] = true;
    int32_t ret1 = DSchedAllConnectManager::GetInstance().WaitAllConnectApplyCb(peerNetworkId1);
    int32_t ret2 = DSchedAllConnectManager::GetInstance().WaitAllConnectApplyCb(peerNetworkId2);
    EXPECT_EQ(ret1, ERR_OK);
    EXPECT_EQ(ret2, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest WaitAllConnectApplyCb003 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, PublishServiceState002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest PublishServiceState002 start" << std::endl;
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.ServiceCollaborationManager_PublishServiceState = nullptr;
    std::string peerNetworkId = "";
    std::string extraInfo = "";
    int32_t ret = DSchedAllConnectManager::GetInstance().PublishServiceState(
        peerNetworkId, extraInfo, ServiceCollaborationManagerBussinessStatus::SCM_IDLE);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedAllConnectManagerTest PublishServiceState002 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, ApplyResult004, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyResult004 start" << std::endl;
    int32_t errorcode = 0;
    int32_t result = 0;
    std::string reason = "reason";
    while (!DSchedAllConnectManager::GetInstance().peerConnectCbQueue_.empty()) {
        DSchedAllConnectManager::GetInstance().peerConnectCbQueue_.pop();
    }
    int32_t ret = DSchedAllConnectManager::GetInstance().ApplyResult(errorcode, result, reason.c_str());
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyResult004 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, OnStop003, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest OnStop003 start" << std::endl;
    std::string peerNetworkId = "testNetworkId12345";
    int32_t ret = DSchedAllConnectManager::GetInstance().OnStop(peerNetworkId.c_str());
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest OnStop003 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, GetResourceRequest003, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest GetResourceRequest003 start" << std::endl;
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    DSchedAllConnectManager::GetInstance().GetResourceRequest(reqInfoSets);
    EXPECT_NE(reqInfoSets.remoteHardwareList, nullptr);
    EXPECT_NE(reqInfoSets.localHardwareList, nullptr);
    EXPECT_EQ(reqInfoSets.remoteHardwareList->hardWareType, ServiceCollaborationManagerHardwareType::SCM_DISPLAY);
    EXPECT_EQ(reqInfoSets.localHardwareList->hardWareType, ServiceCollaborationManagerHardwareType::SCM_DISPLAY);
    DTEST_LOG << "DSchedAllConnectManagerTest GetResourceRequest003 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, ApplyAdvanceResource004, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource004 start" << std::endl;
    std::string peerNetworkId = "testNetworkId";
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    reqInfoSets.remoteHardwareListSize = 0;
    reqInfoSets.localHardwareListSize = 0;
    reqInfoSets.communicationRequest = nullptr;
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.ServiceCollaborationManager_ApplyAdvancedResource =
        nullptr;
    int32_t ret = DSchedAllConnectManager::GetInstance().ApplyAdvanceResource(peerNetworkId, reqInfoSets);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource004 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, UninitAllConnectManager001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest UninitAllConnectManager001 start" << std::endl;
    DSchedAllConnectManager::GetInstance().allConnectMgrV3_Api_.ServiceCollaborationManager_PublishServiceState =
        reinterpret_cast<int32_t (*)(ServiceCollaborationManager_ServiceStateInfo*,
        ServiceCollaborationManager_ResourceRequestInfoSets*, int32_t)>(0x1);
    DSchedAllConnectManager::GetInstance().UninitAllConnectManager();

    auto& publishServiceState = DSchedAllConnectManager::GetInstance().allConnectMgrV3_Api_
        .ServiceCollaborationManager_PublishServiceState;
    EXPECT_EQ(publishServiceState, nullptr);
    DTEST_LOG << "DSchedAllConnectManagerTest UninitAllConnectManager001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
