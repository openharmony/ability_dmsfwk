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
#include <cstring>

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

HWTEST_F(DSchedAllConnectManagerTest, QueryAllServiceStateContext001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext001 start" << std::endl;
    DSchedAllConnectManager::GetInstance().allConnectMgrV3_Api_.ServiceCollaborationManager_GetAllServiceState = nullptr;
    std::vector<std::string> result = DSchedAllConnectManager::GetInstance().QueryAllServiceStateContext();
    EXPECT_TRUE(result.empty());
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext001 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, QueryAllServiceStateContext002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext002 start" << std::endl;
    auto mockGetAllServiceState = [](uint16_t* out_count) -> ServiceCollaborationManager_ServiceStateInfo* {
        *out_count = 0;
        return nullptr;
    };
    DSchedAllConnectManager::GetInstance().allConnectMgrV3_Api_.ServiceCollaborationManager_GetAllServiceState =
        mockGetAllServiceState;
    std::vector<std::string> result = DSchedAllConnectManager::GetInstance().QueryAllServiceStateContext();
    EXPECT_TRUE(result.empty());
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext002 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, QueryAllServiceStateContext003, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext003 start" << std::endl;
    auto mockGetAllServiceState = [](uint16_t* out_count) -> ServiceCollaborationManager_ServiceStateInfo* {
        *out_count = 2;
        auto info = new ServiceCollaborationManager_ServiceStateInfo[2];
        info[0].serviceName = strdup("Service1");
        info[1].serviceName = strdup("Service2");
        return info;
    };
    DSchedAllConnectManager::GetInstance().allConnectMgrV3_Api_.ServiceCollaborationManager_GetAllServiceState =
        mockGetAllServiceState;
    std::vector<std::string> result = DSchedAllConnectManager::GetInstance().QueryAllServiceStateContext();
    EXPECT_EQ(result.size(), 2u);
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext003 end" << std::endl;
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

HWTEST_F(DSchedAllConnectManagerTest, PublishServiceState002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest PublishServiceState002 start" << std::endl;
    auto mockPublish = [](const char*, const char*, const char*, ServiceCollaborationManagerBussinessStatus) -> int32_t {
        return ERR_OK;
    };
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.ServiceCollaborationManager_PublishServiceState = mockPublish;
    std::string peerNetworkId = "testNetworkId";
    std::string extraInfo = "testInfo";
    int32_t ret = DSchedAllConnectManager::GetInstance().PublishServiceState(
        peerNetworkId, extraInfo, ServiceCollaborationManagerBussinessStatus::SCM_CONNECTED);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedAllConnectManagerTest PublishServiceState002 end" << std::endl;
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

HWTEST_F(DSchedAllConnectManagerTest, ApplyAdvanceResource002, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource002 start" << std::endl;
    std::string peerNetworkId = "testNetworkId";
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    auto mockApply = [](const char*, const char*, ServiceCollaborationManager_ResourceRequestInfoSets*,
        ServiceCollaborationManager_Callback*) -> int32_t {
        return ERR_OK;
    };
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.ServiceCollaborationManager_ApplyAdvancedResource = mockApply;
    int32_t ret = DSchedAllConnectManager::GetInstance().ApplyAdvanceResource(peerNetworkId, reqInfoSets);
    EXPECT_EQ(ret, DMS_CONNECT_APPLY_TIMEOUT_FAILED);
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource002 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, UninitAllConnectManager001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest UninitAllConnectManager001 start" << std::endl;
    DSchedAllConnectManager::GetInstance().allConnectMgrV3_Api_.ServiceCollaborationManager_PublishServiceState =
        reinterpret_cast<int32_t (*)(ServiceCollaborationManager_ServiceStateInfo*,
        ServiceCollaborationManager_ResourceRequestInfoSets*, int32_t)>(0x1);
    DSchedAllConnectManager::GetInstance().UninitAllConnectManager();
    EXPECT_EQ(DSchedAllConnectManager::GetInstance().allConnectMgrV3_Api_.ServiceCollaborationManager_PublishServiceState,
        nullptr);
    DTEST_LOG << "DSchedAllConnectManagerTest UninitAllConnectManager001 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, LoadV3ApiExtended001, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest LoadV3ApiExtended001 start" << std::endl;
    DSchedAllConnectManager::GetInstance().dllHandle_ = nullptr;
    DSchedAllConnectManager::GetInstance().LoadV3ApiExtended();
    EXPECT_EQ(DSchedAllConnectManager::GetInstance().allConnectMgrV3_Api_.ServiceCollaborationManager_GetAllServiceState,
        nullptr);
    DTEST_LOG << "DSchedAllConnectManagerTest LoadV3ApiExtended001 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, QueryAllServiceStateContext004, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext004 start" << std::endl;
    auto mockGetAllServiceState = [](uint16_t* out_count) -> ServiceCollaborationManager_ServiceStateInfo* {
        *out_count = 1;
        auto info = new ServiceCollaborationManager_ServiceStateInfo[1];
        info[0].serviceName = nullptr;
        info[0].peerNetworkId = strdup("networkId");
        info[0].extraInfo = strdup("extraInfo");
        return info;
    };
    DSchedAllConnectManager::GetInstance().allConnectMgrV3_Api_.ServiceCollaborationManager_GetAllServiceState =
        mockGetAllServiceState;
    std::vector<std::string> result = DSchedAllConnectManager::GetInstance().QueryAllServiceStateContext();
    EXPECT_TRUE(result.empty());
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext004 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, QueryAllServiceStateContext005, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext005 start" << std::endl;
    auto mockGetAllServiceState = [](uint16_t* out_count) -> ServiceCollaborationManager_ServiceStateInfo* {
        *out_count = 3;
        auto info = new ServiceCollaborationManager_ServiceStateInfo[3];
        info[0].serviceName = strdup("TaskContinue");
        info[0].peerNetworkId = strdup("network1");
        info[0].extraInfo = strdup("info1");
        info[1].serviceName = strdup("ScreenShare");
        info[1].peerNetworkId = strdup("network2");
        info[1].extraInfo = strdup("info2");
        info[2].serviceName = strdup("AudioCall");
        info[2].peerNetworkId = strdup("network3");
        info[2].extraInfo = strdup("info3");
        return info;
    };
    DSchedAllConnectManager::GetInstance().allConnectMgrV3_Api_.ServiceCollaborationManager_GetAllServiceState =
        mockGetAllServiceState;
    std::vector<std::string> result = DSchedAllConnectManager::GetInstance().QueryAllServiceStateContext();
    EXPECT_EQ(result.size(), 3u);
    EXPECT_EQ(result[0], "TaskContinue");
    EXPECT_EQ(result[1], "ScreenShare");
    EXPECT_EQ(result[2], "AudioCall");
    DTEST_LOG << "DSchedAllConnectManagerTest QueryAllServiceStateContext005 end" << std::endl;
}

HWTEST_F(DSchedAllConnectManagerTest, ApplyAdvanceResource003, TestSize.Level3)
{
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource003 start" << std::endl;
    std::string peerNetworkId = "testNetworkId";
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    auto mockApply = [](const char*, const char*, ServiceCollaborationManager_ResourceRequestInfoSets*,
        ServiceCollaborationManager_Callback*) -> int32_t {
        return INVALID_PARAMETERS_ERR;
    };
    DSchedAllConnectManager::GetInstance().allConnectMgrApi_.ServiceCollaborationManager_ApplyAdvancedResource = mockApply;
    int32_t ret = DSchedAllConnectManager::GetInstance().ApplyAdvanceResource(peerNetworkId, reqInfoSets);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedAllConnectManagerTest ApplyAdvanceResource003 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
