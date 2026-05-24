/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>

#define private public
#include "intent_all_connect_manager.h"
#undef private

#include "distributed_intent_error_code.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string PEER_NETWORK_ID = "peer_network_id_12345";
}

class DistributedIntentAllConnectManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void DistributedIntentAllConnectManagerTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedIntentAllConnectManagerTest::SetUpTestCase" << std::endl;
}

void DistributedIntentAllConnectManagerTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedIntentAllConnectManagerTest::TearDownTestCase" << std::endl;
}

void DistributedIntentAllConnectManagerTest::SetUp()
{
    DTEST_LOG << "DistributedIntentAllConnectManagerTest::SetUp" << std::endl;
    auto& manager = IntentAllConnectManager::GetInstance();
    manager.api_ = {};
    manager.isAvailable_ = false;
    while (!IntentAllConnectManager::applyQueue_.empty()) {
        IntentAllConnectManager::applyQueue_.pop();
    }
    manager.decisions_.clear();
}

void DistributedIntentAllConnectManagerTest::TearDown()
{
    DTEST_LOG << "DistributedIntentAllConnectManagerTest::TearDown" << std::endl;
    auto& manager = IntentAllConnectManager::GetInstance();
    manager.api_ = {};
    manager.isAvailable_ = false;
    while (!IntentAllConnectManager::applyQueue_.empty()) {
        IntentAllConnectManager::applyQueue_.pop();
    }
    manager.decisions_.clear();
}

/**
 * @tc.name: IsAllConnectAvailable_DefaultFalse_001
 * @tc.desc: Verify IsAllConnectAvailable returns false by default
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, IsAllConnectAvailable_DefaultFalse, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    EXPECT_FALSE(manager.IsAllConnectAvailable());
}

/**
 * @tc.name: IsAllConnectAvailable_SetTrue_001
 * @tc.desc: Verify IsAllConnectAvailable returns true after setting isAvailable_ to true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, IsAllConnectAvailable_SetTrue, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    manager.isAvailable_ = true;
    EXPECT_TRUE(manager.IsAllConnectAvailable());
    manager.isAvailable_ = false;
}

/**
 * @tc.name: PublishServiceState_NullApi_001
 * @tc.desc: Verify PublishServiceState returns error when api is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, PublishServiceState_NullApi, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    EXPECT_EQ(manager.PublishServiceState(PEER_NETWORK_ID, SCM_IDLE), INVALID_PARAMETERS_ERR);
}

/**
 * @tc.name: ApplyResource_NullApi_001
 * @tc.desc: Verify ApplyResource returns error when api is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, ApplyResource_NullApi, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    EXPECT_EQ(manager.ApplyResource(PEER_NETWORK_ID), INVALID_PARAMETERS_ERR);
}

/**
 * @tc.name: OnStopCallback_NullPeerNetworkId_001
 * @tc.desc: Verify OnStopCallback returns ok with null peer network id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, OnStopCallback_NullPeerNetworkId, TestSize.Level3)
{
    EXPECT_EQ(IntentAllConnectManager::OnStopCallback(nullptr), ERR_OK);
}

/**
 * @tc.name: ApplyResultCallback_EmptyQueue_001
 * @tc.desc: Verify ApplyResultCallback handles empty queue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, ApplyResultCallback_EmptyQueue, TestSize.Level3)
{
    EXPECT_EQ(IntentAllConnectManager::ApplyResultCallback(0, 0, ""), ERR_OK);
}

/**
 * @tc.name: ApplyResultCallback_Approved_001
 * @tc.desc: Verify ApplyResultCallback with approved result and non-empty queue
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, ApplyResultCallback_Approved, TestSize.Level3)
{
    IntentAllConnectManager::applyQueue_.push(PEER_NETWORK_ID);
    int32_t result = ServiceCollaborationManagerResultCode::PASS;
    EXPECT_EQ(IntentAllConnectManager::ApplyResultCallback(0, result, ""), ERR_OK);
    auto& manager = IntentAllConnectManager::GetInstance();
    EXPECT_TRUE(manager.decisions_.find(PEER_NETWORK_ID)
        != manager.decisions_.end());
}

/**
 * @tc.name: ApplyResultCallback_Rejected_001
 * @tc.desc: Verify ApplyResultCallback with rejected result
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, ApplyResultCallback_Rejected, TestSize.Level3)
{
    IntentAllConnectManager::applyQueue_.push(PEER_NETWORK_ID);
    int32_t result = ServiceCollaborationManagerResultCode::REJECT;
    EXPECT_EQ(IntentAllConnectManager::ApplyResultCallback(0, result, ""), ERR_OK);
    auto& manager = IntentAllConnectManager::GetInstance();
    EXPECT_TRUE(manager.decisions_.find(PEER_NETWORK_ID)
        != manager.decisions_.end());
}

/**
 * @tc.name: NotifyApplyResult_Approved_001
 * @tc.desc: Verify NotifyApplyResult sets decision to approved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, NotifyApplyResult_Approved, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    manager.NotifyApplyResult(PEER_NETWORK_ID, true);
    EXPECT_TRUE(manager.decisions_.find(PEER_NETWORK_ID) != manager.decisions_.end());
    EXPECT_TRUE(manager.decisions_.at(PEER_NETWORK_ID).load());
}

/**
 * @tc.name: NotifyApplyResult_Rejected_001
 * @tc.desc: Verify NotifyApplyResult sets decision to rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, NotifyApplyResult_Rejected, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    manager.NotifyApplyResult(PEER_NETWORK_ID, false);
    EXPECT_TRUE(manager.decisions_.find(PEER_NETWORK_ID) != manager.decisions_.end());
    EXPECT_FALSE(manager.decisions_.at(PEER_NETWORK_ID).load());
}

/**
 * @tc.name: RegisterLifecycleCallback_NullApi_001
 * @tc.desc: Verify RegisterLifecycleCallback returns error when api is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, RegisterLifecycleCallback_NullApi, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    manager.api_ = {};
    EXPECT_EQ(manager.RegisterLifecycleCallback(), INVALID_PARAMETERS_ERR);
}

/**
 * @tc.name: UnregisterLifecycleCallback_NullApi_001
 * @tc.desc: Verify UnregisterLifecycleCallback returns error when api is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, UnregisterLifecycleCallback_NullApi, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    manager.api_ = {};
    EXPECT_EQ(manager.UnregisterLifecycleCallback(), INVALID_PARAMETERS_ERR);
}

/**
 * @tc.name: Uninit_DllHandleNull_001
 * @tc.desc: Verify Uninit succeeds when dllHandle_ is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, Uninit_DllHandleNull, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    manager.api_ = {};
    manager.dllHandle_ = nullptr;
    manager.isAvailable_ = true;
    EXPECT_EQ(manager.Uninit(), ERR_OK);
    EXPECT_FALSE(manager.isAvailable_);
}

/**
 * @tc.name: WaitForApplyResult_Timeout_001
 * @tc.desc: Verify WaitForApplyResult returns timeout when no decision is made
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, WaitForApplyResult_Timeout, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    manager.decisions_.clear();
    EXPECT_EQ(manager.WaitForApplyResult(PEER_NETWORK_ID),
        DMS_CONNECT_APPLY_TIMEOUT_FAILED);
}

/**
 * @tc.name: WaitForApplyResult_Approved_001
 * @tc.desc: Verify WaitForApplyResult returns ok when decision is approved
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, WaitForApplyResult_Approved, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    manager.NotifyApplyResult(PEER_NETWORK_ID, true);
    EXPECT_EQ(manager.WaitForApplyResult(PEER_NETWORK_ID), ERR_OK);
}

/**
 * @tc.name: WaitForApplyResult_Rejected_001
 * @tc.desc: Verify WaitForApplyResult returns reject when decision is rejected
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentAllConnectManagerTest, WaitForApplyResult_Rejected, TestSize.Level3)
{
    auto& manager = IntentAllConnectManager::GetInstance();
    manager.NotifyApplyResult(PEER_NETWORK_ID, false);
    EXPECT_EQ(manager.WaitForApplyResult(PEER_NETWORK_ID),
        DMS_CONNECT_APPLY_REJECT_FAILED);
}

} // namespace DistributedSchedule
} // namespace OHOS
