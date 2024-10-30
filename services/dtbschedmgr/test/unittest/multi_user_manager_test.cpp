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

#include "multi_user_manager_test.h"

#define private public
#include "multi_user_manager.h"
#undef private
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TYPE = "type";
}

void MultiUserManagerTest::SetUpTestCase()
{
    DTEST_LOG << "MultiUserManagerTest::SetUpTestCase" << std::endl;
}

void MultiUserManagerTest::TearDownTestCase()
{
    DTEST_LOG << "MultiUserManagerTest::TearDownTestCase" << std::endl;
}

void MultiUserManagerTest::TearDown()
{
    DTEST_LOG << "MultiUserManagerTest::TearDown" << std::endl;
}

void MultiUserManagerTest::SetUp()
{
    DTEST_LOG << "MultiUserManagerTest::SetUp" << std::endl;
}

void RemoteOnListenerStubTest::OnCallback(const uint32_t ContinueState, const std::string& srcDeviceId,
    const std::string &bundleName, const std::string &continueType, const std::string &srcBundleName)
{
}

/**
 * @tc.name: MultiUserManager_Init_001
 * @tc.desc: test Init
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_Init_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_Init_001 start" << std::endl;
    /**
     * @tc.steps: step1. test Init with set currentUserId_ sendMgr recvMgr;
     */
    int32_t accountId = 100;
    MultiUserManager::GetInstance().Init();
    EXPECT_EQ(MultiUserManager::GetInstance().currentUserId_, accountId);
    auto sendMgr = MultiUserManager::GetInstance().sendMgrMap_.find(accountId);
    EXPECT_NE(sendMgr->second, nullptr);
    auto recvMgr = MultiUserManager::GetInstance().recvMgrMap_.find(accountId);
    EXPECT_NE(recvMgr->second, nullptr);
    MultiUserManager::GetInstance().UnInit();
    DTEST_LOG << "MultiUserManager_Init_001 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_UnInit_001
 * @tc.desc: test UnInit
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_UnInit_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_UnInit_001 start" << std::endl;
    /**
     * @tc.steps: step1. test UnInit with delete sendMgr recvMgr;
     */
    int32_t accountId = 100;
    MultiUserManager::GetInstance().Init();
    MultiUserManager::GetInstance().UnInit();
    
    EXPECT_TRUE(MultiUserManager::GetInstance().sendMgrMap_.empty());
    EXPECT_TRUE(MultiUserManager::GetInstance().recvMgrMap_.empty());

    DTEST_LOG << "MultiUserManager_UnInit_001 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_OnUserSwitched_001
 * @tc.desc: test OnUserSwitched
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_OnUserSwitched_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_OnUserSwitched_001 start" << std::endl;
    /**
     * @tc.steps: step1. test OnUserSwitched with no cache switched user;
     */
    int32_t accountId = 100;
    int32_t switchedAccountId = 101;
    MultiUserManager::GetInstance().Init();
    MultiUserManager::GetInstance().OnUserSwitched(switchedAccountId);
    EXPECT_EQ(MultiUserManager::GetInstance().currentUserId_, switchedAccountId);
    MultiUserManager::GetInstance().UnInit();
    DTEST_LOG << "MultiUserManager_OnUserSwitched_001 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_OnUserSwitched_002
 * @tc.desc: test OnUserSwitched
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_OnUserSwitched_002, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_OnUserSwitched_002 start" << std::endl;
    /**
     * @tc.steps: step1. test OnUserSwitched with cache switched user;
     */
    int32_t accountId = 100;
    int32_t switchedAccountId = 101;
    MultiUserManager::GetInstance().Init();

    std::map<std::string, sptr<IRemoteObject>> param;
    sptr<IRemoteObject> obj(new RemoteOnListenerStubTest());
    param.emplace(TYPE, obj);
    MultiUserManager::GetInstance().listenerCache_.emplace(switchedAccountId, param);

    MultiUserManager::GetInstance().OnUserSwitched(switchedAccountId);
    EXPECT_EQ(MultiUserManager::GetInstance().currentUserId_, switchedAccountId);
    EXPECT_TRUE(MultiUserManager::GetInstance().listenerCache_.empty());
    MultiUserManager::GetInstance().UnInit();
    DTEST_LOG << "MultiUserManager_OnUserSwitched_002 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_OnUserRemoved_001
 * @tc.desc: test OnUserRemoved
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_OnUserRemoved_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_OnUserRemoved_001 start" << std::endl;
    /**
     * @tc.steps: step1. test OnUserRemoved with remove by accountId sendMgr recvMgr;
     */
    int32_t accountId = 100;
    MultiUserManager::GetInstance().Init();
    MultiUserManager::GetInstance().OnUserRemoved(accountId);
    
    auto sendMgr = MultiUserManager::GetInstance().sendMgrMap_.find(accountId);
    EXPECT_TRUE(sendMgr == MultiUserManager::GetInstance().sendMgrMap_.end());
    auto recvMgr = MultiUserManager::GetInstance().recvMgrMap_.find(accountId);
    EXPECT_TRUE(recvMgr == MultiUserManager::GetInstance().recvMgrMap_.end());

    MultiUserManager::GetInstance().UnInit();
    DTEST_LOG << "MultiUserManager_OnUserRemoved_001 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_CreateNewSendMgr_001
 * @tc.desc: test CreateNewSendMgr
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_CreateNewSendMgr_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_CreateNewSendMgr_001 start" << std::endl;
    /**
     * @tc.steps: step1. test OnUserRemoved with create current user sendMgr;
     */
    MultiUserManager::GetInstance().Init();
    int32_t ret = MultiUserManager::GetInstance().CreateNewSendMgr();
    EXPECT_EQ(ret, ERR_OK);

    MultiUserManager::GetInstance().UnInit();
    DTEST_LOG << "MultiUserManager_CreateNewSendMgr_001 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_CreateNewRecvMgr_001
 * @tc.desc: test CreateNewRecvMgr
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_CreateNewRecvMgr_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_CreateNewRecvMgr_001 start" << std::endl;
    /**
     * @tc.steps: step1. test OnUserRemoved with create current user recvMgr;
     */
    MultiUserManager::GetInstance().Init();
    int32_t ret = MultiUserManager::GetInstance().CreateNewRecvMgr();
    EXPECT_EQ(ret, ERR_OK);

    MultiUserManager::GetInstance().UnInit();
    DTEST_LOG << "MultiUserManager_CreateNewRecvMgr_001 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_GetCurrentSendMgr_001
 * @tc.desc: test GetCurrentSendMgr
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_GetCurrentSendMgr_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_GetCurrentSendMgr_001 start" << std::endl;
    /**
     * @tc.steps: step1. test OnUserRemoved with create current user sendMgr;
     */
    int32_t accountId = 100;
    MultiUserManager::GetInstance().Init();
    auto sendMgr = MultiUserManager::GetInstance().sendMgrMap_.find(accountId)->second;

    auto ret = MultiUserManager::GetInstance().GetCurrentSendMgr();
    EXPECT_EQ(ret, sendMgr);

    MultiUserManager::GetInstance().sendMgrMap_.insert({accountId, nullptr});
    ret = MultiUserManager::GetInstance().GetCurrentSendMgr();
    EXPECT_NE(ret, nullptr);

    MultiUserManager::GetInstance().UnInit();
    DTEST_LOG << "MultiUserManager_GetCurrentSendMgr_001 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_GetCurrentRecvMgr_001
 * @tc.desc: test GetCurrentRecvMgr
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_GetCurrentRecvMgr_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_GetCurrentRecvMgr_001 start" << std::endl;
    /**
     * @tc.steps: step1. test OnUserRemoved with create current user recvMgr;
     */
    int32_t accountId = 100;
    MultiUserManager::GetInstance().Init();
    auto recvMgr = MultiUserManager::GetInstance().recvMgrMap_.find(accountId)->second;

    auto ret = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    EXPECT_EQ(ret, recvMgr);

    MultiUserManager::GetInstance().recvMgrMap_.insert({accountId, nullptr});
    ret = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    EXPECT_NE(ret, nullptr);


    MultiUserManager::GetInstance().UnInit();
    DTEST_LOG << "MultiUserManager_GetCurrentRecvMgr_001 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_OnRegisterOnListener_001
 * @tc.desc: test OnRegisterOnListener
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_OnRegisterOnListener_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_OnRegisterOnListener_001 start" << std::endl;
    /**
     * @tc.steps: step1. test OnUserRemoved with register listener
     */
    MultiUserManager::GetInstance().Init();

    int32_t callingUid = 0;
    sptr<IRemoteObject> obj(new RemoteOnListenerStubTest());
    auto ret = MultiUserManager::GetInstance().OnRegisterOnListener(TYPE, obj, callingUid);
    EXPECT_EQ(ret, ERR_OK);

    MultiUserManager::GetInstance().UnInit();
    DTEST_LOG << "MultiUserManager_OnRegisterOnListener_001 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_OnRegisterOffListener_001
 * @tc.desc: test OnRegisterOffListener
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_OnRegisterOffListener_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_OnRegisterOffListener_001 start" << std::endl;
    /**
     * @tc.steps: step1. test OnUserRemoved with unregister listener
     */
    MultiUserManager::GetInstance().Init();

    int32_t callingUid = 0;
    sptr<IRemoteObject> obj(new RemoteOnListenerStubTest());
    auto ret = MultiUserManager::GetInstance().OnRegisterOffListener(TYPE, obj, callingUid);
    EXPECT_EQ(ret, DMS_NOT_FOREGROUND_USER);

    MultiUserManager::GetInstance().UnInit();
    DTEST_LOG << "MultiUserManager_OnRegisterOffListener_001 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_GetForegroundUser_001
 * @tc.desc: test GetForegroundUser
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_GetForegroundUser_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_GetForegroundUser_001 start" << std::endl;
    /**
     * @tc.steps: step1. test OnUserRemoved with get currrent accountid
     */
    int32_t accountId = 100;
    int32_t ret = MultiUserManager::GetInstance().GetForegroundUser();
    EXPECT_EQ(ret, accountId);

    DTEST_LOG << "MultiUserManager_GetForegroundUser_001 end" << std::endl;
}

/**
 * @tc.name: MultiUserManager_IsUserForeground_001
 * @tc.desc: test IsUserForeground
 * @tc.type: FUNC
 */
HWTEST_F(MultiUserManagerTest, MultiUserManager_IsUserForeground_001, TestSize.Level3)
{
    DTEST_LOG << "MultiUserManager_IsUserForeground_001 start" << std::endl;
    /**
     * @tc.steps: step1. test OnUserRemoved with is foreground user
     */
    int32_t accountId = 100;
    int32_t otherAccountId = 101;

    bool ret = MultiUserManager::GetInstance().IsUserForeground(accountId);
    EXPECT_TRUE(ret);

    ret = MultiUserManager::GetInstance().IsUserForeground(otherAccountId);
    EXPECT_FALSE(ret);

    DTEST_LOG << "MultiUserManager_IsCallerForeground_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
