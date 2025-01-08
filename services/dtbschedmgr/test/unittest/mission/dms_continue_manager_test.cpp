/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "dms_continue_manager_test.h"

#include "datetime_ex.h"
#include "distributed_sched_test_util.h"
#include "dtbschedmgr_log.h"
#define private public
#include "mission/dms_continue_send_manager.h"
#include "mission/dms_continue_recv_manager.h"
#undef private
#include "multi_user_manager.h"
#include "softbus_adapter/softbus_adapter.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TYPE = "type";
const std::string BUNDLENAME_01 = "bundleName01";
const std::string BUNDLENAME_02 = "bundleName02";
const std::string NETWORKID_01 = "networkId01";
const std::string NETWORKID_02 = "networkId02";
const std::string ABILITY_NAME_01 = "abilityName01";
const std::string CANCEL_FOCUSED_TASK = "cancel_mission_focused_task";
const int32_t WAITTIME = 2000;
constexpr static int32_t DMS_SEND_LEN = 5;
constexpr static uint8_t DMS_0X0F = 0x0f;
constexpr int32_t MISSIONID_01 = 1;
constexpr int32_t MISSIONID_02 = 2;
constexpr int32_t ACTIVE = 0;
constexpr int32_t INACTIVE = 1;
constexpr int32_t CANCEL_FOCUSED_DELAYED = 10000;
constexpr int32_t DBMS_RETRY_MAX_TIME = 5;
constexpr uint8_t DMS_FOCUSED_TYPE = 0x00;
}

int32_t SoftbusAdapter::SendSoftbusEvent(std::shared_ptr<DSchedDataBuffer> buffer)
{
    return CAN_NOT_FOUND_ABILITY_ERR;
}

void DMSContinueManagerTest::SetUpTestCase()
{
}

void DMSContinueManagerTest::TearDownTestCase()
{
}

void DMSContinueManagerTest::SetUp()
{
    MultiUserManager::GetInstance().Init();
}

void DMSContinueManagerTest::TearDown()
{
}

void RemoteOnListenerStubTest::OnCallback(const uint32_t ContinueState, const std::string& srcDeviceId,
    const std::string &bundleName, const std::string &continueType, const std::string &srcBundleName)
{
}

/**
 * @tc.name: testRegisterOnListener001
 * @tc.desc: test RegisterOnListener
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testRegisterOnListener001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testRegisterOnListener001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t accountId = 100;
    recvMgr->Init(accountId);
    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    int32_t ret = recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(ret, ERR_OK);

    ret = recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(ret, NO_MISSION_INFO_FOR_MISSION_ID);

    sptr<IRemoteObject> obj02(new RemoteOnListenerStubTest());
    ret = recvMgr->RegisterOnListener(TYPE, obj02);
    EXPECT_EQ(ret, ERR_OK);
    recvMgr->UnInit();
    DTEST_LOG << "DMSContinueManagerTest testRegisterOnListener001 end" << std::endl;
}

/**
 * @tc.name: testRegisterOffListener001
 * @tc.desc: test RegisterOffListener
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testRegisterOffListener001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testRegisterOffListener001 start" << std::endl;
    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->RegisterOnListener(TYPE, obj01);
    ret = recvMgr->RegisterOffListener(TYPE, obj01);
    EXPECT_EQ(ret, ERR_OK);

    ret = recvMgr->RegisterOffListener(TYPE, nullptr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DMSContinueManagerTest testRegisterOffListener001 end" << std::endl;
}

/**
 * @tc.name: testRegisterOffListener002
 * @tc.desc: test RegisterOffListener when iterItem->second is empty.
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DMSContinueManagerTest, testRegisterOffListener002, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testRegisterOffListener002 start" << std::endl;
    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(ret, ERR_OK);

    {
        std::lock_guard<std::mutex> registerOnListenerMapLock(recvMgr->eventMutex_);
        recvMgr->registerOnListener_[TYPE].clear();
    }
    ret = recvMgr->RegisterOffListener(TYPE, obj01);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DMSContinueManagerTest testRegisterOffListener002 end" << std::endl;
}

/**
 * @tc.name: testVerifyBroadcastSource001
 * @tc.desc: test testVerifyBroadcastSource001.
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testVerifyBroadcastSource001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testVerifyBroadcastSource001 start" << std::endl;

    int32_t state = ACTIVE;
    std::string networkId = "test networkId";
    std::string sourceBundleName = "test sourceBundleName";
    std::string sinkBundleName = "test sinkBundleName";
    std::string continueType = "test continueType";
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->VerifyBroadcastSource(networkId,
        sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, ERR_OK);

    state = INACTIVE;
    ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: testVerifyBroadcastSource002
 * @tc.desc: test testVerifyBroadcastSource002.
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testVerifyBroadcastSource002, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testVerifyBroadcastSource002 start" << std::endl;

    int32_t state = ACTIVE;
    std::string networkId = "test networkId";
    std::string sourceBundleName = "test sourceBundleName";
    std::string sinkBundleName = "test sinkBundleName";
    std::string continueType = "test continueType";
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, ERR_OK);

    state = INACTIVE;
    networkId = "invalid networkId";
    ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
}

/**
 * @tc.name: testVerifyBroadcastSource003
 * @tc.desc: test testVerifyBroadcastSource003.
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testVerifyBroadcastSource003, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testVerifyBroadcastSource003 start" << std::endl;

    int32_t state = ACTIVE;
    std::string networkId = "test networkId";
    std::string sourceBundleName = "test sourceBundleName";
    std::string sinkBundleName = "test sinkBundleName";
    std::string continueType = "test continueType";
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, ERR_OK);

    state = INACTIVE;
    sourceBundleName = "invalid sourceBundleName";
    sinkBundleName = "invalid sinkBundleName";
    ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
}

/**
 * @tc.name: testDealOnBroadcastBusiness001
 * @tc.desc: test DealOnBroadcastBusiness.
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DMSContinueManagerTest, testDealOnBroadcastBusiness001, TestSize.Level3)
{
    DTEST_LOG << "DMSContinueManagerTest testDealOnBroadcastBusiness001 start" << std::endl;

    /**
     * @tc.steps: step1. test DealOnBroadcastBusiness when senderNetworkId is invalid;
     */
    std::string senderNetworkId = "invalid senderNetworkId";
    uint16_t bundleNameId = 0;
    uint8_t continueTypeId = 0;
    int32_t state = 0;

    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->PostOnBroadcastBusiness(senderNetworkId, bundleNameId, continueTypeId, state);

    int32_t ret = recvMgr->DealOnBroadcastBusiness(senderNetworkId, bundleNameId, continueTypeId, state, 0);
    EXPECT_EQ(ret, ERR_OK);

    ret = recvMgr->DealOnBroadcastBusiness(senderNetworkId, bundleNameId, continueTypeId, state, DBMS_RETRY_MAX_TIME);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    /**
     * @tc.steps: step2. test NotifyRecvBroadcast when obj is nullptr;
     */
    sptr<IRemoteObject> obj = nullptr;
    std::string networkId = "invalid networkId";
    std::string sourceBundleName = "invalid sourceBundleName";
    std::string sinkBundleName = "invalid sinkBundleName";
    std::string continueType = "invalid continueType";
    recvMgr->NotifyRecvBroadcast(obj,
        currentIconInfo(networkId, sourceBundleName, sinkBundleName, continueType), state);

    /**
     * @tc.steps: step3. test NotifyRecvBroadcast when missionId is invalid;
     */
    obj =  new RemoteOnListenerStubTest();
    recvMgr->NotifyRecvBroadcast(obj,
        currentIconInfo(networkId, sourceBundleName, sinkBundleName, continueType), state);

    DTEST_LOG << "DMSContinueManagerTest testDealOnBroadcastBusiness001 end" << std::endl;
}

/**
 * @tc.name: testNotifyDied001
 * @tc.desc: test NotifyDied
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyDied001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyDied001 start" << std::endl;
    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_EQ(false, recvMgr->registerOnListener_.empty());
    recvMgr->NotifyDied(obj01);
    DTEST_LOG << "DMSContinueManagerTest testNotifyDied001 end" << std::endl;
}

/**
 * @tc.name: testNotifyDeviceOffline001
 * @tc.desc: test NotifyDeviceOffline normal
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyDeviceOffline001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.senderNetworkId = NETWORKID_01;
    recvMgr->NotifyDeviceOffline(NETWORKID_01);

    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_NE(recvMgr->registerOnListener_.size(), 0);
    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline001 end" << std::endl;
}

/**
 * @tc.name: testNotifyDeviceOffline002
 * @tc.desc: test NotifyDeviceOffline networkId empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyDeviceOffline002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline002 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.senderNetworkId = NETWORKID_01;
    recvMgr->NotifyDeviceOffline("");
    EXPECT_EQ(recvMgr->iconInfo_.senderNetworkId, NETWORKID_01);

    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline002 end" << std::endl;
}

/**
 * @tc.name: testNotifyDeviceOffline003
 * @tc.desc: test NotifyDeviceOffline networkId not match
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyDeviceOffline003, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline003 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.senderNetworkId = NETWORKID_01;
    recvMgr->NotifyDeviceOffline(NETWORKID_02);
    EXPECT_EQ(recvMgr->iconInfo_.senderNetworkId, NETWORKID_01);

    DTEST_LOG << "DMSContinueManagerTest testNotifyDeviceOffline003 end" << std::endl;
}

/**
 * @tc.name: NotifyPackageRemoved001
 * @tc.desc: test NotifyPackageRemoved normal
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, notifyPackageRemoved001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved001 start" << std::endl;
    sptr<IRemoteObject> obj01(new RemoteOnListenerStubTest());
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->RegisterOnListener(TYPE, obj01);
    EXPECT_NE(recvMgr->registerOnListener_.size(), 0);

    recvMgr->iconInfo_.bundleName = BUNDLENAME_01;
    recvMgr->NotifyPackageRemoved(BUNDLENAME_01);
    EXPECT_EQ(recvMgr->iconInfo_.bundleName, "");

    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved001 end" << std::endl;
}

/**
 * @tc.name: NotifyPackageRemoved002
 * @tc.desc: test NotifyPackageRemoved bundleName empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, notifyPackageRemoved002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved002 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.bundleName = BUNDLENAME_01;
    recvMgr->NotifyPackageRemoved("");
    EXPECT_EQ(recvMgr->iconInfo_.bundleName, BUNDLENAME_01);

    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved002 end" << std::endl;
}

/**
 * @tc.name: NotifyPackageRemoved003
 * @tc.desc: test NotifyPackageRemoved bundleName not match
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, notifyPackageRemoved003, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved003 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.bundleName = BUNDLENAME_01;
    recvMgr->NotifyPackageRemoved(BUNDLENAME_02);
    EXPECT_EQ(recvMgr->iconInfo_.bundleName, BUNDLENAME_01);

    DTEST_LOG << "DMSContinueManagerTest notifyPackageRemoved003 end" << std::endl;
}

/**
 * @tc.name: testNotifyDataRecv001
 * @tc.desc: NotifyDataRecv
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testNotifyDataRecv001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testNotifyDataRecv001 start" << std::endl;
    std::string senderNetworkId = NETWORKID_01;
    uint8_t payload[] = {0xf0};
    uint32_t dataLen1 = DMS_SEND_LEN - 1;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->NotifyDataRecv(senderNetworkId, payload, dataLen1);

    uint32_t dataLen2 = DMS_SEND_LEN;
    recvMgr->NotifyDataRecv(senderNetworkId, payload, dataLen2);
    EXPECT_NE(payload[0] & DMS_0X0F, sizeof(uint32_t));
    DTEST_LOG << "DMSContinueManagerTest testNotifyDataRecv001 end" << std::endl;
}

/**
 * @tc.name: testGetContinueType_001
 * @tc.desc: test GetContinueType
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testGetContinueType_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetContinueType_001 start" << std::endl;
    int32_t state = ACTIVE;
    std::string networkId = "test networkId";
    std::string sourceBundleName = "test sourceBundleName";
    std::string sinkBundleName = "test sinkBundleName";
    std::string continueType = "test continueType";
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    int32_t ret = recvMgr->VerifyBroadcastSource(networkId, sourceBundleName, sinkBundleName, continueType, state);
    EXPECT_EQ(ret, ERR_OK);

    EXPECT_FALSE(recvMgr->GetContinueType(sinkBundleName).empty());
    DTEST_LOG << "DMSContinueManagerTest testGetContinueType_001 end" << std::endl;
}

/**
 * @tc.name: testGetFinalBundleName_001
 * @tc.desc: test GetFinalBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testGetFinalBundleName_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testGetFinalBundleName_001 start" << std::endl;
    DmsBundleInfo info;
    std::string finalBundleName;
    AppExecFwk::BundleInfo localBundleInfo;
    std::string continueType;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->GetFinalBundleName(info, finalBundleName, localBundleInfo, continueType);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DMSContinueManagerTest testGetFinalBundleName_001 end" << std::endl;
}

/**
 * @tc.name: testIsBundleContinuable_001
 * @tc.desc: all continuable = false  => res = false
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testIsBundleContinuable_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_001 start" << std::endl;
    std::string srcAbilityName = "abilityName";
    std::string srcModuleName = "module1";
    std::string srcContinueType = "continueType";

    AppExecFwk::BundleInfo localBundleInfo;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<std::string> continueTypes;
    continueTypes.push_back(srcContinueType);
    abilityInfo.continueType = continueTypes;
    abilityInfo.continuable = false;
    abilityInfo.name = srcAbilityName;
    abilityInfo.moduleName = srcModuleName;
    abilityInfos.push_back(abilityInfo);

    localBundleInfo.abilityInfos = abilityInfos;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName, srcModuleName, srcContinueType);
    EXPECT_EQ(ret, false);

    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_001 end" << std::endl;
}

/**
 * @tc.name: testIsBundleContinuable_002
 * @tc.desc: continuable = true; same continueType  => res = true
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testIsBundleContinuable_002, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_002 start" << std::endl;
    std::string srcAbilityName = "abilityName";
    std::string srcModuleName = "module1";
    std::string srcContinueType = "continueType";

    AppExecFwk::BundleInfo localBundleInfo;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<std::string> continueTypes;
    continueTypes.push_back(srcContinueType + "_ContinueQuickStart");
    abilityInfo.continueType = continueTypes;
    abilityInfo.continuable = true;
    abilityInfo.name = srcAbilityName;
    abilityInfo.moduleName = srcModuleName;
    abilityInfos.push_back(abilityInfo);

    localBundleInfo.abilityInfos = abilityInfos;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName, srcModuleName, srcContinueType);
    EXPECT_EQ(ret, true);

    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_002 end" << std::endl;
}

/**
 * @tc.name: testIsBundleContinuable_003
 * @tc.desc: continuable = true; diff continueType; diff BundleName  => res = false;
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testIsBundleContinuable_003, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_003 start" << std::endl;
    std::string srcAbilityName = "srcAbilityName";
    std::string sinkAbilityName = "sinkAbilityName";
    std::string srcModuleName = "module1";
    std::string srcContinueType = "srcContinueType";
    std::string sinkContinueType = "sinkContinueType";

    AppExecFwk::BundleInfo localBundleInfo;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<std::string> continueTypes;
    continueTypes.push_back(sinkContinueType + "_ContinueQuickStart");
    abilityInfo.continueType = continueTypes;
    abilityInfo.continuable = true;
    abilityInfo.name = sinkAbilityName;
    abilityInfo.moduleName = srcModuleName;
    abilityInfos.push_back(abilityInfo);

    localBundleInfo.abilityInfos = abilityInfos;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName, srcModuleName, srcContinueType);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_003 end" << std::endl;
}

/**
 * @tc.name: testIsBundleContinuable_004
 * @tc.desc: continuable = true; diff continueType; same abilityName; diff modulename  => res = false;
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testIsBundleContinuable_004, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_004 start" << std::endl;
    std::string srcAbilityName = "srcAbilityName";
    std::string srcModuleName = "module1";
    std::string sinkModuleName = "module2";
    std::string srcContinueType = srcAbilityName;
    std::string sinkContinueType = "sinkContinueType";

    AppExecFwk::BundleInfo localBundleInfo;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<std::string> continueTypes;
    continueTypes.push_back(sinkContinueType + "_ContinueQuickStart");
    abilityInfo.continueType = continueTypes;
    abilityInfo.continuable = true;
    abilityInfo.name = srcAbilityName;
    abilityInfo.moduleName = sinkModuleName;
    abilityInfos.push_back(abilityInfo);

    localBundleInfo.abilityInfos = abilityInfos;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName, srcModuleName, srcContinueType);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_004 end" << std::endl;
}

/**
 * @tc.name: testIsBundleContinuable_004
 * @tc.desc: continuable = true; diff continueType; same abilityName; same modulename  => res = true;
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, testIsBundleContinuable_005, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_005 start" << std::endl;
    std::string srcAbilityName = "srcAbilityName";
    std::string srcModuleName = "module1";
    std::string srcContinueType = srcAbilityName;
    std::string sinkContinueType = "sinkContinueType";

    AppExecFwk::BundleInfo localBundleInfo;
    std::vector<AppExecFwk::AbilityInfo> abilityInfos;
    AppExecFwk::AbilityInfo abilityInfo;
    std::vector<std::string> continueTypes;
    continueTypes.push_back(sinkContinueType + "_ContinueQuickStart");
    abilityInfo.continueType = continueTypes;
    abilityInfo.continuable = true;
    abilityInfo.name = srcAbilityName;
    abilityInfo.moduleName = srcModuleName;
    abilityInfos.push_back(abilityInfo);

    localBundleInfo.abilityInfos = abilityInfos;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    bool ret = recvMgr->IsBundleContinuable(localBundleInfo, srcAbilityName, srcModuleName, srcContinueType);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DMSContinueManagerTest testIsBundleContinuable_005 end" << std::endl;
}

/**
 * @tc.name: OnContinueSwitchOff_001
 * @tc.desc: test OnContinueSwitchOff
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, OnContinueSwitchOff_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest OnContinueSwitchOff_001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.senderNetworkId = "";
    recvMgr->iconInfo_.bundleName = "";
    recvMgr->iconInfo_.continueType = "";
    recvMgr->OnContinueSwitchOff();
    EXPECT_EQ(recvMgr->iconInfo_.isEmpty(), true);

    recvMgr->iconInfo_.senderNetworkId = "senderNetworkId";
    recvMgr->iconInfo_.bundleName = "bundleName";
    recvMgr->iconInfo_.continueType = "continueType";
    recvMgr->registerOnListener_.clear();
    recvMgr->OnContinueSwitchOff();
    EXPECT_EQ(recvMgr->registerOnListener_.empty(), true);
    DTEST_LOG << "DMSContinueManagerTest OnContinueSwitchOff_001 end" << std::endl;
}

/**
 * @tc.name: OnUserSwitch_001
 * @tc.desc: test OnUserSwitch
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, OnUserSwitch_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest OnUserSwitch_001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    recvMgr->iconInfo_.senderNetworkId = "";
    recvMgr->iconInfo_.bundleName = "";
    recvMgr->iconInfo_.continueType = "";
    recvMgr->OnUserSwitch();
    EXPECT_EQ(recvMgr->iconInfo_.isEmpty(), true);

    recvMgr->iconInfo_.senderNetworkId = "senderNetworkId";
    recvMgr->iconInfo_.bundleName = "bundleName";
    recvMgr->iconInfo_.continueType = "continueType";
    recvMgr->registerOnListener_.clear();
    recvMgr->OnUserSwitch();
    EXPECT_EQ(recvMgr->registerOnListener_.empty(), true);
    DTEST_LOG << "DMSContinueManagerTest OnUserSwitch_001 end" << std::endl;
}

/**
 * @tc.name: FindToNotifyRecvBroadcast_001
 * @tc.desc: test FindToNotifyRecvBroadcast
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, FindToNotifyRecvBroadcast_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest FindToNotifyRecvBroadcast_001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    std::string senderNetworkId = "senderNetworkId";
    std::string bundleName = "bundleName";
    std::string continueType = "senderNetworkId";
    recvMgr->iconInfo_.senderNetworkId = senderNetworkId;
    recvMgr->iconInfo_.bundleName = bundleName;
    recvMgr->iconInfo_.continueType = continueType;
    recvMgr->registerOnListener_.clear();
    recvMgr->FindToNotifyRecvBroadcast(senderNetworkId, bundleName, continueType);
    EXPECT_EQ(recvMgr->registerOnListener_.empty(), true);
    DTEST_LOG << "DMSContinueManagerTest FindToNotifyRecvBroadcast_001 end" << std::endl;
}

/**
 * @tc.name: NotifyIconDisappear_001
 * @tc.desc: test NotifyIconDisappear
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, NotifyIconDisappear_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest NotifyIconDisappear_001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    std::string senderNetworkId = "senderNetworkId";
    std::string bundleName = "bundleName";
    std::string continueType = "senderNetworkId";
    uint16_t bundleNameId = 0;
    std::string finalBundleName = "finalBundleName";
    int32_t state = 0;
    recvMgr->iconInfo_.senderNetworkId = senderNetworkId;
    recvMgr->registerOnListener_.clear();
    recvMgr->NotifyIconDisappear(bundleNameId, senderNetworkId, state);
    EXPECT_EQ(recvMgr->registerOnListener_.empty(), true);
    DTEST_LOG << "DMSContinueManagerTest NotifyIconDisappear_001 end" << std::endl;
}

/**
 * @tc.name: NotifyDockDisplay_001
 * @tc.desc: test NotifyDockDisplay
 * @tc.type: FUNC
 */
HWTEST_F(DMSContinueManagerTest, NotifyDockDisplay_001, TestSize.Level1)
{
    DTEST_LOG << "DMSContinueManagerTest NotifyDockDisplay_001 start" << std::endl;
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    ASSERT_NE(nullptr, recvMgr);
    std::string senderNetworkId = "senderNetworkId";
    std::string bundleName = "bundleName";
    std::string continueType = "senderNetworkId";
    uint16_t bundleNameId = 0;
    std::string finalBundleName = "finalBundleName";
    int32_t state = 0;
    recvMgr->registerOnListener_.clear();
    int32_t ret = recvMgr->NotifyDockDisplay(bundleNameId,
        currentIconInfo(senderNetworkId, bundleName, finalBundleName, continueType), state);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    std::vector<sptr<IRemoteObject>> objs;
    {
        std::lock_guard<std::mutex> registerOnListenerMapLock(recvMgr->eventMutex_);
        recvMgr->registerOnListener_[TYPE] = objs;
    }
    ret = recvMgr->NotifyDockDisplay(bundleNameId,
        currentIconInfo(senderNetworkId, bundleName, finalBundleName, continueType), state);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DMSContinueManagerTest NotifyDockDisplay_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
