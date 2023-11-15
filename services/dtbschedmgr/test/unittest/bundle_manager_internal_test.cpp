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

#include <thread>

#include "bundle_manager_internal_test.h"
#include "bundle/bundle_manager_internal.h"

#define private public
#include "bundle/bundle_manager_callback_stub.h"
#undef private

#include "distributed_sched_util.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const string GROUP_ID = "TEST_GROUP_ID";
constexpr int32_t SLEEP_TIME = 1000;
}

void BundleManagerInternalTest::SetUpTestCase()
{
    DTEST_LOG << "BundleManagerInternalTest::SetUpTestCase" << std::endl;
    DistributedSchedUtil::InstallThirdPartyHap();
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
}

void BundleManagerInternalTest::TearDownTestCase()
{
    DTEST_LOG << "BundleManagerInternalTest::TearDownTestCase" << std::endl;
}

void BundleManagerInternalTest::TearDown()
{
    DTEST_LOG << "BundleManagerInternalTest::TearDown" << std::endl;
}

void BundleManagerInternalTest::SetUp()
{
    DTEST_LOG << "BundleManagerInternalTest::SetUp" << std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_001, TestSize.Level0)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_001 begin" << std::endl;
    AAFwk::Want want;
    AppExecFwk::ExtensionAbilityInfo extensionInfo;

    bool ret = BundleManagerInternal::QueryExtensionAbilityInfo(want, extensionInfo);
    EXPECT_TRUE(!ret);
    EXPECT_TRUE(extensionInfo.name.empty());
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_002
 * @tc.desc: test ability info convert
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_002, TestSize.Level0)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_002 begin" << std::endl;
    AppExecFwk::AbilityInfo abilityInfo;
    AppExecFwk::ExtensionAbilityInfo extensionInfo;
    extensionInfo.bundleName.append("bundleName");
    extensionInfo.name.append("name");
    vector<string> permissions;
    extensionInfo.permissions = permissions;
    extensionInfo.visible = true;
    
    BundleManagerInternal::InitAbilityInfoFromExtension(extensionInfo, abilityInfo);
    EXPECT_TRUE(abilityInfo.bundleName.compare("bundleName") == 0);
    EXPECT_TRUE(abilityInfo.name.compare("name") == 0);
    EXPECT_TRUE(abilityInfo.permissions == permissions);
    EXPECT_TRUE(abilityInfo.visible);
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_002 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_003
 * @tc.desc: test CheckRemoteBundleInfo with empty bundleName
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_003, TestSize.Level1)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_003 begin" << std::endl;
    string deviceId = "123456";
    string bundleName = "";
    AppExecFwk::DistributedBundleInfo remoteBundleInfo;
    int ret = BundleManagerInternal::CheckRemoteBundleInfoForContinuation(deviceId, bundleName, remoteBundleInfo);
    EXPECT_TRUE(INVALID_PARAMETERS_ERR == ret);

    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_003 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_004
 * @tc.desc: test CheckRemoteBundleInfo with unexist bundle
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_004, TestSize.Level1)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_004 begin" << std::endl;
    string deviceId = "123456";
    string bundleName = "ohos.samples.testApp";
    AppExecFwk::DistributedBundleInfo remoteBundleInfo;
    int ret = BundleManagerInternal::CheckRemoteBundleInfoForContinuation(deviceId, bundleName, remoteBundleInfo);
    EXPECT_TRUE(INVALID_PARAMETERS_ERR == ret);

    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_004 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_005
 * @tc.desc: test CheckRemoteBundleInfo with valid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_005, TestSize.Level1)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_005 begin" << std::endl;
    string deviceId = "123456";
    string bundleName = "com.ohos.mms";
    AppExecFwk::DistributedBundleInfo remoteBundleInfo;
    int ret = BundleManagerInternal::CheckRemoteBundleInfoForContinuation(deviceId, bundleName, remoteBundleInfo);
    EXPECT_TRUE(CONTINUE_REMOTE_UNINSTALLED_UNSUPPORT_FREEINSTALL == ret);

    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_005 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_006
 * @tc.desc: test CheckIfRemoteCanInstall with valid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_006, TestSize.Level1)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_006 begin" << std::endl;
    string deviceId = "123456";
    string bundleName = "com.ohos.mms";
    string moduleName = "entry";
    string abilityName = "bmsThirdBundle";
    AAFwk::Want want;
    want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    int32_t missionId = 0;
    bool ret = BundleManagerInternal::CheckIfRemoteCanInstall(want, missionId);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_006 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_007
 * @tc.desc: test CheckIfRemoteCanInstall with invalid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_007, TestSize.Level1)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_007 begin" << std::endl;
    string deviceId = "";
    string bundleName = "ohos.samples.testApp";
    string moduleName = "entry";
    string abilityName = "MainAbility";
    AAFwk::Want want;
    want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    int32_t missionId = 0;
    bool ret = BundleManagerInternal::CheckIfRemoteCanInstall(want, missionId);
    EXPECT_EQ(ret, false);

    deviceId = "123456";
    bundleName = "";
    want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    ret = BundleManagerInternal::CheckIfRemoteCanInstall(want, missionId);
    EXPECT_EQ(ret, false);

    bundleName = "ohos.samples.testApp";
    moduleName = "";
    want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    ret = BundleManagerInternal::CheckIfRemoteCanInstall(want, missionId);
    EXPECT_EQ(ret, false);

    moduleName = "entry";
    abilityName = "";
    want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    ret = BundleManagerInternal::CheckIfRemoteCanInstall(want, missionId);
    EXPECT_EQ(ret, false);

    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_007 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_008
 * @tc.desc: test CheckIfRemoteCanInstall with unexist bundle
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_008, TestSize.Level1)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_008 begin" << std::endl;
    string deviceId = "123456";
    string bundleName = "ohos.samples.testApp";
    string moduleName = "entry";
    string abilityName = "MainAbility";
    AAFwk::Want want;
    want.SetElementName(deviceId, bundleName, abilityName, moduleName);
    int32_t missionId = 0;
    bool ret = BundleManagerInternal::CheckIfRemoteCanInstall(want, missionId);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_008 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_009
 * @tc.desc: test get callerappId from bms with invalid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_009, TestSize.Level4)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_009 begin" << std::endl;
    int32_t callingUid = -1;
    string appId;
    bool ret = BundleManagerInternal::GetCallerAppIdFromBms(callingUid, appId);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_009 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_010
 * @tc.desc: test get callerappId from bms with invalid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_010, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_010 begin" << std::endl;
    int32_t callingUid = 5522;
    string appId;
    bool ret = BundleManagerInternal::GetCallerAppIdFromBms(callingUid, appId);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_010 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_011
 * @tc.desc: test IsSameAppId with invalid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_011, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_011 begin" << std::endl;
    string appId;
    string targetBundleName;
    bool ret = BundleManagerInternal::IsSameAppId(appId, targetBundleName);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_011 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_012
 * @tc.desc: test IsSameAppId with invalid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_012, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_012 begin" << std::endl;
    string appId = "1001";
    string targetBundleName = "ohos.samples.testApp";
    bool ret = BundleManagerInternal::IsSameAppId(appId, targetBundleName);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_012 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerInternalTest_013
 * @tc.desc: test IsSameAppId with invalid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerInternalTest_013, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_013 begin" << std::endl;
    string bundleName = "ohos.samples.testApp";
    int32_t uid = BundleManagerInternal::GetUidFromBms(bundleName);
    EXPECT_EQ(uid, -1);
    DTEST_LOG << "BundleManagerInternalTest BundleManagerInternalTest_013 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerCallBackTest_001
 * @tc.desc: test OnQueryInstallationFinished with failed result
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerCallBackTest_001, TestSize.Level1)
{
    DTEST_LOG << "BundleManagerCallBackTest BundleManagerCallBackTest_001 begin" << std::endl;
    int32_t resultCode = -1;
    int32_t missionId = 0;
    int32_t versionCode = 10000;
    auto callback = new DmsBundleManagerCallbackStub();
    int32_t ret = callback->OnQueryInstallationFinished(resultCode, missionId, versionCode);
    EXPECT_TRUE(CONTINUE_REMOTE_UNINSTALLED_CANNOT_FREEINSTALL == ret);
    DTEST_LOG << "BundleManagerCallBackTest BundleManagerCallBackTest_001 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerCallBackTest_002
 * @tc.desc: test OnQueryInstallationFinished
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerCallBackTest_002, TestSize.Level1)
{
    DTEST_LOG << "BundleManagerCallBackTest BundleManagerCallBackTest_002 begin" << std::endl;
    int32_t resultCode = 0;
    int32_t missionId = 0;
    int32_t versionCode = 10000;
    auto callback = new DmsBundleManagerCallbackStub();
    int32_t ret = callback->OnQueryInstallationFinished(resultCode, missionId, versionCode);
    EXPECT_TRUE(ERR_OK != ret);
    DTEST_LOG << "BundleManagerCallBackTest BundleManagerCallBackTest_002 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerCallBackTest_003
 * @tc.desc: test OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerCallBackTest_003, TestSize.Level1)
{
    DTEST_LOG << "BundleManagerCallBackTest BundleManagerCallBackTest_003 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto callback = new DmsBundleManagerCallbackStub();
    int32_t ret = callback->OnRemoteRequest(-1, data, reply, option);
    EXPECT_TRUE(ERR_OK != ret);
    DTEST_LOG << "BundleManagerCallBackTest BundleManagerCallBackTest_003 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerCallBackTest_004
 * @tc.desc: test OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerCallBackTest_004, TestSize.Level1)
{
    DTEST_LOG << "BundleManagerCallBackTest BundleManagerCallBackTest_004 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto callback = new DmsBundleManagerCallbackStub();
    data.WriteInterfaceToken(callback->GetDescriptor());
    int32_t ret = callback->OnRemoteRequest(-1, data, reply, option);
    EXPECT_TRUE(ERR_OK != ret);
    DTEST_LOG << "BundleManagerCallBackTest BundleManagerCallBackTest_004 end "<< std::endl;
}

/**
 * @tc.name: BundleManagerCallBackTest_005
 * @tc.desc: test OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, BundleManagerCallBackTest_005, TestSize.Level1)
{
    DTEST_LOG << "BundleManagerCallBackTest BundleManagerCallBackTest_005 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    auto callback = new DmsBundleManagerCallbackStub();
    data.WriteInterfaceToken(callback->GetDescriptor());
    int32_t ret = callback->OnRemoteRequest(1, data, reply, option);
    EXPECT_TRUE(ERR_OK != ret);
    DTEST_LOG << "BundleManagerCallBackTest BundleManagerCallBackTest_005 end "<< std::endl;
}

/**
 * @tc.name: GetBundleNameListFromBms_001
 * @tc.desc: test GetBundleNameListFromBms
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, GetBundleNameListFromBms_001, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerCallBackTest GetBundleNameListFromBms_001 begin" << std::endl;
    const std::string bundleName = "com.ohos.launcher";
    int32_t uid = BundleManagerInternal::GetUidFromBms(bundleName);
    if (uid <= 0) {
        return;
    }
    std::vector<std::u16string> u16BundleNameList;
    BundleManagerInternal::GetBundleNameListFromBms(uid, u16BundleNameList);
    EXPECT_TRUE(!u16BundleNameList.empty());
    u16BundleNameList.clear();
    BundleManagerInternal::GetBundleNameListFromBms(-1, u16BundleNameList);
    EXPECT_TRUE(u16BundleNameList.empty());
    DTEST_LOG << "BundleManagerCallBackTest GetBundleNameListFromBms_001 end "<< std::endl;
}

/**
 * @tc.name: GetBundleNameListFromBms_002
 * @tc.desc: test GetBundleNameListFromBms
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, GetBundleNameListFromBms_002, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerCallBackTest GetBundleNameListFromBms_002 begin" << std::endl;
    const std::string bundleName = "com.ohos.permissionmanager";
    int32_t uid = BundleManagerInternal::GetUidFromBms(bundleName);
    if (uid <= 0) {
        return;
    }
    std::vector<std::u16string> u16BundleNameList;
    bool ret1 = BundleManagerInternal::GetBundleNameListFromBms(uid, u16BundleNameList);
    EXPECT_EQ(ret1, true);
    u16BundleNameList.clear();
    bool ret2 = BundleManagerInternal::GetBundleNameListFromBms(-1, u16BundleNameList);
    EXPECT_EQ(ret2, false);
    DTEST_LOG << "BundleManagerCallBackTest GetBundleNameListFromBms_002 end "<< std::endl;
}

/**
 * @tc.name: GetCallerAppIdFromBms_001
 * @tc.desc: test get callerappId from bms
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, GetCallerAppIdFromBms_001, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerInternalTest GetCallerAppIdFromBms_001 begin" << std::endl;
    const std::string bundleName = "com.ohos.launcher";
    int32_t uid = BundleManagerInternal::GetUidFromBms(bundleName);
    if (uid <= 0) {
        return;
    }
    string appId;
    bool ret = BundleManagerInternal::GetCallerAppIdFromBms(uid, appId);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "BundleManagerInternalTest GetCallerAppIdFromBms_001 end "<< std::endl;
}

/**
 * @tc.name: IsSameAppId_001
 * @tc.desc: test IsSameAppId with invalid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, IsSameAppId_001, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerInternalTest IsSameAppId_001 begin" << std::endl;
    string appId = "1001";
    string targetBundleName = "ohos.samples.dms.testApp";
    bool ret = BundleManagerInternal::IsSameAppId(appId, targetBundleName);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "BundleManagerInternalTest IsSameAppId_001 end "<< std::endl;
}

/**
 * @tc.name: IsSameAppId_002
 * @tc.desc: test IsSameAppId with invalid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, IsSameAppId_002, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerInternalTest IsSameAppId_002 begin" << std::endl;
    string appId = "1001";
    string targetBundleName = "";
    bool ret = BundleManagerInternal::IsSameAppId(appId, targetBundleName);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "BundleManagerInternalTest IsSameAppId_002 end "<< std::endl;
}

/**
 * @tc.name: IsSameAppId_003
 * @tc.desc: test IsSameAppId with invalid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, IsSameAppId_003, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerInternalTest IsSameAppId_003 begin" << std::endl;
    string appId = "";
    string targetBundleName = "ohos.samples.dms.testApp";
    bool ret = BundleManagerInternal::IsSameAppId(appId, targetBundleName);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "BundleManagerInternalTest IsSameAppId_003 end "<< std::endl;
}

/**
 * @tc.name: IsSameAppId_004
 * @tc.desc: test IsSameAppId with invalid param
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, IsSameAppId_004, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerInternalTest IsSameAppId_004 begin" << std::endl;
    string appId = "";
    string targetBundleName = "";
    bool ret = BundleManagerInternal::IsSameAppId(appId, targetBundleName);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "BundleManagerInternalTest IsSameAppId_004 end "<< std::endl;
}

/**
 * @tc.name: GetBundleIdFromBms_001
 * @tc.desc: test get accessTokenId from bms
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, GetBundleIdFromBms_001, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerInternalTest GetBundleIdFromBms_001 begin" << std::endl;
    const std::string bundleName = "ohos.samples.dms.testApp";
    uint32_t accessTokenId;
    int32_t ret = BundleManagerInternal::GetBundleIdFromBms(bundleName, accessTokenId);
    EXPECT_EQ(ret, CAN_NOT_FOUND_ABILITY_ERR);
    DTEST_LOG << "BundleManagerInternalTest GetBundleIdFromBms_001 end "<< std::endl;
}

/**
 * @tc.name: GetBundleIdFromBms_002
 * @tc.desc: test get accessTokenId from bms
 * @tc.type: FUNC
 */
HWTEST_F(BundleManagerInternalTest, GetBundleIdFromBms_002, TestSize.Level3)
{
    DTEST_LOG << "BundleManagerInternalTest GetBundleIdFromBms_002 begin" << std::endl;
    const std::string bundleName = "com.ohos.mms";
    uint32_t accessTokenId;
    BundleManagerInternal::GetDistributedBundleManager();
    int32_t ret = BundleManagerInternal::GetBundleIdFromBms(bundleName, accessTokenId);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "BundleManagerInternalTest GetBundleIdFromBms_002 end "<< std::endl;
}
}
}