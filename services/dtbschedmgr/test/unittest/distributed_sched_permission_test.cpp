/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include "distributed_sched_permission_test.h"

#include "accesstoken_kit.h"
#include "adapter/dnetwork_adapter.h"
#include "bundle/bundle_manager_internal.h"
#include "distributed_sched_interface.h"
#define private public
#include "distributed_sched_permission.h"
#undef private
#include "distributed_sched_util.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "nativetoken_kit.h"
#include "test_log.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DistributedHardware;
using namespace OHOS::Security::AccessToken;

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr uint32_t ACCESS_TOKEN = 100000000;
constexpr uint32_t INVALID_ACCESS_TOKEN = 0;
const string BUNDLE_NAME = "com.ohos.mms";
const string INVALID_BUNDLE_NAME = "";
const string PACKAGE_NAME = "com.ohos.mms";
const string ABILITY_NAME = "com.ohos.mms.MainAbility";
const string INVALID_ABILITY_NAME = "";
const string GROUP_ID = "TEST_GROUP_ID";
const string INVALID_GROUP_ID = "";
const string DEVICE_ID = "255.255.255.255";
const string INVALID_DEVICE_ID = "";
const string PERMISSION_NAME = "ohos.permission.DISTRIBUTED_DATASYNC";
const string INVALID_PERMISSION_NAME = "ohos.permission.TEST";
const string DMS_IS_CALLER_BACKGROUND = "dmsIsCallerBackGround";
const string DMS_API_VERSION = "dmsApiVersion";
const string DMS_MISSION_ID = "dmsMissionId";
const string DMS_VERSION_ID = "dmsVersion";
const string DMS_VERSION = "4.0.0";
const int API_VERSION = 9;
const int FA_MODULE_ALLOW_MIN_API_VERSION = 8;

const string MOCK_FIELD_GROUP_NAME = "MockName";
const string MOCK_FIELD_GROUP_ID = "MockId";
const string MOCK_FIELD_GROUP_OWNER = "MockOwner";
const int32_t MOCK_FIELD_GROUP_TYPE = 0;
const int32_t MOCK_FIELD_GROUP_VISIBILITY = 0;
const string FIELD_GROUP_NAME = "groupName";
const string FIELD_GROUP_ID = "groupId";
const string FIELD_GROUP_OWNER = "groupOwner";
const string FIELD_GROUP_TYPE = "groupType";
const string FIELD_GROUP_VISIBILITY = "groupVisibility";
const char* FOUNDATION_PROCESS_NAME = "foundation";

void NativeTokenGet()
{
    uint32_t tokenId = AccessTokenKit::GetNativeTokenId("token_sync_service");
    ASSERT_NE(tokenId, 0);
    SetSelfTokenID(tokenId);
}
}

void DistributedSchedPermissionTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedSchedPermissionTest::SetUpTestCase" << std::endl;
    const std::string pkgName = "DBinderBus_PermissionTest" + std::to_string(getprocpid());
    std::shared_ptr<DmInitCallback> initCallback_ = std::make_shared<DeviceInitCallBack>();
    DeviceManager::GetInstance().InitDeviceManager(pkgName, initCallback_);
}

void DistributedSchedPermissionTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedSchedPermissionTest::TearDownTestCase" << std::endl;
}

void DistributedSchedPermissionTest::TearDown()
{
    DTEST_LOG << "DistributedSchedPermissionTest::TearDown" << std::endl;
}

void DistributedSchedPermissionTest::SetUp()
{
    DTEST_LOG << "DistributedSchedPermissionTest::SetUp" << std::endl;
    DistributedSchedUtil::MockPermission();
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(deviceId_);

    NativeTokenGet();
}

void DistributedSchedPermissionTest::DeviceInitCallBack::OnRemoteDied()
{
}

/**
 * @tc.name: CheckSendResultPermission_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSendResultPermission_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_001 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckSendResultPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckSendResultPermission_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSendResultPermission_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckSendResultPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckSendResultPermission_005
 * @tc.desc: call CheckDPermission with illegal parameter
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSendResultPermission_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_005 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    std::string localDeviceId = DEVICE_ID;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckSendResultPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_005 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckSendResultPermission_006
 * @tc.desc: call CheckDPermission with different account type
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSendResultPermission_006, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_006 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    string localDeviceId = DEVICE_ID;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckSendResultPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_006 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckSendResultPermission_007
 * @tc.desc: call CheckDPermission with illegal ability info
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSendResultPermission_007, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_007 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    string localDeviceId = DEVICE_ID;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckSendResultPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_007 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckSendResultPermission_008
 * @tc.desc: call CheckDPermission with same account type
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSendResultPermission_008, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_008 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    string localDeviceId = DEVICE_ID;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckSendResultPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_008 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckSendResultPermission_009
 * @tc.desc: call CheckDPermission with illegal account info
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSendResultPermission_009, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_009 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string localDeviceId = DEVICE_ID;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckSendResultPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_009 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckSendResultPermission_010
 * @tc.desc: call CheckDPermission with illegal account info
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSendResultPermission_010, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_010 begin" << std::endl;
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string localDeviceId = DEVICE_ID;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckSendResultPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_010 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartPermission_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartPermission_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartPermission_001 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckStartPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartPermission_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartPermission_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartPermission_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartPermission_002 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckStartPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartPermission_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartPermission_003
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartPermission_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartPermission_003 begin" << std::endl;
    AAFwk::Want want;
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckStartPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartPermission_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartPermission_005
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartPermission_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartPermission_005 begin" << std::endl;
    AAFwk::Want want;
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.push_back(INVALID_PERMISSION_NAME);
    int32_t ret = DistributedSchedPermission::GetInstance().CheckStartPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartPermission_005 end ret:" << ret << std::endl;
}

/**
 * @tc.name: GetTargetAbility_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, GetTargetAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_001 begin" << std::endl;
    AAFwk::Want want;
    AppExecFwk::AbilityInfo targetAbility;
    bool ret = DistributedSchedPermission::GetInstance().GetTargetAbility(want, targetAbility, false);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: GetTargetAbility_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, GetTargetAbility_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_002 begin" << std::endl;
    DistributedSchedUtil::MockBundlePermission();
    AAFwk::Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);
    AppExecFwk::AbilityInfo targetAbility;
    bool ret = DistributedSchedPermission::GetInstance().GetTargetAbility(want, targetAbility, false);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: GetTargetAbility_003
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, GetTargetAbility_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_003 begin" << std::endl;
    DistributedSchedUtil::MockBundlePermission();
    AAFwk::Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);
    want.SetParam(DMS_MISSION_ID, 0);
    AppExecFwk::AbilityInfo targetAbility;
    bool ret = DistributedSchedPermission::GetInstance().GetTargetAbility(want, targetAbility, false);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: GetTargetAbility_004
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, GetTargetAbility_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_004 begin" << std::endl;
    DistributedSchedUtil::MockBundlePermission();
    AAFwk::Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);
    AppExecFwk::AbilityInfo targetAbility;
    bool ret = DistributedSchedPermission::GetInstance().GetTargetAbility(want, targetAbility, true);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_004 end ret:" << ret << std::endl;
}

/**
 * @tc.name: GetTargetAbility_005
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, GetTargetAbility_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_005 begin" << std::endl;
    DistributedSchedUtil::MockBundlePermission();
    AAFwk::Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);
    want.SetParam(DMS_MISSION_ID, 8);
    AppExecFwk::AbilityInfo targetAbility;
    bool ret = DistributedSchedPermission::GetInstance().GetTargetAbility(want, targetAbility, true);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_005 end ret:" << ret << std::endl;
}

/**
 * @tc.name: GetTargetAbility_006
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, GetTargetAbility_006, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_006 begin" << std::endl;
    DistributedSchedUtil::MockBundlePermission();
    AAFwk::Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);
    want.SetParam(DMS_MISSION_ID, 8);
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.type = AppExecFwk::AbilityType::SERVICE;
    bool ret = DistributedSchedPermission::GetInstance().GetTargetAbility(want, targetAbility, true);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_006 end ret:" << ret << std::endl;
}

/**
 * @tc.name: GetTargetAbility_007
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, GetTargetAbility_007, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_007 begin" << std::endl;
    DistributedSchedUtil::MockBundlePermission();
    AAFwk::Want want;
    ElementName name;
    name.SetAbilityName(ABILITY_NAME);
    name.SetBundleName(BUNDLE_NAME);
    want.SetElement(name);
    want.SetParam(DMS_MISSION_ID, 8);
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.type = AppExecFwk::AbilityType::EXTENSION;
    bool ret = DistributedSchedPermission::GetInstance().GetTargetAbility(want, targetAbility, true);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest GetTargetAbility_007 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckGetCallerPermission_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckGetCallerPermission_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckGetCallerPermission_001 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckGetCallerPermission(want, callerInfo, accountInfo,
        targetAbility);
    EXPECT_EQ(ret, DMS_ACCOUNT_ACCESS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckGetCallerPermission_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_001 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    AAFwk::Want want;
    want.AddFlags(want.FLAG_ABILITY_CONTINUATION);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_002 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.bundleName = BUNDLE_NAME;
    CallerInfo callerInfo;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    AAFwk::Want want;
    want.AddFlags(want.FLAG_ABILITY_CONTINUATION);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_003
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_003 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    AAFwk::Want want;
    want.AddFlags(want.FLAG_ABILITY_CONTINUATION);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_004
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_004 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    AAFwk::Want want;
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_004 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_005
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_005 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    AAFwk::Want want;
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_005 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_006
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_006, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_006 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.bundleName = BUNDLE_NAME;
    CallerInfo callerInfo;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    AAFwk::Want want;
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_006 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_007
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_007, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_007 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    AAFwk::Want want;
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_007 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_008
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_008, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_008 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    targetAbility.isStageBasedModel = true;
    CallerInfo callerInfo;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    AAFwk::Want want;
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_008 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_009
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_009, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_009 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    targetAbility.type = AppExecFwk::AbilityType::PAGE;
    CallerInfo callerInfo;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    AAFwk::Want want;
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_009 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_010
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_010, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_010 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    targetAbility.type = AppExecFwk::AbilityType::SERVICE;
    CallerInfo callerInfo;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    AAFwk::Want want;
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_010 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_011
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_011, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_011 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    targetAbility.type = AppExecFwk::AbilityType::SERVICE;
    targetAbility.applicationInfo.associatedWakeUp = true;
    CallerInfo callerInfo;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    AAFwk::Want want;
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_011 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_012
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_012, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_012 begin" << std::endl;
    DistributedSchedUtil::MockBundlePermission();
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    targetAbility.type = AppExecFwk::AbilityType::SERVICE;
    targetAbility.applicationInfo.associatedWakeUp = true;
    targetAbility.bundleName = BUNDLE_NAME;
    CallerInfo callerInfo;
    EXPECT_EQ(ERR_OK, LoadContinueConfig());
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    AAFwk::Want want;
    want.AddFlags(want.FLAG_ABILITY_CONTINUATION);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_012 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_013
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_013, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_013 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    targetAbility.type = AppExecFwk::AbilityType::SERVICE;
    targetAbility.applicationInfo.associatedWakeUp = true;
    CallerInfo callerInfo;
    AAFwk::Want want;
    want.AddFlags(want.FLAG_ABILITY_CONTINUATION);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_013 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckStartControlPermission_014
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckStartControlPermission_014, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_014 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    targetAbility.type = AppExecFwk::AbilityType::SERVICE;
    targetAbility.applicationInfo.associatedWakeUp = true;
    CallerInfo callerInfo;
    AAFwk::Want want;
    want.AddFlags(want.FLAG_ABILITY_CONTINUATION);
    bool ret = DistributedSchedPermission::GetInstance().CheckStartControlPermission(targetAbility, callerInfo, want);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartControlPermission_014 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckBackgroundPermission_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckBackgroundPermission_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_001 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    AAFwk::Want want;
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    bool ret = DistributedSchedPermission::GetInstance().CheckBackgroundPermission(targetAbility, callerInfo, want,
        false);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckBackgroundPermission_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckBackgroundPermission_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_002 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    AAFwk::Want want;
    bool ret = DistributedSchedPermission::GetInstance().CheckBackgroundPermission(targetAbility, callerInfo, want,
        false);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckBackgroundPermission_003
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckBackgroundPermission_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_003 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.isStageBasedModel = true;
    CallerInfo callerInfo;
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    AAFwk::Want want;
    bool ret = DistributedSchedPermission::GetInstance().CheckBackgroundPermission(targetAbility, callerInfo, want,
        true);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckBackgroundPermission_004
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckBackgroundPermission_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_004 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.type = AppExecFwk::AbilityType::SERVICE;
    CallerInfo callerInfo;
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    AAFwk::Want want;
    want.SetParam(DMS_API_VERSION, FA_MODULE_ALLOW_MIN_API_VERSION);
    bool ret = DistributedSchedPermission::GetInstance().CheckBackgroundPermission(targetAbility, callerInfo, want,
        true);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_004 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckBackgroundPermission_005
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckBackgroundPermission_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_005 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    callerInfo.sourceDeviceId = "";
    callerInfo.accessToken = GetSelfTokenID();
    AAFwk::Want want;
    bool ret = DistributedSchedPermission::GetInstance().CheckBackgroundPermission(targetAbility, callerInfo, want,
        false);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_005 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckBackgroundPermission_006
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckBackgroundPermission_006, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_006 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    callerInfo.sourceDeviceId = deviceId_;
    uint64_t tokenId = GetSelfTokenID();
    callerInfo.accessToken = tokenId;
    AAFwk::Want want;
    bool ret = DistributedSchedPermission::GetInstance().CheckBackgroundPermission(targetAbility, callerInfo, want,
        false);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_006 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckBackgroundPermission_007
 * @tc.desc: check CheckTargetAbilityVisible
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckBackgroundPermission_007, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_007 begin" << std::endl;
    std::string udid = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(deviceId_);
    std::string deviceId = udid;
    AccessTokenKit::DeleteRemoteToken(deviceId, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.dms_test",
        .instIndex = 1,
        .appID = "dmstest",
        .deviceID = udid,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .permissionName = "ohos.permission.START_INVISIBLE_ABILITY",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED}, // first grant
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int result = AccessTokenKit::SetRemoteHapTokenInfo(deviceId, remoteTokenInfo);
    ASSERT_EQ(result, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(deviceId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    callerInfo.sourceDeviceId = deviceId_;
    callerInfo.accessToken = 0x20100000;
    AAFwk::Want want;
    bool ret = DistributedSchedPermission::GetInstance().CheckBackgroundPermission(targetAbility, callerInfo, want,
        false);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckBackgroundPermission_007 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckMinApiVersion_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckMinApiVersion_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckMinApiVersion_001 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.isStageBasedModel = true;
    bool ret = DistributedSchedPermission::GetInstance().CheckMinApiVersion(targetAbility, API_VERSION);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckMinApiVersion_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckMinApiVersion_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckMinApiVersion_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckMinApiVersion_002 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.type = AppExecFwk::AbilityType::PAGE;
    bool ret = DistributedSchedPermission::GetInstance().CheckMinApiVersion(targetAbility, API_VERSION);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckMinApiVersion_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckMinApiVersion_003
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckMinApiVersion_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckMinApiVersion_003 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.type = AppExecFwk::AbilityType::SERVICE;
    bool ret = DistributedSchedPermission::GetInstance().CheckMinApiVersion(targetAbility, API_VERSION);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckMinApiVersion_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckMinApiVersion_004
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckMinApiVersion_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckMinApiVersion_004 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.type = AppExecFwk::AbilityType::SERVICE;
    bool ret = DistributedSchedPermission::GetInstance().CheckMinApiVersion(targetAbility,
        FA_MODULE_ALLOW_MIN_API_VERSION);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckMinApiVersion_004 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckTargetAbilityVisible_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckTargetAbilityVisible_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckTargetAbilityVisible_001 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    CallerInfo callerInfo;
    bool ret = DistributedSchedPermission::GetInstance().CheckTargetAbilityVisible(targetAbility, callerInfo);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckTargetAbilityVisible_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckTargetAbilityVisible_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckTargetAbilityVisible_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckTargetAbilityVisible_002 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = "";
    callerInfo.accessToken = GetSelfTokenID();
    bool ret = DistributedSchedPermission::GetInstance().CheckTargetAbilityVisible(targetAbility, callerInfo);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckTargetAbilityVisible_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckTargetAbilityVisible_003
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckTargetAbilityVisible_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckTargetAbilityVisible_003 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = "deviceId_";
    callerInfo.accessToken = GetSelfTokenID();
    bool ret = DistributedSchedPermission::GetInstance().CheckTargetAbilityVisible(targetAbility, callerInfo);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckTargetAbilityVisible_003 end ret:" << ret << std::endl;
}

#ifdef TOKEN_SYNC_ENABLE
/**
 * @tc.name: CheckTargetAbilityVisible_004
 * @tc.desc: check CheckTargetAbilityVisible
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckTargetAbilityVisible_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckTargetAbilityVisible_004 begin" << std::endl;
    std::string udid = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(deviceId_);
    std::string deviceId = udid;
    AccessTokenKit::DeleteRemoteToken(deviceId, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.dms_test",
        .instIndex = 1,
        .appID = "dmstest",
        .deviceID = udid,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .permissionName = "ohos.permission.START_INVISIBLE_ABILITY",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_GRANTED}, // first grant
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int result = AccessTokenKit::SetRemoteHapTokenInfo(deviceId, remoteTokenInfo);
    ASSERT_EQ(result, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(deviceId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = deviceId_;
    callerInfo.accessToken = 0x20100000;
    bool ret = DistributedSchedPermission::GetInstance().CheckTargetAbilityVisible(targetAbility, callerInfo);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckTargetAbilityVisible_004 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckTargetAbilityVisible_005
 * @tc.desc: check CheckTargetAbilityVisible
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckTargetAbilityVisible_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckTargetAbilityVisible_005 begin" << std::endl;
    std::string udid = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(deviceId_);
    std::string deviceId = udid;
    AccessTokenKit::DeleteRemoteToken(deviceId, 0x20100000);
    HapTokenInfo baseInfo = {
        .apl = APL_NORMAL,
        .ver = 1,
        .userID = 1,
        .bundleName = "com.ohos.dms_test",
        .instIndex = 1,
        .appID = "dmstest",
        .deviceID = udid,
        .tokenID = 0x20100000,
        .tokenAttr = 0
    };

    PermissionStateFull infoManagerTestState = {
        .permissionName = "ohos.permission.START_INVISIBLE_ABILITY",
        .isGeneral = true,
        .resDeviceID = {"local"},
        .grantStatus = {PermissionState::PERMISSION_DENIED},
        .grantFlags = {PermissionFlag::PERMISSION_SYSTEM_FIXED}};
    std::vector<PermissionStateFull> permStateList;
    permStateList.emplace_back(infoManagerTestState);

    HapTokenInfoForSync remoteTokenInfo = {
        .baseInfo = baseInfo,
        .permStateList = permStateList
    };

    int result = AccessTokenKit::SetRemoteHapTokenInfo(deviceId, remoteTokenInfo);
    ASSERT_EQ(result, RET_SUCCESS);

    // Get local map token ID
    AccessTokenID mapID = AccessTokenKit::AllocLocalTokenID(deviceId_, 0x20100000);
    ASSERT_NE(mapID, 0);

    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = deviceId_;
    callerInfo.accessToken = 0x20100000;
    bool ret = DistributedSchedPermission::GetInstance().CheckTargetAbilityVisible(targetAbility, callerInfo);
    EXPECT_FALSE(ret);
    DTEST_LOG << "DistributedSchedPermissionTest CheckTargetAbilityVisible_005 end ret:" << ret << std::endl;
}
#endif

/**
 * @tc.name: GetAccountInfo_001
 * @tc.desc: call GetAccountInfo with empty networkId
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, GetAccountInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetAccountInfo_001 begin" << std::endl;
    std::string remoteNetworkId;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t ret = DistributedSchedPermission::GetInstance().GetAccountInfo(
        remoteNetworkId, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedPermissionTest GetAccountInfo_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: GetAccountInfo_002
 * @tc.desc: call GetAccountInfo with invalid networkId
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, GetAccountInfo_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetAccountInfo_002 begin" << std::endl;
    std::string remoteNetworkId = "0";
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t ret = DistributedSchedPermission::GetInstance().GetAccountInfo(
        remoteNetworkId, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedPermissionTest GetAccountInfo_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: GetRelatedGroups_001
 * @tc.desc: call GetRelatedGroups with empty bundleNames
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, GetRelatedGroups_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_001 begin" << std::endl;
    std::string udid;
    std::vector<std::string> bundleNames;
    IDistributedSched::AccountInfo accountInfo;
    bool ret = DistributedSchedPermission::GetInstance().GetRelatedGroups(
        udid, bundleNames, accountInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: GetRelatedGroups_002
 * @tc.desc: call GetRelatedGroups with invalid bundleNames
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, GetRelatedGroups_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_002 begin" << std::endl;
    std::string udid = "0";
    std::vector<std::string> bundleNames = {"mock.bundle1", "mock.bundle2"};
    IDistributedSched::AccountInfo accountInfo;
    bool ret = DistributedSchedPermission::GetInstance().GetRelatedGroups(
        udid, bundleNames, accountInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: ParseGroupInfos_001
 * @tc.desc: call ParseGroupInfos with empty returnGroupStr
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, ParseGroupInfos_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest ParseGroupInfos_001 begin" << std::endl;
    std::string returnGroupStr;
    std::vector<GroupInfo> groupInfos;
    bool ret = DistributedSchedPermission::GetInstance().ParseGroupInfos(
        returnGroupStr, groupInfos);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: ParseGroupInfos_002
 * @tc.desc: call ParseGroupInfos with invalid returnGroupStr
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, ParseGroupInfos_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest ParseGroupInfos_002 begin" << std::endl;
    std::string returnGroupStr = "mockInvalidGroup";
    std::vector<GroupInfo> groupInfos;
    bool ret = DistributedSchedPermission::GetInstance().ParseGroupInfos(
        returnGroupStr, groupInfos);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: ParseGroupInfos_003
 * @tc.desc: call ParseGroupInfos
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, ParseGroupInfos_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest ParseGroupInfos_003 begin" << std::endl;
    std::string returnGroupStr = "[{\"groupName\":\"mockGroupName\",\"groupId\":\"mockGroupId\",";
    returnGroupStr += "\"groupOwner\":\"mockGroupOwner\",\"groupType\":0,\"groupVisibility\":0}]";
    std::vector<GroupInfo> groupInfos;
    bool ret = DistributedSchedPermission::GetInstance().ParseGroupInfos(
        returnGroupStr, groupInfos);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_003 end result:" << ret << std::endl;
}

/**
 * @tc.name: IsFoundationCall_001
 * @tc.desc: call IsFoundationCall not from foundation
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, IsFoundationCall_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest IsFoundationCall_001 begin" << std::endl;
    bool ret = DistributedSchedPermission::GetInstance().IsFoundationCall();
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest IsFoundationCall_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: IsFoundationCall_002
 * @tc.desc: call IsFoundationCall from foundation
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, IsFoundationCall_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest IsFoundationCall_002 begin" << std::endl;
    DistributedSchedUtil::MockProcess(FOUNDATION_PROCESS_NAME);
    bool ret = DistributedSchedPermission::GetInstance().IsFoundationCall();
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest IsFoundationCall_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckAccountAccessPermission_001
 * @tc.desc: call CheckAccountAccessPermission in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckAccountAccessPermission_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_001 begin" << std::endl;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    string targetBundle = BUNDLE_NAME;
    bool ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_001
 * @tc.desc: call CheckComponentAccessPermission in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_001 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_002
 * @tc.desc: call CheckComponentAccessPermission with invalid accessToken in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_002 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_003
 * @tc.desc: call CheckComponentAccessPermission with invalid groupId in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_003 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = INVALID_GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_003 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_004
 * @tc.desc: call CheckComponentAccessPermission with invalid bundleName in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_004 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", INVALID_BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_004 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_005
 * @tc.desc: call CheckComponentAccessPermission with invalid abilityName in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_005, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_005 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_005 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_006
 * @tc.desc: call CheckComponentAccessPermission with visible: true in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_006, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_006 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_006 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_007
 * @tc.desc: call CheckComponentAccessPermission with visible: false in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_007, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_007 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = false;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_007 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_008
 * @tc.desc: call CheckComponentAccessPermission in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_008, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_008 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_008 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_009
 * @tc.desc: call CheckComponentAccessPermission with invalid accessToken in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_009, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_009 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_009 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_010
 * @tc.desc: call CheckComponentAccessPermission with invalid groupId in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_010, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_010 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = INVALID_GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_010 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_011
 * @tc.desc: call CheckComponentAccessPermission with invalid bundleName in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_011, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_011 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", INVALID_BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_011 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_012
 * @tc.desc: call CheckComponentAccessPermission with invalid abilityName in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_012, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_012 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_012 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_013
 * @tc.desc: call CheckComponentAccessPermission with visible: true in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_013, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_013 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_013 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_014
 * @tc.desc: call CheckComponentAccessPermission with visible: false in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_014, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_014 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = false;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_014 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckPermission_001
 * @tc.desc: call CheckPermission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckPermission_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_001 begin" << std::endl;
    uint32_t accessToken = ACCESS_TOKEN;
    string permissionName = PERMISSION_NAME;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckPermission(accessToken, permissionName);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckPermission_002
 * @tc.desc: call CheckPermission with invalid accessToken
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckPermission_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_002 begin" << std::endl;
    uint32_t accessToken = INVALID_ACCESS_TOKEN;
    string permissionName = PERMISSION_NAME;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckPermission(accessToken, permissionName);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckPermission_003
 * @tc.desc: call CheckPermission with invalid permission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckPermission_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_003 begin" << std::endl;
    uint32_t accessToken = INVALID_ACCESS_TOKEN;
    string permissionName = PERMISSION_NAME;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckPermission(accessToken, permissionName);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_003 end result:" << ret << std::endl;
}

/**
 * @tc.name: from_json_001
 * @tc.desc: parse groupInfo from json
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, FromJson_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest FromJson_001 begin" << std::endl;
    GroupInfo groupInfo;
    nlohmann::json jsonObject = nlohmann::json {
        {FIELD_GROUP_NAME, MOCK_FIELD_GROUP_NAME},
        {FIELD_GROUP_ID, MOCK_FIELD_GROUP_ID},
        {FIELD_GROUP_OWNER, MOCK_FIELD_GROUP_OWNER},
        {FIELD_GROUP_TYPE, MOCK_FIELD_GROUP_TYPE},
        {FIELD_GROUP_VISIBILITY, MOCK_FIELD_GROUP_VISIBILITY}
    };
    if (jsonObject.is_discarded()) {
        return;
    }
    from_json(jsonObject, groupInfo);
    EXPECT_EQ(groupInfo.groupName, MOCK_FIELD_GROUP_NAME);
    DTEST_LOG << "DistributedSchedPermissionTest FromJson_001 end" <<  std::endl;
}

/**
 * @tc.name: from_json_002
 * @tc.desc: parse groupInfo from json with invalid params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, FromJson_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest FromJson_002 begin" << std::endl;
    GroupInfo groupInfo;
    nlohmann::json jsonObject;
    if (jsonObject.is_discarded()) {
        return;
    }
    from_json(jsonObject, groupInfo);
    EXPECT_EQ(groupInfo.groupName, "");
    DTEST_LOG << "DistributedSchedPermissionTest FromJson_002 end " <<  std::endl;
}

/**
 * @tc.name: MarkUriPermission_001
 * @tc.desc: parse groupInfo from json with invalid params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, MarkUriPermission_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest MarkUriPermission_001 begin" << std::endl;
    AAFwk::Want want;
    want.AddFlags(want.FLAG_AUTH_READ_URI_PERMISSION);
    want.SetUri("file://ohos.dms.ets/data/test_B");
    DistributedSchedPermission::GetInstance().MarkUriPermission(want, 0);
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = INVALID_GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = INVALID_BUNDLE_NAME;
    bool ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest MarkUriPermission_001 end " <<  std::endl;
}

/**
 * @tc.name: MarkUriPermission_002
 * @tc.desc: parse groupInfo from json with invalid params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, MarkUriPermission_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest MarkUriPermission_002 begin" << std::endl;
    AAFwk::Want want;
    want.AddFlags(want.FLAG_AUTH_READ_URI_PERMISSION);
    want.SetUri("file://com.ohos.mms/data/test_B");
    DistributedSchedPermission::GetInstance().MarkUriPermission(want, 0);
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = INVALID_GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = INVALID_BUNDLE_NAME;
    bool ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest MarkUriPermission_002 end " <<  std::endl;
}

/**
 * @tc.name: MarkUriPermission_003
 * @tc.desc: parse groupInfo from json with invalid params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, MarkUriPermission_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest MarkUriPermission_003 begin" << std::endl;
    DistributedSchedUtil::MockBundlePermission();
    AAFwk::Want want;
    want.AddFlags(want.FLAG_AUTH_READ_URI_PERMISSION);
    want.SetUri("file://com.ohos.mms/data/test_B");
    const std::string bundleName = "com.ohos.mms";
    uint16_t accessTokenId = 0;
    int32_t ret = BundleManagerInternal::GetBundleNameId(bundleName, accessTokenId);
    EXPECT_EQ(ret, CAN_NOT_FOUND_ABILITY_ERR);
    DistributedSchedPermission::GetInstance().MarkUriPermission(want, accessTokenId);
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = INVALID_GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = INVALID_BUNDLE_NAME;
    ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest MarkUriPermission_003 end " <<  std::endl;
}

/**
 * @tc.name: GetDeviceSecurityLevel_001
 * @tc.desc: parse groupInfo from json with invalid params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, GetDeviceSecurityLevel_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetDeviceSecurityLevel_001 begin" << std::endl;
    string udid = "123456";
    int32_t ret = DistributedSchedPermission::GetInstance().GetDeviceSecurityLevel(udid);
    EXPECT_NE(ret, 0);
    DTEST_LOG << "DistributedSchedPermissionTest GetDeviceSecurityLevel_001 end " <<  std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS