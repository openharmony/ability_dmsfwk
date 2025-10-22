/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#include "distributed_sched_test_util.h"
#include "distributed_sched_utils.h"
#include "dms_constant.h"
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
using namespace Constants;
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
const int API_VERSION = 9;
const int FA_MODULE_ALLOW_MIN_API_VERSION = 8;

const string MOCK_FIELD_GROUP_NAME = "MockName";
const string MOCK_FIELD_GROUP_ID = "MockId";
const string MOCK_FIELD_GROUP_OWNER = "MockOwner";
const int32_t MOCK_FIELD_GROUP_TYPE = 0;
const int32_t MOCK_FIELD_GROUP_VISIBILITY = 0;
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
    bundleMgrMock_ = std::make_shared<BundleManagerInternalMock>();
    BundleManagerInternalMock::bundleMgrMock = bundleMgrMock_;
    storageMock_ = std::make_shared<DtbschedmgrDeviceInfoStorageMock>();
    DtbschedmgrDeviceInfoStorageMock::storageMock = storageMock_;
    adapter_ = std::make_shared<DistributedSchedAdapterMock>();
    DistributedSchedAdapterMock::adapter = adapter_;
    netAdapter_ = std::make_shared<DnetworkAdapterMock>();
    DnetworkAdapterMock::netAdapter = netAdapter_;
}

void DistributedSchedPermissionTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedSchedPermissionTest::TearDownTestCase" << std::endl;
    BundleManagerInternalMock::bundleMgrMock = nullptr;
    bundleMgrMock_ = nullptr;
    DtbschedmgrDeviceInfoStorageMock::storageMock = nullptr;
    storageMock_ = nullptr;
    DistributedSchedAdapterMock::adapter = nullptr;
    adapter_ = nullptr;
    DnetworkAdapterMock::netAdapter = nullptr;
    netAdapter_ = nullptr;
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
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_)).WillRepeatedly(Return(false));
    int32_t ret = DistributedSchedPermission::GetInstance().CheckSendResultPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_EQ(ret, DMS_ACCOUNT_ACCESS_PERMISSION_DENIED);
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
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_002 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = false;
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*adapter_, CheckAccessToGroup(_, _)).WillRepeatedly(Return(true));
    int32_t ret = DistributedSchedPermission::GetInstance().CheckSendResultPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_EQ(ret, DMS_COMPONENT_ACCESS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckSendResultPermission_003
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSendResultPermission_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_003 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckSendResultPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSendResultPermission_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_001
 * @tc.desc: call CheckCustomPermission with no permissions
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_001 begin" << std::endl;
    const AAFwk::Want want;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(want, targetAbility, callerInfo);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_002
 * @tc.desc: call CheckCustomPermission with no permissions and invalid accessToken
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_002 begin" << std::endl;
    const AAFwk::Want want;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(want, targetAbility, callerInfo);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_003
 * @tc.desc: call CheckCustomPermission with invalid permissions
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_003 begin" << std::endl;
    const AAFwk::Want want;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.emplace_back(INVALID_PERMISSION_NAME);
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(want, targetAbility, callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_003 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_004
 * @tc.desc: call CheckCustomPermission with invalid permissions and invalid accessToken
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_004 begin" << std::endl;
    const AAFwk::Want want;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.emplace_back(INVALID_PERMISSION_NAME);
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(want, targetAbility, callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_004 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_005
 * @tc.desc: call CheckCustomPermission with correct permissions
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_005, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_005 begin" << std::endl;
    const AAFwk::Want want;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.emplace_back(PERMISSION_NAME);
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(want, targetAbility, callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_005 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_006
 * @tc.desc: call CheckCustomPermission with correct permissions and invalid accessToken
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_006, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_006 begin" << std::endl;
    const AAFwk::Want want;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.emplace_back(PERMISSION_NAME);
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(want, targetAbility, callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_006 end result:" << ret << std::endl;
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
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_)).WillRepeatedly(Return(false));
    int32_t ret = DistributedSchedPermission::GetInstance().CheckStartPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_EQ(ret, DMS_ACCOUNT_ACCESS_PERMISSION_DENIED);
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
    want.SetFlags(AAFwk::Want::FLAG_ABILITY_CONTINUATION);
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*adapter_, CheckAccessToGroup(_, _)).WillRepeatedly(Return(true));
    int32_t ret = DistributedSchedPermission::GetInstance().CheckStartPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_EQ(ret, DMS_START_CONTROL_PERMISSION_DENIED);
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
    want.SetFlags(AAFwk::Want::FLAG_ABILITY_CONTINUATION);
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckStartPermission(want,
        callerInfo, accountInfo, targetAbility, false);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckStartPermission_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckCollabStartPermission_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCollabStartPermission_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCollabStartPermission_001 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_)).WillRepeatedly(Return(false));
    int32_t ret = DistributedSchedPermission::GetInstance().CheckCollabStartPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_EQ(ret, DMS_ACCOUNT_ACCESS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCollabStartPermission_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckCollabStartPermission_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCollabStartPermission_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCollabStartPermission_002 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*bundleMgrMock_, IsSameAppId(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*adapter_, CheckAccessToGroup(_, _)).WillRepeatedly(Return(true));
    int32_t ret = DistributedSchedPermission::GetInstance().CheckCollabStartPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_EQ(ret, DMS_START_CONTROL_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCollabStartPermission_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckCollabStartPermission_003
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCollabStartPermission_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCollabStartPermission_003 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_)).WillRepeatedly(Return(true));
    EXPECT_CALL(*bundleMgrMock_, IsSameAppId(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*adapter_, CheckAccessToGroup(_, _)).WillRepeatedly(Return(true));
    int32_t ret = DistributedSchedPermission::GetInstance().CheckCollabStartPermission(want,
        callerInfo, accountInfo, targetAbility);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCollabStartPermission_003 end ret:" << ret << std::endl;
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
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_)).WillRepeatedly(Return(false));
    int32_t ret = DistributedSchedPermission::GetInstance().CheckGetCallerPermission(want, callerInfo, accountInfo,
        targetAbility);
    EXPECT_EQ(ret, DMS_ACCOUNT_ACCESS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckGetCallerPermission_001 end ret:" << ret << std::endl;
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
    EXPECT_CALL(*netAdapter_, GetUdidByNetworkId(_)).WillOnce(Return(""));
    int32_t ret = DistributedSchedPermission::GetInstance().GetAccountInfo(
        remoteNetworkId, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedPermissionTest GetAccountInfo_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: GetAccountInfo_003
 * @tc.desc: call GetAccountInfo with invalid networkId
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, GetAccountInfo_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetAccountInfo_003 begin" << std::endl;
    std::string remoteNetworkId = "0";
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    EXPECT_CALL(*netAdapter_, GetUdidByNetworkId(_)).WillOnce(Return("udid"));
    int32_t ret = DistributedSchedPermission::GetInstance().GetAccountInfo(
        remoteNetworkId, callerInfo, accountInfo);
    EXPECT_NE(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedPermissionTest GetAccountInfo_003 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckDeviceSecurityLevel_001
 * @tc.desc: call CheckDeviceSecurityLevel
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDeviceSecurityLevel_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDeviceSecurityLevel_001 begin" << std::endl;
    std::string srcDeviceId;
    std::string dstDeviceId;
    EXPECT_CALL(*netAdapter_, GetUdidByNetworkId(_)).WillOnce(Return(""));
    bool ret = DistributedSchedPermission::GetInstance().CheckDeviceSecurityLevel(
        srcDeviceId, dstDeviceId);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDeviceSecurityLevel_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckDeviceSecurityLevel_002
 * @tc.desc: call CheckDeviceSecurityLevel
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDeviceSecurityLevel_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDeviceSecurityLevel_002 begin" << std::endl;
    std::string srcDeviceId;
    std::string dstDeviceId;
    EXPECT_CALL(*netAdapter_, GetUdidByNetworkId(_)).WillOnce(Return("srcudid")).WillOnce(Return(""));
    bool ret = DistributedSchedPermission::GetInstance().CheckDeviceSecurityLevel(
        srcDeviceId, dstDeviceId);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDeviceSecurityLevel_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckDeviceSecurityLevel_003
 * @tc.desc: call CheckDeviceSecurityLevel
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDeviceSecurityLevel_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDeviceSecurityLevel_003 begin" << std::endl;
    std::string srcDeviceId;
    std::string dstDeviceId;
    EXPECT_CALL(*netAdapter_, GetUdidByNetworkId(_)).WillOnce(Return("srcudid")).WillRepeatedly(Return("dstUdid"));
    bool ret = DistributedSchedPermission::GetInstance().CheckDeviceSecurityLevel(
        srcDeviceId, dstDeviceId);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDeviceSecurityLevel_003 end result:" << ret << std::endl;
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
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_)).WillRepeatedly(Return(false));
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
    ASSERT_NE(true, jsonObject.is_discarded());
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
    ASSERT_NE(true, jsonObject.is_discarded());
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
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_)).WillRepeatedly(Return(false));
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
    AAFwk::Want want;
    want.AddFlags(want.FLAG_AUTH_READ_URI_PERMISSION);
    want.SetUri("file://com.ohos.mms/data/test_B");
    const std::string bundleName = "com.ohos.mms";
    uint16_t bundleNameId = 0;
    BundleManagerInternal::GetBundleNameId(bundleName, bundleNameId);
    DistributedSchedPermission::GetInstance().MarkUriPermission(want, bundleNameId);
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = INVALID_GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = INVALID_BUNDLE_NAME;
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_)).WillRepeatedly(Return(false));
    int32_t ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
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

/**
 * @tc.name: IsHigherAclVersion_001
 * @tc.desc: call IsHigherAclVersion
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, IsHigherAclVersion_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest IsHigherAclVersion_001 begin" << std::endl;
    CallerInfo callerInfo;
    bool ret = DistributedSchedPermission::GetInstance().IsHigherAclVersion(callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest IsHigherAclVersion_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: IsHigherAclVersion_002
 * @tc.desc: call IsHigherAclVersion
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, IsHigherAclVersion_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest IsHigherAclVersion_002 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    bool ret = DistributedSchedPermission::GetInstance().IsHigherAclVersion(callerInfo);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest IsHigherAclVersion_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: IsHigherAclVersion_003
 * @tc.desc: call IsHigherAclVersion
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, IsHigherAclVersion_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest IsHigherAclVersion_003 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.extraInfoJson[DMS_VERSION_ID] = "500";
    bool ret = DistributedSchedPermission::GetInstance().IsHigherAclVersion(callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest IsHigherAclVersion_003 end result:" << ret << std::endl;
}

/**
 * @tc.name: IsHigherAclVersion_004
 * @tc.desc: call IsHigherAclVersion
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, IsHigherAclVersion_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest IsHigherAclVersion_004 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.extraInfoJson[DMS_VERSION_ID] = "5.1.0";
    bool ret = DistributedSchedPermission::GetInstance().IsHigherAclVersion(callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest IsHigherAclVersion_004 end result:" << ret << std::endl;
}

/**
 * @tc.name: IsHigherAclVersion_005
 * @tc.desc: call IsHigherAclVersion
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, IsHigherAclVersion_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest IsHigherAclVersion_005 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.extraInfoJson[DMS_VERSION_ID] = 0;
    bool ret = DistributedSchedPermission::GetInstance().IsHigherAclVersion(callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest IsHigherAclVersion_005 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckNewAclList_001
 * @tc.desc: call CheckNewAclList
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckNewAclList_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckNewAclList_001 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckNewAclList(dstNetworkId,
        dmsAccountInfo, callerInfo, true);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckNewAclList_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckNewAclList_002
 * @tc.desc: call CheckNewAclList
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckNewAclList_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckNewAclList_002 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckNewAclList(dstNetworkId,
        dmsAccountInfo, callerInfo, false);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckNewAclList_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckLowVersionAclList_001
 * @tc.desc: call CheckLowVersionAclList
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckLowVersionAclList_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckLowVersionAclList_001 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckLowVersionAclList(dstNetworkId,
        dmsAccountInfo, callerInfo, true);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckLowVersionAclList_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckLowVersionAclList_002
 * @tc.desc: call CheckLowVersionAclList
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckLowVersionAclList_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckLowVersionAclList_002 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckLowVersionAclList(dstNetworkId,
        dmsAccountInfo, callerInfo, false);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckLowVersionAclList_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckAclList_001
 * @tc.desc: call CheckAclList
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckAclList_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckAclList_001 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckAclList(dstNetworkId,
        dmsAccountInfo, callerInfo, true);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckAclList_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckAclList_002
 * @tc.desc: call CheckAclList
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckAclList_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckAclList_002 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckAclList(dstNetworkId,
        dmsAccountInfo, callerInfo, false);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckAclList_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckDstSameAccount_001
 * @tc.desc: call CheckDstSameAccount
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDstSameAccount_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDstSameAccount_001 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckDstSameAccount(dstNetworkId,
        dmsAccountInfo, callerInfo, true);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDstSameAccount_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckDstSameAccount_002
 * @tc.desc: call CheckDstSameAccount
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDstSameAccount_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDstSameAccount_002 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckDstSameAccount(dstNetworkId,
        dmsAccountInfo, callerInfo, false);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDstSameAccount_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckLowVersionSameAccount_001
 * @tc.desc: call CheckLowVersionSameAccount
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckLowVersionSameAccount_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckLowVersionSameAccount_001 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckLowVersionSameAccount(dstNetworkId,
        dmsAccountInfo, callerInfo, true);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckLowVersionSameAccount_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckLowVersionSameAccount_002
 * @tc.desc: call CheckLowVersionSameAccount
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckLowVersionSameAccount_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckLowVersionSameAccount_002 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckLowVersionSameAccount(dstNetworkId,
        dmsAccountInfo, callerInfo, false);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckLowVersionSameAccount_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckSameAccount_001
 * @tc.desc: call CheckSameAccount
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSameAccount_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSameAccount_001 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckSameAccount(dstNetworkId,
        dmsAccountInfo, callerInfo, true);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSameAccount_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckSameAccount_002
 * @tc.desc: call CheckSameAccount
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSameAccount_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSameAccount_002 begin" << std::endl;
    std::string dstNetworkId;
    IDistributedSched::AccountInfo dmsAccountInfo;
    CallerInfo callerInfo;
    DistributedSchedPermission::GetInstance().GetOsAccountData(dmsAccountInfo);
    bool ret = DistributedSchedPermission::GetInstance().CheckSameAccount(dstNetworkId,
        dmsAccountInfo, callerInfo, false);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSameAccount_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckSrcBackgroundPermission_001
 * @tc.desc: call CheckSrcBackgroundPermission
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckSrcBackgroundPermission_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckSrcBackgroundPermission_001 begin" << std::endl;
    uint32_t accessTokenId = 0;
    bool ret = DistributedSchedPermission::GetInstance().CheckSrcBackgroundPermission(accessTokenId);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckSrcBackgroundPermission_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: RemoveRemoteObjectFromWant_001
 * @tc.desc: call RemoveRemoteObjectFromWant
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, RemoveRemoteObjectFromWant_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest RemoveRemoteObjectFromWant_001 begin" << std::endl;
    EXPECT_NO_FATAL_FAILURE(DistributedSchedPermission::GetInstance().RemoveRemoteObjectFromWant(nullptr));
    DTEST_LOG << "DistributedSchedPermissionTest RemoveRemoteObjectFromWant_001 end" << std::endl;
}

/**
 * @tc.name: CheckPermissionAll_001
 * @tc.desc: call CheckPermissionAll_001
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckPermissionAll_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermissionAll_001 begin" << std::endl;
    uint32_t accessToken = 0;
    std::string permissionName;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckPermissionAll(accessToken, permissionName);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermissionAll_001 end" << std::endl;
}

/**
 * @tc.name: CheckCollaborateStartCtrlPer_001
 * @tc.desc: call CheckCollaborateStartCtrlPer
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCollaborateStartCtrlPer_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCollaborateStartCtrlPer_001 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    AAFwk::Want want;
    bool ret = DistributedSchedPermission::GetInstance().CheckCollaborateStartCtrlPer(targetAbility,
        callerInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCollaborateStartCtrlPer_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
