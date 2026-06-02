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
#include <gmock/gmock.h>

#define private public
#include "intent_permission_checker.h"
#undef private

#include "distributed_sched_permission_mock.h"
#include "dtbschedmgr_device_info_storage_mock.h"
#include "bundle_manager_internal_mock.h"
#include "access_token_kit_mock.h"
#include "os_account_manager_mock.h"
#include "ohos_account_kits_mock.h"
#include "device_manager_mock.h"
#include "../mock/dnetwork_adapter_mock.h"
#include "remote_intent_manager.h"
#include "test_log.h"
#include "want.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
#define DMSFWK_SAME_ACCOUNT

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string LOCAL_DEVICE_ID = "local_device_id_12345";
const std::string REMOTE_DEVICE_ID = "remote_device_id_67890";
const std::string SRC_DEVICE_ID = "src_device_id_11111";
const std::string EMPTY_STRING;
const int32_t ERR_OK = 0;
const int32_t ERR_FAIL = -1;
constexpr int32_t TEST_CALLER_UID = 1000;
constexpr uint64_t TEST_INVALID_ACCESS_TOKEN = 0;
constexpr uint32_t TEST_ACCESS_TOKEN = 200;
constexpr uint32_t TEST_SPECIFY_TOKEN_ID = 300;
constexpr uint64_t TEST_D_ACCESS_TOKEN = 400;
const std::string BUNDLE_NAME = "com.test.bundle";
const std::string ABILITY_NAME = "MainAbility";
const std::string PERMISSION = "ohos.permission.EXECUTE_INSIGHT_INTENT";
}

struct PermissionCheckerMocks {
    std::shared_ptr<DtbschedmgrDeviceInfoStorageMock> deviceInfoMock;
    std::shared_ptr<AppExecFwk::BundleManagerInternalMock> bundleMock;
    std::shared_ptr<Security::AccessToken::AccessTokenKitMock> tokenMock;
    std::shared_ptr<DnetworkAdapterMock> networkMock;
    std::shared_ptr<AccountSA::OsAccountManagerMock> osAccountMock;
    std::shared_ptr<AccountSA::OhosAccountKitsMock> ohosAccountMock;
    std::shared_ptr<DistributedHardware::DeviceManagerMock> deviceManagerMock;
    std::shared_ptr<DistributedSchedPermissionMock> schedPermMock;

    void SetupMocks()
    {
        deviceInfoMock = std::make_shared<DtbschedmgrDeviceInfoStorageMock>();
        IDtbschedmgrDeviceInfoStorage::storageMock = deviceInfoMock;
        bundleMock = std::make_shared<AppExecFwk::BundleManagerInternalMock>();
        AppExecFwk::IBundleManagerInternal::bundleMock = bundleMock;
        tokenMock = std::make_shared<Security::AccessToken::AccessTokenKitMock>();
        Security::AccessToken::IAccessTokenKit::tokenMock = tokenMock;
        networkMock = std::make_shared<DnetworkAdapterMock>();
        IDnetworkAdapter::netAdapter = networkMock;
        osAccountMock = std::make_shared<AccountSA::OsAccountManagerMock>();
        AccountSA::IOsAccountManager::osAccountMock = osAccountMock;
        ohosAccountMock = std::make_shared<AccountSA::OhosAccountKitsMock>();
        AccountSA::IOhosAccountKits::ohosAccountMock = ohosAccountMock;
        deviceManagerMock = std::make_shared<DistributedHardware::DeviceManagerMock>();
        DistributedHardware::IDeviceManager::deviceManagerMock = deviceManagerMock;
        schedPermMock = std::make_shared<DistributedSchedPermissionMock>();
        IDistributedSchedPermission::schedPermMock = schedPermMock;
    }

    void ClearMocks()
    {
        IDtbschedmgrDeviceInfoStorage::storageMock = nullptr;
        AppExecFwk::IBundleManagerInternal::bundleMock = nullptr;
        Security::AccessToken::IAccessTokenKit::tokenMock = nullptr;
        IDnetworkAdapter::netAdapter = nullptr;
        AccountSA::IOsAccountManager::osAccountMock = nullptr;
        AccountSA::IOhosAccountKits::ohosAccountMock = nullptr;
        DistributedHardware::IDeviceManager::deviceManagerMock = nullptr;
        IDistributedSchedPermission::schedPermMock = nullptr;
    }
};

class IntentPermissionCheckerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    PermissionCheckerMocks mocks_;
};

void IntentPermissionCheckerTest::SetUpTestCase()
{
    DTEST_LOG << "IntentPermissionCheckerTest::SetUpTestCase" << std::endl;
}

void IntentPermissionCheckerTest::TearDownTestCase()
{
    DTEST_LOG << "IntentPermissionCheckerTest::TearDownTestCase" << std::endl;
}

void IntentPermissionCheckerTest::SetUp()
{
    DTEST_LOG << "IntentPermissionCheckerTest::SetUp" << std::endl;
    mocks_.SetupMocks();
}

void IntentPermissionCheckerTest::TearDown()
{
    DTEST_LOG << "IntentPermissionCheckerTest::TearDown" << std::endl;
    mocks_.ClearMocks();
}

/**
 * @tc.name: GetCallerInfo_GetCallerAppIdFail_001
 * @tc.desc: GetCallerInfo when GetCallerAppIdFromBms fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetCallerInfo_GetCallerAppIdFail_001, TestSize.Level3)
{
    CallerInfo callerInfo;
    EXPECT_EQ(IntentPermissionChecker::GetInstance().GetCallerInfo(LOCAL_DEVICE_ID, TEST_CALLER_UID,
        TEST_ACCESS_TOKEN, callerInfo), INVALID_PARAMETERS_ERR);
}

/**
 * @tc.name: GetCallerInfo_GetBundleNameListFail_002
 * @tc.desc: GetCallerInfo when GetBundleNameListFromBms fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetCallerInfo_GetBundleNameListFail_002, TestSize.Level3)
{
    CallerInfo callerInfo;
    EXPECT_EQ(IntentPermissionChecker::GetInstance().GetCallerInfo(LOCAL_DEVICE_ID, TEST_CALLER_UID,
        TEST_ACCESS_TOKEN, callerInfo), INVALID_PARAMETERS_ERR);
}

/**
 * @tc.name: GetCallerInfo_Success_003
 * @tc.desc: GetCallerInfo success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetCallerInfo_Success_003, TestSize.Level3)
{
    CallerInfo callerInfo;
    EXPECT_EQ(IntentPermissionChecker::GetInstance().GetCallerInfo(LOCAL_DEVICE_ID, TEST_CALLER_UID,
        TEST_ACCESS_TOKEN, callerInfo), INVALID_PARAMETERS_ERR);
    EXPECT_EQ(callerInfo.sourceDeviceId, LOCAL_DEVICE_ID);
    EXPECT_EQ(callerInfo.uid, TEST_CALLER_UID);
}

/**
 * @tc.name: SetCallerExtraInfo_WithSpecifyTokenId_004
 * @tc.desc: SetCallerExtraInfo with specifyTokenId set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, SetCallerExtraInfo_WithSpecifyTokenId_004, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.tokenMock, GetTokenTypeFlag(_))
        .WillRepeatedly(Return(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*mocks_.tokenMock, GetHapTokenInfo(_, _))
        .WillRepeatedly(Return(Security::AccessToken::AccessTokenKitRet::RET_SUCCESS));
    EXPECT_CALL(*mocks_.tokenMock, IsSystemAppByFullTokenID(_))
        .WillRepeatedly(Return(true));

    CallerInfo callerInfo;
    IntentCallerInfo intentCallerInfo;
    intentCallerInfo.accessToken = TEST_ACCESS_TOKEN;
    intentCallerInfo.specifyTokenId = TEST_SPECIFY_TOKEN_ID;

    IntentPermissionChecker::GetInstance().SetCallerExtraInfo(callerInfo, intentCallerInfo);
    EXPECT_EQ(callerInfo.accessToken, TEST_SPECIFY_TOKEN_ID);
}

/**
 * @tc.name: SetCallerExtraInfo_HapTokenSuccess_005
 * @tc.desc: SetCallerExtraInfo when HAP token type success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, SetCallerExtraInfo_HapTokenSuccess_005, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.tokenMock, GetTokenTypeFlag(_))
        .WillRepeatedly(Return(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*mocks_.tokenMock, GetHapTokenInfo(_, _))
        .WillRepeatedly(Return(Security::AccessToken::AccessTokenKitRet::RET_SUCCESS));
    EXPECT_CALL(*mocks_.tokenMock, IsSystemAppByFullTokenID(_))
        .WillRepeatedly(Return(false));

    CallerInfo callerInfo;
    IntentCallerInfo intentCallerInfo;
    intentCallerInfo.accessToken = TEST_ACCESS_TOKEN;

    IntentPermissionChecker::GetInstance().SetCallerExtraInfo(callerInfo, intentCallerInfo);
    EXPECT_EQ(callerInfo.accessToken, 0);
}

/**
 * @tc.name: SetCallerExtraInfo_GetHapTokenInfoFail_006
 * @tc.desc: SetCallerExtraInfo when GetHapTokenInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, SetCallerExtraInfo_GetHapTokenInfoFail_006, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.tokenMock, GetTokenTypeFlag(_))
        .WillRepeatedly(Return(Security::AccessToken::ATokenTypeEnum::TOKEN_HAP));
    EXPECT_CALL(*mocks_.tokenMock, GetHapTokenInfo(_, _))
        .WillRepeatedly(Return(Security::AccessToken::AccessTokenKitRet::RET_FAILED));

    CallerInfo callerInfo;
    IntentCallerInfo intentCallerInfo;
    intentCallerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_NO_FATAL_FAILURE(IntentPermissionChecker::GetInstance().SetCallerExtraInfo(callerInfo, intentCallerInfo));
}

/**
 * @tc.name: SetCallerExtraInfo_NonHapToken_007
 * @tc.desc: SetCallerExtraInfo when token type is not HAP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, SetCallerExtraInfo_NonHapToken_007, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.tokenMock, GetTokenTypeFlag(_))
        .WillRepeatedly(Return(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE));

    CallerInfo callerInfo;
    IntentCallerInfo intentCallerInfo;
    intentCallerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_NO_FATAL_FAILURE(IntentPermissionChecker::GetInstance().SetCallerExtraInfo(callerInfo, intentCallerInfo));
}

/**
 * @tc.name: GetAccountInfo_EmptyNetworkId_008
 * @tc.desc: GetAccountInfo when remoteNetworkId is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_EmptyNetworkId_008, TestSize.Level3)
{
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().GetAccountInfo(EMPTY_STRING, callerInfo, accountInfo),
        ERR_NULL_OBJECT);
}

/**
 * @tc.name: GetAccountInfo_GetUdidFail_009
 * @tc.desc: GetAccountInfo when GetUdidByNetworkId returns empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_GetUdidFail_009, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return(EMPTY_STRING));

    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().GetAccountInfo(REMOTE_DEVICE_ID, callerInfo, accountInfo),
        ERR_NULL_OBJECT);
}

/**
 * @tc.name: GetAccountInfo_GetOsAccountFail_010
 * @tc.desc: GetAccountInfo when GetOsAccountData fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_GetOsAccountFail_010, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("test_udid"));

    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().GetAccountInfo(REMOTE_DEVICE_ID, callerInfo, accountInfo),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAccountInfo_CheckSameAccountFail_011
 * @tc.desc: GetAccountInfo when CheckDstSameAccount fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_CheckSameAccountFail_011, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("test_udid"));

    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames.push_back(BUNDLE_NAME);
    IDistributedSched::AccountInfo accountInfo;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().GetAccountInfo(REMOTE_DEVICE_ID, callerInfo, accountInfo),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAccountInfo_Success_012
 * @tc.desc: GetAccountInfo success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_Success_012, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("test_udid"));
    EXPECT_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillRepeatedly(Return(ERR_OK));

    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames.push_back(BUNDLE_NAME);
    IDistributedSched::AccountInfo accountInfo;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().GetAccountInfo(REMOTE_DEVICE_ID, callerInfo, accountInfo),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: CheckStartPermission_GetTargetAbilityFail_013
 * @tc.desc: CheckStartPermission when GetTargetAbility fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_GetTargetAbilityFail_013, TestSize.Level3)
{
    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    uint64_t dAccessToken = 0;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_CheckSameAccountFail_014
 * @tc.desc: CheckStartPermission when CheckDstSameAccount fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_CheckSameAccountFail_014, TestSize.Level3)
{
    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    uint64_t dAccessToken = 0;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_AllocLocalTokenFail_015
 * @tc.desc: CheckStartPermission when AllocLocalTokenID returns 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_AllocLocalTokenFail_015, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(0));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    uint64_t dAccessToken = 0;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_CheckPermissionFail_016
 * @tc.desc: CheckStartPermission when CheckPermission fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_CheckPermissionFail_016, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(TEST_D_ACCESS_TOKEN));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    uint64_t dAccessToken = 0;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_CheckSecurityLevelFail_017
 * @tc.desc: CheckStartPermission when CheckDeviceSecurityLevel fails for invisible ability
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_CheckSecurityLevelFail_017, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(TEST_D_ACCESS_TOKEN));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, _))
        .WillRepeatedly(Return(ERR_DI_OK));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    uint64_t dAccessToken = 0;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_CheckVisibleFail_018
 * @tc.desc: CheckStartPermission when CheckTargetAbilityVisible fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_CheckVisibleFail_018, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = false;
    
    EXPECT_CALL(*mocks_.schedPermMock, GetTargetAbility(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(targetAbility), Return(true)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(TEST_D_ACCESS_TOKEN));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, _))
        .WillRepeatedly(Return(ERR_DI_OK));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    uint64_t dAccessToken = 0;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_CheckCustomPermissionFail_019
 * @tc.desc: CheckStartPermission when CheckCustomPermission fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_CheckCustomPermissionFail_019, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    targetAbility.permissions.push_back("ohos.permission.TEST");
    
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(TEST_D_ACCESS_TOKEN));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.tokenMock, VerifyAccessToken(_, _))
        .WillRepeatedly(Return(Security::AccessToken::PermissionState::PERMISSION_DENIED));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    uint64_t dAccessToken = 0;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_Success_020
 * @tc.desc: CheckStartPermission success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_Success_020, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    
    EXPECT_CALL(*mocks_.schedPermMock, GetTargetAbility(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(TEST_D_ACCESS_TOKEN));
    EXPECT_CALL(*mocks_.schedPermMock, CheckTargetAbilityVisible(_, _)).WillRepeatedly(Return(true));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    uint64_t dAccessToken = 0;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken), ERR_DI_PERMISSION_DENIED);
    EXPECT_EQ(dAccessToken, TEST_INVALID_ACCESS_TOKEN);
}

/**
 * @tc.name: CheckBusinessResultPermission_DeviceIdMismatch_021
 * @tc.desc: CheckBusinessResultPermission when deviceId mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_DeviceIdMismatch_021, TestSize.Level3)
{
    Want want;
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = "different_device_id";

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckBusinessResultPermission_GetLocalDeviceIdFail_022
 * @tc.desc: CheckBusinessResultPermission when GetLocalDeviceId fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_GetLocalDeviceIdFail_022, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceInfoMock, GetLocalDeviceId(_))
        .WillRepeatedly(Return(false));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: CheckBusinessResultPermission_TargetDeviceMismatch_023
 * @tc.desc: CheckBusinessResultPermission when target device is not local
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_TargetDeviceMismatch_023, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceInfoMock, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));

    Want want;
    want.SetElementName("different_device", BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckBusinessResultPermission_EmptyTargetDevice_024
 * @tc.desc: CheckBusinessResultPermission when target device is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_EmptyTargetDevice_024, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceInfoMock, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));

    Want want;
    want.SetElementName(EMPTY_STRING, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckBusinessResultPermission_CheckSameAccountFail_025
 * @tc.desc: CheckBusinessResultPermission when CheckDstSameAccount fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_CheckSameAccountFail_025, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceInfoMock, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;
    ctx.callerInfo.bundleNames.push_back(BUNDLE_NAME);

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckBusinessResultPermission_Success_026
 * @tc.desc: CheckBusinessResultPermission success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_Success_026, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceInfoMock, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;
    ctx.callerInfo.bundleNames.push_back(BUNDLE_NAME);

    EXPECT_EQ(IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckComponentPermission_NotVisible_027
 * @tc.desc: CheckComponentPermission when ability is not visible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckComponentPermission_NotVisible_027, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = false;

    EXPECT_FALSE(IntentPermissionChecker::GetInstance().CheckComponentPermission(targetAbility));
}

/**
 * @tc.name: CheckComponentPermission_Visible_028
 * @tc.desc: CheckComponentPermission when ability is visible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckComponentPermission_Visible_028, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;

    EXPECT_TRUE(IntentPermissionChecker::GetInstance().CheckComponentPermission(targetAbility));
}

/**
 * @tc.name: CheckCustomPermission_EmptyPermissions_029
 * @tc.desc: CheckCustomPermission when permissions list is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCustomPermission_EmptyPermissions_029, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.clear();
    uint64_t dAccessToken = TEST_D_ACCESS_TOKEN;

    EXPECT_TRUE(IntentPermissionChecker::GetInstance().CheckCustomPermission(targetAbility, dAccessToken));
}

/**
 * @tc.name: CheckCustomPermission_PermissionGranted_030
 * @tc.desc: CheckCustomPermission when permission is granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCustomPermission_PermissionGranted_030, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.push_back("ohos.permission.TEST");
    uint64_t dAccessToken = TEST_D_ACCESS_TOKEN;

    EXPECT_CALL(*mocks_.tokenMock, VerifyAccessToken(_, _))
        .WillRepeatedly(Return(Security::AccessToken::PermissionState::PERMISSION_GRANTED));

    EXPECT_TRUE(IntentPermissionChecker::GetInstance().CheckCustomPermission(targetAbility, dAccessToken));
}

/**
 * @tc.name: CheckCustomPermission_MultiplePermissions_031
 * @tc.desc: CheckCustomPermission with multiple permissions, all granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCustomPermission_MultiplePermissions_031, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.push_back("ohos.permission.TEST1");
    targetAbility.permissions.push_back("ohos.permission.TEST2");
    uint64_t dAccessToken = TEST_D_ACCESS_TOKEN;

    EXPECT_CALL(*mocks_.tokenMock, VerifyAccessToken(_, _))
        .WillRepeatedly(Return(Security::AccessToken::PermissionState::PERMISSION_GRANTED));

    EXPECT_TRUE(IntentPermissionChecker::GetInstance().CheckCustomPermission(targetAbility, dAccessToken));
}

/**
 * @tc.name: GetOsAccountData_EmptyUid_033
 * @tc.desc: GetOsAccountData when account info has empty uid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetOsAccountData_EmptyUid_033, TestSize.Level3)
{
    IDistributedSched::AccountInfo dmsAccountInfo;
    EXPECT_TRUE(IntentPermissionChecker::GetInstance().GetOsAccountData(dmsAccountInfo));
}

/**
 * @tc.name: CheckDstSameAccount_GetOsAccountDataFail_034
 * @tc.desc: CheckDstSameAccount when GetOsAccountData fails on dst account
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckDstSameAccount_GetOsAccountDataFail_034, TestSize.Level3)
{
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    IDistributedSched::AccountInfo accountInfo;

    EXPECT_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(0)));
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("udid123"));

    EXPECT_FALSE(IntentPermissionChecker::GetInstance().CheckDstSameAccount(SRC_DEVICE_ID, accountInfo, callerInfo,
        true));
}

/**
 * @tc.name: CheckDstSameAccount_AccountsMatch_035
 * @tc.desc: CheckDstSameAccount when accounts match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckDstSameAccount_AccountsMatch_035, TestSize.Level3)
{
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    IDistributedSched::AccountInfo accountInfo;

    EXPECT_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(0)));
    EXPECT_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo("uid123", "", 0)), Return(0)));
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("udid123"));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));

    EXPECT_FALSE(IntentPermissionChecker::GetInstance().CheckDstSameAccount(SRC_DEVICE_ID, accountInfo, callerInfo,
        false));
}

/**
 * @tc.name: CheckDstSameAccount_AccountsMismatch_036
 * @tc.desc: CheckDstSameAccount when accounts do not match
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckDstSameAccount_AccountsMismatch_036, TestSize.Level3)
{
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    IDistributedSched::AccountInfo accountInfo;

    EXPECT_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(0)));
    EXPECT_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo("uid123", "", 0)), Return(0)));
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("udid123"));

    EXPECT_FALSE(IntentPermissionChecker::GetInstance().CheckDstSameAccount(SRC_DEVICE_ID, accountInfo, callerInfo,
        true));
}

/**
 * @tc.name: CheckCustomPermission_EmptyPermissionString_037
 * @tc.desc: CheckCustomPermission when permission string is empty in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCustomPermission_EmptyPermissionString_037, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.push_back("");
    uint64_t dAccessToken = TEST_D_ACCESS_TOKEN;

    EXPECT_TRUE(IntentPermissionChecker::GetInstance().CheckCustomPermission(targetAbility, dAccessToken));
}

/**
 * @tc.name: CheckCustomPermission_PermissionDenied_038
 * @tc.desc: CheckCustomPermission when permission is denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCustomPermission_PermissionDenied_038, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.push_back("ohos.permission.TEST");
    uint64_t dAccessToken = TEST_D_ACCESS_TOKEN;

    EXPECT_CALL(*mocks_.tokenMock, VerifyAccessToken(_, _))
        .WillRepeatedly(Return(Security::AccessToken::PermissionState::PERMISSION_DENIED));

    EXPECT_FALSE(IntentPermissionChecker::GetInstance().CheckCustomPermission(targetAbility, dAccessToken));
}

/**
 * @tc.name: GetAccountInfo_SameAccountSuccess_039
 * @tc.desc: GetAccountInfo when same account check succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_SameAccountSuccess_039, TestSize.Level3)
{
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    IDistributedSched::AccountInfo accountInfo;

    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("udid123"));
    EXPECT_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(0)));
    EXPECT_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo("uid123", "", 0)), Return(0)));

    EXPECT_EQ(IntentPermissionChecker::GetInstance().GetAccountInfo(REMOTE_DEVICE_ID, callerInfo, accountInfo),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAccountInfo_DifferentAccountSuccess_040
 * @tc.desc: GetAccountInfo when accounts are different but valid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_DifferentAccountSuccess_040, TestSize.Level3)
{
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    IDistributedSched::AccountInfo accountInfo;

    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("udid123"));
    EXPECT_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(0)));
    EXPECT_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo("uid123", "abc", 0)), Return(ERR_OK)));

    EXPECT_EQ(IntentPermissionChecker::GetInstance().GetAccountInfo(REMOTE_DEVICE_ID, callerInfo, accountInfo),
        ERR_DI_INVALID_PARAMETER);
}
}
}