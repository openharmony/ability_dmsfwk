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

#include "dtbschedmgr_log.h"
#include "distributed_sched_permission_mock.h"
#include "dtbschedmgr_device_info_storage_mock.h"
#include "distributed_intent_plugin.h"
#include "distributed_intent_provider_impl.h"
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


namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "IntentPermissionCheckerTest";
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
const std::string PERMISSION_EXECUTE_DISTRIBUTED_INTENT = "ohos.permission.EXECUTE_DISTRIBUTED_INTENT";
const std::string PERMISSION_EXECUTE_INSIGHT_INTENT = "ohos.permission.EXECUTE_INSIGHT_INTENT";
const std::string PERMISSION_START_ABILITIES_FROM_BACKGROUND = "ohos.permission.START_ABILITIES_FROM_BACKGROUND";
constexpr int32_t EXECUTEPARAM_MODE_NUM = 1;
std::shared_ptr<IIntentPlugin> testIntentPlugin_;
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
    HILOGI("IntentPermissionCheckerTest::SetUpTestCase");
    static DmsIntentProviderImpl provider;
    void *pluginPtr = CreateIntentPlugin(&provider);
    testIntentPlugin_.reset(static_cast<IIntentPlugin *>(pluginPtr));
}

void IntentPermissionCheckerTest::TearDownTestCase()
{
    HILOGI("IntentPermissionCheckerTest::TearDownTestCase");
    testIntentPlugin_.reset();
}

void IntentPermissionCheckerTest::SetUp()
{
    HILOGI("IntentPermissionCheckerTest::SetUp");
    mocks_.SetupMocks();
}

void IntentPermissionCheckerTest::TearDown()
{
    HILOGI("IntentPermissionCheckerTest::TearDown");
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
    int32_t ret = IntentPermissionChecker::GetInstance().GetCallerInfo(LOCAL_DEVICE_ID, TEST_CALLER_UID,
        TEST_ACCESS_TOKEN, callerInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
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
    EXPECT_CALL(*mocks_.bundleMock, GetCallerAppIdFromBms(_, _)).WillRepeatedly(Return(true));
    int32_t ret = IntentPermissionChecker::GetInstance().GetCallerInfo(LOCAL_DEVICE_ID, TEST_CALLER_UID,
        TEST_ACCESS_TOKEN, callerInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
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
    EXPECT_CALL(*mocks_.bundleMock, GetCallerAppIdFromBms(_, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.bundleMock, GetBundleNameListFromBms(_, _)).WillRepeatedly(Return(true));
    int32_t ret = IntentPermissionChecker::GetInstance().GetCallerInfo(LOCAL_DEVICE_ID, TEST_CALLER_UID,
        TEST_ACCESS_TOKEN, callerInfo);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SetCallerExtraInfo_WithSpecifyTokenId_001
 * @tc.desc: SetCallerExtraInfo with specifyTokenId set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, SetCallerExtraInfo_WithSpecifyTokenId_001, TestSize.Level3)
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
 * @tc.name: SetCallerExtraInfo_HapTokenSuccess_002
 * @tc.desc: SetCallerExtraInfo when HAP token type success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, SetCallerExtraInfo_HapTokenSuccess_002, TestSize.Level3)
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
 * @tc.name: SetCallerExtraInfo_GetHapTokenInfoFail_003
 * @tc.desc: SetCallerExtraInfo when GetHapTokenInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, SetCallerExtraInfo_GetHapTokenInfoFail_003, TestSize.Level3)
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
 * @tc.name: SetCallerExtraInfo_NonHapToken_004
 * @tc.desc: SetCallerExtraInfo when token type is not HAP
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, SetCallerExtraInfo_NonHapToken_004, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.tokenMock, GetTokenTypeFlag(_))
        .WillRepeatedly(Return(Security::AccessToken::ATokenTypeEnum::TOKEN_NATIVE));

    CallerInfo callerInfo;
    IntentCallerInfo intentCallerInfo;
    intentCallerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_NO_FATAL_FAILURE(IntentPermissionChecker::GetInstance().SetCallerExtraInfo(callerInfo, intentCallerInfo));
}

/**
 * @tc.name: GetOsAccountData_EmptyUid_001
 * @tc.desc: GetOsAccountData when account info has empty uid
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(IntentPermissionCheckerTest, GetOsAccountData_EmptyUid_001, TestSize.Level3)
{
    IDistributedSched::AccountInfo dmsAccountInfo;
    int32_t ret = IntentPermissionChecker::GetInstance().GetOsAccountData(dmsAccountInfo);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CheckDstSameAccount_GetOsAccountData_Fail_001
 * @tc.desc: CheckDstSameAccount when GetOsAccountData fail on dst account
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(IntentPermissionCheckerTest, CheckDstSameAccount_GetOsAccountData_Fail_001, TestSize.Level3)
{
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    IDistributedSched::AccountInfo accountInfo;

    EXPECT_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(0)));
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("udid123"));

    int32_t ret = IntentPermissionChecker::GetInstance().CheckDstSameAccount(SRC_DEVICE_ID, accountInfo, callerInfo,
        true);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CheckDstSameAccount_AccountsMatch_002
 * @tc.desc: CheckDstSameAccount when accounts match
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(IntentPermissionCheckerTest, CheckDstSameAccount_AccountsMatch_002, TestSize.Level3)
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

    int32_t ret = IntentPermissionChecker::GetInstance().CheckDstSameAccount(SRC_DEVICE_ID, accountInfo, callerInfo,
        false);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CheckDstSameAccount_AccountsMisMatch_003
 * @tc.desc: CheckDstSameAccount when accounts do not match
 * @tc.type: FUNC
 * @tc.require:
*/
HWTEST_F(IntentPermissionCheckerTest, CheckDstSameAccount_AccountsMisMatch_003, TestSize.Level3)
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

    int32_t ret = IntentPermissionChecker::GetInstance().CheckDstSameAccount(SRC_DEVICE_ID, accountInfo, callerInfo,
        true);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: GetAccountInfo_EmptyNetworkId_001
 * @tc.desc: GetAccountInfo when remoteNetworkId is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_EmptyNetworkId_001, TestSize.Level3)
{
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;

    int32_t ret = IntentPermissionChecker::GetInstance().GetAccountInfo(EMPTY_STRING, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
}

/**
 * @tc.name: GetAccountInfo_GetUdidFail_002
 * @tc.desc: GetAccountInfo when GetUdidByNetworkId returns empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_GetUdidFail_002, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return(EMPTY_STRING));

    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;

    int32_t ret = IntentPermissionChecker::GetInstance().GetAccountInfo(REMOTE_DEVICE_ID, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
}

/**
 * @tc.name: GetAccountInfo_GetOsAccountFail_003
 * @tc.desc: GetAccountInfo when GetOsAccountData fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_GetOsAccountFail_003, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("test_udid"));
    EXPECT_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_FAIL)));

    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;

    int32_t ret = IntentPermissionChecker::GetInstance().GetAccountInfo(REMOTE_DEVICE_ID, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAccountInfo_CheckSameAccountFail_004
 * @tc.desc: GetAccountInfo when CheckDstSameAccount fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_CheckSameAccountFail_004, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("test_udid"));
    EXPECT_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillOnce(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_OK)));
    EXPECT_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillOnce(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo{"test", "test_account", 0}),
        Return(ERR_OK)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(false));

    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames.push_back(BUNDLE_NAME);
    IDistributedSched::AccountInfo accountInfo;

    int32_t ret = IntentPermissionChecker::GetInstance().GetAccountInfo(REMOTE_DEVICE_ID, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: GetAccountInfo_Success_005
 * @tc.desc: GetAccountInfo success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, GetAccountInfo_Success_005, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.networkMock, GetUdidByNetworkId(_))
        .WillRepeatedly(Return("test_udid"));
    EXPECT_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_OK)));
    EXPECT_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillOnce(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo{"test", "test_account", 0}),
        Return(ERR_OK)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSrcIsSameAccount(_, _))
        .WillRepeatedly(Return(true));

    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames.push_back(BUNDLE_NAME);
    IDistributedSched::AccountInfo accountInfo;

    int32_t ret = IntentPermissionChecker::GetInstance().GetAccountInfo(REMOTE_DEVICE_ID, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: CheckCallerPermission_DISTRIBUTED_INTENT_NOK_001
 * @tc.desc: CheckCallerPermission when DISTRIBUTED_INTENT is not OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCallerPermission_DISTRIBUTED_INTENT_NOK_001, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_DISTRIBUTED_INTENT))
        .WillOnce(Return(DMS_PERMISSION_DENIED));


    Want want;
    want.SetParam("ohos.insightIntent.executeParam.mode", EXECUTEPARAM_MODE_NUM);

    int32_t ret = IntentPermissionChecker::GetInstance().CheckCallerPermission(want, TEST_ACCESS_TOKEN);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckCallerPermission_INSIGHT_INTENT_NOK_002
 * @tc.desc: CheckCallerPermission when INSIGHT_INTENT is not OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCallerPermission_INSIGHT_INTENT_NOK_002, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_DISTRIBUTED_INTENT))
        .WillOnce(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_INSIGHT_INTENT))
        .WillOnce(Return(DMS_PERMISSION_DENIED));


    Want want;
    want.SetParam("ohos.insightIntent.executeParam.mode", -1);

    int32_t ret = IntentPermissionChecker::GetInstance().CheckCallerPermission(want, TEST_ACCESS_TOKEN);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckCallerPermission_DISTRIBUTED_INTENT_NOK_003
 * @tc.desc: CheckCallerPermission when DISTRIBUTED_INTENT is not OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCallerPermission_DISTRIBUTED_INTENT_NOK_003, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_DISTRIBUTED_INTENT))
        .WillOnce(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_INSIGHT_INTENT))
        .WillOnce(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_START_ABILITIES_FROM_BACKGROUND))
        .WillOnce(Return(DMS_PERMISSION_DENIED));


    Want want;
    want.SetParam("ohos.insightIntent.executeParam.mode", 1);

    int32_t ret = IntentPermissionChecker::GetInstance().CheckCallerPermission(want, TEST_ACCESS_TOKEN);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckCallerPermission_ERR_DI_OK_004
 * @tc.desc: CheckCallerPermission when ERR_DI_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCallerPermission_ERR_DI_OK_004, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_DISTRIBUTED_INTENT))
        .WillOnce(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_INSIGHT_INTENT))
        .WillOnce(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_START_ABILITIES_FROM_BACKGROUND))
        .WillOnce(Return(ERR_DI_OK));


    Want want;
    want.SetParam("ohos.insightIntent.executeParam.mode", 1);

    int32_t ret = IntentPermissionChecker::GetInstance().CheckCallerPermission(want, TEST_ACCESS_TOKEN);
    EXPECT_EQ(ret, ERR_DI_OK);
}

/**
 * @tc.name: CheckComponentPermission_NotVisible_001
 * @tc.desc: CheckComponentPermission when ability is not visible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckComponentPermission_NotVisible_001, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = false;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckComponentPermission(targetAbility);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CheckComponentPermission_Visible_002
 * @tc.desc: CheckComponentPermission when ability is visible
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckComponentPermission_Visible_002, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckComponentPermission(targetAbility);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CheckCustomPermission_EmptyPermissions_001
 * @tc.desc: CheckCustomPermission when permissions list is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCustomPermission_EmptyPermissions_001, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.clear();
    uint64_t dAccessToken = TEST_D_ACCESS_TOKEN;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckCustomPermission(targetAbility, dAccessToken);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CheckCustomPermission_PermissionGranted_002
 * @tc.desc: CheckCustomPermission when permission is granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCustomPermission_PermissionGranted_002, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.push_back("ohos.permission.TEST");
    uint64_t dAccessToken = TEST_D_ACCESS_TOKEN;

    EXPECT_CALL(*mocks_.tokenMock, VerifyAccessToken(_, _))
        .WillRepeatedly(Return(Security::AccessToken::PermissionState::PERMISSION_GRANTED));

    int32_t ret = IntentPermissionChecker::GetInstance().CheckCustomPermission(targetAbility, dAccessToken);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CheckCustomPermission_MultiplePermissions_003
 * @tc.desc: CheckCustomPermission with multiple permissions, all granted
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCustomPermission_MultiplePermissions_003, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.push_back("ohos.permission.TEST1");
    targetAbility.permissions.push_back("ohos.permission.TEST2");
    uint64_t dAccessToken = TEST_D_ACCESS_TOKEN;

    EXPECT_CALL(*mocks_.tokenMock, VerifyAccessToken(_, _))
        .WillRepeatedly(Return(Security::AccessToken::PermissionState::PERMISSION_GRANTED));

    int32_t ret = IntentPermissionChecker::GetInstance().CheckCustomPermission(targetAbility, dAccessToken);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CheckCustomPermission_EmptyPermissionString_004
 * @tc.desc: CheckCustomPermission when permission string is empty in list
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCustomPermission_EmptyPermissionString_004, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.push_back("");
    uint64_t dAccessToken = TEST_D_ACCESS_TOKEN;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckCustomPermission(targetAbility, dAccessToken);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: CheckCustomPermission_PermissionDenied_005
 * @tc.desc: CheckCustomPermission when permission is denied
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckCustomPermission_PermissionDenied_005, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.push_back("ohos.permission.TEST");
    uint64_t dAccessToken = TEST_D_ACCESS_TOKEN;

    EXPECT_CALL(*mocks_.tokenMock, VerifyAccessToken(_, _))
        .WillRepeatedly(Return(Security::AccessToken::PermissionState::PERMISSION_DENIED));

    int32_t ret = IntentPermissionChecker::GetInstance().CheckCustomPermission(targetAbility, dAccessToken);
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: CheckStartPermission_CheckDstSameAccount_Fail_001
 * @tc.desc: CheckStartPermission when CheckDstSameAccount fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_CheckDstSameAccount_Fail_001, TestSize.Level3)
{
    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.activeAccountId = "test_account";
    accountInfo.userId = 0;
    uint64_t dAccessToken = 0;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken);

    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_AllocLocalTokenIdFailRetry_002
 * @tc.desc: CheckStartPermission when AllocLocalTokenID returns 0(fail)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_AllocLocalTokenIdFailRetry_002, TestSize.Level3)
{
    ON_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillByDefault(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_OK)));
    ON_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillByDefault(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo{"test", "test_account", 0}),
        Return(ERR_OK)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));

    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames = {BUNDLE_NAME};
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.activeAccountId = "test_account";
    accountInfo.userId = 100;
    Want want;
    uint64_t dAccessToken = 0;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_CheckPermissionFail_003
 * @tc.desc: CheckStartPermission when CheckPermission fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_CheckPermissionFail_003, TestSize.Level3)
{
    ON_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillByDefault(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_OK)));
    ON_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillByDefault(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo{"test", "test_account", 0}),
        Return(ERR_OK)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));

    Want want;
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames = {BUNDLE_NAME};
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.activeAccountId = "test_account";
    accountInfo.userId =100;
    uint64_t dAccessToken = 0;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_CheckCallerPermission_Fail_004
 * @tc.desc: CheckStartPermission when CheckCallerPermission fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_CheckCallerPermission_Fail_004, TestSize.Level3)
{
    ON_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillByDefault(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_OK)));
    ON_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillByDefault(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo{"test", "test_account", 0}),
        Return(ERR_OK)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(TEST_D_ACCESS_TOKEN));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_DISTRIBUTED_INTENT))
        .WillRepeatedly(Return(DMS_PERMISSION_DENIED));

    Want want;
    want.SetElementName(REMOTE_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames = {BUNDLE_NAME};
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.activeAccountId = "test_account";
    accountInfo.userId =100;
    uint64_t dAccessToken = 0;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_GetTargetAbility_Fail_005
 * @tc.desc: CheckStartPermission when GetTargetAbility fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_GetTargetAbility_Fail_005, TestSize.Level3)
{
    ON_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillByDefault(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_OK)));
    ON_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillByDefault(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo{"test", "test_account", 0}),
        Return(ERR_OK)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(TEST_D_ACCESS_TOKEN));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_DISTRIBUTED_INTENT))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_INSIGHT_INTENT))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.schedPermMock, GetTargetAbility(_, _, _))
        .WillRepeatedly(Invoke([](const AAFwk::Want&, AppExecFwk::AbilityInfo& abilityInfo, bool) {
            abilityInfo.bundleName = BUNDLE_NAME;
            abilityInfo.name = ABILITY_NAME;
            abilityInfo.visible = false;
            abilityInfo.permissions = {};
            return false;
        }));

    Want want;
    want.SetElementName(REMOTE_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames = {BUNDLE_NAME};
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.activeAccountId = "test_account";
    accountInfo.userId =100;
    uint64_t dAccessToken = 0;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_CheckDeviceSecurityLevel_Fail_006
 * @tc.desc: CheckStartPermission when CheckDeviceSecurityLevel Fail
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_CheckDeviceSecurityLevel_Fail_006, TestSize.Level3)
{
    ON_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillByDefault(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_OK)));
    ON_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillByDefault(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo{"test", "test_account", 0}),
        Return(ERR_OK)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(TEST_D_ACCESS_TOKEN));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_DISTRIBUTED_INTENT))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_INSIGHT_INTENT))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.schedPermMock, GetTargetAbility(_, _, _))
        .WillRepeatedly(Invoke([](const AAFwk::Want&, AppExecFwk::AbilityInfo& abilityInfo, bool) {
            abilityInfo.bundleName = BUNDLE_NAME;
            abilityInfo.name = ABILITY_NAME;
            abilityInfo.visible = false;
            abilityInfo.permissions = {};
            return true;
        }));
    EXPECT_CALL(*mocks_.schedPermMock, CheckDeviceSecurityLevel(_, _))
        .WillRepeatedly(Return(false));

    Want want;
    want.SetElementName(REMOTE_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames = {BUNDLE_NAME};
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.activeAccountId = "test_account";
    accountInfo.userId = 100;
    uint64_t dAccessToken = 0;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_CheckDeviceSecurityLevel_Fail_007
 * @tc.desc: CheckStartPermission when CheckDeviceSecurityLevel fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_CheckVisible_Fail_007, TestSize.Level3)
{
    ON_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillByDefault(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_OK)));
    ON_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillByDefault(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo{"test", "test_account", 0}),
        Return(ERR_OK)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(TEST_D_ACCESS_TOKEN));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_DISTRIBUTED_INTENT))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_INSIGHT_INTENT))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.schedPermMock, GetTargetAbility(_, _, _))
        .WillRepeatedly(Invoke([](const AAFwk::Want&, AppExecFwk::AbilityInfo& abilityInfo, bool) {
            abilityInfo.bundleName = BUNDLE_NAME;
            abilityInfo.name = ABILITY_NAME;
            abilityInfo.visible = false;
            abilityInfo.permissions = {};
            return true;
        }));
    EXPECT_CALL(*mocks_.schedPermMock, CheckDeviceSecurityLevel(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.schedPermMock, CheckTargetAbilityVisible(_, _))
        .WillRepeatedly(Return(false));

    Want want;
    want.SetElementName(REMOTE_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames = {BUNDLE_NAME};
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.activeAccountId = "test_account";
    accountInfo.userId = 100;
    uint64_t dAccessToken = 0;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_CheckCustomPermission_Fail_008
 * @tc.desc: CheckStartPermission when CheckCustomPermission fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_CheckCustomPermission_Fail_008, TestSize.Level3)
{
    ON_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillByDefault(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_OK)));
    ON_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillByDefault(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo{"test", "test_account", 0}),
        Return(ERR_OK)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(TEST_D_ACCESS_TOKEN));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_DISTRIBUTED_INTENT))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_INSIGHT_INTENT))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.schedPermMock, GetTargetAbility(_, _, _))
        .WillRepeatedly(Invoke([](const AAFwk::Want&, AppExecFwk::AbilityInfo& abilityInfo, bool) {
            abilityInfo.bundleName = BUNDLE_NAME;
            abilityInfo.name = ABILITY_NAME;
            abilityInfo.visible = false;
            abilityInfo.permissions = {"ohos.permission.TEST"};
            return true;
        }));
    EXPECT_CALL(*mocks_.schedPermMock, CheckDeviceSecurityLevel(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.schedPermMock, CheckTargetAbilityVisible(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, VerifyAccessToken(_, _))
        .WillRepeatedly(Return(Security::AccessToken::PermissionState::PERMISSION_DENIED));

    Want want;
    want.SetElementName(REMOTE_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames = {BUNDLE_NAME};
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.activeAccountId = "test_account";
    accountInfo.userId = 100;
    uint64_t dAccessToken = 0;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckStartPermission_Success_009
 * @tc.desc: CheckStartPermission success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckStartPermission_Success_009, TestSize.Level3)
{
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    targetAbility.permissions.push_back("");

    ON_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillByDefault(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_OK)));
    ON_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillByDefault(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo{"test", "test_account", 0}),
        Return(ERR_OK)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.tokenMock, AllocLocalTokenID(_, _))
        .WillRepeatedly(Return(TEST_D_ACCESS_TOKEN));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_DISTRIBUTED_INTENT))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.schedPermMock, CheckPermission(_, PERMISSION_EXECUTE_INSIGHT_INTENT))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.schedPermMock, GetTargetAbility(_, _, _))
        .WillRepeatedly(Invoke([](const AAFwk::Want&, AppExecFwk::AbilityInfo& abilityInfo, bool) {
            abilityInfo.bundleName = BUNDLE_NAME;
            abilityInfo.name = ABILITY_NAME;
            abilityInfo.visible = false;
            abilityInfo.permissions = {};
            return true;
        }));
    EXPECT_CALL(*mocks_.schedPermMock, CheckDeviceSecurityLevel(_, _))
        .WillRepeatedly(Return(true));
    EXPECT_CALL(*mocks_.schedPermMock, CheckTargetAbilityVisible(_, _))
        .WillRepeatedly(Return(true));

    Want want;
    want.SetElementName(REMOTE_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    callerInfo.bundleNames = {BUNDLE_NAME};
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.activeAccountId = "test_account";
    accountInfo.userId = 100;
    uint64_t dAccessToken = 0;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckStartPermission(LOCAL_DEVICE_ID, want,
        callerInfo, accountInfo, dAccessToken);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckBusinessResultPermission_DeviceIdMismatch_001
 * @tc.desc: CheckBusinessResultPermission when deviceId mismatch
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_DeviceIdMismatch_001, TestSize.Level3)
{
    Want want;
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = "different_device_id";

    int32_t ret = IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx);
    EXPECT_EQ(ret,
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckBusinessResultPermission_GetLocalDeviceIdFail_002
 * @tc.desc: CheckBusinessResultPermission when GetLocalDeviceId fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_GetLocalDeviceIdFail_002, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceInfoMock, GetLocalDeviceId(_))
        .WillRepeatedly(Return(false));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx);
    EXPECT_EQ(ret, ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: CheckBusinessResultPermission_TargetDeviceMismatch_003
 * @tc.desc: CheckBusinessResultPermission when target device is not local
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_TargetDeviceMismatch_003, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceInfoMock, GetLocalDeviceId(_))
        .WillRepeatedly(Return(true));

    Want want;
    want.SetElementName("different_device", BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckBusinessResultPermission_EmptyTargetDevice_004
 * @tc.desc: CheckBusinessResultPermission when target device is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_EmptyTargetDevice_004, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceInfoMock, GetLocalDeviceId(_))
        .WillRepeatedly(Return(true));

    Want want;
    want.SetElementName(EMPTY_STRING, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;

    int32_t ret = IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckBusinessResultPermission_CheckSameAccountFail_005
 * @tc.desc: CheckBusinessResultPermission when CheckDstSameAccount fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_CheckSameAccountFail_005, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceInfoMock, GetLocalDeviceId(_))
        .WillRepeatedly(Return(true));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;
    ctx.callerInfo.bundleNames.push_back(BUNDLE_NAME);

    int32_t ret = IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckBusinessResultPermission_Success_006
 * @tc.desc: CheckBusinessResultPermission success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(IntentPermissionCheckerTest, CheckBusinessResultPermission_Success_006, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.deviceInfoMock, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));
    ON_CALL(*mocks_.osAccountMock, QueryActiveOsAccountIds(_))
        .WillByDefault(DoAll(SetArgReferee<0>(std::vector<int32_t>{100}), Return(ERR_OK)));
    ON_CALL(*mocks_.ohosAccountMock, GetOhosAccountInfo(_))
        .WillByDefault(DoAll(SetArgReferee<0>(AccountSA::OhosAccountInfo{"test", "test_account", 0}),
        Return(ERR_OK)));
    EXPECT_CALL(*mocks_.deviceManagerMock, CheckSinkIsSameAccount(_, _))
        .WillRepeatedly(Return(true));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;
    ctx.callerInfo.bundleNames.push_back(BUNDLE_NAME);

    int32_t ret = IntentPermissionChecker::GetInstance().CheckBusinessResultPermission(SRC_DEVICE_ID, want, ctx);
    EXPECT_EQ(ret, ERR_DI_PERMISSION_DENIED);
}
}
}