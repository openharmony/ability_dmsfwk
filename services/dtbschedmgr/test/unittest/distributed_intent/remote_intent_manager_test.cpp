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
#include "remote_intent_manager.h"
#include "intent_permission_checker.h"
#include "distributed_intent_dsoftbus_adapter.h"
#undef private

#include "softbus_mock.h"
#include "distributed_intent_dsoftbus_adapter_mock.h"
#include "distributed_intent_provider_mock.h"
#include "distributed_intent_version_checker_mock.h"
#include "dtbschedmgr_device_info_storage_mock.h"
#include "intent_permission_checker_mock.h"
#include "distributed_sched_permission_mock.h"
#include "ability_manager_client_mock.h"
#include "bundle_manager_internal_mock.h"
#include "access_token_kit_mock.h"
#include "os_account_manager_mock.h"
#include "ohos_account_kits_mock.h"
#include "device_manager_mock.h"
#include "test_log.h"
#include "want.h"
#include "mock_remote_stub.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace DistributedSchedule {

namespace {
const std::string LOCAL_DEVICE_ID = "local_device_id_12345";
const std::string DST_DEVICE_ID = "dst_device_id_67890";
const std::string SRC_DEVICE_ID = "src_device_id_11111";
const std::string EMPTY_STRING;
constexpr int32_t TEST_CALLER_UID = 1000;
constexpr int32_t TEST_CALLER_PID = 2000;
constexpr uint64_t TEST_REQUEST_CODE = 100;
constexpr uint32_t TEST_ACCESS_TOKEN = 200;
constexpr uint32_t TEST_SPECIFY_TOKEN_ID = 300;
constexpr int32_t TEST_SOCKET_FD = 10;
constexpr int64_t CALLBACK_TIMEOUT_MS = 30000;
const std::string BUNDLE_NAME = "com.test.bundle";
const std::string ABILITY_NAME = "MainAbility";
const std::string RESULT_MSG = "test_result";
}

struct DistributedIntentMocks {
    std::shared_ptr<SoftbusMock> softbusMock;
    std::shared_ptr<DistributedIntentDsoftbusAdapterMock> adapterMock;
    std::shared_ptr<DtbschedmgrDeviceInfoStorageMock> deviceInfoMock;
    std::shared_ptr<IntentPermissionCheckerMock> permCheckerMock;
    std::shared_ptr<DistributedSchedPermissionMock> schedPermMock;
    std::shared_ptr<AbilityManagerClientMock> abilityMock;
    std::shared_ptr<AppExecFwk::BundleManagerInternalMock> bundleMock;
    std::shared_ptr<Security::AccessToken::AccessTokenKitMock> tokenMock;
    std::shared_ptr<AccountSA::OsAccountManagerMock> osAccountMock;
    std::shared_ptr<AccountSA::OhosAccountKitsMock> ohosAccountMock;
    std::shared_ptr<DistributedHardware::DeviceManagerMock> deviceManagerMock;
    std::shared_ptr<MockIntentProvider> providerMock;
    std::shared_ptr<DistributedIntentVersionCheckerMock> versionCheckerMock;

    void SetupMocks()
    {
        softbusMock = std::make_shared<SoftbusMock>();
        ISoftbusInterface::softbusMock = softbusMock;
        adapterMock = std::make_shared<DistributedIntentDsoftbusAdapterMock>();
        IDistributedIntentDsoftbusAdapter::adapterMock = adapterMock;
        deviceInfoMock = std::make_shared<DtbschedmgrDeviceInfoStorageMock>();
        IDtbschedmgrDeviceInfoStorage::storageMock = deviceInfoMock;
        permCheckerMock = std::make_shared<IntentPermissionCheckerMock>();
        IIntentPermissionChecker::permCheckerMock = permCheckerMock;
        schedPermMock = std::make_shared<DistributedSchedPermissionMock>();
        IDistributedSchedPermission::schedPermMock = schedPermMock;
        abilityMock = std::make_shared<AbilityManagerClientMock>();
        IAbilityManagerClient::abilityMock = abilityMock;
        bundleMock = std::make_shared<AppExecFwk::BundleManagerInternalMock>();
        AppExecFwk::IBundleManagerInternal::bundleMock = bundleMock;
        tokenMock = std::make_shared<Security::AccessToken::AccessTokenKitMock>();
        Security::AccessToken::IAccessTokenKit::tokenMock = tokenMock;
        osAccountMock = std::make_shared<AccountSA::OsAccountManagerMock>();
        AccountSA::IOsAccountManager::osAccountMock = osAccountMock;
        ohosAccountMock = std::make_shared<AccountSA::OhosAccountKitsMock>();
        AccountSA::IOhosAccountKits::ohosAccountMock = ohosAccountMock;
        deviceManagerMock = std::make_shared<DistributedHardware::DeviceManagerMock>();
        DistributedHardware::IDeviceManager::deviceManagerMock = deviceManagerMock;
        providerMock = std::make_shared<MockIntentProvider>();
        IntentPermissionChecker::GetInstance().SetProvider(providerMock.get());
        ON_CALL(*providerMock, SerializeIntentData(_, _, _, _))
            .WillByDefault(DoAll(SetArgReferee<2>("mock_data"), Return(ERR_DI_OK)));
        ON_CALL(*providerMock, SerializeResultData(_, _, _, _))
            .WillByDefault(DoAll(SetArgReferee<3>("mock_result"), Return(ERR_DI_OK)));
        ON_CALL(*providerMock, DeserializeIntentData(_, _, _, _))
            .WillByDefault(Return(ERR_DI_INVALID_PARAMETER));
        ON_CALL(*providerMock, ParseResultData(_, _, _, _))
            .WillByDefault(Return(false));
        ON_CALL(*providerMock, GetLocalDeviceId(_))
            .WillByDefault(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));
        versionCheckerMock = std::make_shared<DistributedIntentVersionCheckerMock>();
        IDistributedIntentVersionChecker::versionCheckerMock = versionCheckerMock;
        ON_CALL(*versionCheckerMock, CheckRemoteDistributedIntentSupport(_))
            .WillByDefault(Return(ERR_DI_OK));
    }

    void ClearMocks()
    {
        ISoftbusInterface::softbusMock = nullptr;
        IDistributedIntentDsoftbusAdapter::adapterMock = nullptr;
        IDtbschedmgrDeviceInfoStorage::storageMock = nullptr;
        IIntentPermissionChecker::permCheckerMock = nullptr;
        IDistributedSchedPermission::schedPermMock = nullptr;
        IAbilityManagerClient::abilityMock = nullptr;
        AppExecFwk::IBundleManagerInternal::bundleMock = nullptr;
        Security::AccessToken::IAccessTokenKit::tokenMock = nullptr;
        AccountSA::IOsAccountManager::osAccountMock = nullptr;
        AccountSA::IOhosAccountKits::ohosAccountMock = nullptr;
        DistributedHardware::IDeviceManager::deviceManagerMock = nullptr;
        IntentPermissionChecker::GetInstance().SetProvider(nullptr);
        IDistributedIntentVersionChecker::versionCheckerMock = nullptr;
        providerMock = nullptr;
        versionCheckerMock = nullptr;
    }
};

class RemoteIntentManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    DistributedIntentMocks mocks_;
    sptr<MockRemoteStub> callback_;
};

void RemoteIntentManagerTest::SetUpTestCase()
{
    DTEST_LOG << "RemoteIntentManagerTest::SetUpTestCase" << std::endl;
}

void RemoteIntentManagerTest::TearDownTestCase()
{
    DTEST_LOG << "RemoteIntentManagerTest::TearDownTestCase" << std::endl;
}

void RemoteIntentManagerTest::SetUp()
{
    DTEST_LOG << "RemoteIntentManagerTest::SetUp" << std::endl;
    mocks_.SetupMocks();
    callback_ = new MockRemoteStub();
}

void RemoteIntentManagerTest::TearDown()
{
    DTEST_LOG << "RemoteIntentManagerTest::TearDown" << std::endl;
    mocks_.ClearMocks();
    callback_ = nullptr;
}

/**
 * @tc.name: StartRemoteIntent_EmptyDstDeviceId_001
 * @tc.desc: StartRemoteIntent when dstDeviceId is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_EmptyDstDeviceId_001, TestSize.Level3)
{
    Want want;
    want.SetElementName(EMPTY_STRING, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: StartRemoteIntent_GetLocalDeviceIdFail_002
 * @tc.desc: StartRemoteIntent when GetLocalDeviceId returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_GetLocalDeviceIdFail_002, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.providerMock, GetLocalDeviceId(_))
        .WillRepeatedly(Return(false));

    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: StartRemoteIntent_LocalSameAsDst_003
 * @tc.desc: StartRemoteIntent when localDeviceId equals dstDeviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_LocalSameAsDst_003, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.providerMock, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(DST_DEVICE_ID), Return(true)));

    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: StartRemoteIntent_GetCallerInfoFail_004
 * @tc.desc: StartRemoteIntent when GetCallerInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_GetCallerInfoFail_004, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.permCheckerMock, GetCallerInfo(_, _, _, _))
        .WillRepeatedly(Return(ERR_DI_SYSTEM_WORK_ABNORMALLY));

    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: StartRemoteIntent_GetAccountInfoFail_005
 * @tc.desc: StartRemoteIntent when GetAccountInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_GetAccountInfoFail_005, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.permCheckerMock, GetCallerInfo(_, _, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.permCheckerMock, GetAccountInfo(_, _, _))
        .WillRepeatedly(Return(ERR_DI_INVALID_PARAMETER));

    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: StartRemoteIntent_CheckCallerPermissionFail_006
 * @tc.desc: StartRemoteIntent when CheckCallerPermission fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_CheckCallerPermissionFail_006, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.permCheckerMock, GetCallerInfo(_, _, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.permCheckerMock, GetAccountInfo(_, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.permCheckerMock, CheckCallerPermission(_, _))
        .WillRepeatedly(Return(ERR_DI_PERMISSION_DENIED));

    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: StartRemoteIntent_BindIntentSessionFail_007
 * @tc.desc: StartRemoteIntent when BindIntentSession fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_BindIntentSessionFail_007, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.permCheckerMock, GetCallerInfo(_, _, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.permCheckerMock, GetAccountInfo(_, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.adapterMock, BindIntentSession(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(-1), Return(ERR_DI_SOCKET_BIND_FAILED)));

    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_SOCKET_BIND_FAILED);
}

/**
 * @tc.name: StartRemoteIntent_SendIntentDataFail_008
 * @tc.desc: StartRemoteIntent when SendIntentDataBySession fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_SendIntentDataFail_008, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.permCheckerMock, GetCallerInfo(_, _, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.permCheckerMock, GetAccountInfo(_, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.adapterMock, BindIntentSession(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(TEST_SOCKET_FD), Return(ERR_DI_OK)));
    EXPECT_CALL(*mocks_.adapterMock, SendIntentDataBySession(_, _, _))
        .WillRepeatedly(Return(ERR_DI_DATA_SEND_FAILED));

    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_DATA_SEND_FAILED);
}

/**
 * @tc.name: StartRemoteIntent_Success_009
 * @tc.desc: StartRemoteIntent success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_Success_009, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.permCheckerMock, GetCallerInfo(_, _, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.permCheckerMock, GetAccountInfo(_, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.adapterMock, BindIntentSession(_, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(TEST_SOCKET_FD), Return(ERR_DI_OK)));
    EXPECT_CALL(*mocks_.adapterMock, SendIntentDataBySession(_, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));

    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_OK);
}

/**
 * @tc.name: HandleIntentExecute_DeserializeFail_010
 * @tc.desc: HandleIntentExecute when DeserializeIntentData fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleIntentExecute_DeserializeFail_010, TestSize.Level3)
{
    std::string invalidData = "invalid_json_data";
    
    EXPECT_EQ(RemoteIntentManager::GetInstance().HandleIntentExecute(SRC_DEVICE_ID, invalidData, TEST_SOCKET_FD),
        ERR_DI_SERIALIZE_FAILED);
}

/**
 * @tc.name: HandleIntentResult_CallbackNotFound_012
 * @tc.desc: HandleIntentResult when callback not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleIntentResult_CallbackNotFound_012, TestSize.Level3)
{
    std::string data = R"({"requestCode":100,"result":0,"resultMsg":"test_result"})";
    EXPECT_CALL(*mocks_.providerMock, ParseResultData(_, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<1>(TEST_REQUEST_CODE), SetArgReferee<2>(0),
                         SetArgReferee<3>(RESULT_MSG), Return(true)));

    RemoteIntentManager::GetInstance().requestCodeCallbackMap_.clear();

    EXPECT_EQ(RemoteIntentManager::GetInstance().HandleIntentResult(SRC_DEVICE_ID, data, TEST_SOCKET_FD),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: HandleBusinessResult_DeserializeFail_013
 * @tc.desc: HandleBusinessResult when DeserializeIntentData fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleBusinessResult_DeserializeFail_013, TestSize.Level3)
{
    std::string invalidData = "invalid_json_data";

    EXPECT_EQ(RemoteIntentManager::GetInstance().HandleBusinessResult(SRC_DEVICE_ID, invalidData, TEST_SOCKET_FD),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: CleanupSocketMapping_Success_016
 * @tc.desc: CleanupSocketMapping removes all mappings for device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, CleanupSocketMapping_Success_016, TestSize.Level3)
{
    RemoteIntentManager::GetInstance().requestSocketMap_.clear();
    RemoteIntentManager::GetInstance().requestSocketMap_[{SRC_DEVICE_ID, TEST_REQUEST_CODE}] = TEST_SOCKET_FD;
    RemoteIntentManager::GetInstance().requestSocketMap_[{SRC_DEVICE_ID, TEST_REQUEST_CODE + 1}] = TEST_SOCKET_FD + 1;
    RemoteIntentManager::GetInstance().requestSocketMap_[{"other_device", TEST_REQUEST_CODE}] = TEST_SOCKET_FD + 2;

    RemoteIntentManager::GetInstance().CleanupSocketMapping(SRC_DEVICE_ID, TEST_SOCKET_FD);

    EXPECT_EQ(RemoteIntentManager::GetInstance().requestSocketMap_.size(), 1u);
    EXPECT_TRUE(RemoteIntentManager::GetInstance().requestSocketMap_.find({"other_device", TEST_REQUEST_CODE})
        != RemoteIntentManager::GetInstance().requestSocketMap_.end());
}

/**
 * @tc.name: HandleSendIntentResult_SocketNotFound_017
 * @tc.desc: HandleSendIntentResult when socket mapping not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleSendIntentResult_SocketNotFound_017, TestSize.Level3)
{
    Want want;
    want.SetElementName(SRC_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    RemoteIntentManager::GetInstance().requestSocketMap_.clear();

    EXPECT_EQ(RemoteIntentManager::GetInstance().HandleSendIntentResult(want, callerInfo, RESULT_MSG),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: SerializeIntentData_Success_018
 * @tc.desc: SerializeIntentData success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, SerializeIntentData_Success_018, TestSize.Level3)
{
    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.requestCode = TEST_REQUEST_CODE;
    ctx.callerInfo.uid = TEST_CALLER_UID;
    ctx.callerInfo.sourceDeviceId = LOCAL_DEVICE_ID;
    std::string data;

    EXPECT_EQ(RemoteIntentManager::GetInstance().SerializeIntentData(want, ctx, data), ERR_DI_OK);
    EXPECT_FALSE(data.empty());
}

/**
 * @tc.name: SerializeResultData_Success_019
 * @tc.desc: SerializeResultData success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, SerializeResultData_Success_019, TestSize.Level3)
{
    std::string data;
    EXPECT_EQ(RemoteIntentManager::GetInstance().SerializeResultData(ERR_DI_OK, RESULT_MSG, TEST_REQUEST_CODE, data),
        ERR_DI_OK);
    EXPECT_FALSE(data.empty());
}

/**
 * @tc.name: SendInnerResultBack_InvalidSocket_021
 * @tc.desc: SendInnerResultBack with invalid socketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, SendInnerResultBack_InvalidSocket_021, TestSize.Level3)
{
    EXPECT_EQ(RemoteIntentManager::GetInstance().SendInnerResultBack(-1, TEST_REQUEST_CODE, ERR_DI_OK,
        IntentDataType::INTENT_DATA_TYPE_DMS_RESULT), ERR_DI_SOFTBUS_COMMUNICATION_FAILED);
}

/**
 * @tc.name: SendInnerResultBack_SendFail_022
 * @tc.desc: SendInnerResultBack when SendIntentDataBySession fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, SendInnerResultBack_SendFail_022, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.adapterMock, SendIntentDataBySession(_, _, _))
        .WillRepeatedly(Return(ERR_DI_DATA_SEND_FAILED));

    EXPECT_EQ(RemoteIntentManager::GetInstance().SendInnerResultBack(TEST_SOCKET_FD, TEST_REQUEST_CODE, ERR_DI_OK,
        IntentDataType::INTENT_DATA_TYPE_DMS_RESULT), ERR_DI_SOFTBUS_COMMUNICATION_FAILED);
}

/**
 * @tc.name: NotifyIntentResult_NullCallback_023
 * @tc.desc: NotifyIntentResult with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, NotifyIntentResult_NullCallback_023, TestSize.Level3)
{
    sptr<IRemoteObject> nullCallback = nullptr;
    std::string resultMsg = RESULT_MSG;

    EXPECT_EQ(RemoteIntentManager::GetInstance().NotifyIntentResult(nullCallback, TEST_REQUEST_CODE, ERR_DI_OK,
        resultMsg), ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: RegisterResultCallback_NullCallback_027
 * @tc.desc: RegisterResultCallback with null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, RegisterResultCallback_NullCallback_027, TestSize.Level3)
{
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_.clear();
    
    RemoteIntentManager::GetInstance().RegisterResultCallback(TEST_REQUEST_CODE, DST_DEVICE_ID, nullptr);
    
    EXPECT_TRUE(RemoteIntentManager::GetInstance().requestCodeCallbackMap_.empty());
}

/**
 * @tc.name: RegisterResultCallback_Success_028
 * @tc.desc: RegisterResultCallback success case
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, RegisterResultCallback_Success_028, TestSize.Level3)
{
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_.clear();
    
    RemoteIntentManager::GetInstance().RegisterResultCallback(TEST_REQUEST_CODE, DST_DEVICE_ID, callback_);
    
    EXPECT_EQ(RemoteIntentManager::GetInstance().requestCodeCallbackMap_.size(), 1u);
    EXPECT_TRUE(RemoteIntentManager::GetInstance().requestCodeCallbackMap_.find(TEST_REQUEST_CODE)
        != RemoteIntentManager::GetInstance().requestCodeCallbackMap_.end());
}

/**
 * @tc.name: HandleIntentExecute_ValidateFail_030
 * @tc.desc: HandleIntentExecute when ValidateExecuteRequest fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleIntentExecute_ValidateFail_030, TestSize.Level3)
{
    IntentContext ctx;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;
    ctx.callerInfo.sourceDeviceId = "mismatch_device";
    ctx.requestCode = TEST_REQUEST_CODE;
    AAFwk::Want want;
    want.SetElementName("wrong_target", BUNDLE_NAME, ABILITY_NAME);
    std::string resultMsg;

    EXPECT_CALL(*mocks_.providerMock, DeserializeIntentData(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(ctx), Return(ERR_DI_OK)));
    EXPECT_CALL(*mocks_.providerMock, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));
    EXPECT_CALL(*mocks_.adapterMock, SendIntentDataBySession(_, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));

    RemoteIntentManager::GetInstance().requestSocketMap_.clear();

    std::string data = "valid_data";
    EXPECT_EQ(RemoteIntentManager::GetInstance().HandleIntentExecute(SRC_DEVICE_ID, data, TEST_SOCKET_FD),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: HandleIntentResult_InvalidJson_031
 * @tc.desc: HandleIntentResult with invalid JSON data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleIntentResult_InvalidJson_031, TestSize.Level3)
{
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_.clear();

    EXPECT_EQ(RemoteIntentManager::GetInstance().HandleIntentResult(SRC_DEVICE_ID, "invalid_json", TEST_SOCKET_FD),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: CleanupExpiredCallbacks_ExpiredCallback_034
 * @tc.desc: CleanupExpiredCallbacks removes expired callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, CleanupExpiredCallbacks_ExpiredCallback_034, TestSize.Level3)
{
    CallbackEntry entry = {
        .callback = callback_,
        .timestamp = std::chrono::steady_clock::now() - std::chrono::milliseconds(CALLBACK_TIMEOUT_MS + 1000),
        .deviceId = DST_DEVICE_ID,
    };
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_[TEST_REQUEST_CODE] = entry;
    RemoteIntentManager::GetInstance().requestSocketMap_[{DST_DEVICE_ID, TEST_REQUEST_CODE}] = TEST_SOCKET_FD;
    
    EXPECT_CALL(*mocks_.adapterMock, UnbindIntentSession(_)).Times(1);
    RemoteIntentManager::GetInstance().CleanupExpiredCallbacks();
    
    EXPECT_TRUE(RemoteIntentManager::GetInstance().requestCodeCallbackMap_.empty());
}

/**
 * @tc.name: CleanupExpiredCallbacks_ActiveCallbackNotRemoved_035
 * @tc.desc: CleanupExpiredCallbacks does not remove active callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, CleanupExpiredCallbacks_ActiveCallbackNotRemoved_035, TestSize.Level3)
{
    CallbackEntry entry = {
        .callback = callback_,
        .timestamp = std::chrono::steady_clock::now(),
        .deviceId = DST_DEVICE_ID,
    };
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_[TEST_REQUEST_CODE] = entry;
    RemoteIntentManager::GetInstance().CleanupExpiredCallbacks();
    
    EXPECT_EQ(RemoteIntentManager::GetInstance().requestCodeCallbackMap_.size(), 1u);
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_.erase(TEST_REQUEST_CODE);
}

/**
 * @tc.name: SendResultToRemote_InvalidSocketFd_036
 * @tc.desc: SendResultToRemote with invalid socketFd
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, SendResultToRemote_InvalidSocketFd_036, TestSize.Level3)
{
    Want want;
    IntentContext ctx;
    EXPECT_EQ(RemoteIntentManager::GetInstance().SendResultToRemote(TEST_SOCKET_FD, want, ctx, RESULT_MSG),
        ERR_DI_OK);
}

/**
 * @tc.name: PrepareResultContext_GetCallerInfoFail_037
 * @tc.desc: PrepareResultContext when GetCallerInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, PrepareResultContext_GetCallerInfoFail_037, TestSize.Level3)
{
    IntentCallerInfo callerInfo;
    IntentContext ctx;
    
    EXPECT_CALL(*mocks_.permCheckerMock, GetCallerInfo(_, _, _, _))
        .WillRepeatedly(Return(ERR_DI_SYSTEM_WORK_ABNORMALLY));
    
    EXPECT_EQ(RemoteIntentManager::GetInstance().PrepareResultContext(SRC_DEVICE_ID, LOCAL_DEVICE_ID,
        callerInfo, ctx), ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: PrepareResultContext_GetAccountInfoFail_038
 * @tc.desc: PrepareResultContext when GetAccountInfo fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, PrepareResultContext_GetAccountInfoFail_038, TestSize.Level3)
{
    IntentCallerInfo callerInfo;
    IntentContext ctx;
    IDistributedSched::AccountInfo accountInfo;
    
    EXPECT_CALL(*mocks_.permCheckerMock, GetCallerInfo(_, _, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.permCheckerMock, GetAccountInfo(_, _, _))
        .WillRepeatedly(Return(ERR_DI_INVALID_PARAMETER));
    
    EXPECT_EQ(RemoteIntentManager::GetInstance().PrepareResultContext(SRC_DEVICE_ID, LOCAL_DEVICE_ID,
        callerInfo, ctx), ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: NotifyLinkDisconnected_Success_042
 * @tc.desc: NotifyLinkDisconnected notifies all callbacks for the device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, NotifyLinkDisconnected_Success_042, TestSize.Level3)
{
    CallbackEntry entry = {
        .callback = callback_,
        .timestamp = std::chrono::steady_clock::now(),
        .deviceId = SRC_DEVICE_ID,
    };
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_[TEST_REQUEST_CODE] = entry;
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_[TEST_REQUEST_CODE + 1] = entry;
    
    RemoteIntentManager::GetInstance().NotifyLinkDisconnected(SRC_DEVICE_ID, 0);
    
    EXPECT_TRUE(RemoteIntentManager::GetInstance().requestCodeCallbackMap_.empty());
}

/**
 * @tc.name: NotifyLinkDisconnected_DifferentDevice_043
 * @tc.desc: NotifyLinkDisconnected does not affect callbacks for different device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, NotifyLinkDisconnected_DifferentDevice_043, TestSize.Level3)
{
    CallbackEntry entry = {
        .callback = callback_,
        .timestamp = std::chrono::steady_clock::now(),
        .deviceId = DST_DEVICE_ID,
    };
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_[TEST_REQUEST_CODE] = entry;
    RemoteIntentManager::GetInstance().NotifyLinkDisconnected(SRC_DEVICE_ID, 0);
    
    EXPECT_EQ(RemoteIntentManager::GetInstance().requestCodeCallbackMap_.size(), 1u);
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_.erase(TEST_REQUEST_CODE);
}

/**
 * @tc.name: HandleSendIntentResult_GetLocalDeviceIdFail_044
 * @tc.desc: HandleSendIntentResult when GetLocalDeviceId fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleSendIntentResult_GetLocalDeviceIdFail_044, TestSize.Level3)
{
    RemoteIntentManager::GetInstance().requestSocketMap_.clear();
    RemoteIntentManager::GetInstance().requestSocketMap_[{SRC_DEVICE_ID, TEST_REQUEST_CODE}] = TEST_SOCKET_FD;

    EXPECT_CALL(*mocks_.providerMock, GetLocalDeviceId(_))
        .WillRepeatedly(Return(false));

    Want want;
    want.SetElementName(SRC_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().HandleSendIntentResult(want, callerInfo, RESULT_MSG),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: HandleBusinessResult_CallbackNotFound_045
 * @tc.desc: HandleBusinessResult when callback not found
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleBusinessResult_CallbackNotFound_045, TestSize.Level3)
{
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_.clear();
    IntentContext ctx;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    ctx.requestCode = TEST_REQUEST_CODE;
    std::string resultMsg;

    EXPECT_CALL(*mocks_.providerMock, DeserializeIntentData(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(ctx), Return(ERR_DI_OK)));

    EXPECT_EQ(RemoteIntentManager::GetInstance().HandleBusinessResult(SRC_DEVICE_ID, "test_data", TEST_SOCKET_FD),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: HandleDisconnect_Success_001
 * @tc.desc: Test HandleDisconnect successfully handles disconnect with valid provider
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleDisconnect_Success, TestSize.Level3)
{
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_.clear();
    RemoteIntentManager::GetInstance().requestSocketMap_.clear();
    CallbackEntry entry = {
        .callback = callback_,
        .timestamp = std::chrono::steady_clock::now(),
        .deviceId = SRC_DEVICE_ID,
    };
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_[TEST_REQUEST_CODE] = entry;
    RemoteIntentManager::GetInstance().requestSocketMap_[{SRC_DEVICE_ID, TEST_REQUEST_CODE}] = TEST_SOCKET_FD;

    EXPECT_CALL(*mocks_.providerMock, ParseDisconnectData(_, _, _)).Times(1);
    EXPECT_CALL(*mocks_.adapterMock, ShutdownDeviceSession(SRC_DEVICE_ID)).Times(1);

    RemoteIntentManager::GetInstance().HandleDisconnect(SRC_DEVICE_ID, "test_data", TEST_SOCKET_FD);
    EXPECT_TRUE(RemoteIntentManager::GetInstance().requestCodeCallbackMap_.empty());
}

/**
 * @tc.name: HandleDisconnect_NullProvider_001
 * @tc.desc: Test HandleDisconnect with null provider does not crash
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleDisconnect_NullProvider, TestSize.Level3)
{
    IntentPermissionChecker::GetInstance().SetProvider(nullptr);
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_.clear();
    RemoteIntentManager::GetInstance().requestSocketMap_.clear();

    EXPECT_CALL(*mocks_.adapterMock, ShutdownDeviceSession(_)).Times(1);

    EXPECT_NO_FATAL_FAILURE(RemoteIntentManager::GetInstance().HandleDisconnect(
        SRC_DEVICE_ID, "test_data", TEST_SOCKET_FD));

    IntentPermissionChecker::GetInstance().SetProvider(mocks_.providerMock.get());
}

/**
 * @tc.name: HandleDisconnect_EmptyDeviceId_001
 * @tc.desc: Test HandleDisconnect with empty device id clears callback map
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleDisconnect_EmptyDeviceId, TestSize.Level3)
{
    RemoteIntentManager::GetInstance().requestCodeCallbackMap_.clear();
    RemoteIntentManager::GetInstance().requestSocketMap_.clear();

    EXPECT_CALL(*mocks_.adapterMock, ShutdownDeviceSession(EMPTY_STRING)).Times(1);

    RemoteIntentManager::GetInstance().HandleDisconnect(EMPTY_STRING, "test_data", TEST_SOCKET_FD);
    EXPECT_TRUE(RemoteIntentManager::GetInstance().requestCodeCallbackMap_.empty());
}

/**
 * @tc.name: SendDisconnectToRemote_Success_001
 * @tc.desc: Test SendDisconnectToRemote returns OK when send succeeds
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, SendDisconnectToRemote_Success, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.adapterMock, SendIntentDataBySession(TEST_SOCKET_FD,
        IntentDataType::INTENT_DATA_TYPE_DISCONNECT, _))
        .WillRepeatedly(Return(ERR_DI_OK));

    EXPECT_EQ(RemoteIntentManager::GetInstance().SendDisconnectToRemote(
        TEST_SOCKET_FD, TEST_REQUEST_CODE, 0, RESULT_MSG), ERR_DI_OK);
}

/**
 * @tc.name: SendDisconnectToRemote_SendFail_001
 * @tc.desc: Test SendDisconnectToRemote returns error when send fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, SendDisconnectToRemote_SendFail, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.adapterMock, SendIntentDataBySession(TEST_SOCKET_FD,
        IntentDataType::INTENT_DATA_TYPE_DISCONNECT, _))
        .WillRepeatedly(Return(ERR_DI_DATA_SEND_FAILED));

    EXPECT_EQ(RemoteIntentManager::GetInstance().SendDisconnectToRemote(
        TEST_SOCKET_FD, TEST_REQUEST_CODE, 0, RESULT_MSG), ERR_DI_DATA_SEND_FAILED);
}

/**
 * @tc.name: StartRemoteIntent_VersionCheckFail_010
 * @tc.desc: StartRemoteIntent when CheckRemoteDistributedIntentSupport fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_VersionCheckFail, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.providerMock, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));
    EXPECT_CALL(*mocks_.versionCheckerMock, CheckRemoteDistributedIntentSupport(_))
        .WillRepeatedly(Return(ERR_DI_CAPABILITY_NOT_SUPPORT));

    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_CAPABILITY_NOT_SUPPORT);
}

/**
 * @tc.name: StartRemoteIntent_LocalDeviceIdEmpty_011
 * @tc.desc: StartRemoteIntent when localDeviceId is empty but GetLocalDeviceId returns true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_LocalDeviceIdEmpty, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.providerMock, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(EMPTY_STRING), Return(true)));

    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: StartRemoteIntent_ProviderNull_012
 * @tc.desc: StartRemoteIntent when provider is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, StartRemoteIntent_ProviderNull, TestSize.Level3)
{
    IntentPermissionChecker::GetInstance().SetProvider(nullptr);

    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().StartRemoteIntent(want, callerInfo, callback_),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);

    IntentPermissionChecker::GetInstance().SetProvider(mocks_.providerMock.get());
}

/**
 * @tc.name: DeserializeIntentData_ProviderNull_013
 * @tc.desc: DeserializeIntentData when provider is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, DeserializeIntentData_ProviderNull, TestSize.Level3)
{
    IntentPermissionChecker::GetInstance().SetProvider(nullptr);
    AAFwk::Want want;
    IntentContext ctx;
    std::string resultMsg;

    EXPECT_EQ(RemoteIntentManager::GetInstance().DeserializeIntentData("test_data", want, ctx, resultMsg),
        ERR_DI_INVALID_PARAMETER);

    IntentPermissionChecker::GetInstance().SetProvider(mocks_.providerMock.get());
}

/**
 * @tc.name: DeserializeIntentData_AccessTokenZero_014
 * @tc.desc: DeserializeIntentData when accessToken is zero after successful deserialize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, DeserializeIntentData_AccessTokenZero, TestSize.Level3)
{
    AAFwk::Want want;
    IntentContext ctx;
    std::string resultMsg;

    EXPECT_CALL(*mocks_.providerMock, DeserializeIntentData(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(ctx), Return(ERR_DI_OK)));

    EXPECT_EQ(RemoteIntentManager::GetInstance().DeserializeIntentData("test_data", want, ctx, resultMsg),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: DeserializeIntentData_SourceDeviceIdEmpty_015
 * @tc.desc: DeserializeIntentData when sourceDeviceId is empty after successful deserialize
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, DeserializeIntentData_SourceDeviceIdEmpty, TestSize.Level3)
{
    AAFwk::Want want;
    IntentContext ctx;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;
    ctx.callerInfo.sourceDeviceId = EMPTY_STRING;
    std::string resultMsg;

    EXPECT_CALL(*mocks_.providerMock, DeserializeIntentData(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(ctx), Return(ERR_DI_OK)));

    EXPECT_EQ(RemoteIntentManager::GetInstance().DeserializeIntentData("test_data", want, ctx, resultMsg),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: DeserializeIntentData_Success_016
 * @tc.desc: DeserializeIntentData success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, DeserializeIntentData_Success, TestSize.Level3)
{
    AAFwk::Want want;
    IntentContext ctx;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    std::string resultMsg;

    EXPECT_CALL(*mocks_.providerMock, DeserializeIntentData(_, _, _, _))
        .WillOnce(DoAll(SetArgReferee<2>(ctx), Return(ERR_DI_OK)));

    EXPECT_EQ(RemoteIntentManager::GetInstance().DeserializeIntentData("test_data", want, ctx, resultMsg),
        ERR_DI_OK);
}

/**
 * @tc.name: ValidateExecuteRequest_DeviceIdMismatch_017
 * @tc.desc: ValidateExecuteRequest when srcDeviceId mismatches sourceDeviceId in context
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, ValidateExecuteRequest_DeviceIdMismatch, TestSize.Level3)
{
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = "different_src_device";
    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);

    EXPECT_EQ(RemoteIntentManager::GetInstance().ValidateExecuteRequest(SRC_DEVICE_ID, want, ctx, LOCAL_DEVICE_ID),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: ValidateExecuteRequest_TargetDeviceIdNotLocal_018
 * @tc.desc: ValidateExecuteRequest when target device is not local device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, ValidateExecuteRequest_TargetDeviceIdNotLocal, TestSize.Level3)
{
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);

    EXPECT_EQ(RemoteIntentManager::GetInstance().ValidateExecuteRequest(SRC_DEVICE_ID, want, ctx, LOCAL_DEVICE_ID),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: ValidateExecuteRequest_TargetDeviceIdEmpty_019
 * @tc.desc: ValidateExecuteRequest when target device id is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, ValidateExecuteRequest_TargetDeviceIdEmpty, TestSize.Level3)
{
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    Want want;

    EXPECT_EQ(RemoteIntentManager::GetInstance().ValidateExecuteRequest(SRC_DEVICE_ID, want, ctx, LOCAL_DEVICE_ID),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: ValidateExecuteRequest_Success_020
 * @tc.desc: ValidateExecuteRequest success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, ValidateExecuteRequest_Success, TestSize.Level3)
{
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);

    EXPECT_EQ(RemoteIntentManager::GetInstance().ValidateExecuteRequest(SRC_DEVICE_ID, want, ctx, LOCAL_DEVICE_ID),
        ERR_DI_OK);
}

/**
 * @tc.name: CheckAndExecuteIntent_CheckStartPermissionFail_021
 * @tc.desc: CheckAndExecuteIntent when CheckStartPermission fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, CheckAndExecuteIntent_CheckStartPermissionFail, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.permCheckerMock, CheckStartPermission(_, _, _, _, _))
        .WillRepeatedly(Return(ERR_DI_PERMISSION_DENIED));
    EXPECT_CALL(*mocks_.adapterMock, SendIntentDataBySession(_, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().CheckAndExecuteIntent(want, SRC_DEVICE_ID, ctx,
        LOCAL_DEVICE_ID, TEST_SOCKET_FD), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: CheckAndExecuteIntent_GetOsAccountDataFail_022
 * @tc.desc: CheckAndExecuteIntent when GetOsAccountData fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, CheckAndExecuteIntent_GetOsAccountDataFail, TestSize.Level3)
{
    EXPECT_CALL(*mocks_.permCheckerMock, CheckStartPermission(_, _, _, _, _))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.permCheckerMock, GetOsAccountData(_))
        .WillRepeatedly(Return(false));
    EXPECT_CALL(*mocks_.adapterMock, SendIntentDataBySession(_, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().CheckAndExecuteIntent(want, SRC_DEVICE_ID, ctx,
        LOCAL_DEVICE_ID, TEST_SOCKET_FD), INVALID_PARAMETERS_ERR);
}

/**
 * @tc.name: CheckAndExecuteIntent_DoExecuteFail_023
 * @tc.desc: CheckAndExecuteIntent when DoExecuteIntent fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, CheckAndExecuteIntent_DoExecuteFail, TestSize.Level3)
{
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.userId = 100;

    EXPECT_CALL(*mocks_.permCheckerMock, CheckStartPermission(_, _, _, _, _))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.permCheckerMock, GetOsAccountData(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(accountInfo), Return(true)));
    EXPECT_CALL(*mocks_.abilityMock, ExecuteIntentForDistributed(_, _, _, _))
        .WillRepeatedly(Return(ERR_DI_EXECUTE_FAILED));
    EXPECT_CALL(*mocks_.adapterMock, SendIntentDataBySession(_, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().CheckAndExecuteIntent(want, SRC_DEVICE_ID, ctx,
        LOCAL_DEVICE_ID, TEST_SOCKET_FD), ERR_DI_EXECUTE_FAILED);
}

/**
 * @tc.name: CheckAndExecuteIntent_Success_024
 * @tc.desc: CheckAndExecuteIntent success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, CheckAndExecuteIntent_Success, TestSize.Level3)
{
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.userId = 100;

    EXPECT_CALL(*mocks_.permCheckerMock, CheckStartPermission(_, _, _, _, _))
        .WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*mocks_.permCheckerMock, GetOsAccountData(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(accountInfo), Return(true)));
    EXPECT_CALL(*mocks_.abilityMock, ExecuteIntentForDistributed(_, _, _, _))
        .WillRepeatedly(Return(ERR_OK));

    Want want;
    want.SetElementName(LOCAL_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_EQ(RemoteIntentManager::GetInstance().CheckAndExecuteIntent(want, SRC_DEVICE_ID, ctx,
        LOCAL_DEVICE_ID, TEST_SOCKET_FD), ERR_DI_OK);
}

/**
 * @tc.name: SerializeIntentData_NullProvider_025
 * @tc.desc: SerializeIntentData when provider is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, SerializeIntentData_NullProvider, TestSize.Level3)
{
    IntentPermissionChecker::GetInstance().SetProvider(nullptr);
    Want want;
    IntentContext ctx;
    std::string data;

    EXPECT_EQ(RemoteIntentManager::GetInstance().SerializeIntentData(want, ctx, data),
        ERR_DI_SERIALIZE_FAILED);

    IntentPermissionChecker::GetInstance().SetProvider(mocks_.providerMock.get());
}

/**
 * @tc.name: SerializeResultData_NullProvider_026
 * @tc.desc: SerializeResultData when provider is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, SerializeResultData_NullProvider, TestSize.Level3)
{
    IntentPermissionChecker::GetInstance().SetProvider(nullptr);
    std::string data;

    EXPECT_EQ(RemoteIntentManager::GetInstance().SerializeResultData(ERR_DI_OK, RESULT_MSG, TEST_REQUEST_CODE, data),
        ERR_DI_SERIALIZE_FAILED);

    IntentPermissionChecker::GetInstance().SetProvider(mocks_.providerMock.get());
}

/**
 * @tc.name: HandleIntentResult_NullProvider_027
 * @tc.desc: HandleIntentResult when provider is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleIntentResult_NullProvider, TestSize.Level3)
{
    IntentPermissionChecker::GetInstance().SetProvider(nullptr);

    EXPECT_EQ(RemoteIntentManager::GetInstance().HandleIntentResult(SRC_DEVICE_ID, "test_data", TEST_SOCKET_FD),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);

    IntentPermissionChecker::GetInstance().SetProvider(mocks_.providerMock.get());
}

/**
 * @tc.name: PrepareCallerContext_Success_028
 * @tc.desc: PrepareCallerContext success path
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, PrepareCallerContext_Success, TestSize.Level3)
{
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    IntentCallerInfo intentCallerInfo;
    intentCallerInfo.callerUid = TEST_CALLER_UID;
    intentCallerInfo.accessToken = TEST_ACCESS_TOKEN;

    EXPECT_CALL(*mocks_.permCheckerMock, GetCallerInfo(_, _, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));
    EXPECT_CALL(*mocks_.permCheckerMock, GetAccountInfo(_, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));

    EXPECT_EQ(RemoteIntentManager::GetInstance().PrepareCallerContext(LOCAL_DEVICE_ID, DST_DEVICE_ID,
        intentCallerInfo, callerInfo, accountInfo), ERR_DI_OK);
}

/**
 * @tc.name: HandleIntentExecute_ProviderNull_029
 * @tc.desc: HandleIntentExecute when provider is null after deserialize success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(RemoteIntentManagerTest, HandleIntentExecute_ProviderNull, TestSize.Level3)
{
    IntentContext ctx;
    ctx.callerInfo.accessToken = TEST_ACCESS_TOKEN;
    ctx.callerInfo.sourceDeviceId = SRC_DEVICE_ID;
    ctx.requestCode = TEST_REQUEST_CODE;

    EXPECT_CALL(*mocks_.adapterMock, SendIntentDataBySession(_, _, _))
        .WillRepeatedly(Return(ERR_DI_OK));

    std::string data = "valid_data";
    RemoteIntentManager::GetInstance().requestSocketMap_.clear();

    IntentPermissionChecker::GetInstance().SetProvider(nullptr);
    EXPECT_EQ(RemoteIntentManager::GetInstance().HandleIntentExecute(SRC_DEVICE_ID, data, TEST_SOCKET_FD),
        ERR_DI_SERIALIZE_FAILED);
    IntentPermissionChecker::GetInstance().SetProvider(mocks_.providerMock.get());
}
}
}
