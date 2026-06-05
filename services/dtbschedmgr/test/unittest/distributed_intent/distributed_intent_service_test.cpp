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

#include "distributed_intent_service.h"
#include "distributed_intent_error_code.h"
#include "distributed_intent_provider_mock.h"
#include "dtbschedmgr_device_info_storage_mock.h"
#include "test_log.h"
#include "want.h"
#include "mock_remote_stub.h"

#define private public
#include "distributed_intent_service_stub.h"
#include "remote_intent_manager.h"
#undef private

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string LOCAL_DEVICE_ID = "local_device_id_12345";
const std::string DST_DEVICE_ID = "dst_device_id_67890";
const std::string EMPTY_STRING;
constexpr int32_t TEST_CALLER_UID = 1000;
constexpr uint64_t TEST_REQUEST_CODE = 100;
constexpr uint32_t TEST_ACCESS_TOKEN = 200;
const std::string BUNDLE_NAME = "com.test.bundle";
const std::string ABILITY_NAME = "MainAbility";
const std::string RESULT_MSG = "test_result";
}

class DistributedIntentServiceTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    std::shared_ptr<DistributedIntentService> service_;
    std::shared_ptr<DtbschedmgrDeviceInfoStorageMock> storageMock_;
    std::shared_ptr<MockIntentProvider> providerMock_;
};

void DistributedIntentServiceTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedIntentServiceTest::SetUpTestCase" << std::endl;
}

void DistributedIntentServiceTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedIntentServiceTest::TearDownTestCase" << std::endl;
}

void DistributedIntentServiceTest::SetUp()
{
    DTEST_LOG << "DistributedIntentServiceTest::SetUp" << std::endl;
    service_ = std::make_shared<DistributedIntentService>();
    storageMock_ = std::make_shared<DtbschedmgrDeviceInfoStorageMock>();
    IDtbschedmgrDeviceInfoStorage::storageMock = storageMock_;
    providerMock_ = std::make_shared<MockIntentProvider>();
}

void DistributedIntentServiceTest::TearDown()
{
    DTEST_LOG << "DistributedIntentServiceTest::TearDown" << std::endl;
    DistributedIntentServiceStub::SetProvider(nullptr);
    IDtbschedmgrDeviceInfoStorage::storageMock = nullptr;
    service_ = nullptr;
    providerMock_ = nullptr;
}

/**
 * @tc.name: StartRemoteIntent_GetLocalDeviceIdFail_001
 * @tc.desc: StartRemoteIntent when GetLocalDeviceId returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_GetLocalDeviceIdFail_001, TestSize.Level3)
{
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_))
        .WillRepeatedly(Return(false));

    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    EXPECT_EQ(service_->StartRemoteIntent(want, callerInfo, callback), ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: StartRemoteIntent_BothConditionsHitL36First_002
 * @tc.desc: StartRemoteIntent when GetLocalDeviceId fails and dstDeviceId is empty, L36 hits first
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_BothConditionsHitL36First_002, TestSize.Level3)
{
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_))
        .WillRepeatedly(Return(false));

    OHOS::AAFwk::Want want;
    want.SetElementName("", BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    EXPECT_EQ(service_->StartRemoteIntent(want, callerInfo, callback), ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: StartRemoteIntent_DstDeviceIdEmpty_003
 * @tc.desc: StartRemoteIntent when dstDeviceId is empty string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_DstDeviceIdEmpty_003, TestSize.Level3)
{
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));

    OHOS::AAFwk::Want want;
    want.SetElementName("", BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    EXPECT_EQ(service_->StartRemoteIntent(want, callerInfo, callback), ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: StartRemoteIntent_NoElementSet_004
 * @tc.desc: StartRemoteIntent when Want has no element, GetDeviceID returns empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_NoElementSet_004, TestSize.Level3)
{
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));

    OHOS::AAFwk::Want want;
    IntentCallerInfo callerInfo;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    EXPECT_EQ(service_->StartRemoteIntent(want, callerInfo, callback), ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: StartRemoteIntent_NormalPath_005
 * @tc.desc: StartRemoteIntent with valid params and callback is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_NormalPath_005, TestSize.Level3)
{
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));

    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    int32_t result = service_->StartRemoteIntent(want, callerInfo, callback);
    EXPECT_NE(result, ERR_DI_PERMISSION_DENIED);
    EXPECT_NE(result, ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: StartRemoteIntent_WithCallback_006
 * @tc.desc: StartRemoteIntent with valid params and non-null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_WithCallback_006, TestSize.Level3)
{
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));

    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    int32_t result = service_->StartRemoteIntent(want, callerInfo, callback);
    EXPECT_NE(result, ERR_DI_PERMISSION_DENIED);
    EXPECT_NE(result, ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: StartRemoteIntent_LocalDeviceIdEmptyOut_007
 * @tc.desc: StartRemoteIntent when GetLocalDeviceId returns true but localDeviceId is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_LocalDeviceIdEmptyOut_007, TestSize.Level3)
{
    EXPECT_CALL(*storageMock_, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>(EMPTY_STRING), Return(true)));

    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    int32_t result = service_->StartRemoteIntent(want, callerInfo, callback);
    EXPECT_NE(result, ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: SendIntentResult_WithMsg_001
 * @tc.desc: SendIntentResult with non-empty resultMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, SendIntentResult_WithMsg_001, TestSize.Level3)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;

    int32_t result = service_->SendIntentResult(want, callerInfo, RESULT_MSG);
    EXPECT_EQ(result, static_cast<int32_t>(ERR_DI_SYSTEM_WORK_ABNORMALLY));
}

/**
 * @tc.name: SendIntentResult_EmptyMsg_002
 * @tc.desc: SendIntentResult with empty resultMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, SendIntentResult_EmptyMsg_002, TestSize.Level3)
{
    OHOS::AAFwk::Want want;
    IntentCallerInfo callerInfo;
    std::string emptyMsg;

    int32_t result = service_->SendIntentResult(want, callerInfo, emptyMsg);
    EXPECT_EQ(result, static_cast<int32_t>(ERR_DI_SYSTEM_WORK_ABNORMALLY));
}

/**
 * @tc.name: SendIntentResult_ZeroRequestCode_003
 * @tc.desc: SendIntentResult with requestCode zero
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, SendIntentResult_ZeroRequestCode_003, TestSize.Level3)
{
    OHOS::AAFwk::Want want;
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = 0;
    callerInfo.requestCode = 0;

    int32_t result = service_->SendIntentResult(want, callerInfo, RESULT_MSG);
    EXPECT_EQ(result, static_cast<int32_t>(ERR_DI_SYSTEM_WORK_ABNORMALLY));
}

/**
 * @tc.name: SendIntentResult_NegativeUid_004
 * @tc.desc: SendIntentResult with negative callerUid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, SendIntentResult_NegativeUid_004, TestSize.Level3)
{
    OHOS::AAFwk::Want want;
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = -1;
    callerInfo.requestCode = TEST_REQUEST_CODE;

    int32_t result = service_->SendIntentResult(want, callerInfo, RESULT_MSG);
    EXPECT_EQ(result, static_cast<int32_t>(ERR_DI_SYSTEM_WORK_ABNORMALLY));
}

/**
 * @tc.name: SendIntentResult_AllDefault_005
 * @tc.desc: SendIntentResult with all default fields
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, SendIntentResult_AllDefault_005, TestSize.Level3)
{
    OHOS::AAFwk::Want want;
    IntentCallerInfo callerInfo;
    std::string emptyMsg;

    int32_t result = service_->SendIntentResult(want, callerInfo, emptyMsg);
    EXPECT_EQ(result, static_cast<int32_t>(ERR_DI_SYSTEM_WORK_ABNORMALLY));
}

/**
 * @tc.name: ConstructorAndDestructor_001
 * @tc.desc: Test constructor and destructor of DistributedIntentService
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, ConstructorAndDestructor_001, TestSize.Level3)
{
    auto svc = std::make_shared<DistributedIntentService>();
    EXPECT_NE(svc, nullptr);
    svc.reset();
    EXPECT_EQ(svc, nullptr);
}

/**
 * @tc.name: ConstructorAndDestructor_Multiple_002
 * @tc.desc: Test multiple rounds of constructor and destructor
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, ConstructorAndDestructor_Multiple_002, TestSize.Level3)
{
    for (int i = 0; i < 3; i++) {
        auto svc = std::make_shared<DistributedIntentService>();
        EXPECT_NE(svc, nullptr);
        svc.reset();
    }
}

/**
 * @tc.name: StartRemoteIntent_CallBack_Null_001
 * @tc.desc: StartRemoteIntent when call back is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_CallBack_Null_001, TestSize.Level3)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    sptr<IRemoteObject> callback = nullptr;

    EXPECT_EQ(service_->StartRemoteIntent(want, callerInfo, callback), ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: StartRemoteIntent_ProviderNull_001
 * @tc.desc: StartRemoteIntent when provider is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_ProviderNull_001, TestSize.Level3)
{
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    EXPECT_EQ(service_->StartRemoteIntent(want, callerInfo, callback), ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: StartRemoteIntent_GetLocalDeviceIdFail_ProviderSet_001
 * @tc.desc: StartRemoteIntent when GetLocalDeviceId returns false with provider set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_GetLocalDeviceIdFail_ProviderSet_001, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, GetLocalDeviceId(_))
        .WillOnce(Return(false));

    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    EXPECT_EQ(service_->StartRemoteIntent(want, callerInfo, callback), ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: StartRemoteIntent_DstDeviceIdEmpty_ProviderSet_001
 * @tc.desc: StartRemoteIntent when dstDeviceId is empty with provider set and GetLocalDeviceId success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_DstDeviceIdEmpty_ProviderSet_001, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, GetLocalDeviceId(_))
        .WillOnce(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));

    OHOS::AAFwk::Want want;
    want.SetElementName("", BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    EXPECT_EQ(service_->StartRemoteIntent(want, callerInfo, callback), ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: StartRemoteIntent_NoElementSet_ProviderSet_001
 * @tc.desc: StartRemoteIntent when Want has no element with provider set and GetLocalDeviceId success
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_NoElementSet_ProviderSet_001, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, GetLocalDeviceId(_))
        .WillOnce(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));

    OHOS::AAFwk::Want want;
    IntentCallerInfo callerInfo;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    EXPECT_EQ(service_->StartRemoteIntent(want, callerInfo, callback), ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: StartRemoteIntent_NormalPath_ProviderSet_001
 * @tc.desc: StartRemoteIntent normal path with provider set, GetLocalDeviceId success, valid dstDeviceId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_NormalPath_ProviderSet_001, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, GetLocalDeviceId(_))
        .WillOnce(DoAll(SetArgReferee<0>(LOCAL_DEVICE_ID), Return(true)));

    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = TEST_CALLER_UID;
    callerInfo.requestCode = TEST_REQUEST_CODE;
    callerInfo.accessToken = TEST_ACCESS_TOKEN;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    int32_t result = service_->StartRemoteIntent(want, callerInfo, callback);
    EXPECT_NE(result, ERR_DI_OK);
}

/**
 * @tc.name: StartRemoteIntent_GetLocalDeviceIdEmptyOut_ProviderSet_001
 * @tc.desc: StartRemoteIntent when GetLocalDeviceId returns true but localDeviceId is empty with provider set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceTest, StartRemoteIntent_GetLocalDeviceIdEmptyOut_ProviderSet_001, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, GetLocalDeviceId(_))
        .WillOnce(DoAll(SetArgReferee<0>(EMPTY_STRING), Return(true)));

    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    int32_t result = service_->StartRemoteIntent(want, callerInfo, callback);
    EXPECT_NE(result, ERR_DI_OK);
}

} // namespace DistributedSchedule
} // namespace OHOS
