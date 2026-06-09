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
#include "distributed_intent_service_stub.h"
#include "distributed_intent_service.h"
#undef private

#include "parcel.h"
#include "want.h"
#include "test_log.h"
#include "dtbschedmgr_log.h"
#include "distributedsched_ipc_interface_code.h"
#include "mock_remote_stub.h"
#include "distributed_intent_error_code.h"
#include "distributed_intent_provider_mock.h"
#include "dtbschedmgr_device_info_storage_mock.h"
#include "distributed_sched_permission.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::u16string INTENT_SERVICE_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
const std::u16string INVALID_TOKEN = u"invalid.token";
const std::u16string EMPTY_TOKEN = u"";
constexpr int32_t TEST_CALLER_UID = 1000;
constexpr uint64_t TEST_REQUEST_CODE = 100;
constexpr uint32_t TEST_ACCESS_TOKEN = 200;
constexpr uint32_t TEST_SPECIFY_TOKEN_ID = 300;
const std::string DST_DEVICE_ID = "dst_device_id_67890";
const std::string BUNDLE_NAME = "com.test.bundle";
const std::string ABILITY_NAME = "MainAbility";
const std::string TEST_RESULT_MSG = "test_result_message";
}

class DistributedIntentServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    sptr<DistributedIntentService> service_;
    std::shared_ptr<DtbschedmgrDeviceInfoStorageMock> deviceInfoMock_;
    std::shared_ptr<MockIntentProvider> providerMock_;
};

void DistributedIntentServiceStubTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedIntentServiceStubTest::SetUpTestCase" << std::endl;
}

void DistributedIntentServiceStubTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedIntentServiceStubTest::TearDownTestCase" << std::endl;
}

void DistributedIntentServiceStubTest::SetUp()
{
    DTEST_LOG << "DistributedIntentServiceStubTest::SetUp" << std::endl;
    service_ = new DistributedIntentService();
    deviceInfoMock_ = std::make_shared<DtbschedmgrDeviceInfoStorageMock>();
    IDtbschedmgrDeviceInfoStorage::storageMock = deviceInfoMock_;
    providerMock_ = std::make_shared<MockIntentProvider>();
}

void DistributedIntentServiceStubTest::TearDown()
{
    DTEST_LOG << "DistributedIntentServiceStubTest::TearDown" << std::endl;
    DistributedIntentServiceStub::SetProvider(nullptr);
    IDtbschedmgrDeviceInfoStorage::storageMock = nullptr;
    providerMock_ = nullptr;
}

void DistributedSchedPermission::RemoveRemoteObjectFromWant(
    std::shared_ptr<AAFwk::Want> want) const {}

void DistributedSchedPermission::MarkUriPermission(
    OHOS::AAFwk::Want& want, uint32_t accessToken) {}


/**
 * @tc.name: OnRemoteRequest_InvalidToken_001
 * @tc.desc: OnRemoteRequest with invalid interface token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, OnRemoteRequest_InvalidToken_001, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INVALID_TOKEN);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data, reply, option),
        ERR_TRANSACTION_FAILED);
}

/**
 * @tc.name: OnRemoteRequest_EmptyToken_002
 * @tc.desc: OnRemoteRequest with empty interface token
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, OnRemoteRequest_EmptyToken_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(EMPTY_TOKEN);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data, reply, option),
        ERR_TRANSACTION_FAILED);
}

/**
 * @tc.name: OnRemoteRequest_UnknownCode_003
 * @tc.desc: OnRemoteRequest with unregistered code
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, OnRemoteRequest_UnknownCode_003, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);

    EXPECT_NE(service_->OnRemoteRequest(9999, data, reply, option), ERR_OK);
}

/**
 * @tc.name: OnRemoteRequest_CodeZero_004
 * @tc.desc: OnRemoteRequest with code 0 which is not registered
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, OnRemoteRequest_CodeZero_004, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);

    EXPECT_NE(service_->OnRemoteRequest(0, data, reply, option), ERR_OK);
}

/**
 * @tc.name: RequestHandlers_RegisteredCorrectly_001
 * @tc.desc: Verify requestHandlers_ has exactly 2 entries for START_REMOTE_INTENT and SEND_INTENT_RESULT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, RequestHandlers_RegisteredCorrectly_001, TestSize.Level3)
{
    EXPECT_NE(service_->requestHandlers_.find(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT)),
        service_->requestHandlers_.end());
    EXPECT_NE(service_->requestHandlers_.find(
        static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT)),
        service_->requestHandlers_.end());
    EXPECT_EQ(service_->requestHandlers_.size(), 2u);
}

/**
 * @tc.name: StartRemoteIntentInner_ProviderNull_009
 * @tc.desc: StartRemoteIntentInner when provider is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_ProviderNull_009, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(nullptr);
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);

    EXPECT_EQ(service_->StartRemoteIntentInner(data, reply), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: StartRemoteIntentInner_NotFoundationWithProvider_010
 * @tc.desc: StartRemoteIntentInner when provider is set but IsFoundationCall returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_NotFoundationWithProvider_010, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, IsFoundationCall())
        .WillOnce(Return(false));

    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.Marshalling(data);

    EXPECT_EQ(service_->StartRemoteIntentInner(data, reply), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: StartRemoteIntentInner_WantNullWithProvider_011
 * @tc.desc: StartRemoteIntentInner when Want deserialization returns nullptr with provider set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_WantNullWithProvider_011, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, IsFoundationCall())
        .WillOnce(Return(true));

    MessageParcel data;
    MessageParcel reply;

    EXPECT_EQ(service_->StartRemoteIntentInner(data, reply), ERR_NULL_OBJECT);
}

/**
 * @tc.name: StartRemoteIntentInner_CallbackNullWithProvider_012
 * @tc.desc: StartRemoteIntentInner when resultCallback is nullptr with provider set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_CallbackNullWithProvider_012, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, IsFoundationCall())
        .WillOnce(Return(true));
    EXPECT_CALL(*providerMock_, RemoveRemoteObjectFromWant(_))
        .Times(1);

    MessageParcel data;
    MessageParcel reply;
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    data.WriteParcelable(&want);
    data.WriteString("test_module");
    data.WriteInt32(TEST_CALLER_UID);
    data.WriteUint64(TEST_REQUEST_CODE);
    data.WriteUint32(TEST_ACCESS_TOKEN);
    data.WriteUint32(TEST_SPECIFY_TOKEN_ID);
    data.WriteRemoteObject(nullptr);

    EXPECT_EQ(service_->StartRemoteIntentInner(data, reply), ERR_NULL_OBJECT);
}

/**
 * @tc.name: StartRemoteIntentInner_FullPathWithProvider_013
 * @tc.desc: StartRemoteIntentInner full path with all valid params and provider set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_FullPathWithProvider_013, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, IsFoundationCall())
        .WillOnce(Return(true));
    EXPECT_CALL(*providerMock_, RemoveRemoteObjectFromWant(_))
        .Times(1);
    EXPECT_CALL(*providerMock_, MarkUriPermission(_, TEST_ACCESS_TOKEN))
        .Times(1);

    MessageParcel data;
    MessageParcel reply;
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    data.WriteParcelable(&want);
    data.WriteString("test_module");
    data.WriteInt32(TEST_CALLER_UID);
    data.WriteUint64(TEST_REQUEST_CODE);
    data.WriteUint32(TEST_ACCESS_TOKEN);
    data.WriteUint32(TEST_SPECIFY_TOKEN_ID);
    sptr<IRemoteObject> cb = new MockRemoteStub();
    data.WriteRemoteObject(cb);

    int32_t result = service_->StartRemoteIntentInner(data, reply);
    EXPECT_NE(result, ERR_DI_PERMISSION_DENIED);
    EXPECT_NE(result, ERR_NULL_OBJECT);
    EXPECT_NE(result, ERR_FLATTEN_OBJECT);
}

/**
 * @tc.name: SendIntentResultInner_ProviderNull_009
 * @tc.desc: SendIntentResultInner when provider is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_ProviderNull_009, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(nullptr);
    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);

    EXPECT_EQ(service_->SendIntentResultInner(data, reply), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: SendIntentResultInner_NotFoundationWithProvider_010
 * @tc.desc: SendIntentResultInner when provider is set but IsFoundationCall returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_NotFoundationWithProvider_010, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, IsFoundationCall())
        .WillOnce(Return(false));

    MessageParcel data;
    MessageParcel reply;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.Marshalling(data);

    EXPECT_EQ(service_->SendIntentResultInner(data, reply), ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: SendIntentResultInner_WantNullWithProvider_011
 * @tc.desc: SendIntentResultInner when Want deserialization returns nullptr with provider set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_WantNullWithProvider_011, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, IsFoundationCall())
        .WillOnce(Return(true));

    MessageParcel data;
    MessageParcel reply;

    EXPECT_EQ(service_->SendIntentResultInner(data, reply), ERR_NULL_OBJECT);
}

/**
 * @tc.name: SendIntentResultInner_FullPathWithProvider_012
 * @tc.desc: SendIntentResultInner full path with all valid params and provider set
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_FullPathWithProvider_012, TestSize.Level3)
{
    DistributedIntentServiceStub::SetProvider(providerMock_.get());
    EXPECT_CALL(*providerMock_, IsFoundationCall())
        .WillOnce(Return(true));

    MessageParcel data;
    MessageParcel reply;
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    data.WriteParcelable(&want);
    data.WriteInt32(TEST_CALLER_UID);
    data.WriteUint64(TEST_REQUEST_CODE);
    data.WriteUint32(TEST_ACCESS_TOKEN);
    data.WriteUint32(TEST_SPECIFY_TOKEN_ID);
    data.WriteString(TEST_RESULT_MSG);

    int32_t result = service_->SendIntentResultInner(data, reply);
    EXPECT_NE(result, ERR_DI_PERMISSION_DENIED);
    EXPECT_NE(result, ERR_NULL_OBJECT);
    EXPECT_NE(result, ERR_FLATTEN_OBJECT);
}

} // namespace DistributedSchedule
} // namespace OHOS
