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

static bool g_isFoundationCall = true;

class DistributedIntentServiceStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    sptr<DistributedIntentService> service_;
    std::shared_ptr<DtbschedmgrDeviceInfoStorageMock> deviceInfoMock_;
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
    g_isFoundationCall = true;
}

void DistributedIntentServiceStubTest::TearDown()
{
    DTEST_LOG << "DistributedIntentServiceStubTest::TearDown" << std::endl;
    IDtbschedmgrDeviceInfoStorage::storageMock = nullptr;
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
 * @tc.name: StartRemoteIntentInner_NotFoundation_001
 * @tc.desc: StartRemoteIntentInner when IsFoundationCall returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_NotFoundation_001, TestSize.Level3)
{
    g_isFoundationCall = false;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.Marshalling(data);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: StartRemoteIntentInner_WantNull_002
 * @tc.desc: StartRemoteIntentInner when Want deserialization returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_WantNull_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: StartRemoteIntentInner_MissingCallerUid_003
 * @tc.desc: StartRemoteIntentInner when callerUid is missing after Want
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_MissingCallerUid_003, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    want.Marshalling(data);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: StartRemoteIntentInner_MissingRequestCode_004
 * @tc.desc: StartRemoteIntentInner when requestCode is missing after callerUid
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_MissingRequestCode_004, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    want.Marshalling(data);
    data.WriteInt32(TEST_CALLER_UID);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: StartRemoteIntentInner_MissingAccessToken_005
 * @tc.desc: StartRemoteIntentInner when accessToken is missing after requestCode
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_MissingAccessToken_005, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    want.Marshalling(data);
    data.WriteInt32(TEST_CALLER_UID);
    data.WriteUint64(TEST_REQUEST_CODE);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: StartRemoteIntentInner_MissingSpecifyTokenId_006
 * @tc.desc: StartRemoteIntentInner when specifyTokenId is missing after accessToken
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_MissingSpecifyTokenId_006, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    want.Marshalling(data);
    data.WriteInt32(TEST_CALLER_UID);
    data.WriteUint64(TEST_REQUEST_CODE);
    data.WriteUint32(TEST_ACCESS_TOKEN);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: StartRemoteIntentInner_NormalCallbackNull_007
 * @tc.desc: StartRemoteIntentInner normal path with callback nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_NormalCallbackNull_007, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    want.Marshalling(data);
    data.WriteInt32(TEST_CALLER_UID);
    data.WriteUint64(TEST_REQUEST_CODE);
    data.WriteUint32(TEST_ACCESS_TOKEN);
    data.WriteUint32(TEST_SPECIFY_TOKEN_ID);
    data.WriteRemoteObject(nullptr);

    EXPECT_CALL(*deviceInfoMock_, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>("local_device_id"), Return(true)));

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: StartRemoteIntentInner_NormalCallbackNonNull_008
 * @tc.desc: StartRemoteIntentInner normal path with non-null callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, StartRemoteIntentInner_NormalCallbackNonNull_008, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    data.WriteParcelable(&want);
    data.WriteInt32(TEST_CALLER_UID);
    data.WriteUint64(TEST_REQUEST_CODE);
    data.WriteUint32(TEST_ACCESS_TOKEN);
    data.WriteUint32(TEST_SPECIFY_TOKEN_ID);
    sptr<IRemoteObject> cb = new MockRemoteStub();
    data.WriteRemoteObject(cb);

    EXPECT_CALL(*deviceInfoMock_, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>("local_device_id"), Return(true)));

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}


/**
 * @tc.name: SendIntentResultInner_NotFoundation_001
 * @tc.desc: SendIntentResultInner when IsFoundationCall returns false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_NotFoundation_001, TestSize.Level3)
{
    g_isFoundationCall = false;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.Marshalling(data);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: SendIntentResultInner_WantNull_002
 * @tc.desc: SendIntentResultInner when Want deserialization returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_WantNull_002, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: SendIntentResultInner_MissingCallerUid_003
 * @tc.desc: SendIntentResultInner when callerUid is missing after Want
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_MissingCallerUid_003, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    want.Marshalling(data);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: SendIntentResultInner_MissingRequestCode_004
 * @tc.desc: SendIntentResultInner when requestCode is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_MissingRequestCode_004, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    want.Marshalling(data);
    data.WriteInt32(TEST_CALLER_UID);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: SendIntentResultInner_MissingAccessToken_005
 * @tc.desc: SendIntentResultInner when accessToken is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_MissingAccessToken_005, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    want.Marshalling(data);
    data.WriteInt32(TEST_CALLER_UID);
    data.WriteUint64(TEST_REQUEST_CODE);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: SendIntentResultInner_MissingSpecifyTokenId_006
 * @tc.desc: SendIntentResultInner when specifyTokenId is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_MissingSpecifyTokenId_006, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    want.Marshalling(data);
    data.WriteInt32(TEST_CALLER_UID);
    data.WriteUint64(TEST_REQUEST_CODE);
    data.WriteUint32(TEST_ACCESS_TOKEN);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: SendIntentResultInner_NormalWithMsg_007
 * @tc.desc: SendIntentResultInner normal path with non-empty resultMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_NormalWithMsg_007, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    data.WriteParcelable(&want);
    data.WriteInt32(TEST_CALLER_UID);
    data.WriteUint64(TEST_REQUEST_CODE);
    data.WriteUint32(TEST_ACCESS_TOKEN);
    data.WriteUint32(TEST_SPECIFY_TOKEN_ID);
    data.WriteString(TEST_RESULT_MSG);

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
}

/**
 * @tc.name: SendIntentResultInner_NormalEmptyMsg_008
 * @tc.desc: SendIntentResultInner normal path with empty resultMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentServiceStubTest, SendIntentResultInner_NormalEmptyMsg_008, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    OHOS::AAFwk::Want want;
    data.WriteParcelable(&want);
    data.WriteInt32(TEST_CALLER_UID);
    data.WriteUint64(TEST_REQUEST_CODE);
    data.WriteUint32(TEST_ACCESS_TOKEN);
    data.WriteUint32(TEST_SPECIFY_TOKEN_ID);
    data.WriteString("");

    EXPECT_EQ(service_->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT), data, reply, option),
        ERR_DI_PERMISSION_DENIED);
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

} // namespace DistributedSchedule
} // namespace OHOS
