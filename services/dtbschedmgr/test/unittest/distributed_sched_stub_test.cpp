/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#define private public
#include "distributed_sched_service.h"
#undef private
#include "distributed_sched_stub_test.h"
#include "distributed_sched_util.h"
#include "mock_distributed_sched.h"
#include "mock_remote_stub.h"
#include "parcel_helper.h"
#include "test_log.h"
#include "token_setproc.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::u16string DMS_STUB_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
const std::u16string MOCK_INVALID_DESCRIPTOR = u"invalid descriptor";
const std::string EXTRO_INFO_JSON_KEY_ACCESS_TOKEN = "accessTokenID";
constexpr const char* FOUNDATION_PROCESS_NAME = "foundation";
const char *PERMS[] = {
    "ohos.permission.DISTRIBUTED_DATASYNC"
};
}

void DistributedSchedStubTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedSchedStubTest::SetUpTestCase" << std::endl;
}

void DistributedSchedStubTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedSchedStubTest::TearDownTestCase" << std::endl;
}

void DistributedSchedStubTest::TearDown()
{
    DTEST_LOG << "DistributedSchedStubTest::TearDown" << std::endl;
}

void DistributedSchedStubTest::SetUp()
{
    DTEST_LOG << "DistributedSchedStubTest::SetUp" << std::endl;
    distributedSchedStub_ = new DistributedSchedService();
    DistributedSchedUtil::MockProcessAndPermission(FOUNDATION_PROCESS_NAME, PERMS, 1);
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: check OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, OnRemoteRequest_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest OnRemoteRequest_001 begin" << std::endl;
    int32_t code = DistributedSchedStub::START_REMOTE_ABILITY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(MOCK_INVALID_DESCRIPTOR);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest OnRemoteRequest_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityInner_001
 * @tc.desc: check StartRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteAbilityInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityInner_001 begin" << std::endl;
    int32_t code = DistributedSchedStub::START_REMOTE_ABILITY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityInner_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityInner_002
 * @tc.desc: check StartRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteAbilityInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityInner_002 begin" << std::endl;
    int32_t code = DistributedSchedStub::START_REMOTE_ABILITY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    Want want;
    data.WriteParcelable(&want);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(result, ERR_NONE);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteParcelable(&want);
    int32_t callingUid = 0;
    data.WriteInt32(callingUid);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(result, ERR_NONE);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteParcelable(&want);
    data.WriteInt32(callingUid);
    int32_t requestCode = 0;
    data.WriteInt32(requestCode);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(result, ERR_NONE);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteParcelable(&want);
    data.WriteInt32(callingUid);
    data.WriteInt32(requestCode);
    uint32_t accessToken = 0;
    data.WriteUint32(accessToken);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityInner_002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityInner_003
 * @tc.desc: check StartRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteAbilityInner_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityInner_003 begin" << std::endl;
    int32_t code = DistributedSchedStub::START_REMOTE_ABILITY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    Want want;
    data.WriteParcelable(&want);
    int32_t callingUid = 0;
    data.WriteInt32(callingUid);
    int32_t requestCode = 0;
    data.WriteInt32(requestCode);
    uint32_t accessToken = GetSelfTokenID();
    data.WriteUint32(accessToken);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityInner_003 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityInner_004
 * @tc.desc: check StartRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteAbilityInner_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityInner_004 begin" << std::endl;
    int32_t code = DistributedSchedStub::START_REMOTE_ABILITY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityInner_004 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemoteInner_001
 * @tc.desc: check StartAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartAbilityFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartAbilityFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->StartAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    Want want;
    data.WriteParcelable(&want);
    result = distributedSchedStub_->StartAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteParcelable(&want);
    AbilityInfo abilityInfo;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    abilityInfo.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo);
    data.WriteParcelable(&compatibleAbilityInfo);
    result = distributedSchedStub_->StartAbilityFromRemoteInner(data, reply);
    EXPECT_NE(result, ERR_NONE);

    data.WriteParcelable(&want);
    data.WriteParcelable(&compatibleAbilityInfo);
    int32_t requestCode = 0;
    data.WriteInt32(requestCode);
    result = distributedSchedStub_->StartAbilityFromRemoteInner(data, reply);
    EXPECT_NE(result, ERR_NONE);

    data.WriteParcelable(&want);
    data.WriteParcelable(&compatibleAbilityInfo);
    data.WriteInt32(requestCode);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    data.WriteInt32(callerInfo.uid);
    result = distributedSchedStub_->StartAbilityFromRemoteInner(data, reply);
    EXPECT_NE(result, ERR_NONE);

    data.WriteParcelable(&want);
    data.WriteParcelable(&compatibleAbilityInfo);
    data.WriteInt32(requestCode);
    data.WriteInt32(callerInfo.uid);
    callerInfo.sourceDeviceId = "";
    data.WriteString(callerInfo.sourceDeviceId);
    result = distributedSchedStub_->StartAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartAbilityFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemoteInner_002
 * @tc.desc: check StartAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartAbilityFromRemoteInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartAbilityFromRemoteInner_002 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    Want want;
    AbilityInfo abilityInfo;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    int32_t requestCode = 0;
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "";

    data.WriteParcelable(&want);
    data.WriteParcelable(&compatibleAbilityInfo);
    data.WriteInt32(requestCode);
    data.WriteInt32(callerInfo.uid);
    data.WriteString(callerInfo.sourceDeviceId);
    DistributedSchedService::AccountInfo accountInfo;
    accountInfo.accountType = 0;
    data.WriteInt32(accountInfo.accountType);
    int32_t result = distributedSchedStub_->StartAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);

    data.WriteParcelable(&want);
    data.WriteParcelable(&compatibleAbilityInfo);
    data.WriteInt32(requestCode);
    data.WriteInt32(callerInfo.uid);
    data.WriteString(callerInfo.sourceDeviceId);
    data.WriteInt32(accountInfo.accountType);
    callerInfo.callerAppId = "";
    data.WriteString(callerInfo.callerAppId);
    result = distributedSchedStub_->StartAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartAbilityFromRemoteInner_002 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemoteInner_003
 * @tc.desc: check StartAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartAbilityFromRemoteInner_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartAbilityFromRemoteInner_003 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    Want want;
    data.WriteParcelable(&want);
    AbilityInfo abilityInfo;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    data.WriteParcelable(&compatibleAbilityInfo);
    int32_t requestCode = 0;
    data.WriteInt32(requestCode);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    data.WriteInt32(callerInfo.uid);
    callerInfo.sourceDeviceId = "";
    data.WriteString(callerInfo.sourceDeviceId);
    DistributedSchedService::AccountInfo accountInfo;
    accountInfo.accountType = 0;
    data.WriteInt32(accountInfo.accountType);
    data.WriteStringVector(accountInfo.groupIdList);
    callerInfo.callerAppId = "";
    data.WriteString(callerInfo.callerAppId);
    nlohmann::json extraInfoJson;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = 0;
    std::string extraInfo = extraInfoJson.dump();
    data.WriteString(extraInfo);
    int32_t result = distributedSchedStub_->StartAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartAbilityFromRemoteInner_003 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemoteInner_001
 * @tc.desc: check SendResultFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, SendResultFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest SendResultFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    Want want;
    data.WriteParcelable(&want);
    result = distributedSchedStub_->SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteParcelable(&want);
    int32_t requestCode = 0;
    data.WriteInt32(requestCode);
    result = distributedSchedStub_->SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteParcelable(&want);
    data.WriteInt32(requestCode);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    data.WriteInt32(callerInfo.uid);
    result = distributedSchedStub_->SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteParcelable(&want);
    data.WriteInt32(requestCode);
    data.WriteInt32(callerInfo.uid);
    callerInfo.sourceDeviceId = "";
    data.WriteString(callerInfo.sourceDeviceId);
    result = distributedSchedStub_->SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest SendResultFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemoteInner_002
 * @tc.desc: check SendResultFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, SendResultFromRemoteInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest SendResultFromRemoteInner_002 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    Want want;
    int32_t requestCode = 0;
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "";
    callerInfo.callerAppId = "";

    data.WriteParcelable(&want);
    data.WriteInt32(requestCode);
    data.WriteInt32(callerInfo.uid);
    data.WriteString(callerInfo.sourceDeviceId);
    DistributedSchedService::AccountInfo accountInfo;
    accountInfo.accountType = 0;
    data.WriteInt32(accountInfo.accountType);
    int32_t result = distributedSchedStub_->SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteParcelable(&want);
    data.WriteInt32(requestCode);
    data.WriteInt32(callerInfo.uid);
    data.WriteString(callerInfo.sourceDeviceId);
    data.WriteInt32(accountInfo.accountType);
    data.WriteString(callerInfo.callerAppId);
    int32_t resultCode = 0;
    data.WriteInt32(resultCode);
    result = distributedSchedStub_->SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteParcelable(&want);
    data.WriteInt32(requestCode);
    data.WriteInt32(callerInfo.uid);
    data.WriteString(callerInfo.sourceDeviceId);
    data.WriteInt32(accountInfo.accountType);
    data.WriteString(callerInfo.callerAppId);
    data.WriteInt32(resultCode);
    nlohmann::json extraInfoJson;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = 0;
    std::string extraInfo = extraInfoJson.dump();
    data.WriteString(extraInfo);
    result = distributedSchedStub_->SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest SendResultFromRemoteInner_002 end" << std::endl;
}

/**
 * @tc.name: ContinueMissionInner_001
 * @tc.desc: check ContinueMissionInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ContinueMissionInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest ContinueMissionInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->ContinueMissionInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest ContinueMissionInner_001 end" << std::endl;
}

/**
 * @tc.name: ContinueMissionInner_002
 * @tc.desc: check ContinueMissionInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ContinueMissionInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest ContinueMissionInner_002 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    std::string srcDevId = "";
    data.WriteString(srcDevId);
    result = distributedSchedStub_->ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);
    
    data.WriteString(srcDevId);
    std::string dstDevId = "";
    data.WriteString(dstDevId);
    result = distributedSchedStub_->ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteString(srcDevId);
    data.WriteString(dstDevId);
    int32_t missionId = 0;
    data.WriteInt32(missionId);
    result = distributedSchedStub_->ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteString(srcDevId);
    data.WriteString(dstDevId);
    data.WriteInt32(missionId);
    sptr<IRemoteObject> dsched = new DistributedSchedService();
    data.WriteRemoteObject(dsched);
    result = distributedSchedStub_->ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteString(srcDevId);
    data.WriteString(dstDevId);
    data.WriteInt32(missionId);
    data.WriteRemoteObject(dsched);
    WantParams wantParams = {};
    data.WriteParcelable(&wantParams);
    result = distributedSchedStub_->ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest ContinueMissionInner_002 end" << std::endl;
}

/**
 * @tc.name: StartContinuationInner_001
 * @tc.desc: check StartContinuationInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartContinuationInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartContinuationInner_001 begin" << std::endl;
    int32_t code = DistributedSchedStub::START_CONTINUATION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StartContinuationInner_001 end" << std::endl;
}

/**
 * @tc.name: StartContinuationInner_002
 * @tc.desc: check StartContinuationInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartContinuationInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartContinuationInner_002 begin" << std::endl;
    int32_t code = DistributedSchedStub::START_CONTINUATION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    Want want;
    data.WriteParcelable(&want);
    int32_t missionId = 0;
    data.WriteInt32(missionId);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    int32_t status = 0;
    data.WriteInt32(status);
    uint32_t accessToken = GetSelfTokenID();
    data.WriteUint32(accessToken);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartContinuationInner_002 end" << std::endl;
}

/**
 * @tc.name: StartContinuationInner_003
 * @tc.desc: check StartContinuationInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartContinuationInner_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartContinuationInner_003 begin" << std::endl;
    int32_t code = DistributedSchedStub::START_CONTINUATION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    Want want;
    data.WriteParcelable(&want);
    int32_t missionId = 0;
    data.WriteInt32(missionId);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    int32_t status = 0;
    data.WriteInt32(status);
    uint32_t accessToken = 0;
    data.WriteUint32(accessToken);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StartContinuationInner_003 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteContinuationInner_001
 * @tc.desc: check NotifyCompleteContinuationInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyCompleteContinuationInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyCompleteContinuationInner_001 begin" << std::endl;
    int32_t code = DistributedSchedStub::NOTIFY_COMPLETE_CONTINUATION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest NotifyCompleteContinuationInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteContinuationInner_002
 * @tc.desc: check NotifyCompleteContinuationInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyCompleteContinuationInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyCompleteContinuationInner_002 begin" << std::endl;
    int32_t code = DistributedSchedStub::NOTIFY_COMPLETE_CONTINUATION;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::u16string devId = u"192.168.43.100";
    data.WriteString16(devId);
    int32_t sessionId = 0;
    data.WriteInt32(sessionId);
    bool isSuccess = false;
    data.WriteBool(isSuccess);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest NotifyCompleteContinuationInner_002 end" << std::endl;
}

/**
 * @tc.name: NotifyContinuationResultFromRemoteInner_001
 * @tc.desc: check NotifyContinuationResultFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyContinuationResultFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyContinuationResultFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t sessionId = 0;
    data.WriteInt32(sessionId);
    bool continuationResult = false;
    data.WriteBool(continuationResult);
    int32_t result = distributedSchedStub_->NotifyContinuationResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedStubTest NotifyContinuationResultFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: ConnectRemoteAbilityInner_001
 * @tc.desc: check ConnectRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ConnectRemoteAbilityInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest ConnectRemoteAbilityInner_001 begin" << std::endl;
    int32_t code = DistributedSchedStub::CONNECT_REMOTE_ABILITY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest ConnectRemoteAbilityInner_001 end" << std::endl;
}

/**
 * @tc.name: ConnectRemoteAbilityInner_002
 * @tc.desc: check ConnectRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ConnectRemoteAbilityInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest ConnectRemoteAbilityInner_002 begin" << std::endl;
    int32_t code = DistributedSchedStub::CONNECT_REMOTE_ABILITY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    Want want;
    data.WriteParcelable(&want);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    int32_t callerPid = 0;
    data.WriteInt32(callerPid);
    uint32_t accessToken = 0;
    data.WriteUint32(accessToken);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest ConnectRemoteAbilityInner_002 end" << std::endl;
}

/**
 * @tc.name: ConnectRemoteAbilityInner_003
 * @tc.desc: check ConnectRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ConnectRemoteAbilityInner_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest ConnectRemoteAbilityInner_003 begin" << std::endl;
    int32_t code = DistributedSchedStub::CONNECT_REMOTE_ABILITY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    Want want;
    data.WriteParcelable(&want);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    int32_t callerPid = 0;
    data.WriteInt32(callerPid);
    uint32_t accessToken = GetSelfTokenID();
    data.WriteUint32(accessToken);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest ConnectRemoteAbilityInner_003 end" << std::endl;
}

/**
 * @tc.name: DisconnectRemoteAbilityInner_001
 * @tc.desc: check DisconnectRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, DisconnectRemoteAbilityInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest DisconnectRemoteAbilityInner_001 begin" << std::endl;
    int32_t code = DistributedSchedStub::DISCONNECT_REMOTE_ABILITY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest DisconnectRemoteAbilityInner_001 end" << std::endl;
}

/**
 * @tc.name: DisconnectRemoteAbilityInner_002
 * @tc.desc: check DisconnectRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, DisconnectRemoteAbilityInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest DisconnectRemoteAbilityInner_002 begin" << std::endl;
    int32_t code = DistributedSchedStub::DISCONNECT_REMOTE_ABILITY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    sptr<IRemoteObject> connect;
    data.WriteRemoteObject(connect);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    uint32_t accessToken = 0;
    data.WriteUint32(accessToken);
    int result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest DisconnectRemoteAbilityInner_002 end" << std::endl;
}

/**
 * @tc.name: DisconnectRemoteAbilityInner_003
 * @tc.desc: check DisconnectRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, DisconnectRemoteAbilityInner_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest DisconnectRemoteAbilityInner_003 begin" << std::endl;
    int32_t code = DistributedSchedStub::DISCONNECT_REMOTE_ABILITY;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    sptr<IRemoteObject> connect;
    data.WriteRemoteObject(connect);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    uint32_t accessToken = GetSelfTokenID();
    data.WriteUint32(accessToken);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest DisconnectRemoteAbilityInner_003 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemoteInner_001
 * @tc.desc: check ConnectAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ConnectAbilityFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest ConnectAbilityFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->ConnectAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    Want want;
    data.WriteParcelable(&want);
    result = distributedSchedStub_->ConnectAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteParcelable(&want);
    AbilityInfo abilityInfo;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    abilityInfo.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo);
    data.WriteParcelable(&compatibleAbilityInfo);
    sptr<IRemoteObject> connect;
    data.WriteRemoteObject(connect);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    data.WriteInt32(callerInfo.uid);
    callerInfo.pid = 0;
    data.WriteInt32(callerInfo.pid);
    callerInfo.sourceDeviceId = "";
    data.WriteString(callerInfo.sourceDeviceId);
    DistributedSchedService::AccountInfo accountInfo;
    accountInfo.accountType = 0;
    data.WriteInt32(accountInfo.accountType);
    callerInfo.callerAppId = "";
    data.WriteString(callerInfo.callerAppId);
    result = distributedSchedStub_->ConnectAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest ConnectAbilityFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemoteInner_002
 * @tc.desc: check ConnectAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ConnectAbilityFromRemoteInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest ConnectAbilityFromRemoteInner_002 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    Want want;
    data.WriteParcelable(&want);
    AbilityInfo abilityInfo;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    abilityInfo.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo);
    data.WriteParcelable(&compatibleAbilityInfo);
    sptr<IRemoteObject> connect;
    data.WriteRemoteObject(connect);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    data.WriteInt32(callerInfo.uid);
    callerInfo.pid = 0;
    data.WriteInt32(callerInfo.pid);
    callerInfo.sourceDeviceId = "";
    data.WriteString(callerInfo.sourceDeviceId);
    DistributedSchedService::AccountInfo accountInfo;
    accountInfo.accountType = 0;
    data.WriteInt32(accountInfo.accountType);
    data.WriteStringVector(accountInfo.groupIdList);
    callerInfo.callerAppId = "";
    data.WriteString(callerInfo.callerAppId);
    nlohmann::json extraInfoJson;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = 0;
    std::string extraInfo = extraInfoJson.dump();
    data.WriteString(extraInfo);
    int32_t result = distributedSchedStub_->ConnectAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest ConnectAbilityFromRemoteInner_002 end" << std::endl;
}

/**
 * @tc.name: DisconnectAbilityFromRemoteInner_001
 * @tc.desc: check DisconnectAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, DisconnectAbilityFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest DisconnectAbilityFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t uid = 0;
    data.WriteInt32(uid);
    std::string sourceDeviceId = "";
    data.WriteString(sourceDeviceId);
    int32_t result = distributedSchedStub_->DisconnectAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest DisconnectAbilityFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyProcessDiedFromRemoteInner_001
 * @tc.desc: check NotifyProcessDiedFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyProcessDiedFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyProcessDiedFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t uid = 0;
    data.WriteInt32(uid);
    int32_t pid = 0;
    data.WriteInt32(pid);
    std::string sourceDeviceId = "";
    data.WriteString(sourceDeviceId);
    int32_t result = distributedSchedStub_->NotifyProcessDiedFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest NotifyProcessDiedFromRemoteInner_001 end" << std::endl;
}

#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
/**
 * @tc.name: GetMissionInfosInner_001
 * @tc.desc: check GetMissionInfosInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, GetMissionInfosInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest GetMissionInfosInner_001 begin" << std::endl;
    int32_t code = DistributedSchedStub::GET_MISSION_INFOS;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest GetMissionInfosInner_001 end" << std::endl;
}

/**
 * @tc.name: GetMissionInfosInner_002
 * @tc.desc: check GetMissionInfosInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, GetMissionInfosInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest GetMissionInfosInner_002 begin" << std::endl;
    int32_t code = DistributedSchedStub::GET_MISSION_INFOS;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::u16string deviceId = u"192.168.43.100";
    data.WriteString16(deviceId);
    int32_t numMissions = 0;
    data.WriteInt32(numMissions);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedStubTest GetMissionInfosInner_002 end" << std::endl;
}

/**
 * @tc.name: GetRemoteMissionSnapshotInfoInner_001
 * @tc.desc: check GetRemoteMissionSnapshotInfoInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, GetRemoteMissionSnapshotInfoInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest GetRemoteMissionSnapshotInfoInner_001 begin" << std::endl;
    int32_t code = DistributedSchedStub::GET_REMOTE_MISSION_SNAPSHOT_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest GetRemoteMissionSnapshotInfoInner_001 end" << std::endl;
}

/**
 * @tc.name: GetRemoteMissionSnapshotInfoInner_002
 * @tc.desc: check GetRemoteMissionSnapshotInfoInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, GetRemoteMissionSnapshotInfoInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest GetRemoteMissionSnapshotInfoInner_002 begin" << std::endl;
    int32_t code = DistributedSchedStub::GET_REMOTE_MISSION_SNAPSHOT_INFO;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::string networkId = "255.255.255.255";
    data.WriteString(networkId);
    int32_t missionId = -1;
    data.WriteInt32(missionId);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteString(networkId);
    missionId = 0;
    data.WriteInt32(missionId);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest GetRemoteMissionSnapshotInfoInner_002 end" << std::endl;
}
#endif
}
}