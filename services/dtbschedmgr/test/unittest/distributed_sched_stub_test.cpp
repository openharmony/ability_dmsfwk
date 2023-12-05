/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "bundle/bundle_manager_internal.h"
#include "distributed_sched_service.h"
#undef private
#include "distributed_sched_stub_test.h"
#include "distributed_sched_util.h"
#define private public
#include "mission/distributed_sched_mission_manager.h"
#undef private
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
const std::string EXTRO_INFO_JSON_KEY_REQUEST_CODE = "requestCode";
const std::string DMS_VERSION_ID = "dmsVersion";
const std::string CMPT_PARAM_FREEINSTALL_BUNDLENAMES = "ohos.extra.param.key.allowedBundles";
constexpr const char* FOUNDATION_PROCESS_NAME = "foundation";
constexpr int32_t MAX_WAIT_TIME = 5000;
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
    distributedSchedStub_ = nullptr;
}

void DistributedSchedStubTest::SetUp()
{
    DTEST_LOG << "DistributedSchedStubTest::SetUp" << std::endl;
    distributedSchedStub_ = new DistributedSchedService();
    DistributedSchedUtil::MockProcessAndPermission(FOUNDATION_PROCESS_NAME, PERMS, 1);
}

void DistributedSchedStubTest::WaitHandlerTaskDone(const std::shared_ptr<AppExecFwk::EventHandler> &handler)
{
    DTEST_LOG << "DistributedSchedStubTest::WaitHandlerTaskDone" << std::endl;
    // Wait until all asyn tasks are completed before exiting the test suite
    isTaskDone_ = false;
    auto taskDoneNotifyTask = [this]() {
        std::lock_guard<std::mutex> autoLock(taskDoneLock_);
        isTaskDone_ = true;
        taskDoneCondition_.notify_all();
    };
    if (handler != nullptr) {
        handler->PostTask(taskDoneNotifyTask);
    }
    std::unique_lock<std::mutex> lock(taskDoneLock_);
    taskDoneCondition_.wait_for(lock, std::chrono::milliseconds(MAX_WAIT_TIME),
        [&] () { return isTaskDone_; });
}

void DistributedSchedStubTest::CallerInfoMarshalling(const CallerInfo& callerInfo, MessageParcel& data)
{
    data.WriteInt32(callerInfo.uid);
    data.WriteInt32(callerInfo.pid);
    data.WriteInt32(callerInfo.callerType);
    data.WriteString(callerInfo.sourceDeviceId);
    data.WriteInt32(callerInfo.duid);
    data.WriteString(callerInfo.callerAppId);
    data.WriteInt32(callerInfo.dmsVersion);
}

void DistributedSchedStubTest::FreeInstallInfoMarshalling(const CallerInfo& callerInfo,
    const DistributedSchedService::AccountInfo accountInfo, const int64_t taskId, MessageParcel& data)
{
    data.WriteInt32(callerInfo.uid);
    data.WriteString(callerInfo.sourceDeviceId);
    data.WriteInt32(accountInfo.accountType);
    data.WriteStringVector(accountInfo.groupIdList);
    data.WriteString(callerInfo.callerAppId);
    data.WriteInt64(taskId);
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: check OnRemoteRequest
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, OnRemoteRequest_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest OnRemoteRequest_001 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY);
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
 * @tc.require: I70WDT
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteAbilityInner_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityInner_004 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t ret = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);

    Want want;
    std::string eventName;
    int32_t result = 0;
    int32_t uid = -1;
    distributedSchedStub_->ReportEvent(want, eventName, result, uid);

    const std::string bundleName = "com.third.hiworld.example";
    uid = BundleManagerInternal::GetUidFromBms(bundleName);
    if (uid <= 0) {
        return;
    }
    distributedSchedStub_->ReportEvent(want, eventName, result, uid);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
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
 * @tc.name:ContinueMissionOfBundleNameInner_003
 * @tc.desc: call ContinueMissionOfBundleNameInner
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DistributedSchedStubTest, ContinueMissionOfBundleNameInner_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest ContinueMissionOfBundleNameInner_003 start" << std::endl;

    MessageParcel data;
    MessageParcel reply;

    /**
     * @tc.steps: step1. test ContinueMission when callback is nullptr;
     */
    std::string srcDevId = "srcDevId";
    std::string dstDevId = "dstDevId";
    std::string bundleName = "bundleName";
    data.WriteString(srcDevId);
    data.WriteString(dstDevId);
    data.WriteString(bundleName);
    int32_t result = distributedSchedStub_->ContinueMissionOfBundleNameInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    DTEST_LOG << "DistributedSchedStubTest ContinueMissionOfBundleNameInner_003 end" << std::endl;
}

/**
 * @tc.name: StartContinuationInner_001
 * @tc.desc: check StartContinuationInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartContinuationInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartContinuationInner_001 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_CONTINUATION);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_CONTINUATION);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_CONTINUATION);
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
    EXPECT_EQ(result, ERR_NONE);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_COMPLETE_CONTINUATION);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_COMPLETE_CONTINUATION);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::CONNECT_REMOTE_ABILITY);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::CONNECT_REMOTE_ABILITY);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::CONNECT_REMOTE_ABILITY);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::DISCONNECT_REMOTE_ABILITY);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::DISCONNECT_REMOTE_ABILITY);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::DISCONNECT_REMOTE_ABILITY);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::GET_MISSION_INFOS);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::GET_MISSION_INFOS);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::GET_REMOTE_MISSION_SNAPSHOT_INFO);
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
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::GET_REMOTE_MISSION_SNAPSHOT_INFO);
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

/**
 * @tc.name: RegisterMissionListenerInner_001
 * @tc.desc: check RegisterMissionListenerInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, RegisterMissionListenerInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest RegisterMissionListenerInner_001 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_MISSION_LISTENER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest RegisterMissionListenerInner_001 end" << std::endl;
}

/**
 * @tc.name: RegisterMissionListenerInner_002
 * @tc.desc: check RegisterMissionListenerInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, RegisterMissionListenerInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest RegisterMissionListenerInner_002 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_MISSION_LISTENER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::u16string devId = u"192.168.43.100";
    data.WriteString16(devId);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteString16(devId);
    sptr<IRemoteObject> missionChangedListener = new DistributedSchedService();
    data.WriteRemoteObject(missionChangedListener);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest RegisterMissionListenerInner_002 end" << std::endl;
}

/**
 * @tc.name: RegisterMissionListenerInner_003
 * @tc.desc: check RegisterOnListenerInner
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DistributedSchedStubTest, RegisterOnListenerInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest RegisterMissionListenerInner_003 begin" << std::endl;
    
    MessageParcel data;
    MessageParcel reply;

    /**
     * @tc.steps: step1. test RegisterOnListenerInner when type is empty;
     */
    int32_t result = distributedSchedStub_->RegisterOnListenerInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    /**
     * @tc.steps: step2. test RegisterOnListenerInner when type is not empty;
     */
    data.WriteString("type");
    result = distributedSchedStub_->RegisterOnListenerInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    /**
     * @tc.steps: step3. test RegisterOnListenerInner when onListener is not empty;
     */
    data.WriteString("type");
    sptr<IRemoteObject> onListener = new DistributedSchedService();
    data.WriteRemoteObject(onListener);
    result = distributedSchedStub_->RegisterOnListenerInner(data, reply);
    EXPECT_EQ(result, ERR_OK);

    DTEST_LOG << "DistributedSchedStubTest RegisterMissionListenerInner_003 end" << std::endl;
}

/**
 * @tc.name: UnRegisterMissionListenerInner_001
 * @tc.desc: check UnRegisterMissionListenerInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, UnRegisterMissionListenerInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest UnRegisterMissionListenerInner_001 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::UNREGISTER_MISSION_LISTENER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest UnRegisterMissionListenerInner_001 end" << std::endl;
}

/**
 * @tc.name: UnRegisterMissionListenerInner_002
 * @tc.desc: check UnRegisterMissionListenerInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, UnRegisterMissionListenerInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest UnRegisterMissionListenerInner_002 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::UNREGISTER_MISSION_LISTENER);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::u16string devId = u"192.168.43.100";
    data.WriteString16(devId);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteString16(devId);
    sptr<IRemoteObject> missionChangedListener = new DistributedSchedService();
    data.WriteRemoteObject(missionChangedListener);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest UnRegisterMissionListenerInner_002 end" << std::endl;
}

/**
 * @tc.name: StartSyncMissionsFromRemoteInner_001
 * @tc.desc: check StartSyncMissionsFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartSyncMissionsFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartSyncMissionsFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->StartSyncMissionsFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest StartSyncMissionsFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: StartSyncMissionsFromRemoteInner_002
 * @tc.desc: check StartSyncMissionsFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartSyncMissionsFromRemoteInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartSyncMissionsFromRemoteInner_002 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    CallerInfo callerInfo;
    CallerInfoMarshalling(callerInfo, data);

    DistributedSchedMissionManager::GetInstance().Init();
    int32_t result = distributedSchedStub_->StartSyncMissionsFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    WaitHandlerTaskDone(DistributedSchedMissionManager::GetInstance().missionHandler_);
    DTEST_LOG << "DistributedSchedStubTest StartSyncMissionsFromRemoteInner_002 end" << std::endl;
}

/**
 * @tc.name: StopSyncRemoteMissionsInner_001
 * @tc.desc: check StopSyncRemoteMissionsInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StopSyncRemoteMissionsInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StopSyncRemoteMissionsInner_001 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::STOP_SYNC_MISSIONS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StopSyncRemoteMissionsInner_001 end" << std::endl;
}

/**
 * @tc.name: StopSyncRemoteMissionsInner_002
 * @tc.desc: check StopSyncRemoteMissionsInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StopSyncRemoteMissionsInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StopSyncRemoteMissionsInner_002 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::STOP_SYNC_MISSIONS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::u16string deviceId = u"192.168.43.100";
    data.WriteString16(deviceId);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StopSyncRemoteMissionsInner_002 end" << std::endl;
}

/**
 * @tc.name: StopSyncMissionsFromRemoteInner_001
 * @tc.desc: check StopSyncMissionsFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StopSyncMissionsFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StopSyncMissionsFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->StopSyncMissionsFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest StopSyncMissionsFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: StopSyncMissionsFromRemoteInner_002
 * @tc.desc: check StopSyncMissionsFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StopSyncMissionsFromRemoteInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StopSyncMissionsFromRemoteInner_002 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    CallerInfo callerInfo;
    CallerInfoMarshalling(callerInfo, data);

    DistributedSchedMissionManager::GetInstance().Init();
    int32_t result = distributedSchedStub_->StopSyncMissionsFromRemoteInner(data, reply);
    EXPECT_NE(result, ERR_FLATTEN_OBJECT);
    WaitHandlerTaskDone(DistributedSchedMissionManager::GetInstance().missionHandler_);
    DTEST_LOG << "DistributedSchedStubTest StopSyncMissionsFromRemoteInner_002 end" << std::endl;
}

/**
 * @tc.name: NotifyMissionsChangedFromRemoteInner_001
 * @tc.desc: check NotifyMissionsChangedFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyMissionsChangedFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyMissionsChangedFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t version = 0;
    data.WriteInt32(version);
    int32_t result = distributedSchedStub_->NotifyMissionsChangedFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest NotifyMissionsChangedFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: StartSyncRemoteMissionsInner_001
 * @tc.desc: check StartSyncRemoteMissionsInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartSyncRemoteMissionsInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartSyncRemoteMissionsInner_001 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_SYNC_MISSIONS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StartSyncRemoteMissionsInner_001 end" << std::endl;
}

/**
 * @tc.name: StartSyncRemoteMissionsInner_002
 * @tc.desc: check StartSyncRemoteMissionsInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartSyncRemoteMissionsInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartSyncRemoteMissionsInner_002 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_SYNC_MISSIONS);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::u16string deviceId = u"192.168.43.100";
    data.WriteString16(deviceId);
    bool fixConflict = false;
    data.WriteBool(fixConflict);
    int64_t tag = 0;
    data.WriteInt64(tag);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartSyncRemoteMissionsInner_002 end" << std::endl;
}

/**
 * @tc.name: SetMissionContinueStateInner_001
 * @tc.desc: check SetMissionContinueStateInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, SetMissionContinueStateInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest SetMissionContinueStateInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t missionId = 0;
    int32_t state = 0;
    data.WriteInt32(missionId);
    data.WriteInt32(state);
    int32_t result = distributedSchedStub_->SetMissionContinueStateInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest SetMissionContinueStateInner_001 end" << std::endl;
}
#endif

/**
 * @tc.name: CallerInfoUnmarshalling_001
 * @tc.desc: check CallerInfoUnmarshalling
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, CallerInfoUnmarshalling_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest CallerInfoUnmarshalling_001 begin" << std::endl;
    MessageParcel data;
    int32_t uid = 0;
    data.WriteInt32(uid);
    int32_t pid = 0;
    data.WriteInt32(pid);
    int32_t callerType = 0;
    data.WriteInt32(callerType);
    std::string sourceDeviceId = "";
    data.WriteString(sourceDeviceId);
    int32_t duid = 0;
    data.WriteInt32(duid);
    std::string callerAppId = "test";
    data.WriteString(callerAppId);
    int32_t version = 0;
    data.WriteInt32(version);
    CallerInfo callerInfo;
    bool result = distributedSchedStub_->CallerInfoUnmarshalling(callerInfo, data);
    EXPECT_TRUE(result);
    DTEST_LOG << "DistributedSchedStubTest CallerInfoUnmarshalling_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityByCallInner_001
 * @tc.desc: check StartRemoteAbilityByCallInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteAbilityByCallInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityByCallInner_001 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY_BY_CALL);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityByCallInner_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityByCallInner_002
 * @tc.desc: check StartRemoteAbilityByCallInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteAbilityByCallInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityByCallInner_002 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY_BY_CALL);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    Want want;
    data.WriteParcelable(&want);
    sptr<IRemoteObject> connect;
    data.WriteRemoteObject(connect);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    int32_t callerPid = 0;
    data.WriteInt32(callerPid);
    uint32_t accessToken = 0;
    data.WriteUint32(accessToken);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityByCallInner_002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityByCallInner_003
 * @tc.desc: check StartRemoteAbilityByCallInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteAbilityByCallInner_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityByCallInner_003 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY_BY_CALL);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    Want want;
    data.WriteParcelable(&want);
    sptr<IRemoteObject> connect;
    data.WriteRemoteObject(connect);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    int32_t callerPid = 0;
    data.WriteInt32(callerPid);
    uint32_t accessToken = GetSelfTokenID();
    data.WriteUint32(accessToken);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteAbilityByCallInner_003 end" << std::endl;
}

/**
 * @tc.name: ReleaseRemoteAbilityInner_001
 * @tc.desc: check ReleaseRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ReleaseRemoteAbilityInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest ReleaseRemoteAbilityInner_001 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::RELEASE_REMOTE_ABILITY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest ReleaseRemoteAbilityInner_001 end" << std::endl;
}

/**
 * @tc.name: ReleaseRemoteAbilityInner_002
 * @tc.desc: check ReleaseRemoteAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ReleaseRemoteAbilityInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest ReleaseRemoteAbilityInner_002 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::RELEASE_REMOTE_ABILITY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    sptr<IRemoteObject> connect;
    data.WriteRemoteObject(connect);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteRemoteObject(connect);
    ElementName element;
    data.WriteParcelable(&element);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest ReleaseRemoteAbilityInner_002 end" << std::endl;
}

/**
 * @tc.name: StartAbilityByCallFromRemoteInner_001
 * @tc.desc: check StartAbilityByCallFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartAbilityByCallFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartAbilityByCallFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

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
    int32_t result = distributedSchedStub_->StartAbilityByCallFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteRemoteObject(connect);
    data.WriteInt32(callerInfo.uid);
    data.WriteInt32(callerInfo.pid);
    data.WriteString(callerInfo.sourceDeviceId);
    data.WriteInt32(accountInfo.accountType);
    data.WriteStringVector(accountInfo.groupIdList);
    data.WriteString(callerInfo.callerAppId);
    nlohmann::json extraInfoJson;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = 0;
    std::string extraInfo = extraInfoJson.dump();
    data.WriteString(extraInfo);
    result = distributedSchedStub_->StartAbilityByCallFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest StartAbilityByCallFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: StartAbilityByCallFromRemoteInner_002
 * @tc.desc: check StartAbilityByCallFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartAbilityByCallFromRemoteInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartAbilityByCallFromRemoteInner_002 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

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
    Want want;
    data.WriteParcelable(&want);
    int32_t result = distributedSchedStub_->StartAbilityByCallFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartAbilityByCallFromRemoteInner_002 end" << std::endl;
}

/**
 * @tc.name: ReleaseAbilityFromRemoteInner_001
 * @tc.desc: check ReleaseAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ReleaseAbilityFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest ReleaseAbilityFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    sptr<IRemoteObject> connect;
    data.WriteRemoteObject(connect);
    int32_t result = distributedSchedStub_->ReleaseAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    data.WriteRemoteObject(connect);
    ElementName element;
    data.WriteParcelable(&element);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = "";
    data.WriteString(callerInfo.sourceDeviceId);
    nlohmann::json extraInfoJson;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = 0;
    std::string extraInfo = extraInfoJson.dump();
    data.WriteString(extraInfo);
    result = distributedSchedStub_->ReleaseAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest ReleaseAbilityFromRemoteInner_001 end" << std::endl;
}

#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
/**
 * @tc.name: StartRemoteShareFormInner_001
 * @tc.desc: check StartRemoteShareFormInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteShareFormInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteShareFormInner_001 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_SHARE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteShareFormInner_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteShareFormInner_002
 * @tc.desc: check StartRemoteShareFormInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteShareFormInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteShareFormInner_002 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_SHARE_FORM);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::string deviceId = "";
    data.WriteString(deviceId);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteString(deviceId);
    FormShareInfo formShareInfo;
    data.WriteParcelable(&formShareInfo);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteShareFormInner_002 end" << std::endl;
}

/**
 * @tc.name: StartShareFormFromRemoteInner_001
 * @tc.desc: check StartShareFormFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartShareFormFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartShareFormFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    std::string deviceId = "";
    data.WriteString(deviceId);
    int32_t result = distributedSchedStub_->StartShareFormFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);

    data.WriteString(deviceId);
    FormShareInfo formShareInfo;
    data.WriteParcelable(&formShareInfo);
    result = distributedSchedStub_->StartShareFormFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartShareFormFromRemoteInner_001 end" << std::endl;
}
#endif

/**
 * @tc.name: StartRemoteFreeInstallInner_001
 * @tc.desc: check StartRemoteFreeInstallInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteFreeInstallInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteFreeInstallInner_001 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_FREE_INSTALL);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedSchedUtil::MockPermission();
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteFreeInstallInner_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteFreeInstallInner_002
 * @tc.desc: check StartRemoteFreeInstallInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteFreeInstallInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteFreeInstallInner_002 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_FREE_INSTALL);
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
    int32_t requestCode = 0;
    data.WriteInt32(requestCode);
    uint32_t accessToken = 0;
    data.WriteUint32(accessToken);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteParcelable(&want);
    data.WriteInt32(callerUid);
    data.WriteInt32(requestCode);
    data.WriteUint32(accessToken);
    sptr<IRemoteObject> callback = new DistributedSchedService();
    data.WriteRemoteObject(callback);
    result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteFreeInstallInner_002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteFreeInstallInner_003
 * @tc.desc: check StartRemoteFreeInstallInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartRemoteFreeInstallInner_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartRemoteFreeInstallInner_003 begin" << std::endl;
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_FREE_INSTALL);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    Want want;
    data.WriteParcelable(&want);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    int32_t requestCode = 0;
    data.WriteInt32(requestCode);
    uint32_t accessToken = GetSelfTokenID();
    data.WriteUint32(accessToken);
    sptr<IRemoteObject> callback = new DistributedSchedService();
    data.WriteRemoteObject(callback);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartRemoteFreeInstallInner_003 end" << std::endl;
}

/**
 * @tc.name: StartFreeInstallFromRemoteInner_001
 * @tc.desc: check StartFreeInstallFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartFreeInstallFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartFreeInstallFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->StartFreeInstallFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest StartFreeInstallFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: StartFreeInstallFromRemoteInner_002
 * @tc.desc: check StartFreeInstallFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartFreeInstallFromRemoteInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartFreeInstallFromRemoteInner_002 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    Want want;
    data.WriteParcelable(&want);

    int32_t result = distributedSchedStub_->StartFreeInstallFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest StartFreeInstallFromRemoteInner_002 end" << std::endl;
}

/**
 * @tc.name: StartFreeInstallFromRemoteInner_003
 * @tc.desc: check StartFreeInstallFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartFreeInstallFromRemoteInner_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartFreeInstallFromRemoteInner_003 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    Want want;
    CallerInfo callerInfo;
    DistributedSchedService::AccountInfo accountInfo;
    int64_t taskId = 0;
    Want cmpWant;
    std::string extraInfo = "extraInfo";
    data.WriteParcelable(&want);
    FreeInstallInfoMarshalling(callerInfo, accountInfo, taskId, data);
    data.WriteParcelable(&cmpWant);
    data.WriteString(extraInfo);

    int32_t result = distributedSchedStub_->StartFreeInstallFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartFreeInstallFromRemoteInner_003 end" << std::endl;
}

/**
 * @tc.name: StartFreeInstallFromRemoteInner_004
 * @tc.desc: check StartFreeInstallFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartFreeInstallFromRemoteInner_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartFreeInstallFromRemoteInner_004 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    Want want;
    CallerInfo callerInfo;
    DistributedSchedService::AccountInfo accountInfo;
    int64_t taskId = 0;
    Want cmpWant;
    std::string extraInfo = "{\"accessTokenID\": 0}";
    data.WriteParcelable(&want);
    FreeInstallInfoMarshalling(callerInfo, accountInfo, taskId, data);
    data.WriteParcelable(&cmpWant);
    data.WriteString(extraInfo);

    int32_t result = distributedSchedStub_->StartFreeInstallFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartFreeInstallFromRemoteInner_004 end" << std::endl;
}

/**
 * @tc.name: StartFreeInstallFromRemoteInner_005
 * @tc.desc: check StartFreeInstallFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartFreeInstallFromRemoteInner_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest StartFreeInstallFromRemoteInner_005 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    Want want;
    CallerInfo callerInfo;
    DistributedSchedService::AccountInfo accountInfo;
    int64_t taskId = 0;
    Want cmpWant;
    std::string extraInfo = "{\"requestCode\": 0, \"accessTokenID\": 0}";
    data.WriteParcelable(&want);
    FreeInstallInfoMarshalling(callerInfo, accountInfo, taskId, data);
    data.WriteParcelable(&cmpWant);
    data.WriteString(extraInfo);

    int32_t result = distributedSchedStub_->StartFreeInstallFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StartFreeInstallFromRemoteInner_005 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteFreeInstallFromRemoteInner_001
 * @tc.desc: check NotifyCompleteFreeInstallFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyCompleteFreeInstallFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyCompleteFreeInstallFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->NotifyCompleteFreeInstallFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    int64_t taskId = 0;
    data.WriteInt64(taskId);
    int32_t resultCode = 0;
    data.WriteInt32(resultCode);
    result = distributedSchedStub_->NotifyCompleteFreeInstallFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest NotifyCompleteFreeInstallFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: StopRemoteExtensionAbilityInner_001
 * @tc.desc: check StopRemoteExtensionAbilityInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StopRemoteExtensionAbilityInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest StopRemoteExtensionAbilityInner_001 begin" << std::endl;
    const char* processName = "testCase";
    const char* permissionState[] = {
        "ohos.permission.ACCESS_SERVICE_DM"
    };
    Want want;
    want.SetElementName("test.test.test", "Ability");
    int32_t callerUid = 0;
    uint32_t accessToken = 0;
    int32_t serviceType = 0;
    MessageParcel reply;

    MessageParcel dataFirst;
    DistributedSchedUtil::MockProcessAndPermission(processName, permissionState, 1);
    auto result = distributedSchedStub_->StopRemoteExtensionAbilityInner(dataFirst, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);

    DistributedSchedUtil::MockProcessAndPermission(FOUNDATION_PROCESS_NAME, permissionState, 1);
    MessageParcel dataSecond;
    result = distributedSchedStub_->StopRemoteExtensionAbilityInner(dataSecond, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    DistributedSchedUtil::MockProcessAndPermission(FOUNDATION_PROCESS_NAME, permissionState, 1);

    MessageParcel dataThird;
    dataThird.WriteParcelable(&want);
    dataThird.WriteInt32(callerUid);
    dataThird.WriteUint32(accessToken);
    dataThird.WriteInt32(serviceType);
    result = distributedSchedStub_->StopRemoteExtensionAbilityInner(dataThird, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StopRemoteExtensionAbilityInner_001 end" << std::endl;
}

/**
 * @tc.name: StopExtensionAbilityFromRemoteInner_001
 * @tc.desc: check StopExtensionAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StopExtensionAbilityFromRemoteInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest StopExtensionAbilityFromRemoteInner_001 begin" << std::endl;
    Want want;
    want.SetElementName("test.test.test", "Ability");
    int32_t callerUid = 0;
    int32_t serviceType = 0;
    std::string deviceId = "1234567890abcdefghijklmnopqrstuvwxyz";
    std::vector<std::string> list = {
        "test1",
        "test2"
    };
    std::string appId = "1234567890abcdefghijklmnopqrstuvwxyz";
    std::string extraInfo = "{ \"accessTokenID\": 1989 }";
    std::string extraInfoEmptr = "";
    MessageParcel reply;

    MessageParcel dataFirst;
    auto result = distributedSchedStub_->StopExtensionAbilityFromRemoteInner(dataFirst, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    MessageParcel dataSecond;
    dataSecond.WriteParcelable(&want);
    dataSecond.WriteInt32(serviceType);
    dataSecond.WriteInt32(callerUid);
    dataSecond.WriteString(deviceId);
    dataSecond.WriteStringVector(list);
    dataSecond.WriteString(appId);
    dataSecond.WriteString(extraInfo);
    result = distributedSchedStub_->StopExtensionAbilityFromRemoteInner(dataSecond, reply);
    EXPECT_EQ(result, ERR_NONE);

    MessageParcel dataThird;
    dataThird.WriteParcelable(&want);
    dataThird.WriteInt32(serviceType);
    dataThird.WriteInt32(callerUid);
    dataThird.WriteString(deviceId);
    dataThird.WriteStringVector(list);
    dataThird.WriteString(appId);
    dataThird.WriteString(extraInfoEmptr);
    result = distributedSchedStub_->StopExtensionAbilityFromRemoteInner(dataThird, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StopExtensionAbilityFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemoteInner_001
 * @tc.desc: check NotifyStateChangedFromRemoteInner
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedStubTest, NotifyStateChangedFromRemoteInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyStateChangedFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t abilityState = 0;
    data.WriteInt32(abilityState);
    int32_t missionId = 0;
    data.WriteInt32(missionId);
    ElementName element;
    data.WriteParcelable(&element);

    int32_t result = distributedSchedStub_->NotifyStateChangedFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest NotifyStateChangedFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemoteInner_002
 * @tc.desc: check NotifyStateChangedFromRemoteInner
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedStubTest, NotifyStateChangedFromRemoteInner_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyStateChangedFromRemoteInner_002 begin" << std::endl;

    nlohmann::json extraInfoJson;
    CallerInfo callerInfo;
    distributedSchedStub_->SaveExtraInfo(extraInfoJson, callerInfo);

    nlohmann::json extraInfoJson1;
    extraInfoJson[DMS_VERSION_ID] = "4";
    CallerInfo callerInfo1;
    distributedSchedStub_->SaveExtraInfo(extraInfoJson1, callerInfo1);

    nlohmann::json extraInfoJson2;
    extraInfoJson[DMS_VERSION_ID] = 4;
    CallerInfo callerInfo2;
    distributedSchedStub_->SaveExtraInfo(extraInfoJson2, callerInfo2);

    MessageParcel data;
    MessageParcel reply;

    int32_t abilityState = 0;
    data.WriteInt32(abilityState);
    int32_t missionId = 0;
    data.WriteInt32(missionId);
    int32_t result = distributedSchedStub_->NotifyStateChangedFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    DTEST_LOG << "DistributedSchedStubTest NotifyStateChangedFromRemoteInner_002 end" << std::endl;
}

/**
 * @tc.name: StopRemoteExtensionAbilityInner_002
 * @tc.desc: check StopRemoteExtensionAbilityInner
 * @tc.type: FUNC
 * @tc.require: I6YLV1
 */
HWTEST_F(DistributedSchedStubTest, StopRemoteExtensionAbilityInner_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest StopRemoteExtensionAbilityInner_002 begin" << std::endl;

    nlohmann::json extraInfoJson;
    CallerInfo callerInfo;
    distributedSchedStub_->SaveExtraInfo(extraInfoJson, callerInfo);

    nlohmann::json extraInfoJson1;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = 0;
    CallerInfo callerInfo1;
    distributedSchedStub_->SaveExtraInfo(extraInfoJson1, callerInfo1);

    nlohmann::json extraInfoJson2;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = "4";
    CallerInfo callerInfo2;
    distributedSchedStub_->SaveExtraInfo(extraInfoJson2, callerInfo2);

    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::STOP_REMOTE_EXTERNSION_ABILITY);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    Want want;
    data.WriteParcelable(&want);
    int32_t callingUid = 0;
    data.WriteInt32(callingUid);
    uint32_t accessToken = GetSelfTokenID();
    data.WriteUint32(accessToken);
    int32_t serviceType = 0;
    data.WriteInt32(serviceType);
    int32_t result = distributedSchedStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StopRemoteExtensionAbilityInner_002 end" << std::endl;
}
}
}