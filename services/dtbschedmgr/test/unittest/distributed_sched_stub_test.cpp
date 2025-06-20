/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "distributed_sched_test_util.h"
#define private public
#include "mission/distributed_sched_mission_manager.h"
#undef private
#include "mock_distributed_sched.h"
#include "mock_remote_stub.h"
#include "multi_user_manager.h"
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
const std::string DMS_UID_SPEC_BUNDLE_NAME = "dmsCallerUidBundleName";
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
}

void DistributedSchedStubTest::SetUp()
{
    DTEST_LOG << "DistributedSchedStubTest::SetUp" << std::endl;
    DistributedSchedUtil::MockProcessAndPermission(FOUNDATION_PROCESS_NAME, PERMS, 1);
}

static bool g_isForeground = true;

bool MultiUserManager::IsCallerForeground(int32_t callingUid)
{
    return g_isForeground;
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
        [&] () { return isTaskDone_;});
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(result, ERR_NONE);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteParcelable(&want);
    int32_t callingUid = 0;
    data.WriteInt32(callingUid);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(result, ERR_NONE);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteParcelable(&want);
    data.WriteInt32(callingUid);
    int32_t requestCode = 0;
    data.WriteInt32(requestCode);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(result, ERR_NONE);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteParcelable(&want);
    data.WriteInt32(callingUid);
    data.WriteInt32(requestCode);
    uint32_t accessToken = 0;
    data.WriteUint32(accessToken);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t ret = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);

    Want want;
    std::string eventName;
    int32_t result = 0;
    int32_t uid = -1;
    DistributedSchedService::GetInstance().ReportEvent(want, eventName, result, uid);
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

    int32_t result = DistributedSchedService::GetInstance().StartAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    Want want;
    data.WriteParcelable(&want);
    result = DistributedSchedService::GetInstance().StartAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    data.WriteParcelable(&want);
    AbilityInfo abilityInfo;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    abilityInfo.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo);
    data.WriteParcelable(&compatibleAbilityInfo);
    result = DistributedSchedService::GetInstance().StartAbilityFromRemoteInner(data, reply);
    EXPECT_NE(result, ERR_NONE);

    data.WriteParcelable(&want);
    data.WriteParcelable(&compatibleAbilityInfo);
    int32_t requestCode = 0;
    data.WriteInt32(requestCode);
    result = DistributedSchedService::GetInstance().StartAbilityFromRemoteInner(data, reply);
    EXPECT_NE(result, ERR_NONE);

    data.WriteParcelable(&want);
    data.WriteParcelable(&compatibleAbilityInfo);
    data.WriteInt32(requestCode);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    data.WriteInt32(callerInfo.uid);
    result = DistributedSchedService::GetInstance().StartAbilityFromRemoteInner(data, reply);
    EXPECT_NE(result, ERR_NONE);

    data.WriteParcelable(&want);
    data.WriteParcelable(&compatibleAbilityInfo);
    data.WriteInt32(requestCode);
    data.WriteInt32(callerInfo.uid);
    callerInfo.sourceDeviceId = "";
    data.WriteString(callerInfo.sourceDeviceId);
    result = DistributedSchedService::GetInstance().StartAbilityFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().StartAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);

    data.WriteParcelable(&want);
    data.WriteParcelable(&compatibleAbilityInfo);
    data.WriteInt32(requestCode);
    data.WriteInt32(callerInfo.uid);
    data.WriteString(callerInfo.sourceDeviceId);
    data.WriteInt32(accountInfo.accountType);
    callerInfo.callerAppId = "";
    data.WriteString(callerInfo.callerAppId);
    result = DistributedSchedService::GetInstance().StartAbilityFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().StartAbilityFromRemoteInner(data, reply);
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

    int32_t result = DistributedSchedService::GetInstance().SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    Want want;
    data.WriteParcelable(&want);
    result = DistributedSchedService::GetInstance().SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteParcelable(&want);
    int32_t requestCode = 0;
    data.WriteInt32(requestCode);
    result = DistributedSchedService::GetInstance().SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteParcelable(&want);
    data.WriteInt32(requestCode);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    data.WriteInt32(callerInfo.uid);
    result = DistributedSchedService::GetInstance().SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteParcelable(&want);
    data.WriteInt32(requestCode);
    data.WriteInt32(callerInfo.uid);
    callerInfo.sourceDeviceId = "";
    data.WriteString(callerInfo.sourceDeviceId);
    result = DistributedSchedService::GetInstance().SendResultFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteParcelable(&want);
    data.WriteInt32(requestCode);
    data.WriteInt32(callerInfo.uid);
    data.WriteString(callerInfo.sourceDeviceId);
    data.WriteInt32(accountInfo.accountType);
    data.WriteString(callerInfo.callerAppId);
    int32_t resultCode = 0;
    data.WriteInt32(resultCode);
    result = DistributedSchedService::GetInstance().SendResultFromRemoteInner(data, reply);
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
    result = DistributedSchedService::GetInstance().SendResultFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().ContinueMissionInner(data, reply);
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

    int32_t result = DistributedSchedService::GetInstance().ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    std::string srcDevId = "";
    data.WriteString(srcDevId);
    result = DistributedSchedService::GetInstance().ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteString(srcDevId);
    std::string dstDevId = "";
    data.WriteString(dstDevId);
    result = DistributedSchedService::GetInstance().ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteString(srcDevId);
    data.WriteString(dstDevId);
    int32_t missionId = 0;
    data.WriteInt32(missionId);
    result = DistributedSchedService::GetInstance().ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteString(srcDevId);
    data.WriteString(dstDevId);
    data.WriteInt32(missionId);
    sptr<IRemoteObject> dsched(new DistributedSchedService());
    data.WriteRemoteObject(dsched);
    result = DistributedSchedService::GetInstance().ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteString(srcDevId);
    data.WriteString(dstDevId);
    data.WriteInt32(missionId);
    data.WriteRemoteObject(dsched);
    WantParams wantParams = {};
    data.WriteParcelable(&wantParams);
    result = DistributedSchedService::GetInstance().ContinueMissionInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest ContinueMissionInner_002 end" << std::endl;
}

/**
 * @tc.name: CheckPermission_001
 * @tc.desc: check CheckPermission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, CheckPermission_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedStubTest CheckPermission_001 begin" << std::endl;
    auto result = DistributedSchedService::GetInstance().CheckPermission(true);
    EXPECT_EQ(result, true);
    DTEST_LOG << "DistributedSchedStubTest CheckPermission_001 end" << std::endl;
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
    int32_t result = DistributedSchedService::GetInstance().ContinueMissionOfBundleNameInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::u16string devId = u"192.168.43.100";
    data.WriteString16(devId);
    int32_t sessionId = 0;
    data.WriteInt32(sessionId);
    bool isSuccess = false;
    data.WriteBool(isSuccess);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    std::string info(DMS_VERSION_ID);
    data.WriteString(info.c_str());
    int32_t result = DistributedSchedService::GetInstance().NotifyContinuationResultFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    sptr<IRemoteObject> connect = nullptr;
    data.WriteRemoteObject(connect);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    uint32_t accessToken = 0;
    data.WriteUint32(accessToken);
    int result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
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
    sptr<IRemoteObject> connect = nullptr;
    data.WriteRemoteObject(connect);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    uint32_t accessToken = GetSelfTokenID();
    data.WriteUint32(accessToken);
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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

    int32_t result = DistributedSchedService::GetInstance().ConnectAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    Want want;
    data.WriteParcelable(&want);
    result = DistributedSchedService::GetInstance().ConnectAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    data.WriteParcelable(&want);
    AbilityInfo abilityInfo;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    abilityInfo.ConvertToCompatiableAbilityInfo(compatibleAbilityInfo);
    data.WriteParcelable(&compatibleAbilityInfo);
    sptr<IRemoteObject> connect = nullptr;
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
    result = DistributedSchedService::GetInstance().ConnectAbilityFromRemoteInner(data, reply);
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
    sptr<IRemoteObject> connect = nullptr;
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
    int32_t result = DistributedSchedService::GetInstance().ConnectAbilityFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().DisconnectAbilityFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().NotifyProcessDiedFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::string networkId = "255.255.255.255";
    data.WriteString(networkId);
    int32_t missionId = -1;
    data.WriteInt32(missionId);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteString(networkId);
    missionId = 0;
    data.WriteInt32(missionId);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::u16string devId = u"192.168.43.100";
    data.WriteString16(devId);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteString16(devId);
    sptr<IRemoteObject> missionChangedListener(new DistributedSchedService());
    data.WriteRemoteObject(missionChangedListener);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().RegisterOnListenerInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    /**
     * @tc.steps: step2. test RegisterOnListenerInner when type is not empty;
     */
    data.WriteString("type");
    result = DistributedSchedService::GetInstance().RegisterOnListenerInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    /**
     * @tc.steps: step3. test RegisterOnListenerInner when onListener is not empty;
     */
    data.WriteString("type");
    sptr<IRemoteObject> onListener(new DistributedSchedService());
    data.WriteRemoteObject(onListener);
    result = DistributedSchedService::GetInstance().RegisterOnListenerInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::u16string devId = u"192.168.43.100";
    data.WriteString16(devId);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteString16(devId);
    sptr<IRemoteObject> missionChangedListener(new DistributedSchedService());
    data.WriteRemoteObject(missionChangedListener);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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

    int32_t result = DistributedSchedService::GetInstance().StartSyncMissionsFromRemoteInner(data, reply);
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
    DistributedSchedUtil::MockManageMissions();
    MessageParcel data;
    MessageParcel reply;
    CallerInfo callerInfo;
    CallerInfoMarshalling(callerInfo, data);

    DistributedSchedMissionManager::GetInstance().Init();
    int32_t result = DistributedSchedService::GetInstance().StartSyncMissionsFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::u16string deviceId = u"192.168.43.100";
    data.WriteString16(deviceId);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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

    int32_t result = DistributedSchedService::GetInstance().StopSyncMissionsFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().StopSyncMissionsFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().NotifyMissionsChangedFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    std::u16string deviceId = u"192.168.43.100";
    data.WriteString16(deviceId);
    bool fixConflict = false;
    data.WriteBool(fixConflict);
    int64_t tag = 0;
    data.WriteInt64(tag);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t callingUid = 0;
    data.WriteInt32(missionId);
    data.WriteInt32(state);
    data.WriteInt32(callingUid);
    int32_t result = DistributedSchedService::GetInstance().SetMissionContinueStateInner(data, reply);
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
    bool result = DistributedSchedService::GetInstance().CallerInfoUnmarshalling(callerInfo, data);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    Want want;
    data.WriteParcelable(&want);
    sptr<IRemoteObject> connect = nullptr;
    data.WriteRemoteObject(connect);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    int32_t callerPid = 0;
    data.WriteInt32(callerPid);
    uint32_t accessToken = 0;
    data.WriteUint32(accessToken);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
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
    sptr<IRemoteObject> connect = nullptr;
    data.WriteRemoteObject(connect);
    int32_t callerUid = 0;
    data.WriteInt32(callerUid);
    int32_t callerPid = 0;
    data.WriteInt32(callerPid);
    uint32_t accessToken = GetSelfTokenID();
    data.WriteUint32(accessToken);
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    sptr<IRemoteObject> connect = nullptr;
    data.WriteRemoteObject(connect);
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_VALUE);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteRemoteObject(connect);
    ElementName element;
    data.WriteParcelable(&element);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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

    sptr<IRemoteObject> connect = nullptr;
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
    int32_t result = DistributedSchedService::GetInstance().StartAbilityByCallFromRemoteInner(data, reply);
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
    result = DistributedSchedService::GetInstance().StartAbilityByCallFromRemoteInner(data, reply);
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

    sptr<IRemoteObject> connect = nullptr;
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
    int32_t result = DistributedSchedService::GetInstance().StartAbilityByCallFromRemoteInner(data, reply);
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

    sptr<IRemoteObject> connect = nullptr;
    data.WriteRemoteObject(connect);
    int32_t result = DistributedSchedService::GetInstance().ReleaseAbilityFromRemoteInner(data, reply);
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
    result = DistributedSchedService::GetInstance().ReleaseAbilityFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteString(deviceId);
    FormShareInfo formShareInfo;
    data.WriteParcelable(&formShareInfo);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().StartShareFormFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);

    data.WriteString(deviceId);
    FormShareInfo formShareInfo;
    data.WriteParcelable(&formShareInfo);
    result = DistributedSchedService::GetInstance().StartShareFormFromRemoteInner(data, reply);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteParcelable(&want);
    data.WriteInt32(callerUid);
    data.WriteInt32(requestCode);
    data.WriteUint32(accessToken);
    sptr<IRemoteObject> callback(new DistributedSchedService());
    data.WriteRemoteObject(callback);
    result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
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
    sptr<IRemoteObject> callback(new DistributedSchedService());
    data.WriteRemoteObject(callback);
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
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

    int32_t result = DistributedSchedService::GetInstance().StartFreeInstallFromRemoteInner(data, reply);
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

    int32_t result = DistributedSchedService::GetInstance().StartFreeInstallFromRemoteInner(data, reply);
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

    int32_t result = DistributedSchedService::GetInstance().StartFreeInstallFromRemoteInner(data, reply);
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

    int32_t result = DistributedSchedService::GetInstance().StartFreeInstallFromRemoteInner(data, reply);
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

    int32_t result = DistributedSchedService::GetInstance().StartFreeInstallFromRemoteInner(data, reply);
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

    int32_t result = DistributedSchedService::GetInstance().NotifyCompleteFreeInstallFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    int64_t taskId = 0;
    data.WriteInt64(taskId);
    int32_t resultCode = 0;
    data.WriteInt32(resultCode);
    result = DistributedSchedService::GetInstance().NotifyCompleteFreeInstallFromRemoteInner(data, reply);
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
    auto result = DistributedSchedService::GetInstance().StopRemoteExtensionAbilityInner(dataFirst, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);

    DistributedSchedUtil::MockProcessAndPermission(FOUNDATION_PROCESS_NAME, permissionState, 1);
    MessageParcel dataSecond;
    result = DistributedSchedService::GetInstance().StopRemoteExtensionAbilityInner(dataSecond, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    DistributedSchedUtil::MockProcessAndPermission(FOUNDATION_PROCESS_NAME, permissionState, 1);

    MessageParcel dataThird;
    dataThird.WriteParcelable(&want);
    dataThird.WriteInt32(callerUid);
    dataThird.WriteUint32(accessToken);
    dataThird.WriteInt32(serviceType);
    result = DistributedSchedService::GetInstance().StopRemoteExtensionAbilityInner(dataThird, reply);
    EXPECT_EQ(result, ERR_NONE);
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
    auto result = DistributedSchedService::GetInstance().StopExtensionAbilityFromRemoteInner(dataFirst, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    MessageParcel dataSecond;
    dataSecond.WriteParcelable(&want);
    dataSecond.WriteInt32(serviceType);
    dataSecond.WriteInt32(callerUid);
    dataSecond.WriteString(deviceId);
    dataSecond.WriteStringVector(list);
    dataSecond.WriteString(appId);
    dataSecond.WriteString(extraInfo);
    result = DistributedSchedService::GetInstance().StopExtensionAbilityFromRemoteInner(dataSecond, reply);
    EXPECT_EQ(result, ERR_NONE);

    MessageParcel dataThird;
    dataThird.WriteParcelable(&want);
    dataThird.WriteInt32(serviceType);
    dataThird.WriteInt32(callerUid);
    dataThird.WriteString(deviceId);
    dataThird.WriteStringVector(list);
    dataThird.WriteString(appId);
    dataThird.WriteString(extraInfoEmptr);
    result = DistributedSchedService::GetInstance().StopExtensionAbilityFromRemoteInner(dataThird, reply);
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

    int32_t result = DistributedSchedService::GetInstance().NotifyStateChangedFromRemoteInner(data, reply);
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
    IDistributedSched::AccountInfo accountInfo;
    DistributedSchedService::GetInstance().SaveExtraInfo(extraInfoJson, callerInfo, accountInfo);

    nlohmann::json extraInfoJson1;
    extraInfoJson[DMS_VERSION_ID] = "4";
    CallerInfo callerInfo1;
    DistributedSchedService::GetInstance().SaveExtraInfo(extraInfoJson1, callerInfo1, accountInfo);

    nlohmann::json extraInfoJson2;
    extraInfoJson[DMS_VERSION_ID] = 4;
    CallerInfo callerInfo2;
    DistributedSchedService::GetInstance().SaveExtraInfo(extraInfoJson2, callerInfo2, accountInfo);

    MessageParcel data;
    MessageParcel reply;

    int32_t abilityState = 0;
    data.WriteInt32(abilityState);
    int32_t missionId = 0;
    data.WriteInt32(missionId);
    int32_t result = DistributedSchedService::GetInstance().NotifyStateChangedFromRemoteInner(data, reply);
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
    IDistributedSched::AccountInfo accountInfo;
    DistributedSchedService::GetInstance().SaveExtraInfo(extraInfoJson, callerInfo, accountInfo);

    nlohmann::json extraInfoJson1;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = 0;
    CallerInfo callerInfo1;
    DistributedSchedService::GetInstance().SaveExtraInfo(extraInfoJson1, callerInfo1, accountInfo);

    nlohmann::json extraInfoJson2;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = "4";
    CallerInfo callerInfo2;
    DistributedSchedService::GetInstance().SaveExtraInfo(extraInfoJson2, callerInfo2, accountInfo);

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
    int32_t result = DistributedSchedService::GetInstance().OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest StopRemoteExtensionAbilityInner_002 end" << std::endl;
}

/**
 * @tc.name: IsRemoteInstall_001
 * @tc.desc: check IsRemoteInstall
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, IsRemoteInstall_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest IsRemoteInstall_001 begin" << std::endl;
    std::string networkId = "networkId";
    std::string bundleName = "bundleName";
    bool result = DistributedSchedService::GetInstance().IsRemoteInstall(networkId, bundleName);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DistributedSchedStubTest IsRemoteInstall_001 end" << std::endl;
}

/**
 * @tc.name: RegisterOffListenerInner_001
 * @tc.desc: check RegisterOffListenerInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, RegisterOffListenerInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest RegisterOffListenerInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t ret = DistributedSchedService::GetInstance().RegisterOffListenerInner(data, reply);
    EXPECT_EQ(ret, ERR_FLATTEN_OBJECT);

    data.WriteString("type");
    ret = DistributedSchedService::GetInstance().RegisterOffListenerInner(data, reply);
    EXPECT_EQ(ret, ERR_FLATTEN_OBJECT);

    data.WriteString("type");
    sptr<IRemoteObject> onListener(new DistributedSchedService());
    data.WriteRemoteObject(onListener);
    ret = DistributedSchedService::GetInstance().RegisterOffListenerInner(data, reply);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedStubTest RegisterOffListenerInner_001 end" << std::endl;
}

/**
 * @tc.name: IsUsingQos_001
 * @tc.desc: check IsUsingQos
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, IsUsingQos_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest IsUsingQos_001 begin" << std::endl;
    std::string remoteDeviceId = "remoteDeviceId";
    bool result = DistributedSchedService::GetInstance().IsUsingQos(remoteDeviceId);
    EXPECT_EQ(result, true);

    remoteDeviceId = "";
    result = DistributedSchedService::GetInstance().IsUsingQos(remoteDeviceId);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DistributedSchedStubTest IsUsingQos_001 end" << std::endl;
}

/**
 * @tc.name: NotifyDSchedEventResultFromRemoteInner_001
 * @tc.desc: check NotifyDSchedEventResultFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyDSchedEventResultFromRemoteInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyDSchedEventResultFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().NotifyDSchedEventResultFromRemoteInner(data, reply);
    EXPECT_NE(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest NotifyDSchedEventResultFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: CollabMissionInner_001
 * @tc.desc: check CollabMissionInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, CollabMissionInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest CollabMissionInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().CollabMissionInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    int32_t collabSessionId = 0;
    data.WriteInt32(collabSessionId);
    result = DistributedSchedService::GetInstance().CollabMissionInner(data, reply);
    EXPECT_EQ(result, ERR_FLATTEN_OBJECT);

    std::string srcSocketName = "socketName";
    data.WriteInt32(collabSessionId);
    data.WriteString(srcSocketName);
    result = DistributedSchedService::GetInstance().CollabMissionInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteInt32(collabSessionId);
    data.WriteString(srcSocketName);
    CollabMessage msg;
    data.WriteParcelable(&msg);
    result = DistributedSchedService::GetInstance().CollabMissionInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);

    data.WriteInt32(collabSessionId);
    data.WriteString(srcSocketName);
    data.WriteParcelable(&msg);
    CollabMessage msg1;
    data.WriteParcelable(&msg1);
    result = DistributedSchedService::GetInstance().CollabMissionInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest CollabMissionInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyRejectReason_001
 * @tc.desc: check NotifyRejectReason
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyRejectReason_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyRejectReason_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().NotifyRejectReason(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest CollabMissionInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyStartAbilityResultInner_001
 * @tc.desc: check NotifyStartAbilityResultInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyStartAbilityResultInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyStartAbilityResultInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().NotifyStartAbilityResultInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest NotifyStartAbilityResultInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyCollabPrepareResultInner_001
 * @tc.desc: check NotifyCollabPrepareResultInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyCollabPrepareResultInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyCollabPrepareResultInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().NotifyCollabPrepareResultInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedStubTest NotifyCollabPrepareResultInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyCloseCollabSessionInner_001
 * @tc.desc: check NotifyCloseCollabSessionInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyCloseCollabSessionInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyCloseCollabSessionInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().NotifyCloseCollabSessionInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedStubTest NotifyCloseCollabSessionInner_001 end" << std::endl;
}

/**
 * @tc.name: IsNewCollabVersion_001
 * @tc.desc: check IsNewCollabVersion
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, IsNewCollabVersion_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest IsNewCollabVersion_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    auto rlt = DistributedSchedService::GetInstance().IsNewCollabVersion("");
    EXPECT_EQ(rlt, false);

    std::string remoteDeviceId = "remoteDeviceId";
    rlt = DistributedSchedService::GetInstance().IsNewCollabVersion(remoteDeviceId);
    EXPECT_EQ(rlt, true);
    DTEST_LOG << "DistributedSchedStubTest IsNewCollabVersion_001 end" << std::endl;
}

/**
 * @tc.name: SaveExtraInfo_001
 * @tc.desc: check SaveExtraInfo
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, SaveExtraInfo_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest SaveExtraInfo_001 begin" << std::endl;
    nlohmann::json extraInfoJson;
    CallerInfo callerInfo;
    AccountInfo accountInfo;
    DistributedSchedService::GetInstance().SaveExtraInfo(extraInfoJson, callerInfo, accountInfo);
    EXPECT_TRUE(accountInfo.activeAccountId.empty());

    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = "test";
    extraInfoJson[DMS_VERSION_ID] = 1;
    extraInfoJson[DMS_UID_SPEC_BUNDLE_NAME] = 1;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID] = 1;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_USERID_ID] = "test";
    DistributedSchedService::GetInstance().SaveExtraInfo(extraInfoJson, callerInfo, accountInfo);
    EXPECT_TRUE(accountInfo.activeAccountId.empty());

    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = 1u;
    extraInfoJson[DMS_VERSION_ID] = "dmService";
    extraInfoJson[DMS_UID_SPEC_BUNDLE_NAME] = "bundleName";
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID] = "test";
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_USERID_ID] = 999;
    DistributedSchedService::GetInstance().SaveExtraInfo(extraInfoJson, callerInfo, accountInfo);
    EXPECT_EQ(callerInfo.accessToken, 1u);
    EXPECT_EQ(callerInfo.extraInfoJson[DMS_VERSION_ID], extraInfoJson[DMS_VERSION_ID]);
    EXPECT_EQ(callerInfo.extraInfoJson[DMS_UID_SPEC_BUNDLE_NAME],
        extraInfoJson[DMS_UID_SPEC_BUNDLE_NAME]);
    EXPECT_EQ(accountInfo.activeAccountId, extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID]);
    EXPECT_EQ(accountInfo.userId, extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_USERID_ID]);
    DTEST_LOG << "DistributedSchedStubTest SaveExtraInfo_001 end" << std::endl;
}

/**
 * @tc.name: SaveSendResultExtraInfo_001
 * @tc.desc: check SaveSendResultExtraInfo
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, SaveSendResultExtraInfo_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest SaveSendResultExtraInfo_001 begin" << std::endl;
    nlohmann::json extraInfoJson;
    CallerInfo callerInfo;
    AccountInfo accountInfo;
    DistributedSchedService::GetInstance().SaveSendResultExtraInfo(extraInfoJson, callerInfo, accountInfo);
    EXPECT_TRUE(accountInfo.activeAccountId.empty());

    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID] = 1;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_USERID_ID] = "test";
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_CALLER_INFO_EX] = 1;
    DistributedSchedService::GetInstance().SaveSendResultExtraInfo(extraInfoJson, callerInfo, accountInfo);
    EXPECT_TRUE(accountInfo.activeAccountId.empty());

    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_CALLER_INFO_EX] = "";
    DistributedSchedService::GetInstance().SaveSendResultExtraInfo(extraInfoJson, callerInfo, accountInfo);
    EXPECT_TRUE(accountInfo.activeAccountId.empty());

    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID] = "test";
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_USERID_ID] = 999;
    nlohmann::json temp;
    temp["name"] = "John Doe";
    temp["age"] = 30;
    extraInfoJson[Constants::EXTRO_INFO_JSON_KEY_CALLER_INFO_EX] = temp.dump();
    DistributedSchedService::GetInstance().SaveSendResultExtraInfo(extraInfoJson, callerInfo, accountInfo);
    EXPECT_EQ(accountInfo.activeAccountId, "test");
    EXPECT_EQ(accountInfo.userId, 999);
    EXPECT_EQ(callerInfo.extraInfoJson, temp);
    DTEST_LOG << "DistributedSchedStubTest SaveSendResultExtraInfo_001 end" << std::endl;
}

#ifdef DMSFWK_INTERACTIVE_ADAPTER
/**
 * @tc.name: StartAbilityFromRemoteAdapterInner_001
 * @tc.desc: check StartAbilityFromRemoteAdapterInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StartAbilityFromRemoteAdapterInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest StartAbilityFromRemoteAdapterInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().StartAbilityFromRemoteAdapterInner(data, reply);
    EXPECT_NE(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StartAbilityFromRemoteAdapterInner_001 end" << std::endl;
}

/**
 * @tc.name: StopAbilityFromRemoteAdapterInner_001
 * @tc.desc: check StopAbilityFromRemoteAdapterInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, StopAbilityFromRemoteAdapterInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest StopAbilityFromRemoteAdapterInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().StopAbilityFromRemoteAdapterInner(data, reply);
    EXPECT_NE(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest StopAbilityFromRemoteAdapterInner_001 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemoteAdapterInner_001
 * @tc.desc: check ConnectAbilityFromRemoteAdapterInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ConnectAbilityFromRemoteAdapterInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest ConnectAbilityFromRemoteAdapterInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().ConnectAbilityFromRemoteAdapterInner(data, reply);
    EXPECT_NE(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest ConnectAbilityFromRemoteAdapterInner_001 end" << std::endl;
}

/**
 * @tc.name: DisconnectAbilityFromRemoteAdapterInner_001
 * @tc.desc: check DisconnectAbilityFromRemoteAdapterInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, DisconnectAbilityFromRemoteAdapterInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest DisconnectAbilityFromRemoteAdapterInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().DisconnectAbilityFromRemoteAdapterInner(data, reply);
    EXPECT_NE(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest DisconnectAbilityFromRemoteAdapterInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyAbilityLifecycleChangedFromRemoteAdapterInner_001
 * @tc.desc: check NotifyAbilityLifecycleChangedFromRemoteAdapterInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, NotifyAbilityLifecycleChangedFromRemoteAdapterInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest NotifyAbilityLifecycleChangedFromRemoteAdapterInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().NotifyAbilityLifecycleChangedFromRemoteAdapterInner(
        data, reply);
    EXPECT_NE(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedStubTest NotifyAbilityLifecycleChangedFromRemoteAdapterInner_001 end" << std::endl;
}

/**
 * @tc.name: ConnectDExtensionFromRemoteInner_001
 * @tc.desc: check ConnectDExtensionFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ConnectDExtensionFromRemoteInner_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest ConnectDExtensionFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_INVALID_DATA);
    DTEST_LOG << "DistributedSchedStubTest ConnectDExtensionFromRemoteInner_001 begin" << std::endl;
}

/**
 * @tc.name: ConnectDExtensionFromRemoteInner_002
 * @tc.desc: check ConnectDExtensionFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedStubTest, ConnectDExtensionFromRemoteInner_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedStubTest ConnectDExtensionFromRemoteInner_002 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    DExtSourceInfo sourceInfo("device123", "network123", "bundleName", "moduleName", "abilityName");
    DExtSinkInfo sinkInfo(-1, 1234, "bundleName", "moduleName", "abilityName", "serviceName"); // Invalid userId
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");

    data.WriteParcelable(&connectInfo);
    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);

    DTEST_LOG << " DistributedSchedStubTest ConnectDExtensionFromRemoteInner_002 end" << std::endl;
}
#endif
}
}