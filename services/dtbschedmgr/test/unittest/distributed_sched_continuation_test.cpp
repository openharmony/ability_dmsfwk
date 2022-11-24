/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "distributed_sched_continuation_test.h"
#include "distributed_sched_util.h"
#include "dtbschedmgr_device_info_storage.h"
#include "ipc_skeleton.h"
#include "mock_distributed_sched.h"
#include "mock_remote_stub.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DistributedHardware;
using string = std::string;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::u16string MOCK_DEVICE_ID = u"MOCK_DEVICE_ID";
constexpr int32_t MOCK_SESSION_ID = 123;
constexpr int32_t MOCK_TASK_ID = 456;
const string LOCAL_DEVICE_ID = "192.168.43.100";
constexpr int32_t REQUEST_CODE_ERR = 305;
}

void DSchedContinuationTest::SetUpTestCase()
{
    const std::string pkgName = "DBinderBus_" + std::to_string(getpid());
    std::shared_ptr<DmInitCallback> initCallback_ = std::make_shared<DeviceInitCallBack>();
    DeviceManager::GetInstance().InitDeviceManager(pkgName, initCallback_);
}

void DSchedContinuationTest::TearDownTestCase()
{
}

void DSchedContinuationTest::SetUp()
{
    DistributedSchedUtil::MockPermission();
    dschedContinuation_ = std::make_shared<DSchedContinuation>();
}

void DSchedContinuationTest::TearDown()
{
    dschedContinuation_ = nullptr;
}

void DSchedContinuationTest::DeviceInitCallBack::OnRemoteDied()
{
}

sptr<IRemoteObject> DSchedContinuationTest::GetDSchedService() const
{
    sptr<IRemoteObject> dsched = new MockDistributedSched();
    return dsched;
}

int32_t DSchedContinuationTest::PushAbilityToken()
{
    FuncContinuationCallback continuationCallback = [this] (int32_t missionId) {
        timeoutFlag_ = true;
    };
    dschedContinuation_->Init(continuationCallback);
    int32_t sessionId = dschedContinuation_->GenerateSessionId();
    dschedContinuation_->PushAbilityToken(sessionId, GetDSchedService());
    return sessionId;
}

std::shared_ptr<Want> DSchedContinuationTest::MockWant(const string& bundleName, const string& ability, int32_t flags)
{
    ElementName element("", bundleName, ability);
    std::shared_ptr<Want> spWant = std::make_shared<Want>();
    spWant->SetElement(element);
    spWant->SetFlags(flags);
    return spWant;
}

sptr<IDistributedSched> DSchedContinuationTest::GetDms()
{
    if (proxy_ != nullptr) {
        return proxy_;
    }
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_TRUE(sm != nullptr);
    if (sm == nullptr) {
        DTEST_LOG << "DSchedContinuationTest sm is nullptr" << std::endl;
        return nullptr;
    }
    DTEST_LOG << "DSchedContinuationTest sm is not nullptr" << std::endl;
    auto distributedObject = sm->GetSystemAbility(DISTRIBUTED_SCHED_SA_ID);
    EXPECT_TRUE(distributedObject != nullptr);
    proxy_ = iface_cast<IDistributedSched>(distributedObject);
    if (proxy_ == nullptr) {
        DTEST_LOG << "DSchedContinuationTest DistributedSched is nullptr" << std::endl;
    }
    DTEST_LOG << "DSchedContinuationTest DistributedSched is not nullptr" << std::endl;
    return proxy_;
}

int32_t DSchedContinuationTest::StartContinuation(int32_t missionId, int32_t flags)
{
    string bundleName = "bundleName";
    string abilityName = "abilityName";
    string devId = "devId";
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, flags);
    int callerUid = 0;
    return DistributedSchedService::GetInstance().StartContinuation(*spWant, missionId, callerUid, 0, 0);
}

int32_t DSchedContinuationTest::StartRemoteFreeInstall(int32_t flags, const sptr<IRemoteObject>& callback)
{
    string bundleName = "bundleName";
    string abilityName = "abilityName";
    string devId = "devId";
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, flags);
    int callerUid = 0;
    return DistributedSchedService::GetInstance().StartRemoteFreeInstall(*spWant, callerUid, 0, 0, callback);
}

/**
 * @tc.name: StartContinuation_001
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, StartContinuation_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_001 start" << std::endl;
    /**
     * @tc.steps: step1. want not set continuation flags.
     * @tc.expected: step1. return false.
     */
    int32_t ret = StartContinuation(0, 0);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DSchedContinuationTest StartContinuation002 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_002
 * @tc.desc: get remote dms failed.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, StartContinuation_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_002 start" << std::endl;
    /**
     * @tc.steps: step1. get remote dms failed.
     * @tc.expected: step1. return false.
     */
    int32_t ret = StartContinuation(0, Want::FLAG_ABILITY_CONTINUATION);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DSchedContinuationTest StartContinuation003 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_003
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, StartContinuation_003, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_003 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    int32_t flags = Want::FLAG_ABILITY_CONTINUATION;
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, flags);
    int32_t missionId = 0;
    auto callback = GetDSchedService();
    std::string deviceId = "123456";
    DistributedSchedService::GetInstance().dschedContinuation_->PushCallback(missionId, callback, deviceId, false);
    int32_t status = ERR_OK;
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t accessToken = IPCSkeleton::GetCallingTokenID();
    int32_t ret = DistributedSchedService::GetInstance().StartContinuation(*spWant,
        missionId, uid, status, accessToken);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DSchedContinuationTest StartContinuation_003 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_004
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, StartContinuation_004, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_004 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    int32_t flags = Want::FLAG_ABILITY_CONTINUATION;
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, flags);
    int32_t missionId = 0;
    auto callback = GetDSchedService();
    std::string deviceId = "123456";
    DistributedSchedService::GetInstance().dschedContinuation_->PushCallback(missionId, callback, deviceId, true);
    int32_t status = ERR_OK;
    int32_t uid = IPCSkeleton::GetCallingUid();
    int32_t accessToken = IPCSkeleton::GetCallingTokenID();
    int32_t ret = DistributedSchedService::GetInstance().StartContinuation(*spWant,
        missionId, uid, status, accessToken);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DSchedContinuationTest StartContinuation_004 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteContinuation_001
 * @tc.desc: input invalid session.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, NotifyCompleteContinuation_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteContinuation_001 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid session.
     * @tc.expected: step1. return false.
     */
    DistributedSchedService::GetInstance().NotifyCompleteContinuation(MOCK_DEVICE_ID, -1, true);
    EXPECT_TRUE(!timeoutFlag_);
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteContinuation_001 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteContinuation_002
 * @tc.desc: get remote dms failed.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, NotifyCompleteContinuation_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteContinuation_002 start" << std::endl;
    /**
     * @tc.steps: step1. get remote dms failed.
     * @tc.expected: step1. return false.
     */
    DistributedSchedService::GetInstance().NotifyCompleteContinuation(MOCK_DEVICE_ID, MOCK_SESSION_ID, true);
    EXPECT_TRUE(!timeoutFlag_);
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteContinuation_002 end" << std::endl;
}

/**
 * @tc.name: NotifyContinuationResultFromRemote_001
 * @tc.desc: input invalid session.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, NotifyContinuationResultFromRemote_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyContinuationResultFromRemote_001 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid session.
     * @tc.expected: step1. return false.
     */
    DistributedSchedService::GetInstance().NotifyContinuationResultFromRemote(-1, true);
    EXPECT_TRUE(!timeoutFlag_);
    DTEST_LOG << "DSchedContinuationTest NotifyContinuationResultFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: NotifyContinuationResultFromRemote_002
 * @tc.desc: get remote dms failed.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, NotifyContinuationResultFromRemote_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyContinuationResultFromRemote_002 start" << std::endl;
    /**
     * @tc.steps: step1. get remote dms failed.
     * @tc.expected: step1. return false.
     */
    DistributedSchedService::GetInstance().NotifyContinuationResultFromRemote(MOCK_SESSION_ID, true);
    EXPECT_TRUE(!timeoutFlag_);
    DTEST_LOG << "DSchedContinuationTest NotifyContinuationResultFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: SetWantForContinuation_001
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, SetWantForContinuation_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest SetWantForContinuation_001 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid bundleName.
     * @tc.expected: step1. return err.
     */
    string bundleName = "bundleName";
    string abilityName = "abilityName";
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, 0);
    int32_t missionId = 0;
    int32_t ret = DistributedSchedService::GetInstance().SetWantForContinuation(*spWant, missionId);
    EXPECT_TRUE(INVALID_PARAMETERS_ERR == ret);
    DTEST_LOG << "DSchedContinuationTest SetWantForContinuation_001 end" << std::endl;
}

/**
 * @tc.name: SetWantForContinuation_002
 * @tc.desc: input valid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, SetWantForContinuation_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest SetWantForContinuation_002 start" << std::endl;
    /**
     * @tc.steps: step1. input valid bundleName.
     * @tc.expected: step1. return OK.
     */
    string bundleName = "ohos.samples.distributedcalc";
    string abilityName = "MainAbility";
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, 0);
    int32_t missionId = 0;
    int32_t ret = DistributedSchedService::GetInstance().SetWantForContinuation(*spWant, missionId);
    EXPECT_TRUE(ERR_OK == ret);
    DTEST_LOG << "DSchedContinuationTest SetWantForContinuation_002 end" << std::endl;
}

/**
 * @tc.name: ContinueLocalMission_001
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, ContinueLocalMission_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueLocalMission_001 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid missionId.
     * @tc.expected: step1. return err.
     */
    string deviceId = "123456";
    int32_t missionId = 0;
    auto callback = GetDSchedService();
    WantParams wantParams;
    int32_t ret = DistributedSchedService::GetInstance().ContinueLocalMission(deviceId,
        missionId, callback, wantParams);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinuationTest ContinueLocalMission_001 end" << std::endl;
}

/**
 * @tc.name: ContinueLocalMission_002
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, ContinueLocalMission_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueLocalMission_002 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid mission.
     * @tc.expected: step1. return err.
     */
    string deviceId = "123456";
    int32_t missionId = 0;
    auto callback = GetDSchedService();
    WantParams wantParams;
    DistributedSchedService::GetInstance().OnStart();
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        return;
    }
    DistributedSchedService::GetInstance().dschedContinuation_->PushCallback(missionId, callback, deviceId, false);
    int32_t ret = DistributedSchedService::GetInstance().ContinueLocalMission(
        deviceId, missionId, callback, wantParams);
    EXPECT_EQ(CONTINUE_ALREADY_IN_PROGRESS, ret);
    DTEST_LOG << "DSchedContinuationTest ContinueLocalMission_002 end" << std::endl;
}

/**
 * @tc.name: ContinueLocalMission_003
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DSchedContinuationTest, ContinueLocalMission_003, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueLocalMission_003 start" << std::endl;
    string deviceId = "123456";
    int32_t missionId = -1;
    auto callback = GetDSchedService();
    WantParams wantParams;
    DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    int32_t ret = DistributedSchedService::GetInstance().ContinueLocalMission(
        deviceId, missionId, callback, wantParams);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinuationTest ContinueLocalMission_003 end" << std::endl;
}

/**
 * @tc.name: ContinueLocalMission_004
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DSchedContinuationTest, ContinueLocalMission_004, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueLocalMission_004 start" << std::endl;
    string deviceId;
    int32_t missionId = -1;
    auto callback = GetDSchedService();
    WantParams wantParams;
    DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    int32_t ret = DistributedSchedService::GetInstance().ContinueLocalMission(
        deviceId, missionId, callback, wantParams);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DSchedContinuationTest ContinueLocalMission_004 end" << std::endl;
}

/**
 * @tc.name: ContinueRemoteMission_001
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, ContinueRemoteMission_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueRemoteMission_001 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid deviceId.
     * @tc.expected: step1. return err.
     */
    string srcDeviceId = "123456";
    string dstDeviceid = "123456";
    int32_t missionId = 0;
    auto callback = GetDSchedService();
    WantParams wantParams;
    int32_t ret = DistributedSchedService::GetInstance().ContinueRemoteMission(
        srcDeviceId, dstDeviceid, missionId, callback, wantParams);
    EXPECT_TRUE(INVALID_REMOTE_PARAMETERS_ERR == ret);
    DTEST_LOG << "DSchedContinuationTest ContinueRemoteMission_001 end" << std::endl;
}

/**
 * @tc.name: ContinueRemoteMission_002
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, ContinueRemoteMission_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueRemoteMission_002 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid param.
     * @tc.expected: step1. return err.
     */
    string srcDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(srcDeviceId);
    string dstDeviceid = "123456";
    int32_t missionId = 0;
    auto callback = GetDSchedService();
    WantParams wantParams;
    int32_t ret = DistributedSchedService::GetInstance().ContinueRemoteMission(
        srcDeviceId, dstDeviceid, missionId, callback, wantParams);
    EXPECT_TRUE(ERR_OK != ret);
    DTEST_LOG << "DSchedContinuationTest ContinueRemoteMission_002 end" << std::endl;
}

/**
 * @tc.name: PushAbilityToken_001
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, PushAbilityToken_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PushAbilityToken_001 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid abilityToken.
     * @tc.expected: step1. return false.
     */
    auto sessionId = dschedContinuation_->GenerateSessionId();
    bool ret = dschedContinuation_->PushAbilityToken(sessionId, nullptr);
    EXPECT_TRUE(!ret);
    DTEST_LOG << "DSchedContinuationTest PushAbilityToken_001 end" << std::endl;
}

/**
 * @tc.name: PushAbilityToken_002
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, PushAbilityToken_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PushAbilityToken_002 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid sessionId.
     * @tc.expected: step1. return false.
     */
    bool ret = dschedContinuation_->PushAbilityToken(-1, GetDSchedService());
    EXPECT_TRUE(!ret);
    DTEST_LOG << "DSchedContinuationTest PushAbilityToken_002 end" << std::endl;
}

/**
 * @tc.name: PushAbilityToken_003
 * @tc.desc: init not call.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, PushAbilityToken_003, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PushAbilityToken_003 start" << std::endl;
    /**
     * @tc.steps: step1. input valid abilityToken and valid sessionId.
     * @tc.expected: step1. return false.
     */
    auto sessionId = dschedContinuation_->GenerateSessionId();
    bool ret = dschedContinuation_->PushAbilityToken(sessionId, GetDSchedService());
    EXPECT_TRUE(!ret);
    DTEST_LOG << "DSchedContinuationTest PushAbilityToken_003 end" << std::endl;
}

/**
 * @tc.name: PushAbilityToken_004
 * @tc.desc: Push AbilityToken OK.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, PushAbilityToken_004, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PushAbilityToken_004 start" << std::endl;
    /**
     * @tc.steps: step1. input valid params and init.
     * @tc.expected: step1. return true.
     */
    dschedContinuation_->Init(nullptr);
    auto sessionId = dschedContinuation_->GenerateSessionId();
    bool ret = dschedContinuation_->PushAbilityToken(sessionId, GetDSchedService());
    EXPECT_TRUE(ret);
    DTEST_LOG << "DSchedContinuationTest PushAbilityToken_004 end" << std::endl;
}

/**
 * @tc.name: PushAbilityToken_005
 * @tc.desc: AbilityToken is exist.
 * @tc.type: FUNC
 * @tc.require: I60TOK
 */
HWTEST_F(DSchedContinuationTest, PushAbilityToken_005, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PushAbilityToken_005 start" << std::endl;
    dschedContinuation_->Init(nullptr);
    auto sessionId = 1;
    bool ret = dschedContinuation_->PushAbilityToken(sessionId, GetDSchedService());
    ret = dschedContinuation_->PushAbilityToken(sessionId, GetDSchedService());
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DSchedContinuationTest PushAbilityToken_005 end" << std::endl;
}

/**
 * @tc.name: PopAbilityToken_001
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, PopAbilityToken_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PopAbilityToken_001 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid sessionId.
     * @tc.expected: step1. return false.
     */
    sptr<IRemoteObject> abilityToken = dschedContinuation_->PopAbilityToken(-1);
    EXPECT_TRUE(abilityToken == nullptr);
    DTEST_LOG << "DSchedContinuationTest PopAbilityToken_001 end" << std::endl;
}

/**
 * @tc.name: PopAbilityToken_002
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, PopAbilityToken_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PopAbilityToken_002 start" << std::endl;
    /**
     * @tc.steps: step1. pop not exist sessionId.
     * @tc.expected: step1. return false.
     */
    int32_t sessionId = dschedContinuation_->GenerateSessionId() + 1;
    sptr<IRemoteObject> abilityToken = dschedContinuation_->PopAbilityToken(sessionId);
    EXPECT_TRUE(abilityToken == nullptr);
    DTEST_LOG << "DSchedContinuationTest PopAbilityToken_002 end" << std::endl;
}

/**
 * @tc.name: PopAbilityToken_003
 * @tc.desc: pop abilityToken success.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, PopAbilityToken_003, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PopAbilityToken_003 start" << std::endl;
    /**
     * @tc.steps: step1. pop exist sessionId.
     * @tc.expected: step1. return true.
     */
    int32_t sessionId = PushAbilityToken();
    sptr<IRemoteObject> abilityToken = dschedContinuation_->PopAbilityToken(sessionId);
    EXPECT_TRUE(abilityToken != nullptr);

    /**
     * @tc.steps: step2. duplicate pop abilityToken.
     * @tc.expected: step1. return false.
     */
    abilityToken = dschedContinuation_->PopAbilityToken(sessionId);
    EXPECT_TRUE(abilityToken == nullptr);
    DTEST_LOG << "DSchedContinuationTest PopAbilityToken_003 end" << std::endl;
}

/**
 * @tc.name: PopAbilityToken_004
 * @tc.desc: pop abilityToken success.
 * @tc.type: FUNC
 * @tc.require: I60TOK
 */
HWTEST_F(DSchedContinuationTest, PopAbilityToken_004, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PopAbilityToken_004 start" << std::endl;
    dschedContinuation_->continuationHandler_ = nullptr;

    int32_t sessionId = PushAbilityToken();
    sptr<IRemoteObject> abilityToken = dschedContinuation_->PopAbilityToken(sessionId);
    EXPECT_TRUE(abilityToken != nullptr);
    DTEST_LOG << "DSchedContinuationTest PopAbilityToken_004 end" << std::endl;
}

/**
 * @tc.name: GenerateSessionId_001
 * @tc.desc: test GenerateSessionId when currSessionId is less than zero.
 * @tc.type: FUNC
 * @tc.require: I60TOK
 */
HWTEST_F(DSchedContinuationTest, GenerateSessionId_001, TestSize.Level4)
{
    DTEST_LOG << "DSchedContinuationTest GenerateSessionId_001 start" << std::endl;
    int32_t sessionId =  dschedContinuation_->currSessionId_;
    dschedContinuation_->currSessionId_ = -100;
    dschedContinuation_->GenerateSessionId();
    EXPECT_EQ(dschedContinuation_->currSessionId_, 1);
    dschedContinuation_->currSessionId_ = sessionId;
    DTEST_LOG << "DSchedContinuationTest GenerateSessionId_001 end" << std::endl;
}

/**
 * @tc.name: SetTimeOut_001
 * @tc.desc: test SetTimeOut.
 * @tc.type: FUNC
 * @tc.require: I60TOK
 */
HWTEST_F(DSchedContinuationTest, SetTimeOut_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest SetTimeOut_001 start" << std::endl;
    dschedContinuation_->Init(nullptr);

    int32_t missionId = 0;
    int32_t timeout = 1000;
    dschedContinuation_->SetTimeOut(missionId, timeout);
    EXPECT_NE(dschedContinuation_->continuationHandler_, nullptr);
    DTEST_LOG << "DSchedContinuationTest SetTimeOut_001 end" << std::endl;
}

/**
 * @tc.name: RemoveTimeOut_001
 * @tc.desc: test RemoveTimeOut.
 * @tc.type: FUNC
 * @tc.require: I60TOK
 */
HWTEST_F(DSchedContinuationTest, RemoveTimeOut_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest RemoveTimeOut_001 start" << std::endl;
    dschedContinuation_->Init(nullptr);

    int32_t missionId = 0;
    int32_t timeout = 1000;
    dschedContinuation_->SetTimeOut(missionId, timeout);
    EXPECT_NE(dschedContinuation_->continuationHandler_, nullptr);
    DTEST_LOG << "DSchedContinuationTest RemoveTimeOut_001 end" << std::endl;
}

/**
 * @tc.name: GetTargetDevice_001
 * @tc.desc: test GetTargetDevice.
 * @tc.type: FUNC
 * @tc.require: I60TOK
 */
HWTEST_F(DSchedContinuationTest, GetTargetDevice_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest GetTargetDevice_001 start" << std::endl;
    dschedContinuation_->Init(nullptr);

    int32_t missionId = 0;
    std::string mockDevice = "mockDevice";
    dschedContinuation_->continuationDevices_[missionId] = mockDevice;
    std::string result = dschedContinuation_->GetTargetDevice(missionId);
    EXPECT_EQ(result, mockDevice);
    DTEST_LOG << "DSchedContinuationTest GetTargetDevice_001 end" << std::endl;
}

/**
 * @tc.name: PushCallback_001
 * @tc.desc: test PushCallback when callback is nullptr.
 * @tc.type: FUNC
 * @tc.require: I60TOK
 */
HWTEST_F(DSchedContinuationTest, PushCallback_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest PushCallback_001 start" << std::endl;
    dschedContinuation_->Init(nullptr);

    int32_t missionId = 0;
    const sptr<IRemoteObject> callback = nullptr;
    std::string deviceId = "";
    bool isFreeInstall = true;
    bool result = dschedContinuation_->PushCallback(missionId, callback, deviceId, isFreeInstall);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DSchedContinuationTest PushCallback_001 end" << std::endl;
}

/**
 * @tc.name: PushCallback_002
 * @tc.desc: test PushCallback when callback is exist.
 * @tc.type: FUNC
 * @tc.require: I60TOK
 */
HWTEST_F(DSchedContinuationTest, PushCallback_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest PushCallback_002 start" << std::endl;
    dschedContinuation_->Init(nullptr);

    int32_t missionId = 0;
    const sptr<IRemoteObject> callback = new MockRemoteStub();
    std::string deviceId = "";
    bool isFreeInstall = true;
    dschedContinuation_->callbackMap_[missionId] = callback;
    bool result = dschedContinuation_->PushCallback(missionId, callback, deviceId, isFreeInstall);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DSchedContinuationTest PushCallback_002 end" << std::endl;
}

/**
 * @tc.name: PushCallback_003
 * @tc.desc: test PushCallback when isFreeInstall is true.
 * @tc.type: FUNC
 * @tc.require: I60TOK
 */
HWTEST_F(DSchedContinuationTest, PushCallback_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest PushCallback_003 start" << std::endl;
    dschedContinuation_->Init(nullptr);

    int32_t missionId = 0;
    const sptr<IRemoteObject> callback = new MockRemoteStub();
    std::string deviceId = "";
    bool isFreeInstall = true;
    dschedContinuation_->callbackMap_.clear();
    bool result = dschedContinuation_->PushCallback(missionId, callback, deviceId, isFreeInstall);
    EXPECT_EQ(result, true);
    DTEST_LOG << "DSchedContinuationTest PushCallback_003 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_001
 * @tc.desc: test ContinueMission when srcDeviceId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, ContinueMission_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueMission_001 start" << std::endl;
    WantParams wantParams;
    int32_t ret = DistributedSchedService::GetInstance().ContinueMission("",
        "string", 1, GetDSchedService(), wantParams);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DSchedContinuationTest ContinueMission_001 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_002
 * @tc.desc: test ContinueMission when dstDeviceId is empty.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, ContinueMission_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueMission_002 start" << std::endl;
    WantParams wantParams;
    int32_t ret = DistributedSchedService::GetInstance().ContinueMission("string",
        "", 1, GetDSchedService(), wantParams);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DSchedContinuationTest ContinueMission_002 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_003
 * @tc.desc: test ContinueMission when callback is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, ContinueMission_003, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueMission_003 start" << std::endl;
    WantParams wantParams;
    int32_t ret = DistributedSchedService::GetInstance().ContinueMission("string", "string", 1, nullptr, wantParams);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DSchedContinuationTest ContinueMission_003 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_004
 * @tc.desc: test ContinueMission when srcDeviceId == localDevId.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, ContinueMission_004, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueMission_004 start" << std::endl;
    WantParams wantParams;

    std::string srcDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(srcDeviceId);
    int32_t ret = DistributedSchedService::GetInstance().ContinueMission(srcDeviceId,
        "string", -1, GetDSchedService(), wantParams);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DSchedContinuationTest ContinueMission_004 end" << std::endl;
}

/**
 * @tc.name: StartRemoteFreeInstall_001
 * @tc.desc: input invalid params.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, StartRemoteFreeInstall_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest StartRemoteFreeInstall_001 start" << std::endl;
    /**
     * @tc.steps: step1. want not set continuation flags.
     * @tc.expected: step1. return false.
     */
    int32_t ret = StartRemoteFreeInstall(0, GetDSchedService());
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DSchedContinuationTest StartRemoteFreeInstall_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteFreeInstall_002
 * @tc.desc: get remote dms failed.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, StartRemoteFreeInstall_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest StartRemoteFreeInstall_002 start" << std::endl;
    /**
     * @tc.steps: step1. get remote dms failed.
     * @tc.expected: step1. return false.
     */
    int32_t ret = StartRemoteFreeInstall(Want::FLAG_ABILITY_CONTINUATION, GetDSchedService());
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DSchedContinuationTest StartRemoteFreeInstall_002 end" << std::endl;
}

/**
 * @tc.name: StartFreeInstallFromRemote_001
 * @tc.desc: call StartFreeInstallFromRemote with illegal param
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, StartFreeInstallFromRemote_001, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinuationTest StartFreeInstallFromRemote_001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    IDistributedSched::FreeInstallInfo info = {.want = want,
        .requestCode = 0,
        .callerInfo = callerInfo,
        .accountInfo = accountInfo
    };
    /**
     * @tc.steps: step1. StartFreeInstallFromRemote with uninitialized params
     * @tc.expected: step1. StartFreeInstallFromRemote return INVALID_REMOTE_PARAMETERS_ERR
     */
    int result1 = proxy->StartFreeInstallFromRemote(info, 0);
    DTEST_LOG << "result1:" << result1 << std::endl;
    /**
     * @tc.steps: step1. StartFreeInstallFromRemote with with empty deviceId
     * @tc.expected: step1. StartFreeInstallFromRemote return INVALID_REMOTE_PARAMETERS_ERR
     */
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    int result2 = proxy->StartFreeInstallFromRemote(info, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;
    DTEST_LOG << "DSchedContinuationTest StartFreeInstallFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: StartFreeInstallFromRemote_002
 * @tc.desc: call StartFreeInstallFromRemote
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, StartFreeInstallFromRemote_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest StartFreeInstallFromRemote_002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }

    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    IDistributedSched::FreeInstallInfo info = {.want = want,
        .requestCode = 0,
        .callerInfo = callerInfo,
        .accountInfo = accountInfo
    };

    int result1 = proxy->StartFreeInstallFromRemote(info, 0);
    DTEST_LOG << "result1 is" << result1 << std::endl;

    AppExecFwk::ElementName element2("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    int result2 = proxy->StartFreeInstallFromRemote(info, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;
    DTEST_LOG << "DSchedContinuationTest StartFreeInstallFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: StartFreeInstallFromRemote_003
 * @tc.desc: call StartFreeInstallFromRemote for pressure test
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, StartFreeInstallFromRemote_003, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest StartFreeInstallFromRemote_003 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    /**
     * @tc.steps: step1. set want and abilityInfo
     */
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    IDistributedSched::FreeInstallInfo info = {.want = want,
        .requestCode = 0,
        .callerInfo = callerInfo,
        .accountInfo = accountInfo
    };
    /**
     * @tc.steps: step2. StartFreeInstallFromRemote for pressure test
     * @tc.expected: step2. StartFreeInstallFromRemote for result
     */
    for (int index = 0; index < static_cast<int32_t>(LoopTime::LOOP_TIME); index++) {
        int result = proxy->StartFreeInstallFromRemote(info, 0);
        DTEST_LOG << "pressure" + std::to_string(index) + " result is " << result << std::endl;
    }
    DTEST_LOG << "DSchedContinuationTest StartFreeInstallFromRemote_003 end" << std::endl;
}

/**
 * @tc.name: StartFreeInstallFromRemote_004
 * @tc.desc: call StartFreeInstallFromRemote with dms
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, StartFreeInstallFromRemote_004, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinuationTest StartFreeInstallFromRemote_004 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();

    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    IDistributedSched::FreeInstallInfo info = {.want = want,
        .requestCode = 0,
        .callerInfo = callerInfo,
        .accountInfo = accountInfo
    };

    int result1 = DistributedSchedService::GetInstance().StartFreeInstallFromRemote(info, 0);
    DTEST_LOG << "result1:" << result1 << std::endl;

    AppExecFwk::ElementName element2("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    int result2 = DistributedSchedService::GetInstance().StartFreeInstallFromRemote(info, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result1);
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result2);
    DTEST_LOG << "DSchedContinuationTest StartFreeInstallFromRemote_004 end" << std::endl;
}

/**
 * @tc.name: StartFreeInstallFromRemote_005
 * @tc.desc: call StartFreeInstallFromRemote with dms
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, StartFreeInstallFromRemote_005, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest StartFreeInstallFromRemote_005 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();

    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = 1;
    accountInfo.groupIdList.push_back("123456");
    IDistributedSched::FreeInstallInfo info = {.want = want,
        .requestCode = 0,
        .callerInfo = callerInfo,
        .accountInfo = accountInfo
    };

    int result1 = DistributedSchedService::GetInstance().StartFreeInstallFromRemote(info, 0);
    DTEST_LOG << "result1:" << result1 << std::endl;

    AppExecFwk::ElementName element2("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    int result2 = DistributedSchedService::GetInstance().StartFreeInstallFromRemote(info, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;
    DTEST_LOG << "DSchedContinuationTest StartFreeInstallFromRemote_005 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteFreeInstall_001
 * @tc.desc: input invalid taskId.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, NotifyCompleteFreeInstall_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteFreeInstall_001 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid taskId.
     * @tc.expected: step1. return false.
     */
    IDistributedSched::FreeInstallInfo info;
    DistributedSchedService::GetInstance().NotifyCompleteFreeInstall(info, -1, 0);
    EXPECT_TRUE(!freeInstallTimeoutFlag_);
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteFreeInstall_001 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteFreeInstall_002
 * @tc.desc: get remote dms failed.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, NotifyCompleteFreeInstall_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteFreeInstall_002 start" << std::endl;
    /**
     * @tc.steps: step1. get remote dms failed.
     * @tc.expected: step1. return false.
     */
    IDistributedSched::FreeInstallInfo info;
    DistributedSchedService::GetInstance().NotifyCompleteFreeInstall(info, MOCK_TASK_ID, 0);
    EXPECT_TRUE(!freeInstallTimeoutFlag_);
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteFreeInstall_002 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteFreeInstallFromRemote_001
 * @tc.desc: input invalid taskId.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, NotifyCompleteFreeInstallFromRemote_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteFreeInstallFromRemote_001 start" << std::endl;
    /**
     * @tc.steps: step1. input invalid taskId.
     * @tc.expected: step1. return false.
     */
    DistributedSchedService::GetInstance().NotifyCompleteFreeInstallFromRemote(-1, 0);
    EXPECT_TRUE(!freeInstallTimeoutFlag_);
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteFreeInstallFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteFreeInstallFromRemote_002
 * @tc.desc: dmsCallbackTask_ or dschedContinuation_ is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinuationTest, NotifyCompleteFreeInstallFromRemote_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteFreeInstallFromRemote_002 start" << std::endl;
    /**
     * @tc.steps: step1. dmsCallbackTask_ or dschedContinuation_ is nullptr.
     * @tc.expected: step1. return false.
     */
    DistributedSchedService::GetInstance().NotifyCompleteFreeInstallFromRemote(MOCK_TASK_ID, 0);
    EXPECT_TRUE(!freeInstallTimeoutFlag_);
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteFreeInstallFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: IsFreeInstall_001
 * @tc.desc: missionId is not exist.
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DSchedContinuationTest, IsFreeInstall_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest IsFreeInstall_001 start" << std::endl;
    int32_t missionId = -1;
    bool result = dschedContinuation_->IsFreeInstall(missionId);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DSchedContinuationTest IsFreeInstall_001 end" << std::endl;
}

/**
 * @tc.name: IsFreeInstall_002
 * @tc.desc: missionId is exist.
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DSchedContinuationTest, IsFreeInstall_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest IsFreeInstall_002 start" << std::endl;
    int32_t missionId = 1;
    dschedContinuation_->freeInstall_[missionId] = true;
    bool result = dschedContinuation_->IsFreeInstall(missionId);
    EXPECT_EQ(result, true);
    DTEST_LOG << "DSchedContinuationTest IsFreeInstall_002 end" << std::endl;
}

/**
 * @tc.name: IsFreeInstall_003
 * @tc.desc: missionId is exist.
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DSchedContinuationTest, IsFreeInstall_003, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest IsFreeInstall_003 start" << std::endl;
    int32_t missionId = 1;
    dschedContinuation_->freeInstall_[missionId] = false;
    bool result = dschedContinuation_->IsFreeInstall(missionId);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DSchedContinuationTest IsFreeInstall_003 end" << std::endl;
}

/**
 * @tc.name: PopCallback_001
 * @tc.desc: missionId is not exist in callbackMap_.
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DSchedContinuationTest, PopCallback_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PopCallback_001 start" << std::endl;
    int32_t missionId = -1;
    dschedContinuation_->callbackMap_.erase(missionId);
    sptr<IRemoteObject> result = dschedContinuation_->PopCallback(missionId);
    EXPECT_EQ(result, nullptr);
    DTEST_LOG << "DSchedContinuationTest PopCallback_001 end" << std::endl;
}

/**
 * @tc.name: PopCallback_002
 * @tc.desc: missionId is not exist in continuationDevices_.
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DSchedContinuationTest, PopCallback_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PopCallback_002 start" << std::endl;
    int32_t missionId = -1;
    dschedContinuation_->callbackMap_[missionId] = GetDSchedService();
    dschedContinuation_->continuationDevices_.erase(missionId);
    sptr<IRemoteObject> result = dschedContinuation_->PopCallback(missionId);
    EXPECT_NE(result, nullptr);
    DTEST_LOG << "DSchedContinuationTest PopCallback_002 end" << std::endl;
}

/**
 * @tc.name: PopCallback_003
 * @tc.desc: missionId is not exist in freeInstall_.
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DSchedContinuationTest, PopCallback_003, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PopCallback_003 start" << std::endl;
    int32_t missionId = -1;
    dschedContinuation_->callbackMap_[missionId] = GetDSchedService();
    dschedContinuation_->continuationDevices_[missionId] = "mockDevices";
    dschedContinuation_->freeInstall_.erase(missionId);
    sptr<IRemoteObject> result = dschedContinuation_->PopCallback(missionId);
    EXPECT_NE(result, nullptr);
    DTEST_LOG << "DSchedContinuationTest PopCallback_003 end" << std::endl;
}

/**
 * @tc.name: PopCallback_004
 * @tc.desc: missionId is exist.
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DSchedContinuationTest, PopCallback_004, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest PopCallback_004 start" << std::endl;
    int32_t missionId = -1;
    dschedContinuation_->callbackMap_[missionId] = GetDSchedService();
    dschedContinuation_->continuationDevices_[missionId] = "mockDevices";
    dschedContinuation_->freeInstall_[missionId] = true;
    sptr<IRemoteObject> result = dschedContinuation_->PopCallback(missionId);
    EXPECT_NE(result, nullptr);
    DTEST_LOG << "DSchedContinuationTest PopCallback_004 end" << std::endl;
}

/**
 * @tc.name: NotifyMissionCenterResult_001
 * @tc.desc: missionId is not exist in callbackMap_.
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DSchedContinuationTest, NotifyMissionCenterResult_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyMissionCenterResult_001 start" << std::endl;
    int32_t missionId = -1;
    int32_t resultCode = 0;
    dschedContinuation_->callbackMap_[missionId] = nullptr;
    int32_t result = dschedContinuation_->NotifyMissionCenterResult(missionId, resultCode);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinuationTest NotifyMissionCenterResult_001 end" << std::endl;
}

/**
 * @tc.name: NotifyMissionCenterResult_002
 * @tc.desc: missionId is exist.
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DSchedContinuationTest, NotifyMissionCenterResult_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyMissionCenterResult_002 start" << std::endl;
    int32_t missionId = -1;
    int32_t resultCode = 0;
    dschedContinuation_->callbackMap_[missionId] = GetDSchedService();
    dschedContinuation_->NotifyMissionCenterResult(missionId, resultCode);
    EXPECT_EQ(dschedContinuation_->callbackMap_.size(), 0);
    DTEST_LOG << "DSchedContinuationTest NotifyMissionCenterResult_002 end" << std::endl;
}

/**
 * @tc.name: ProxyCallContinueMission001
 * @tc.desc: call dms proxy ContinueMission
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallContinueMission001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallContinueMission001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    std::string srcDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(srcDeviceId);
    WantParams wantParams;
    int32_t ret = proxy->ContinueMission(srcDeviceId, "MockdevId", 0, GetDSchedService(), wantParams);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallContinueMission001 end" << std::endl;
}

/**
 * @tc.name: ProxyCallContinueMission002
 * @tc.desc: call dms proxy ContinueMission
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallContinueMission002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallContinueMission002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    std::string srcDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(srcDeviceId);
    WantParams wantParams;
    int32_t ret = proxy->ContinueMission(srcDeviceId, "MockdevId", 0, nullptr, wantParams);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallContinueMission002 end" << std::endl;
}

/**
 * @tc.name: ProxyCallStartContinuation001
 * @tc.desc: call dms proxy StartContinuation
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallStartContinuation001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartContinuation001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    OHOS::AAFwk::Want want;
    want.SetElementName("123_remote_device_id", "ohos.demo.bundleName", "abilityName");
    int32_t ret = proxy->StartContinuation(want, 0, 0, 0, 0);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartContinuation001 end" << std::endl;
}

/**
 * @tc.name: ProxyCallNotifyContinuationResultFromRemote001
 * @tc.desc: call dms proxy NotifyContinuationResultFromRemote
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallNotifyContinuationResultFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallNotifyContinuationResultFromRemote001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    std::string srcDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(srcDeviceId);
    proxy->NotifyCompleteContinuation(Str8ToStr16(srcDeviceId), 0, true);
    int32_t ret = proxy->NotifyContinuationResultFromRemote(0, true);
    EXPECT_EQ(ret, REQUEST_CODE_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallNotifyContinuationResultFromRemote001 end" << std::endl;
}

/**
 * @tc.name: NotifyProcessDiedFromRemote001
 * @tc.desc: call dms proxy NotifyProcessDiedFromRemote
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallNotifyProcessDiedFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallNotifyProcessDiedFromRemote001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = "255.255.255.255";
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "123456";
    int32_t ret = proxy->NotifyProcessDiedFromRemote(callerInfo);
    EXPECT_NE(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallNotifyProcessDiedFromRemote001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityByCall001
 * @tc.desc: call dms proxy StartRemoteAbilityByCall
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallStartRemoteAbilityByCall001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartRemoteAbilityByCall001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    string bundleName = "bundleName";
    string abilityName = "abilityName";
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, 0);
    int32_t ret = proxy->StartRemoteAbilityByCall(*spWant, nullptr, 0, 0, 1);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartRemoteAbilityByCall001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityByCall001
 * @tc.desc: call dms proxy StartRemoteAbilityByCall
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallStartRemoteAbilityByCall002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartRemoteAbilityByCall002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    string bundleName = "bundleName";
    string abilityName = "abilityName";
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, 0);
    int32_t ret = proxy->StartRemoteAbilityByCall(*spWant, GetDSchedService(), 0, 0, 1);
    EXPECT_NE(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartRemoteAbilityByCall002 end" << std::endl;
}

/**
 * @tc.name: ReleaseRemoteAbility001
 * @tc.desc: call dms proxy ReleaseRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallReleaseRemoteAbility001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseRemoteAbility001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    int32_t ret = proxy->ReleaseRemoteAbility(nullptr, element);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: ReleaseRemoteAbility002
 * @tc.desc: call dms proxy ReleaseRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallReleaseRemoteAbility002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseRemoteAbility002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    int32_t ret = proxy->ReleaseRemoteAbility(GetDSchedService(), element);
    EXPECT_NE(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseRemoteAbility002 end" << std::endl;
}

/**
 * @tc.name: ProxyCallStartAbilityByCallFromRemote001
 * @tc.desc: call dms proxy StartAbilityByCallFromRemote
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallStartAbilityByCallFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseRemoteAbility001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    // mock want
    string bundleName = "bundleName";
    string abilityName = "abilityName";
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, 0);
    // mock callerinfo
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = "255.255.255.255";
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "123456";
    // mock accountInfo
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = 1;
    accountInfo.groupIdList.push_back("123456");

    int32_t ret = proxy->StartAbilityByCallFromRemote(*spWant, nullptr, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: StartAbilityByCallFromRemote002
 * @tc.desc: call dms proxy StartAbilityByCallFromRemote
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallStartAbilityByCallFromRemote002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseRemoteAbility002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    // mock want
    string bundleName = "bundleName";
    string abilityName = "abilityName";
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, 0);
    // mock callerinfo
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = "255.255.255.255";
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "123456";
    // mock accountInfo
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = 1;
    accountInfo.groupIdList.push_back("123456");

    int32_t ret = proxy->StartAbilityByCallFromRemote(*spWant, GetDSchedService(), callerInfo, accountInfo);
    EXPECT_NE(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseRemoteAbility002 end" << std::endl;
}

/**
 * @tc.name: ReleaseAbilityFromRemote001
 * @tc.desc: call dms proxy ReleaseAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallReleaseAbilityFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseAbilityFromRemote001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    // mock callerinfo
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = "255.255.255.255";
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "123456";

    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    int32_t ret = proxy->ReleaseAbilityFromRemote(nullptr, element, callerInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseAbilityFromRemote001 end" << std::endl;
}

/**
 * @tc.name: ReleaseAbilityFromRemote002
 * @tc.desc: call dms proxy ReleaseAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallReleaseAbilityFromRemote002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseAbilityFromRemote002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    // mock callerinfo
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = "255.255.255.255";
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "123456";

    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    int32_t ret = proxy->ReleaseAbilityFromRemote(GetDSchedService(), element, callerInfo);
    EXPECT_NE(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallReleaseAbilityFromRemote002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteFreeInstall001
 * @tc.desc: call dms proxy StartRemoteFreeInstall
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallStartRemoteFreeInstall001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartRemoteFreeInstall001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    // mock want
    string bundleName = "bundleName";
    string abilityName = "abilityName";
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, 0);

    int32_t ret = proxy->StartRemoteFreeInstall(*spWant, 0, 1, 1, GetDSchedService());
    EXPECT_NE(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartRemoteFreeInstall001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteFreeInstall002
 * @tc.desc: call dms proxy StartRemoteFreeInstall
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallStartRemoteFreeInstall002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartRemoteFreeInstall002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    // mock want
    string bundleName = "bundleName";
    string abilityName = "abilityName";
    std::shared_ptr<Want> spWant = MockWant(bundleName, abilityName, 0);

    int32_t ret = proxy->StartRemoteFreeInstall(*spWant, 0, 1, 1, nullptr);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartRemoteFreeInstall002 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteFreeInstallFromRemote001
 * @tc.desc: call dms proxy NotifyCompleteFreeInstallFromRemote
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallNotifyCompleteFreeInstallFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallNotifyCompleteFreeInstallFromRemote001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    int32_t ret = proxy->NotifyCompleteFreeInstallFromRemote(1, 1);
    EXPECT_NE(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallNotifyCompleteFreeInstallFromRemote001 end" << std::endl;
}

/**
 * @tc.name: GetDistributedComponentList001
 * @tc.desc: call dms proxy GetDistributedComponentList
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallGetDistributedComponentList001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallGetDistributedComponentList001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    vector<string> distributedComponents = { "test "};
    int32_t ret = proxy->GetDistributedComponentList(distributedComponents);
    EXPECT_NE(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallGetDistributedComponentList001 end" << std::endl;
}

#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
/**
 * @tc.name: StartShareFormFromRemote001
 * @tc.desc: call dms proxy StartShareFormFromRemote
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallStartShareFormFromRemote001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartShareFormFromRemote001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    int32_t ret = proxy->StartShareFormFromRemote("", formShareInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartShareFormFromRemote001 end" << std::endl;
}

/**
 * @tc.name: StartShareFormFromRemote002
 * @tc.desc: call dms proxy StartShareFormFromRemote
 * @tc.type: FUNC
 * @tc.require: I5X9O4
 */
HWTEST_F(DSchedContinuationTest, ProxyCallStartShareFormFromRemote002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartShareFormFromRemote002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    int32_t ret = proxy->StartShareFormFromRemote("111", formShareInfo);
    EXPECT_NE(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedServiceTest ProxyCallStartShareFormFromRemote002 end" << std::endl;
}
#endif
} // DistributedSchedule
} // namespace OHOS
