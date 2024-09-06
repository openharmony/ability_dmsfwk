/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <thread>

#define private public
#define protected public
#include "gtest/gtest.h"

#include "ability_connection_wrapper_stub.h"
#include "bundle/bundle_manager_internal.h"
#include "device_manager.h"
#include "distributed_sched_permission.h"
#include "distributed_sched_proxy.h"
#include "distributed_sched_service.h"
#include "distributed_sched_test_util.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "form_mgr_errors.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "mock_form_mgr_service.h"
#include "mock_distributed_sched.h"
#include "system_ability_definition.h"
#include "test_log.h"
#include "thread_pool.h"
#undef private
#undef protected

using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace DistributedSchedule {
using namespace AAFwk;
using namespace AppExecFwk;
using namespace DistributedHardware;
namespace {
    const string LOCAL_DEVICEID = "192.168.43.100";
    const string REMOTE_DEVICEID = "255.255.255.255";
    const std::string DMS_MISSION_ID = "dmsMissionId";
    const std::string DMS_CONNECT_TOKEN = "connectToken";
    constexpr int32_t MISSION_ID = 1;
    const std::string DMS_SRC_NETWORK_ID = "dmsSrcNetworkId";
    const int DEFAULT_REQUEST_CODE = -1;
    const string ABILITY_NAME = "com.ohos.permissionmanager.MainAbility";
    const string BUNDLE_NAME = "com.ohos.permissionmanager";
    const string DMS_IS_CALLER_BACKGROUND = "dmsIsCallerBackGround";
    constexpr int32_t FOREGROUND = 2;
    constexpr int32_t MAX_TOKEN_NUM = 100000000;
    constexpr int32_t SLEEP_TIME = 1000;
}

class DistributedSchedServiceSecondTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    sptr<IDistributedSched> GetDms();
    int32_t InstallBundle(const std::string &bundlePath) const;
    sptr<IDistributedSched> proxy_;

protected:
    enum class LoopTime : int32_t {
        LOOP_TIME = 10,
        LOOP_PRESSURE_TIME = 100,
    };
    sptr<IRemoteObject> GetDSchedService() const;
    void GetAbilityInfo(const std::string& package, const std::string& name,
        const std::string& bundleName, const std::string& deviceId,
        OHOS::AppExecFwk::AbilityInfo& abilityInfo);

    class DeviceInitCallBack : public DmInitCallback {
        void OnRemoteDied() override;
    };
};

void DistributedSchedServiceSecondTest::SetUpTestCase()
{
    if (!DistributedSchedUtil::LoadDistributedSchedService()) {
        DTEST_LOG << "DistributedSchedServiceSecondTest::SetUpTestCase LoadDistributedSchedService failed" << std::endl;
    }
    const std::string pkgName = "DBinderBus_" + std::to_string(getprocpid());
    std::shared_ptr<DmInitCallback> initCallback_ = std::make_shared<DeviceInitCallBack>();
    DeviceManager::GetInstance().InitDeviceManager(pkgName, initCallback_);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
}

void DistributedSchedServiceSecondTest::TearDownTestCase()
{}

void DistributedSchedServiceSecondTest::SetUp()
{
    DistributedSchedUtil::MockPermission();
}

void DistributedSchedServiceSecondTest::TearDown()
{}

void DistributedSchedServiceSecondTest::DeviceInitCallBack::OnRemoteDied()
{}

sptr<IDistributedSched> DistributedSchedServiceSecondTest::GetDms()
{
    if (proxy_ != nullptr) {
        return proxy_;
    }
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_TRUE(sm != nullptr);
    if (sm == nullptr) {
        DTEST_LOG << "DistributedSchedServiceSecondTest sm is nullptr" << std::endl;
        return nullptr;
    }
    DTEST_LOG << "DistributedSchedServiceSecondTest sm is not nullptr" << std::endl;
    auto distributedObject = sm->GetSystemAbility(DISTRIBUTED_SCHED_SA_ID);
    proxy_ = iface_cast<IDistributedSched>(distributedObject);
    if (proxy_ == nullptr) {
        DTEST_LOG << "DistributedSchedServiceSecondTest DistributedSched is nullptr" << std::endl;
    } else {
        DTEST_LOG << "DistributedSchedServiceSecondTest DistributedSched is not nullptr" << std::endl;
    }
    return proxy_;
}

sptr<IRemoteObject> DistributedSchedServiceSecondTest::GetDSchedService() const
{
    sptr<IRemoteObject> dsched(new MockDistributedSched());
    return dsched;
}

void DistributedSchedServiceSecondTest::GetAbilityInfo(const std::string& package, const std::string& name,
    const std::string& bundleName, const std::string& deviceId, OHOS::AppExecFwk::AbilityInfo& abilityInfo)
{
    abilityInfo.bundleName = bundleName;
    abilityInfo.deviceId = deviceId;
}

/**
 * @tc.name: StartRemoteShareForm_001
 * @tc.desc: call StartRemoteShareForm with dms
 * @tc.type: StartRemoteShareForm
 * @tc.require: issueI5M62D
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartRemoteShareForm_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartRemoteShareForm_001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    const std::string remoteDeviceId = "";
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    auto result = proxy->StartRemoteShareForm(remoteDeviceId, formShareInfo);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), result);
    DTEST_LOG << "DistributedSchedServiceSecondTest StartRemoteShareForm_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteShareForm_002
 * @tc.desc: call StartAbilityFromRemote with dms
 * @tc.type: StartRemoteShareForm
 * @tc.require: issueI5M62D
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartRemoteShareForm_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartRemoteShareForm_002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    const std::string remoteDeviceId = "123456";
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    auto result = proxy->StartRemoteShareForm(remoteDeviceId, formShareInfo);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(DMS_PERMISSION_DENIED), result);
    DTEST_LOG << "DistributedSchedServiceSecondTest StartRemoteShareForm_002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteShareForm_003
 * @tc.desc: call StartRemoteShareForm with dms
 * @tc.type: StartRemoteShareForm
 * @tc.require: issueI5M62D
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartRemoteShareForm_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartRemoteShareForm_003 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    auto result = proxy->StartRemoteShareForm(REMOTE_DEVICEID, formShareInfo);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_NE(ERR_OK, result);
    DTEST_LOG << "DistributedSchedServiceSecondTest StartRemoteShareForm_003 end" << std::endl;
}

/**
 * @tc.name: StartShareFormFromRemote_001
 * @tc.desc: call StartAbilityFromRemote with dms
 * @tc.type: StartShareFormFromRemote
 * @tc.require: issueI5M62D
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartShareFormFromRemote_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartShareFormFromRemote_001 start" << std::endl;
    std::string remoteDeviceId = "";
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(remoteDeviceId);
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    DistributedSchedService::GetInstance().formMgrProxy_ = new MockFormMgrService();
    auto result = DistributedSchedService::GetInstance().StartShareFormFromRemote(remoteDeviceId, formShareInfo);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(ERR_OK), result);

    DTEST_LOG << "DistributedSchedServiceSecondTest StartShareFormFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: StartShareFormFromRemote_002
 * @tc.desc: call StartAbilityFromRemote with dms
 * @tc.type: StartShareFormFromRemote
 * @tc.require: issueI5M62D
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartShareFormFromRemote_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartShareFormFromRemote_002 start" << std::endl;
    std::string remoteDeviceId = "123456";
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    /**
     * @tc.steps: step1. call GetContinuaitonDevice
     */
    DTEST_LOG << "DistributedSchedServiceSecondTest GetContinuaitonDevice_001 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    int32_t missionId = MISSION_ID;
    (void)DistributedSchedService::GetInstance().GetContinuaitonDevice(missionId);
    DTEST_LOG << "DistributedSchedServiceSecondTest GetContinuaitonDevice_001 end" << std::endl;

    auto result = DistributedSchedService::GetInstance().StartShareFormFromRemote(remoteDeviceId, formShareInfo);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result);
    DTEST_LOG << "DistributedSchedServiceSecondTest StartShareFormFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: ProcessCalleeDied_001
 * @tc.desc: call ProcessCalleeDied
 * @tc.type: FUNC
 * @tc.require: I6YLV1
 */
HWTEST_F(DistributedSchedServiceSecondTest, ProcessCalleeDied_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest ProcessCalleeDied_001 start" << std::endl;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    DistributedSchedService::GetInstance().ProcessCalleeDied(connect);
    DistributedSchedService::GetInstance().calleeMap_.clear();
    EXPECT_TRUE(DistributedSchedService::GetInstance().calleeMap_.empty());
    DTEST_LOG << "DistributedSchedServiceSecondTest ProcessCalleeDied_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteFreeInstall_001
 * @tc.desc: call StartRemoteFreeInstall
 * @tc.type: FUNC
 * @tc.require: I76THI
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartRemoteFreeInstall_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartRemoteFreeInstall_001 start" << std::endl;
    AAFwk::Want want;
    AppExecFwk::ElementName element("devicdId", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    auto callback = GetDSchedService();
    int32_t result = DistributedSchedService::GetInstance().StartRemoteFreeInstall(want, 0, 0, 0, callback);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest StartRemoteFreeInstall_001 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteFreeInstall_001
 * @tc.desc: call NotifyCompleteFreeInstall
 * @tc.type: FUNC
 * @tc.require: I76THI
 */
HWTEST_F(DistributedSchedServiceSecondTest, NotifyCompleteFreeInstall_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyCompleteFreeInstall_001 start" << std::endl;

    sptr<IDistributedSched> proxy = GetDms();
    ASSERT_NE(nullptr, proxy);

    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    AppExecFwk::AbilityInfo abilityInfo;
    GetAbilityInfo("com.ohos.distributedmusicplayer", "com.ohos.distributedmusicplayer.MainAbility",
        "com.ohos.distributedmusicplayer", "192.168.43.100", abilityInfo);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;

    int result1 = proxy->StartAbilityFromRemote(want, abilityInfo, 0, callerInfo, accountInfo);
    DTEST_LOG << "result1 is" << result1 << std::endl;

    AppExecFwk::ElementName element2("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    GetAbilityInfo("com.ohos.distributedmusicplayer", "com.ohos.distributedmusicplayer.MainAbilityService",
        "com.ohos.distributedmusicplayer", "192.168.43.100", abilityInfo);
    int result2 = proxy->StartAbilityFromRemote(want, abilityInfo, 0, callerInfo, accountInfo);
    DTEST_LOG << "result2:" << result2 << std::endl;

    /**
    * @tc.steps: step1. call NotifyCompleteFreeInstall when resultCode is not ERR_OK.
    */
    IDistributedSched::FreeInstallInfo info;
    int32_t result = DistributedSchedService::GetInstance().NotifyCompleteFreeInstall(info, 1, -1);
    EXPECT_NE(result, ERR_OK);
    /**
    * @tc.steps: step2. call ProcessCallResult.
    */
    sptr<IRemoteObject> connect(new MockDistributedSched());
    DistributedSchedService::GetInstance().ProcessCallResult(connect, connect);
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyCompleteFreeInstall_001 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_001
 * @tc.desc: call NotifyStateChangedFromRemote with illegal params
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DistributedSchedServiceSecondTest, NotifyStateChangedFromRemote_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    ASSERT_NE(nullptr, proxy);
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    int result1 = proxy->NotifyStateChangedFromRemote(0, 0, element);
    DTEST_LOG << "result1:" << result1 << std::endl;

    EXPECT_NE(result1, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_002
 * @tc.desc: test NotifyStateChangedFromRemote
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DistributedSchedServiceSecondTest, NotifyStateChangedFromRemote_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_002 start" << std::endl;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);

    int ret = DistributedSchedService::GetInstance().NotifyStateChangedFromRemote(0, 0, element);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_003
 * @tc.desc: test NotifyStateChangedFromRemote
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DistributedSchedServiceSecondTest, NotifyStateChangedFromRemote_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_003 start" << std::endl;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);

    sptr<IRemoteObject> connect = nullptr;
    DistributedSchedService::GetInstance().callMap_[connect] = {1, localDeviceId};
    int ret = DistributedSchedService::GetInstance().NotifyStateChangedFromRemote(0, 0, element);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_003 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_004
 * @tc.desc: test NotifyStateChangedFromRemote
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceSecondTest, NotifyStateChangedFromRemote_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_004 start" << std::endl;
    sptr<AppStateObserver> appStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChangedFromRemote(abilityState, 0, element);
    DTEST_LOG << "ret:" << ret << std::endl;
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_004 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_005
 * @tc.desc: test NotifyStateChangedFromRemote
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceSecondTest, NotifyStateChangedFromRemote_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_005 start" << std::endl;
    sptr<AppStateObserver> appStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect = nullptr;
    DistributedSchedService::GetInstance().callMap_[connect] = {2, localDeviceId};
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChangedFromRemote(abilityState, 0, element);
    DTEST_LOG << "ret:" << ret << std::endl;
    DistributedSchedService::GetInstance().callMap_.clear();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_005 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_006
 * @tc.desc: test NotifyStateChangedFromRemote
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceSecondTest, NotifyStateChangedFromRemote_006, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_006 start" << std::endl;
    sptr<AppStateObserver> appStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    DistributedSchedService::GetInstance().callMap_[connect] = {3, localDeviceId};
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChangedFromRemote(abilityState, 3, element);
    DTEST_LOG << "ret:" << ret << std::endl;
    DistributedSchedService::GetInstance().callMap_.clear();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChangedFromRemote_006 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChanged_001
 * @tc.desc: test NotifyStateChanged
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DistributedSchedServiceSecondTest, NotifyStateChanged_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChanged_001 start" << std::endl;

    sptr<IDistributedSched> proxy = GetDms();

    AAFwk::Want want;
    AppExecFwk::ElementName element("1.1.1.1", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = 1;
    accountInfo.groupIdList.push_back("123456");
    int missionId = 0;
    want.SetParam(DMS_SRC_NETWORK_ID, callerInfo.sourceDeviceId);
    want.SetParam(DMS_MISSION_ID, missionId);

    int result1 = DistributedSchedService::GetInstance().SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    DTEST_LOG << "result1:" << result1 << std::endl;

    AppExecFwk::ElementName element2("1.1.1.1", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    int result2 = DistributedSchedService::GetInstance().SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;

    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    AppExecFwk::ElementName element3(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChanged(abilityState, element3, nullptr);
    DTEST_LOG << "ret:" << ret << std::endl;
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChanged_001 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChanged_002
 * @tc.desc: test NotifyStateChanged
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceSecondTest, NotifyStateChanged_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChanged_002 start" << std::endl;
    sptr<AppStateObserver> appStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    DistributedSchedService::GetInstance().observerMap_[connect] = {appStateObserver, localDeviceId, 0, BUNDLE_NAME,
        ABILITY_NAME};
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChanged(abilityState, element, nullptr);
    DTEST_LOG << "ret:" << ret << std::endl;
    DistributedSchedService::GetInstance().observerMap_.clear();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChanged_002 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChanged_003
 * @tc.desc: test NotifyStateChanged
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceSecondTest, NotifyStateChanged_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChanged_003 start" << std::endl;
    sptr<AppStateObserver> appStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    DistributedSchedService::GetInstance().observerMap_[connect] = {appStateObserver, REMOTE_DEVICEID, 0, BUNDLE_NAME,
        ABILITY_NAME};
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChanged(abilityState, element, nullptr);
    DTEST_LOG << "ret:" << ret << std::endl;
    DistributedSchedService::GetInstance().observerMap_.clear();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest NotifyStateChanged_003 end" << std::endl;
}

/**
 * @tc.name: StopRemoteExtensionAbility_001
 * @tc.desc: StopRemoteExtensionAbility with uninitialized params, return INVALID_PARAMETERS_ERR.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, StopRemoteExtensionAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StopRemoteExtensionAbility_001 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    uint32_t accessToken = 0;
    int32_t extensionType = 3;
    std::string deviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(deviceId);
    AppExecFwk::ElementName element(deviceId, "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    EXPECT_EQ(DistributedSchedService::GetInstance().StopRemoteExtensionAbility(want, callerUid, accessToken,
        extensionType), INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest StopRemoteExtensionAbility_001 end" << std::endl;
}

/**
 * @tc.name: StopRemoteExtensionAbility_002
 * @tc.desc: StopRemoteExtensionAbility with empty want's deviceId, return INVALID_PARAMETERS_ERR.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, StopRemoteExtensionAbility_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StopRemoteExtensionAbility_002 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    uint32_t accessToken = 0;
    int32_t extensionType = 3;
    AppExecFwk::ElementName element("abcdefg123456", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    EXPECT_EQ(DistributedSchedService::GetInstance().StopRemoteExtensionAbility(want, callerUid, accessToken,
        extensionType), INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest StopRemoteExtensionAbility_002 end" << std::endl;
}

/**
 * @tc.name: StopRemoteExtensionAbility_003
 * @tc.desc: call StopRemoteExtensionAbility
 * @tc.type: FUNC
 * @tc.require: I6YLV1
 */
HWTEST_F(DistributedSchedServiceSecondTest, StopRemoteExtensionAbility_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StopRemoteExtensionAbility_003 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    ASSERT_NE(nullptr, proxy);
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME,
        ABILITY_NAME);
    want.SetElement(element);
    int32_t extensionType = 3;
    int result = proxy->StopRemoteExtensionAbility(want, 0, 0, extensionType);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedServiceSecondTest StopRemoteExtensionAbility_003 end" << std::endl;
}

/**
 * @tc.name: StopExtensionAbilityFromRemote_001
 * @tc.desc: StopExtensionAbilityFromRemote with uninitialized params, return INVALID_REMOTE_PARAMETERS_ERR.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, StopExtensionAbilityFromRemote_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StopExtensionAbilityFromRemote_001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    ASSERT_NE(nullptr, proxy);
    AAFwk::Want remoteWant;
    std::string deviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(deviceId);
    AppExecFwk::ElementName element(deviceId, "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    remoteWant.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    int32_t extensionType = 3;
    EXPECT_EQ(DistributedSchedService::GetInstance().StopExtensionAbilityFromRemote(remoteWant, callerInfo,
        accountInfo, extensionType), INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest StopExtensionAbilityFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: StopExtensionAbilityFromRemote_002
 * @tc.desc: StopExtensionAbilityFromRemote with empty want's deviceId, return DMS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, StopExtensionAbilityFromRemote_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StopExtensionAbilityFromRemote_002 start" << std::endl;

    sptr<IDistributedSched> proxy = GetDms();
    ASSERT_NE(nullptr, proxy);
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
    int missionId = 0;
    want.SetParam(DMS_SRC_NETWORK_ID, callerInfo.sourceDeviceId);
    want.SetParam(DMS_MISSION_ID, missionId);
    /**
     * @tc.steps: step2. SendResultFromRemote for pressure test
     * @tc.expected: step2. SendResultFromRemote for result
     */
    for (int index = 0; index < static_cast<int32_t>(LoopTime::LOOP_TIME); index++) {
        int result = proxy->SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
        DTEST_LOG << "pressure" + to_string(index) + " result is " << result << std::endl;
    }

    AAFwk::Want remoteWant;
    AppExecFwk::ElementName element1("abcdefg123456", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    remoteWant.SetElement(element1);
    CallerInfo callerInfo1;
    callerInfo1.uid = 0;
    callerInfo1.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo1;
    int32_t extensionType = 3;
    EXPECT_EQ(DistributedSchedService::GetInstance().StopExtensionAbilityFromRemote(remoteWant, callerInfo1,
        accountInfo1, extensionType), INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest StopExtensionAbilityFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: StopExtensionAbilityFromRemote_003
 * @tc.desc: StopExtensionAbilityFromRemote with empty want's deviceId, return INVALID_REMOTE_PARAMETERS_ERR.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, StopExtensionAbilityFromRemote_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StopExtensionAbilityFromRemote_003 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    ASSERT_NE(nullptr, proxy);
    AAFwk::Want remoteWant;
    AppExecFwk::ElementName element("abcdefg123456", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    remoteWant.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    int32_t extensionType = 3;
    EXPECT_EQ(proxy->StopExtensionAbilityFromRemote(remoteWant, callerInfo,
        accountInfo, extensionType), IPC_STUB_UNKNOW_TRANS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest StopExtensionAbilityFromRemote_003 end" << std::endl;
}

/**
 * @tc.name: StopExtensionAbilityFromRemote_004
 * @tc.desc: call StopExtensionAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: I6YLV1
 */
HWTEST_F(DistributedSchedServiceSecondTest, StopExtensionAbilityFromRemote_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StopExtensionAbilityFromRemote_004 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME,
        ABILITY_NAME);
    want.SetElement(element);
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.permissions.clear();
    sptr<IRemoteObject> connect(new MockDistributedSched());
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_TRUE(result);
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    int32_t extensionType = 3;
    int ret = DistributedSchedService::GetInstance().StopExtensionAbilityFromRemote(want, callerInfo,
        accountInfo, extensionType);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest StopExtensionAbilityFromRemote_004 end" << std::endl;
}

/**
 * @tc.name: CheckDistributedConnectLocked001
 * @tc.desc: call CheckDistributedConnectLocked
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceSecondTest, CheckDistributedConnectLocked001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest CheckDistributedConnectLocked001 start" << std::endl;
    int32_t uid = IPCSkeleton::GetCallingUid();
    CallerInfo callerInfo;
    callerInfo.uid = uid;
    int32_t ret = DistributedSchedService::GetInstance().CheckDistributedConnectLocked(callerInfo);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceSecondTest CheckDistributedConnectLocked001 end" << std::endl;
}

/**
 * @tc.name: CheckDistributedConnectLocked002
 * @tc.desc: call CheckDistributedConnectLocked
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceSecondTest, CheckDistributedConnectLocked002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest CheckDistributedConnectLocked002 start" << std::endl;
    int32_t uid = -1;
    CallerInfo callerInfo;
    callerInfo.uid = uid;
    int32_t ret = DistributedSchedService::GetInstance().CheckDistributedConnectLocked(callerInfo);
    EXPECT_EQ(ret, BIND_ABILITY_UID_INVALID_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest CheckDistributedConnectLocked002 end" << std::endl;
}

/**
 * @tc.name: TryConnectRemoteAbility001
 * @tc.desc: call TryConnectRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceSecondTest, TryConnectRemoteAbility001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest TryConnectRemoteAbility001 start" << std::endl;
    std::string remoteDeviceId = "remoteDeviceId";
    OHOS::AAFwk::Want want;
    want.SetElementName(remoteDeviceId, "ohos.demo.bundleName", "abilityName");
    sptr<IRemoteObject> connect = nullptr;
    CallerInfo callerInfo;
    int32_t ret = DistributedSchedService::GetInstance().TryConnectRemoteAbility(want, connect, callerInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest TryConnectRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: TryConnectRemoteAbility002
 * @tc.desc: call TryConnectRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceSecondTest, TryConnectRemoteAbility002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest TryConnectRemoteAbility002 start" << std::endl;
    std::string remoteDeviceId = "remoteDeviceId";
    OHOS::AAFwk::Want want;
    want.SetElementName(remoteDeviceId, "ohos.demo.bundleName", "abilityName");
    sptr<IRemoteObject> connect = nullptr;
    CallerInfo callerInfo;
    int32_t ret = DistributedSchedService::GetInstance().TryConnectRemoteAbility(want, connect, callerInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest TryConnectRemoteAbility002 end" << std::endl;
}

/**
 * @tc.name: SetCallerInfo_001
 * @tc.desc: call SetCallerInfo
 * @tc.type: FUNC
 * @tc.require: I76THI
 */
HWTEST_F(DistributedSchedServiceSecondTest, SetCallerInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest SetCallerInfo_001 start" << std::endl;

    sptr<IDistributedSched> proxy = GetDms();
    ASSERT_NE(nullptr, proxy);
    /**
     * @tc.steps: step1. set want and abilityInfo
     */
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    AppExecFwk::AbilityInfo abilityInfo;
    GetAbilityInfo("com.ohos.distributedmusicplayer", "com.ohos.distributedmusicplayer.MainAbility",
        "com.ohos.distributedmusicplayer", "192.168.43.100", abilityInfo);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    /**
     * @tc.steps: step2. StartAbilityFromRemote for pressure test
     * @tc.expected: step2. StartAbilityFromRemote for result
     */
    for (int index = 0; index < static_cast<int32_t>(LoopTime::LOOP_TIME); index++) {
        int result = proxy->StartAbilityFromRemote(want, abilityInfo, 0, callerInfo, accountInfo);
        DTEST_LOG << "pressure" + to_string(index) + " result is " << result << std::endl;
    }

    /**
    * @tc.steps: step1. call SetCallerInfo with invalid parameters.
    */
    CallerInfo callerInfo1;
    int32_t result = DistributedSchedService::GetInstance().SetCallerInfo(0, LOCAL_DEVICEID, 0, callerInfo1);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    /**
    * @tc.steps: step2. call OnRemoteDied.
    */
    const wptr<IRemoteObject> remote;
    CallerDeathRecipient callerDeathRecipient;
    callerDeathRecipient.OnRemoteDied(remote);
    DTEST_LOG << "DistributedSchedServiceSecondTest StartRemoteAbilityByCall_001 end" << std::endl;
}

/**
 * @tc.name: ContinueRemoteMission_001
 * @tc.desc: call ContinueRemoteMission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, ContinueRemoteMission_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueRemoteMission_001 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    int32_t missionId = MISSION_ID;
    int32_t timeout = 5;
    DistributedSchedService::GetInstance().SetContinuationTimeout(missionId, timeout);
    WantParams wantParams;
    EXPECT_EQ(ERR_OK, LoadContinueConfig());
    auto callback = GetDSchedService();
    int32_t result = DistributedSchedService::GetInstance().ContinueRemoteMission(
        "", "string", "bundleName", callback, wantParams);
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result);
    DTEST_LOG << "DSchedContinuationTest ContinueRemoteMission_001 end" << std::endl;
}

/**
 * @tc.name: ContinueRemoteMission_002
 * @tc.desc: call ContinueRemoteMission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, ContinueRemoteMission_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueRemoteMission_002 start" << std::endl;
    WantParams wantParams;
    EXPECT_EQ(ERR_OK, LoadContinueConfig());
    auto callback = GetDSchedService();
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    int32_t result = DistributedSchedService::GetInstance().ContinueRemoteMission(
        "string", localDeviceId, "bundleName", callback, wantParams);
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result);
    DTEST_LOG << "DSchedContinuationTest ContinueRemoteMission_002 end" << std::endl;
}

/**
 * @tc.name: StartLocalAbility_001
 * @tc.desc: call StartLocalAbility with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartLocalAbility_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartLocalAbility_001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();

    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    int missionId = 0;
    want.SetParam(DMS_SRC_NETWORK_ID, callerInfo.sourceDeviceId);
    want.SetParam(DMS_MISSION_ID, missionId);
    DistributedSchedProxy::FreeInstallInfo info = {.want = want, .requestCode = 0, .callerInfo = callerInfo,
        .accountInfo = accountInfo};
    int result1 = DistributedSchedService::GetInstance().StartLocalAbility(info, 0, 0);
    DTEST_LOG << "result1:" << result1 << std::endl;

    AppExecFwk::ElementName element2("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    DistributedSchedProxy::FreeInstallInfo info2 = {.want = want, .requestCode = 0, .callerInfo = callerInfo,
        .accountInfo = accountInfo};
    int result2 = DistributedSchedService::GetInstance().StartLocalAbility(info2, 0, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), result1);
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), result2);
    DTEST_LOG << "DistributedSchedServiceSecondTest StartLocalAbility_001 end" << std::endl;
}

/**
 * @tc.name: StartLocalAbility_002
 * @tc.desc: call StartLocalAbility with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartLocalAbility_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartLocalAbility_002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();

    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    DistributedSchedProxy::FreeInstallInfo info = {.want = want, .requestCode = DEFAULT_REQUEST_CODE,
        .callerInfo = callerInfo, .accountInfo = accountInfo};
    int result1 = DistributedSchedService::GetInstance().StartLocalAbility(info, 0, 0);
    DTEST_LOG << "result1:" << result1 << std::endl;

    AppExecFwk::ElementName element2("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    DistributedSchedProxy::FreeInstallInfo info2 = {.want = want, .requestCode = DEFAULT_REQUEST_CODE,
        .callerInfo = callerInfo, .accountInfo = accountInfo};
    int result2 = DistributedSchedService::GetInstance().StartLocalAbility(info2, 0, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), result1);
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), result2);
    DTEST_LOG << "DistributedSchedServiceSecondTest StartLocalAbility_002 end" << std::endl;
}

/**
 * @tc.name: StartLocalAbility_003
 * @tc.desc: call StartLocalAbility with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartLocalAbility_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartLocalAbility_003 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();

    AAFwk::Want want;
    AppExecFwk::ElementName element("1.1.1.1", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = 1;
    accountInfo.groupIdList.push_back("123456");
    int missionId = 0;
    want.SetParam(DMS_SRC_NETWORK_ID, callerInfo.sourceDeviceId);
    want.SetParam(DMS_MISSION_ID, missionId);
    DistributedSchedProxy::FreeInstallInfo info = {.want = want, .requestCode = 0, .callerInfo = callerInfo,
        .accountInfo = accountInfo};
    int result1 = DistributedSchedService::GetInstance().StartLocalAbility(info, 0, 0);
    DTEST_LOG << "result1:" << result1 << std::endl;

    AppExecFwk::ElementName element2("1.1.1.1", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    DistributedSchedProxy::FreeInstallInfo info2 = {.want = want, .requestCode = 0, .callerInfo = callerInfo,
        .accountInfo = accountInfo};
    int result2 = DistributedSchedService::GetInstance().StartLocalAbility(info2, 0, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;
    DTEST_LOG << "DistributedSchedServiceSecondTest StartLocalAbility_003 end" << std::endl;
}

/**
 * @tc.name: StartLocalAbility_004
 * @tc.desc: call StartLocalAbility with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartLocalAbility_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartLocalAbility_004 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();

    AAFwk::Want want;
    AppExecFwk::ElementName element("1.1.1.1", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = 1;
    accountInfo.groupIdList.push_back("123456");
    DistributedSchedProxy::FreeInstallInfo info = {.want = want, .requestCode = DEFAULT_REQUEST_CODE,
        .callerInfo = callerInfo, .accountInfo = accountInfo};
    int result1 = DistributedSchedService::GetInstance().StartLocalAbility(info, 0, 0);
    DTEST_LOG << "result1:" << result1 << std::endl;

    AppExecFwk::ElementName element2("1.1.1.1", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    DistributedSchedProxy::FreeInstallInfo info2 = {.want = want, .requestCode = DEFAULT_REQUEST_CODE,
        .callerInfo = callerInfo, .accountInfo = accountInfo};
    int result2 = DistributedSchedService::GetInstance().StartLocalAbility(info2, 0, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;
    DTEST_LOG << "DistributedSchedServiceSecondTest StartLocalAbility_004 end" << std::endl;
}

/**
 * @tc.name: StartLocalAbility_005
 * @tc.desc: test StartLocalAbility
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartLocalAbility_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartLocalAbility_005 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.ohos.mms", "bmsThirdBundle");
    want.SetElement(element);
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.permissions.clear();
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms("com.third.hiworld.example", callerInfo.callerAppId);
    EXPECT_TRUE(result);
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    DistributedSchedProxy::FreeInstallInfo info = {.want = want, .requestCode = 0,
        .callerInfo = callerInfo, .accountInfo = accountInfo};
    int ret = DistributedSchedService::GetInstance().StartLocalAbility(info, 0, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceSecondTest StartLocalAbility_005 end" << std::endl;
}

/**
 * @tc.name: HandleLocalCallerDied_001
 * @tc.desc: call HandleLocalCallerDied
 * @tc.type: FUNC
 * @tc.require: I6YLV1
 */
HWTEST_F(DistributedSchedServiceSecondTest, HandleLocalCallerDied_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest HandleLocalCallerDied_001 start" << std::endl;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    std::list<ConnectAbilitySession> sessionsList;
    DistributedSchedService::GetInstance().callerMap_[connect] = sessionsList;
    DistributedSchedService::GetInstance().callMap_[connect] = {4, localDeviceId};
    DistributedSchedService::GetInstance().HandleLocalCallerDied(connect);
    DistributedSchedService::GetInstance().callerMap_.clear();
    EXPECT_TRUE(DistributedSchedService::GetInstance().callerMap_.empty());
    DistributedSchedService::GetInstance().callMap_.clear();
    EXPECT_TRUE(DistributedSchedService::GetInstance().callMap_.empty());
    DTEST_LOG << "DistributedSchedServiceSecondTest HandleLocalCallerDied_001 end" << std::endl;
}

/**
 * @tc.name: RemoveCallerComponent_001
 * @tc.desc: call RemoveCallerComponent
 * @tc.type: FUNC
 * @tc.require: I6YLV1
 */
HWTEST_F(DistributedSchedServiceSecondTest, RemoveCallerComponent_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest RemoveCallerComponent_001 start" << std::endl;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    std::list<ConnectAbilitySession> sessionsList;
    DistributedSchedService::GetInstance().callerMap_[connect] = sessionsList;
    DistributedSchedService::GetInstance().callMap_[connect] = {5, localDeviceId};
    DistributedSchedService::GetInstance().RemoveCallerComponent(connect);
    DistributedSchedService::GetInstance().RemoveCallerComponent(nullptr);
    DistributedSchedService::GetInstance().callerMap_.clear();
    EXPECT_TRUE(DistributedSchedService::GetInstance().callerMap_.empty());
    DistributedSchedService::GetInstance().callMap_.clear();
    EXPECT_TRUE(DistributedSchedService::GetInstance().callMap_.empty());
    DTEST_LOG << "DistributedSchedServiceSecondTest RemoveCallerComponent_001 end" << std::endl;
}

/**
 * @tc.name: ProcessCalleeOffline_001
 * @tc.desc: call ProcessCalleeOffline
 * @tc.type: FUNC
 * @tc.require: I6YLV1
 */
HWTEST_F(DistributedSchedServiceSecondTest, ProcessCalleeOffline_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest ProcessCalleeOffline_001 start" << std::endl;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    std::list<ConnectAbilitySession> sessionsList;
    DistributedSchedService::GetInstance().callerMap_[connect] = sessionsList;
    DistributedSchedService::GetInstance().callMap_[connect] = {6, localDeviceId};
    DistributedSchedService::GetInstance().ProcessCalleeOffline(REMOTE_DEVICEID);

    sptr<IRemoteObject> mockConnect = nullptr;
    DistributedSchedService::GetInstance().callerMap_[mockConnect] = sessionsList;
    DistributedSchedService::GetInstance().ProcessCalleeOffline(localDeviceId);
    DistributedSchedService::GetInstance().callerMap_.clear();
    EXPECT_TRUE(DistributedSchedService::GetInstance().callerMap_.empty());
    DistributedSchedService::GetInstance().callMap_.clear();
    EXPECT_TRUE(DistributedSchedService::GetInstance().callMap_.empty());
    DTEST_LOG << "DistributedSchedServiceSecondTest ProcessCalleeOffline_001 end" << std::endl;
}

/**
 * @tc.name: GetConnectComponentList_001
 * @tc.desc: call GetConnectComponentList
 * @tc.type: FUNC
 * @tc.require: I76THI
 */
HWTEST_F(DistributedSchedServiceSecondTest, GetConnectComponentList_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest GetConnectComponentList_001 start" << std::endl;
    /**
    * @tc.steps: step1. call GetConnectComponentList when iter.second is empty.
    */
    sptr<IRemoteObject> connect(new MockDistributedSched());
    std::list<ConnectAbilitySession> sessionsList;
    std::vector<std::string> distributedComponents;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().distributedLock_);
        DistributedSchedService::GetInstance().distributedConnectAbilityMap_.clear();
        DistributedSchedService::GetInstance().distributedConnectAbilityMap_[connect] = sessionsList;
    }
    DistributedSchedService::GetInstance().GetConnectComponentList(distributedComponents);
    EXPECT_TRUE(distributedComponents.empty());
    /**
    * @tc.steps: step2. call GetConnectComponentList when iter.second is not empty.
    */
    CallerInfo callerInfo;
    ConnectAbilitySession connectAbilitySession("sourceDeviceId", "destinationDeviceId", callerInfo);
    sessionsList.emplace_back(connectAbilitySession);
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().distributedLock_);
        DistributedSchedService::GetInstance().distributedConnectAbilityMap_[connect] = sessionsList;
    }
    DistributedSchedService::GetInstance().GetConnectComponentList(distributedComponents);
    EXPECT_FALSE(distributedComponents.empty());
    /**
    * @tc.steps: step3. call GetConnectComponentList when connectAbilityMap_ is not empty.
    */
    distributedComponents.clear();
    ConnectInfo connectInfo;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().connectLock_);
        DistributedSchedService::GetInstance().connectAbilityMap_[connect] = connectInfo;
    }
    DistributedSchedService::GetInstance().GetConnectComponentList(distributedComponents);
    EXPECT_FALSE(distributedComponents.empty());
    DTEST_LOG << "DistributedSchedServiceSecondTest GetConnectComponentList_001 end" << std::endl;
}

/**
 * @tc.name: GetCallComponentList_001
 * @tc.desc: call GetCallComponentList
 * @tc.type: FUNC
 * @tc.require: I76THI
 */
HWTEST_F(DistributedSchedServiceSecondTest, GetCallComponentList_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest GetCallComponentList_001 start" << std::endl;
    /**
    * @tc.steps: step1. call GetCallComponentList when iter.second is empty.
    */
    sptr<IRemoteObject> connect(new MockDistributedSched());
    std::list<ConnectAbilitySession> sessionsList;
    std::vector<std::string> distributedComponents;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().callerLock_);
        DistributedSchedService::GetInstance().callerMap_.clear();
        DistributedSchedService::GetInstance().callerMap_[connect] = sessionsList;
    }
    DistributedSchedService::GetInstance().GetCallComponentList(distributedComponents);
    EXPECT_TRUE(distributedComponents.empty());
    /**
    * @tc.steps: step2. call GetCallComponentList when iter.second is not empty.
    */
    CallerInfo callerInfo;
    ConnectAbilitySession connectAbilitySession("sourceDeviceId", "destinationDeviceId", callerInfo);
    sessionsList.emplace_back(connectAbilitySession);
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().callerLock_);
        DistributedSchedService::GetInstance().callerMap_[connect] = sessionsList;
    }
    DistributedSchedService::GetInstance().GetCallComponentList(distributedComponents);
    EXPECT_FALSE(distributedComponents.empty());
    /**
    * @tc.steps: step3. call GetCallComponentList when calleeMap_ is not empty.
    */
    distributedComponents.clear();
    ConnectInfo connectInfo;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().calleeLock_);
        DistributedSchedService::GetInstance().calleeMap_[connect] = connectInfo;
    }
    DistributedSchedService::GetInstance().GetCallComponentList(distributedComponents);
    EXPECT_FALSE(distributedComponents.empty());
    DTEST_LOG << "DistributedSchedServiceSecondTest GetCallComponentList_001 end" << std::endl;
}

/**
 * @tc.name: RegisterAppStateObserver_001
 * @tc.desc: test RegisterAppStateObserver
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceSecondTest, RegisterAppStateObserver_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest RegisterAppStateObserver_001 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    want.SetParam(DMS_MISSION_ID, 0);
    want.SetParam(DMS_CONNECT_TOKEN, 0);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = localDeviceId;
    bool ret = DistributedSchedService::GetInstance().RegisterAppStateObserver(want, callerInfo, nullptr, connect);
    DistributedSchedService::GetInstance().UnregisterAppStateObserver(connect);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedServiceSecondTest RegisterAppStateObserver_001 end" << std::endl;
}

/**
 * @tc.name: UnregisterAppStateObserver_001
 * @tc.desc: test UnregisterAppStateObserver
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceSecondTest, UnregisterAppStateObserver_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest UnregisterAppStateObserver_001 start" << std::endl;
    sptr<IRemoteObject> connect = nullptr;
    DistributedSchedService::GetInstance().UnregisterAppStateObserver(connect);
    EXPECT_EQ(connect, nullptr);
    DTEST_LOG << "DistributedSchedServiceSecondTest UnregisterAppStateObserver_001 end" << std::endl;
}

/**
 * @tc.name: UnregisterAppStateObserver_002
 * @tc.desc: test UnregisterAppStateObserver
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceSecondTest, UnregisterAppStateObserver_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest UnregisterAppStateObserver_002 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    want.SetParam(DMS_MISSION_ID, 0);
    want.SetParam(DMS_CONNECT_TOKEN, 0);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = localDeviceId;
    bool ret = DistributedSchedService::GetInstance().RegisterAppStateObserver(want, callerInfo, nullptr, connect);
    EXPECT_TRUE(ret);
    sptr<IRemoteObject> connect1(new MockDistributedSched());
    DistributedSchedService::GetInstance().UnregisterAppStateObserver(connect1);
    EXPECT_NE(connect, connect1);
    DistributedSchedService::GetInstance().SaveCallerComponent(want, nullptr, callerInfo);
    DTEST_LOG << "DistributedSchedServiceSecondTest UnregisterAppStateObserver_002 end" << std::endl;
}

/**
 * @tc.name: GetAppManager_001
 * @tc.desc: test GetAppManager
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceSecondTest, GetAppManager_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest GetAppManager_001 start" << std::endl;
    auto ret = DistributedSchedService::GetInstance().GetAppManager();
    EXPECT_NE(ret, nullptr);
    DTEST_LOG << "DistributedSchedServiceSecondTest GetAppManager_001 end" << std::endl;
}

/**
 * @tc.name: SaveConnectToken_001
 * @tc.desc: call SaveConnectToken
 * @tc.type: FUNC
 * @tc.require: I76THI
 */
HWTEST_F(DistributedSchedServiceSecondTest, SaveConnectToken_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest SaveConnectToken_001 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME,
        ABILITY_NAME);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    /**
    * @tc.steps: step1. call SaveConnectToken
    * @tc.expected: step1. SaveConnectToken return token_
    */
    int32_t token = 0;
    {
        std::lock_guard<std::mutex> tokenLock(DistributedSchedService::GetInstance().tokenMutex_);
        token = DistributedSchedService::GetInstance().token_.load();
    }
    int32_t result = DistributedSchedService::GetInstance().SaveConnectToken(want, connect);
    EXPECT_EQ(result, token + 1);
    /**
    * @tc.steps: step2. call SaveConnectToken when tToken > MAX_TOKEN_NUM
    * @tc.expected: step2. SaveConnectToken return 1
    */
    {
        std::lock_guard<std::mutex> tokenLock(DistributedSchedService::GetInstance().tokenMutex_);
        DistributedSchedService::GetInstance().token_.store(MAX_TOKEN_NUM);
    }
    result = DistributedSchedService::GetInstance().SaveConnectToken(want, connect);
    EXPECT_EQ(result, 1);
    DTEST_LOG << "DistributedSchedServiceSecondTest SaveConnectToken_001 end" << std::endl;
}

/**
 * @tc.name: ContinueMissionBundleName_001
 * @tc.desc: call ContinueMissionBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, ContinueMissionBundleName_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueMissionBundleName_001 start" << std::endl;
    WantParams wantParams;
    auto callback = GetDSchedService();
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    int32_t result = DistributedSchedService::GetInstance().ContinueMission(
        "string", localDeviceId, "bundleName", callback, wantParams);
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result);
    DistributedSchedService::GetInstance().ContinueMission(
        localDeviceId, "string", "bundleName", callback, wantParams);
    DTEST_LOG << "DSchedContinuationTest ContinueMissionBundleName_001 end" << std::endl;
}

/**
 * @tc.name: ContinueMissionBundleName_002
 * @tc.desc: call ContinueMissionBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, ContinueMissionBundleName_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueMissionBundleName_002 start" << std::endl;
    WantParams wantParams;
    auto callback = GetDSchedService();
    int32_t result = DistributedSchedService::GetInstance().ContinueMission(
        "string", "string", "bundleName", callback, wantParams);
    EXPECT_EQ(static_cast<int>(OPERATION_DEVICE_NOT_INITIATOR_OR_TARGET), result);
    DTEST_LOG << "DSchedContinuationTest ContinueMissionBundleName_002 end" << std::endl;
}

/**
 * @tc.name: GetCallerInfo_001
 * @tc.desc: GetCallerInfo
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, GetCallerInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest GetCallerInfo_001 start" << std::endl;
    int32_t callerUid = 0;
    uint32_t accessToken = 0;
    CallerInfo callerInfo;
    int32_t result = DistributedSchedService::GetInstance().GetCallerInfo(
        LOCAL_DEVICEID, callerUid, accessToken, callerInfo);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceSecondTest GetCallerInfo_001 end" << std::endl;
}

/**
 * @tc.name: ProcessContinueLocalMission_001
 * @tc.desc: ProcessContinueLocalMission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, ProcessContinueLocalMission_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest ProcessContinueLocalMission_001 start" << std::endl;
    WantParams wantParams;
    int32_t result = DistributedSchedService::GetInstance().ProcessContinueLocalMission(
        LOCAL_DEVICEID, REMOTE_DEVICEID, BUNDLE_NAME, nullptr, wantParams);

    bool ret = DistributedSchedService::GetInstance().GetIsFreeInstall(0);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedServiceSecondTest ProcessContinueLocalMission_001 end" << std::endl;
}

/**
 * @tc.name: StartAbility_001
 * @tc.desc: StartAbility
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceSecondTest, StartAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceSecondTest StartAbility_001 start" << std::endl;
    Want want;
    int32_t requestCode = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartAbility(want, requestCode);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceSecondTest StartAbility_001 end" << std::endl;
}
}
}