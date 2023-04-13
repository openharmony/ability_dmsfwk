/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "bundle/bundle_manager_internal.h"
#include "device_manager.h"
#include "distributed_sched_permission.h"
#include "distributed_sched_proxy.h"
#include "distributed_sched_service.h"
#include "distributed_sched_util.h"
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
    const std::u16string DEVICE_ID = u"192.168.43.100";
    const std::u16string DEVICE_ID_NULL = u"";
    constexpr int32_t SESSION_ID = 123;
    const std::string DMS_MISSION_ID = "dmsMissionId";
    constexpr int32_t MISSION_ID = 1;
    const std::string DMS_SRC_NETWORK_ID = "dmsSrcNetworkId";
    const int DEFAULT_REQUEST_CODE = -1;
    const string ABILITY_NAME = "com.ohos.launcher.MainAbility";
    const string BUNDLE_NAME = "com.ohos.launcher";
    const string DMS_IS_CALLER_BACKGROUND = "dmsIsCallerBackGround";
    constexpr int32_t SLEEP_TIME = 1000;
    constexpr int32_t FOREGROUND = 2;
}

class DistributedSchedServiceTest : public testing::Test {
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

void DistributedSchedServiceTest::SetUpTestCase()
{
    if (!DistributedSchedUtil::LoadDistributedSchedService()) {
        DTEST_LOG << "DistributedSchedServiceTest::SetUpTestCase LoadDistributedSchedService failed" << std::endl;
    }
    const std::string pkgName = "DBinderBus_" + std::to_string(getpid());
    std::shared_ptr<DmInitCallback> initCallback_ = std::make_shared<DeviceInitCallBack>();
    DeviceManager::GetInstance().InitDeviceManager(pkgName, initCallback_);
    DistributedSchedUtil::InstallThirdPartyHap();
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
}

void DistributedSchedServiceTest::TearDownTestCase()
{}

void DistributedSchedServiceTest::SetUp()
{
    DistributedSchedUtil::MockPermission();
}

void DistributedSchedServiceTest::TearDown()
{}

void DistributedSchedServiceTest::DeviceInitCallBack::OnRemoteDied()
{}

sptr<IDistributedSched> DistributedSchedServiceTest::GetDms()
{
    if (proxy_ != nullptr) {
        return proxy_;
    }
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_TRUE(sm != nullptr);
    if (sm == nullptr) {
        DTEST_LOG << "DistributedSchedServiceTest sm is nullptr" << std::endl;
        return nullptr;
    }
    DTEST_LOG << "DistributedSchedServiceTest sm is not nullptr" << std::endl;
    auto distributedObject = sm->GetSystemAbility(DISTRIBUTED_SCHED_SA_ID);
    proxy_ = iface_cast<IDistributedSched>(distributedObject);
    if (proxy_ == nullptr) {
        DTEST_LOG << "DistributedSchedServiceTest DistributedSched is nullptr" << std::endl;
    } else {
        DTEST_LOG << "DistributedSchedServiceTest DistributedSched is not nullptr" << std::endl;
    }
    return proxy_;
}

sptr<IRemoteObject> DistributedSchedServiceTest::GetDSchedService() const
{
    sptr<IRemoteObject> dsched = new MockDistributedSched();
    return dsched;
}

void DistributedSchedServiceTest::GetAbilityInfo(const std::string& package, const std::string& name,
    const std::string& bundleName, const std::string& deviceId, OHOS::AppExecFwk::AbilityInfo& abilityInfo)
{
    abilityInfo.bundleName = bundleName;
    abilityInfo.deviceId = deviceId;
}

/**
 * @tc.name: StartRemoteAbility_001
 * @tc.desc: call StartRemoteAbility with illegal params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteAbility_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility_001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    /**
     * @tc.steps: step1. StartRemoteAbility with uninitialized params
     * @tc.expected: step1. StartRemoteAbility return INVALID_PARAMETERS_ERR
     */
    AAFwk::Want want;
    int result1 = proxy->StartRemoteAbility(want, 0, 0, 0);
    DTEST_LOG << "result1:" << result1 << std::endl;
    /**
     * @tc.steps: step2. StartRemoteAbility with empty want's deviceId
     * @tc.expected: step2. StartRemoteAbility return INVALID_PARAMETERS_ERR
     */
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    int result2 = proxy->StartRemoteAbility(want, 0, 0, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;

    EXPECT_EQ(static_cast<int>(DMS_PERMISSION_DENIED), result1);
    EXPECT_EQ(static_cast<int>(DMS_PERMISSION_DENIED), result2);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility_002
 * @tc.desc: call StartRemoteAbility with dms with wrong deviceId and local deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteAbility_002, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility_002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    /**
     * @tc.steps: step1. set want with wrong deviceId
     * @tc.expected: step2. StartRemoteAbility return INVALID_PARAMETERS_ERR
     */
    AAFwk::Want want;
    AppExecFwk::ElementName element("123456", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    int result1 = DistributedSchedService::GetInstance().StartRemoteAbility(want, 0, 0, 0);
    DTEST_LOG << "result:" << result1 << std::endl;
    std::string deviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(deviceId);
    AppExecFwk::ElementName element1(deviceId, "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element1);
    int result2 = DistributedSchedService::GetInstance().StartRemoteAbility(want, 0, 0, 0);
    DTEST_LOG << "result:" << result2 << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), result1);
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), result2);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility_002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility_003
 * @tc.desc: call StartRemoteAbility with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteAbility_003, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility_003 start" << std::endl;
    /**
     * @tc.steps: step1. set want with wrong deviceId
     * @tc.expected: step2. StartRemoteAbility return INVALID_PARAMETERS_ERR
     */
    AAFwk::Want want;
    AppExecFwk::ElementName element("123456", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    int result = DistributedSchedService::GetInstance().StartRemoteAbility(want, 0, 0, 0);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), result);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility_003 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility_004
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteAbility_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility_004 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    /**
     * @tc.steps: step1. set want and abilityInfo
     * @tc.expected: step2. StartRemoteAbility return INVALID_PARAMETERS_ERR
     */
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    int result = proxy->StartRemoteAbility(want, 0, 0, 0);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(DMS_PERMISSION_DENIED), result);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility_004 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemote_001
 * @tc.desc: call StartAbilityFromRemote with illegal param
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartAbilityFromRemote_001, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    AAFwk::Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    /**
     * @tc.steps: step1. StartAbilityFromRemote with uninitialized params
     * @tc.expected: step1. StartAbilityFromRemote return INVALID_REMOTE_PARAMETERS_ERR
     */
    int result1 = proxy->StartAbilityFromRemote(want, abilityInfo, 0, callerInfo, accountInfo);
    DTEST_LOG << "result1:" << result1 << std::endl;
    /**
     * @tc.steps: step1. StartAbilityFromRemote with with empty deviceId
     * @tc.expected: step1. StartAbilityFromRemote return INVALID_REMOTE_PARAMETERS_ERR
     */
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    GetAbilityInfo("com.ohos.distributedmusicplayer", "com.ohos.distributedmusicplayer.MainAbility",
        "com.ohos.distributedmusicplayer", "192.168.43.101", abilityInfo);
    int result2 = proxy->StartAbilityFromRemote(want, abilityInfo, 0, callerInfo, accountInfo);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(static_cast<int>(IPC_STUB_UNKNOW_TRANS_ERR), result1);
    EXPECT_EQ(static_cast<int>(IPC_STUB_UNKNOW_TRANS_ERR), result2);
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemote_002
 * @tc.desc: call StartAbilityFromRemote
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartAbilityFromRemote_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }

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
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemote_003
 * @tc.desc: call StartAbilityFromRemote for pressure test
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartAbilityFromRemote_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_003 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_003 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemote_004
 * @tc.desc: call StartAbilityFromRemote with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartAbilityFromRemote_004, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_004 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();

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

    int result1 = DistributedSchedService::GetInstance().StartAbilityFromRemote(want,
        abilityInfo, 0, callerInfo, accountInfo);
    DTEST_LOG << "result1:" << result1 << std::endl;

    AppExecFwk::ElementName element2("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    GetAbilityInfo("com.ohos.distributedmusicplayer", "com.ohos.distributedmusicplayer.MainAbilityService",
        "com.ohos.distributedmusicplayer", "192.168.43.100", abilityInfo);
    int result2 = DistributedSchedService::GetInstance().StartAbilityFromRemote(want,
        abilityInfo, 0, callerInfo, accountInfo);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result1);
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result2);
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_004 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemote_005
 * @tc.desc: call StartAbilityFromRemote with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartAbilityFromRemote_005, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_005 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();

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
    accountInfo.accountType = 1;
    accountInfo.groupIdList.push_back("123456");

    int result1 = DistributedSchedService::GetInstance().StartAbilityFromRemote(want,
        abilityInfo, 0, callerInfo, accountInfo);
    DTEST_LOG << "result1:" << result1 << std::endl;

    AppExecFwk::ElementName element2("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    GetAbilityInfo("com.ohos.distributedmusicplayer", "com.ohos.distributedmusicplayer.MainAbilityService",
        "com.ohos.distributedmusicplayer", "192.168.43.100", abilityInfo);
    int result2 = DistributedSchedService::GetInstance().StartAbilityFromRemote(want,
        abilityInfo, 0, callerInfo, accountInfo);
    DTEST_LOG << "result2:" << result2 << std::endl;
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_005 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_001
 * @tc.desc: call SendResultFromRemote with illegal param
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, SendResultFromRemote_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    /**
     * @tc.steps: step1. SendResultFromRemote with uninitialized params
     * @tc.expected: step1. SendResultFromRemote return INVALID_REMOTE_PARAMETERS_ERR
     */
    int result1 = proxy->SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    DTEST_LOG << "result1:" << result1 << std::endl;
    /**
     * @tc.steps: step1. SendResultFromRemote with with empty deviceId
     * @tc.expected: step1. SendResultFromRemote return INVALID_REMOTE_PARAMETERS_ERR
     */
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    int result2 = proxy->SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(static_cast<int>(IPC_STUB_UNKNOW_TRANS_ERR), result1);
    EXPECT_EQ(static_cast<int>(IPC_STUB_UNKNOW_TRANS_ERR), result2);
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemote_002
 * @tc.desc: call SendResultFromRemote
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, SendResultFromRemote_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }

    AAFwk::Want want;
    AppExecFwk::ElementName element("255.255.255.255", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    AppExecFwk::AbilityInfo abilityInfo;
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;

    int result1 = proxy->SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    DTEST_LOG << "result1 is" << result1 << std::endl;
    AppExecFwk::ElementName element2("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    int missionId = 0;
    want.SetParam(DMS_SRC_NETWORK_ID, callerInfo.sourceDeviceId);
    want.SetParam(DMS_MISSION_ID, missionId);
    int result2 = proxy->SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_003
 * @tc.desc: call SendResultFromRemote for pressure test
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, SendResultFromRemote_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_003 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_003 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_004
 * @tc.desc: call SendResultFromRemote with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, SendResultFromRemote_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_004 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();

    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;

    int result1 = DistributedSchedService::GetInstance().SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    DTEST_LOG << "result1:" << result1 << std::endl;

    AppExecFwk::ElementName element2("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    int result2 = DistributedSchedService::GetInstance().SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result1);
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result2);
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_004 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_005
 * @tc.desc: call SendResultFromRemote with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, SendResultFromRemote_005, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_005 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_005 end" << std::endl;
}

/**
 * @tc.name: StartLocalAbility_001
 * @tc.desc: call StartLocalAbility with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartLocalAbility_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartLocalAbility_001 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceTest StartLocalAbility_001 end" << std::endl;
}

/**
 * @tc.name: StartLocalAbility_002
 * @tc.desc: call StartLocalAbility with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartLocalAbility_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartLocalAbility_002 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceTest StartLocalAbility_002 end" << std::endl;
}

/**
 * @tc.name: StartLocalAbility_003
 * @tc.desc: call StartLocalAbility with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartLocalAbility_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartLocalAbility_003 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceTest StartLocalAbility_003 end" << std::endl;
}

/**
 * @tc.name: StartLocalAbility_004
 * @tc.desc: call StartLocalAbility with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartLocalAbility_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartLocalAbility_004 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceTest StartLocalAbility_004 end" << std::endl;
}

/**
 * @tc.name: StartRemoteShareForm_001
 * @tc.desc: call StartRemoteShareForm with dms
 * @tc.type: StartRemoteShareForm
 * @tc.require: issueI5M62D
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteShareForm_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteShareForm_001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    const std::string remoteDeviceId = "";
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    auto result = proxy->StartRemoteShareForm(remoteDeviceId, formShareInfo);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), result);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteShareForm_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteShareForm_002
 * @tc.desc: call StartAbilityFromRemote with dms
 * @tc.type: StartRemoteShareForm
 * @tc.require: issueI5M62D
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteShareForm_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteShareForm_002 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    const std::string remoteDeviceId = "123456";
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    auto result = proxy->StartRemoteShareForm(remoteDeviceId, formShareInfo);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(DMS_PERMISSION_DENIED), result);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteShareForm_002 end" << std::endl;
}

/**
 * @tc.name: StartShareFormFromRemote_001
 * @tc.desc: call StartAbilityFromRemote with dms
 * @tc.type: StartShareFormFromRemote
 * @tc.require: issueI5M62D
 */
HWTEST_F(DistributedSchedServiceTest, StartShareFormFromRemote_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartShareFormFromRemote_001 start" << std::endl;
    std::string remoteDeviceId = "";
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(remoteDeviceId);
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    DistributedSchedService::GetInstance().formMgrProxy_ = new MockFormMgrService();
    auto result = DistributedSchedService::GetInstance().StartShareFormFromRemote(remoteDeviceId, formShareInfo);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(ERR_OK), result);

    DTEST_LOG << "DistributedSchedServiceTest StartShareFormFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: StartShareFormFromRemote_002
 * @tc.desc: call StartAbilityFromRemote with dms
 * @tc.type: StartShareFormFromRemote
 * @tc.require: issueI5M62D
 */
HWTEST_F(DistributedSchedServiceTest, StartShareFormFromRemote_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartShareFormFromRemote_002 start" << std::endl;
    std::string remoteDeviceId = "123456";
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    /**
     * @tc.steps: step1. call GetContinuaitonDevice
     */
    DTEST_LOG << "DistributedSchedServiceTest GetContinuaitonDevice_001 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    int32_t missionId = MISSION_ID;
    (void)DistributedSchedService::GetInstance().GetContinuaitonDevice(missionId);
    DTEST_LOG << "DistributedSchedServiceTest GetContinuaitonDevice_001 end" << std::endl;

    auto result = DistributedSchedService::GetInstance().StartShareFormFromRemote(remoteDeviceId, formShareInfo);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result);
    DTEST_LOG << "DistributedSchedServiceTest StartShareFormFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemote_006
 * @tc.desc: call StartAbilityFromRemote
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartAbilityFromRemote_006, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_006 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    AppExecFwk::AbilityInfo abilityInfo;
    GetAbilityInfo("com.ohos.distributedmusicplayer", "com.ohos.distributedmusicplayer.MainAbility",
        "com.ohos.distributedmusicplayer", "192.168.43.100", abilityInfo);
    abilityInfo.visible = true;
    abilityInfo.permissions.clear();
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    accountInfo.groupIdList.push_back("123456");
    int result = DistributedSchedService::GetInstance().StartAbilityFromRemote(want,
        abilityInfo, 0, callerInfo, accountInfo);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), result);
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_006 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_006
 * @tc.desc: call SendResultFromRemote
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, SendResultFromRemote_006, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_006 start" << std::endl;
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    want.SetParam(DMS_SRC_NETWORK_ID, localDeviceId);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    IDistributedSched::AccountInfo accountInfo;
    /**
     * @tc.steps: step1. call RemoveContinuationTimeout
     */
    DTEST_LOG << "DistributedSchedServiceTest RemoveContinuationTimeout_001 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    int32_t missionId = MISSION_ID;
    DistributedSchedService::GetInstance().RemoveContinuationTimeout(missionId);
    DTEST_LOG << "DistributedSchedServiceTest RemoveContinuationTimeout_001 end" << std::endl;

    int result = DistributedSchedService::GetInstance().SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), result);
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_006 end" << std::endl;
}

/**
 * @tc.name: SetContinuationTimeout_001
 * @tc.desc: call GetContinuaitonDevice
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, SetContinuationTimeout_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest SetContinuationTimeout_001 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    int32_t missionId = MISSION_ID;
    int32_t timeout = 5;
    DistributedSchedService::GetInstance().SetContinuationTimeout(missionId, timeout);
    DTEST_LOG << "DistributedSchedServiceTest SetContinuationTimeout_001 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_001
 * @tc.desc: call ContinueMission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, ContinueMission_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueMission_001 start" << std::endl;
    WantParams wantParams;
    auto callback = GetDSchedService();
    int32_t missionId = MISSION_ID;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    int32_t result = DistributedSchedService::GetInstance().ContinueMission(
        "string", localDeviceId, missionId, callback, wantParams);
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result);
    DTEST_LOG << "DSchedContinuationTest ContinueMission_001 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_002
 * @tc.desc: call ContinueMission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, ContinueMission_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueMission_002 start" << std::endl;
    WantParams wantParams;
    auto callback = GetDSchedService();
    int32_t missionId = MISSION_ID;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    int32_t result = DistributedSchedService::GetInstance().ContinueMission(
        "string", "string", missionId, callback, wantParams);
    EXPECT_EQ(static_cast<int>(OPERATION_DEVICE_NOT_INITIATOR_OR_TARGET), result);
    DTEST_LOG << "DSchedContinuationTest ContinueMission_002 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_001
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedSchedServiceTest, StartContinuation_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_001 start" << std::endl;
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    int32_t missionId = MISSION_ID;
    int32_t callerUid = 0;
    int32_t status = 1;
    uint32_t accessToken = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartContinuation(
        want, missionId, callerUid, status, accessToken);
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), ret);
    CallerInfo callerInfo;
    ConnectInfo connectInfo;
    /**
     * @tc.steps: step1. ReportDistributedComponentChange when componentChangeHandler_ is nullptr
     */
    DistributedSchedService::GetInstance().componentChangeHandler_ = nullptr;
    DistributedSchedService::GetInstance().ReportDistributedComponentChange(callerInfo,
        1, IDistributedSched::CALL, IDistributedSched::CALLER);
    /**
     * @tc.steps: step2. ReportDistributedComponentChange when componentChangeHandler_ is nullptr
     */
    DistributedSchedService::GetInstance().ReportDistributedComponentChange(connectInfo,
        1, IDistributedSched::CALL, IDistributedSched::CALLEE);
    /**
     * @tc.steps: step3. ReportDistributedComponentChange when componentChangeHandler_ is not nullptr
     */
    auto runner = AppExecFwk::EventRunner::Create("DmsComponentChange");
    DistributedSchedService::GetInstance().componentChangeHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    DistributedSchedService::GetInstance().ReportDistributedComponentChange(callerInfo,
        1, IDistributedSched::CALL, IDistributedSched::CALLER);
    /**
     * @tc.steps: step4. ReportDistributedComponentChange when callerInfo.bundleNames is not empty
     */
    callerInfo.bundleNames.emplace_back("bundleName");
    DistributedSchedService::GetInstance().ReportDistributedComponentChange(callerInfo,
        1, IDistributedSched::CALL, IDistributedSched::CALLER);
    /**
     * @tc.steps: step5. ReportDistributedComponentChange when componentChangeHandler_ is not nullptr
     */
    DistributedSchedService::GetInstance().ReportDistributedComponentChange(connectInfo,
        1, IDistributedSched::CALL, IDistributedSched::CALLEE);
    DTEST_LOG << "DSchedContinuationTest StartContinuation_001 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_002
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StartContinuation_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_002 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    int32_t flags = Want::FLAG_ABILITY_CONTINUATION;
    want.SetElement(element);
    want.SetFlags(flags);
    int32_t missionId = MISSION_ID;
    int32_t callerUid = 0;
    int32_t status = 1;
    uint32_t accessToken = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartContinuation(
        want, missionId, callerUid, status, accessToken);
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), ret);
    DTEST_LOG << "DSchedContinuationTest StartContinuation_002 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_003
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 * @tc.require: I6O5T3
 */
HWTEST_F(DistributedSchedServiceTest, StartContinuation_003, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_003 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    int32_t flags = Want::FLAG_ABILITY_CONTINUATION;
    want.SetElement(element);
    want.SetFlags(flags);
    int32_t missionId = 0;
    int32_t callerUid = 1;
    int32_t status = ERR_OK;
    uint32_t accessToken = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartContinuation(
        want, missionId, callerUid, status, accessToken);
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), ret);
    DTEST_LOG << "DSchedContinuationTest StartContinuation_003 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_004
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 * @tc.require: I6O5T3
 */
HWTEST_F(DistributedSchedServiceTest, StartContinuation_004, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_004 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    int32_t flags = Want::FLAG_ABILITY_CONTINUATION;
    want.SetElement(element);
    want.SetFlags(flags);
    int32_t missionId = 0;
    int32_t callerUid = 0;
    int32_t status = ERR_OK;
    uint32_t accessToken = 1;
    int32_t ret = DistributedSchedService::GetInstance().StartContinuation(
        want, missionId, callerUid, status, accessToken);
    DistributedSchedService::GetInstance().OnStop();
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), ret);
    DTEST_LOG << "DSchedContinuationTest StartContinuation_004 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_005
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 * @tc.require: I6O5T3
 */
HWTEST_F(DistributedSchedServiceTest, StartContinuation_005, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_005 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    int32_t flags = Want::FLAG_ABILITY_CONTINUATION;
    want.SetElement(element);
    want.SetFlags(flags);
    int32_t missionId = 0;
    int32_t callerUid = 1;
    int32_t status = ERR_OK;
    uint32_t accessToken = 1;
    bool resultCode = true;
    int32_t ret = DistributedSchedService::GetInstance().StartContinuation(
        want, missionId, callerUid, status, accessToken);
    DistributedSchedService::GetInstance().NotifyContinuationCallbackResult(missionId, resultCode);
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), ret);
    DTEST_LOG << "DSchedContinuationTest StartContinuation_005 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_006
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 * @tc.require: I6O5T3
 */
HWTEST_F(DistributedSchedServiceTest, StartContinuation_006, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_006 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    int32_t flags = Want::FLAG_ABILITY_CONTINUATION;
    want.SetElement(element);
    want.SetFlags(flags);
    int32_t missionId = 0;
    int32_t callerUid = 0;
    int32_t status = ERR_OK;
    uint32_t accessToken = 0;
    bool resultCode = ERR_OK;
    int32_t ret = DistributedSchedService::GetInstance().StartContinuation(
        want, missionId, callerUid, status, accessToken);
    DistributedSchedService::GetInstance().NotifyContinuationCallbackResult(missionId, resultCode);
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), ret);
    DTEST_LOG << "DSchedContinuationTest StartContinuation_006 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_007
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 * @tc.type: I6O5T3
 */
HWTEST_F(DistributedSchedServiceTest, StartContinuation_007, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_007 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    int32_t flags = Want::FLAG_ABILITY_CONTINUATION;
    want.SetElement(element);
    want.SetFlags(flags);
    int32_t missionId = 0;
    int32_t callerUid = 0;
    int32_t status = ERR_OK;
    uint32_t accessToken = 0;
    bool isSuccess = false;
    /**
     * @tc.steps: step1. call GetFormMgrProxy
     */
    #ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
    DTEST_LOG << "DSchedContinuationTest GetFormMgrProxy_001 start" << std::endl;
    DistributedSchedService::GetInstance().GetFormMgrProxy();
    DTEST_LOG << "DSchedContinuationTest GetFormMgrProxy_001 end" << std::endl;
    #endif
    
    int32_t ret = DistributedSchedService::GetInstance().StartContinuation(
        want, missionId, callerUid, status, accessToken);
    DistributedSchedService::GetInstance().NotifyCompleteContinuation(DEVICE_ID_NULL, SESSION_ID, isSuccess);
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), ret);
    DTEST_LOG << "DSchedContinuationTest StartContinuation_007 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteContinuation_001
 * @tc.desc: call NotifyCompleteContinuation
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, NotifyCompleteContinuation_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteContinuation_001 start" << std::endl;
    bool isSuccess = false;
    DistributedSchedService::GetInstance().NotifyCompleteContinuation(DEVICE_ID, SESSION_ID, isSuccess);
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteContinuation_001 end" << std::endl;
}

/**
 * @tc.name: NotifyContinuationCallbackResult_001
 * @tc.desc: call NotifyContinuationCallbackResult
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, NotifyContinuationCallbackResult_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyContinuationCallbackResult_001 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    int32_t missionId = MISSION_ID;
    bool isSuccess = false;
    DistributedSchedService::GetInstance().NotifyContinuationCallbackResult(missionId, isSuccess);
    DTEST_LOG << "DSchedContinuationTest NotifyContinuationCallbackResult_001 end" << std::endl;
}

/**
 * @tc.name: NotifyContinuationCallbackResult_002
 * @tc.desc: call NotifyContinuationCallbackResult
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, NotifyContinuationCallbackResult_002, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyContinuationCallbackResult_002 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    int32_t missionId = MISSION_ID;
    bool resultCode = ERR_OK;
    DistributedSchedService::GetInstance().NotifyContinuationCallbackResult(missionId, resultCode);
    DTEST_LOG << "DSchedContinuationTest NotifyContinuationCallbackResult_002 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemote_007
 * @tc.desc: test StartAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceTest, StartAbilityFromRemote_007, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_007 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME,
        ABILITY_NAME);
    want.SetElement(element);
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.permissions.clear();
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_TRUE(result);
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    int ret = DistributedSchedService::GetInstance().StartAbilityFromRemote(want,
        abilityInfo, 0, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityFromRemote_007 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_007
 * @tc.desc: test SendResultFromRemote
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceTest, SendResultFromRemote_007, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_007 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    want.SetParam(DMS_SRC_NETWORK_ID, localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.third.hiworld.example",
        "bmsThirdBundle");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    int ret = DistributedSchedService::GetInstance().SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_007 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_008
 * @tc.desc: test SendResultFromRemote
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, SendResultFromRemote_008, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_008 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    want.SetParam(DMS_SRC_NETWORK_ID, localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.third.hiworld.example",
        "bmsThirdBundle");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    int ret = DistributedSchedService::GetInstance().SendResultFromRemote(want, 1, callerInfo, accountInfo, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_008 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_009
 * @tc.desc: test SendResultFromRemote
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, SendResultFromRemote_009, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_009 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    want.SetParam(DMS_SRC_NETWORK_ID, localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.third.hiworld.example",
        "bmsThirdBundle");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 1;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    int ret = DistributedSchedService::GetInstance().SendResultFromRemote(want, 1, callerInfo, accountInfo, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_009 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_010
 * @tc.desc: test SendResultFromRemote
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, SendResultFromRemote_010, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_010 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    want.SetParam(DMS_SRC_NETWORK_ID, localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.third.hiworld.example",
        "bmsThirdBundle");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = localDeviceId;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    int32_t ret = DistributedSchedService::GetInstance().SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_010 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_011
 * @tc.desc: test SendResultFromRemote
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, SendResultFromRemote_011, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_011 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    want.SetParam(DMS_SRC_NETWORK_ID, localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.third.hiworld.example",
        "bmsThirdBundle");
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = localDeviceId;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    int ret = DistributedSchedService::GetInstance().SendResultFromRemote(want, 1, callerInfo, accountInfo, 0);
    EXPECT_NE(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest SendResultFromRemote_011 end" << std::endl;
}

/**
 * @tc.name: StartAbilityByCallFromRemote_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceTest, StartAbilityByCallFromRemote_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityByCallFromRemote_001 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.third.hiworld.example",
        "bmsThirdBundle");
    want.SetElement(element);
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    sptr<IRemoteObject> connect = new MockDistributedSched();
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms("com.third.hiworld.example",
        callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    auto mockDms = iface_cast<IDistributedSched>(GetDSchedService());
    int ret = mockDms->StartAbilityByCallFromRemote(want, connect, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityByCallFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: StartAbilityByCallFromRemote_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceTest, StartAbilityByCallFromRemote_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityByCallFromRemote_002 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.third.hiworld.example",
        "bmsThirdBundle");
    want.SetElement(element);
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    sptr<IRemoteObject> connect = new MockDistributedSched();
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    int ret = DistributedSchedService::GetInstance().StartAbilityByCallFromRemote(want, connect,
        callerInfo, accountInfo);
    EXPECT_EQ(ret, CALL_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedServiceTest StartAbilityByCallFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_001
 * @tc.desc: call NotifyStateChangedFromRemote with illegal params
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DistributedSchedServiceTest, NotifyStateChangedFromRemote_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    int result1 = proxy->NotifyStateChangedFromRemote(0, 0, element);
    DTEST_LOG << "result1:" << result1 << std::endl;

    EXPECT_NE(result1, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChanged_001
 * @tc.desc: test NotifyStateChanged
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DistributedSchedServiceTest, NotifyStateChanged_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChanged_001 start" << std::endl;
    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChanged(abilityState, element);
    DTEST_LOG << "ret:" << ret << std::endl;
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChanged_001 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_002
 * @tc.desc: test NotifyStateChangedFromRemote
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DistributedSchedServiceTest, NotifyStateChangedFromRemote_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_002 start" << std::endl;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);

    int ret = DistributedSchedService::GetInstance().NotifyStateChangedFromRemote(0, 0, element);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_003
 * @tc.desc: test NotifyStateChangedFromRemote
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DistributedSchedServiceTest, NotifyStateChangedFromRemote_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_003 start" << std::endl;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);

    sptr<IRemoteObject> connect = nullptr;
    DistributedSchedService::GetInstance().callMap_[0] = {connect, localDeviceId};
    int ret = DistributedSchedService::GetInstance().NotifyStateChangedFromRemote(0, 0, element);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_003 end" << std::endl;
}

/**
 * @tc.name: RegisterAppStateObserver_001
 * @tc.desc: test RegisterAppStateObserver
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceTest, RegisterAppStateObserver_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest RegisterAppStateObserver_001 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    want.SetParam(DMS_MISSION_ID, 0);
    sptr<IRemoteObject> connect = new MockDistributedSched();
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = localDeviceId;
    bool ret = DistributedSchedService::GetInstance().RegisterAppStateObserver(want, callerInfo, connect);
    DistributedSchedService::GetInstance().UnregisterAppStateObserver(connect);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedSchedServiceTest RegisterAppStateObserver_001 end" << std::endl;
}

/**
 * @tc.name: UnregisterAppStateObserver_001
 * @tc.desc: test UnregisterAppStateObserver
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceTest, UnregisterAppStateObserver_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest UnregisterAppStateObserver_001 start" << std::endl;
    sptr<IRemoteObject> connect;
    DistributedSchedService::GetInstance().UnregisterAppStateObserver(connect);
    EXPECT_EQ(connect, nullptr);
    DTEST_LOG << "DistributedSchedServiceTest UnregisterAppStateObserver_001 end" << std::endl;
}

/**
 * @tc.name: UnregisterAppStateObserver_002
 * @tc.desc: test UnregisterAppStateObserver
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceTest, UnregisterAppStateObserver_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest UnregisterAppStateObserver_002 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    want.SetParam(DMS_MISSION_ID, 0);
    sptr<IRemoteObject> connect = new MockDistributedSched();
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = localDeviceId;
    bool ret = DistributedSchedService::GetInstance().RegisterAppStateObserver(want, callerInfo, connect);
    EXPECT_TRUE(ret);
    sptr<IRemoteObject> connect1 = new MockDistributedSched();
    DistributedSchedService::GetInstance().UnregisterAppStateObserver(connect1);
    EXPECT_NE(connect, connect1);
    DTEST_LOG << "DistributedSchedServiceTest UnregisterAppStateObserver_002 end" << std::endl;
}

/**
 * @tc.name: GetAppManager_001
 * @tc.desc: test GetAppManager
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceTest, GetAppManager_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest GetAppManager_001 start" << std::endl;
    auto ret = DistributedSchedService::GetInstance().GetAppManager();
    EXPECT_NE(ret, nullptr);
    DTEST_LOG << "DistributedSchedServiceTest GetAppManager_001 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChanged_002
 * @tc.desc: test NotifyStateChanged
 * @tc.type: FUNC
 * @tc.require: I6VDBO 
 */
HWTEST_F(DistributedSchedServiceTest, NotifyStateChanged_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChanged_002 start" << std::endl;
    sptr<AppStateObserver> appStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect = new MockDistributedSched();
    DistributedSchedService::GetInstance().observerMap_[connect] = {appStateObserver, localDeviceId, 0, BUNDLE_NAME,
        ABILITY_NAME};
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChanged(abilityState, element);
    DTEST_LOG << "ret:" << ret << std::endl;
    DistributedSchedService::GetInstance().observerMap_.clear();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChanged_002 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChanged_003
 * @tc.desc: test NotifyStateChanged
 * @tc.type: FUNC
 * @tc.require: I6VDBO 
 */
HWTEST_F(DistributedSchedServiceTest, NotifyStateChanged_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChanged_003 start" << std::endl;
    sptr<AppStateObserver> appStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect = new MockDistributedSched();
    DistributedSchedService::GetInstance().observerMap_[connect] = {appStateObserver, REMOTE_DEVICEID, 0, BUNDLE_NAME,
        ABILITY_NAME};
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChanged(abilityState, element);
    DTEST_LOG << "ret:" << ret << std::endl;
    DistributedSchedService::GetInstance().observerMap_.clear();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChanged_003 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_004
 * @tc.desc: test NotifyStateChangedFromRemote
 * @tc.type: FUNC
 * @tc.require: I6VDBO
 */
HWTEST_F(DistributedSchedServiceTest, NotifyStateChangedFromRemote_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_004 start" << std::endl;
    sptr<AppStateObserver> appStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChangedFromRemote(abilityState, 0, element);
    DTEST_LOG << "ret:" << ret << std::endl;
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_004 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_005
 * @tc.desc: test NotifyStateChangedFromRemote
 * @tc.type: FUNC
 * @tc.require: I6VDBO 
 */
HWTEST_F(DistributedSchedServiceTest, NotifyStateChangedFromRemote_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_005 start" << std::endl;
    sptr<AppStateObserver> appStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect = nullptr;
    DistributedSchedService::GetInstance().callMap_[0] = {connect, localDeviceId};
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChangedFromRemote(abilityState, 0, element);
    DTEST_LOG << "ret:" << ret << std::endl;
    DistributedSchedService::GetInstance().callMap_.clear();
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_005 end" << std::endl;
}

/**
 * @tc.name: NotifyStateChangedFromRemote_006
 * @tc.desc: test NotifyStateChangedFromRemote
 * @tc.type: FUNC
 * @tc.require: I6VDBO 
 */
HWTEST_F(DistributedSchedServiceTest, NotifyStateChangedFromRemote_006, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_006 start" << std::endl;
    sptr<AppStateObserver> appStateObserver = sptr<AppStateObserver>(new (std::nothrow) AppStateObserver());
    int32_t abilityState = FOREGROUND;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    sptr<IRemoteObject> connect = new MockDistributedSched();
    DistributedSchedService::GetInstance().callMap_[0] = {connect, localDeviceId};
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME, ABILITY_NAME);
    int32_t ret = DistributedSchedService::GetInstance().NotifyStateChangedFromRemote(abilityState, 0, element);
    DTEST_LOG << "ret:" << ret << std::endl;
    DistributedSchedService::GetInstance().callMap_.clear();
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest NotifyStateChangedFromRemote_006 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemote_001
 * @tc.desc: test ConnectAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceTest, ConnectAbilityFromRemote_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ConnectAbilityFromRemote_001 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME,
        ABILITY_NAME);
    want.SetElement(element);
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.permissions.clear();
    sptr<IRemoteObject> connect = new MockDistributedSched();
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms(BUNDLE_NAME, callerInfo.callerAppId);
    EXPECT_TRUE(result);
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    auto mockDms = iface_cast<IDistributedSched>(GetDSchedService());
    int ret = mockDms->ConnectAbilityFromRemote(want, abilityInfo, connect, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest ConnectAbilityFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemote_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceTest, ConnectAbilityFromRemote_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ConnectAbilityFromRemote_002 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, BUNDLE_NAME,
        ABILITY_NAME);
    want.SetElement(element);
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    AppExecFwk::AbilityInfo abilityInfo;
    abilityInfo.permissions.clear();
    sptr<IRemoteObject> connect = new MockDistributedSched();
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    int32_t ret1 = DistributedSchedService::GetInstance().ConnectAbilityFromRemote(want,
        abilityInfo, connect, callerInfo, accountInfo);
    AppExecFwk::AbilityInfo targetAbility;
    bool ret2 = DistributedSchedPermission::GetInstance().GetTargetAbility(want, targetAbility, true);
    EXPECT_EQ(ret2, true);
    if (targetAbility.visible) {
        EXPECT_EQ(ret1, ERR_OK);
    } else {
        EXPECT_EQ(ret1, DMS_START_CONTROL_PERMISSION_DENIED);
    }
    DTEST_LOG << "DistributedSchedServiceTest ConnectAbilityFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: StartLocalAbility_005
 * @tc.desc: test StartLocalAbility
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceTest, StartLocalAbility_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StartLocalAbility_005 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.third.hiworld.example", "bmsThirdBundle");
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
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest StartLocalAbility_005 end" << std::endl;
}

/**
 * @tc.name: Dump001
 * @tc.desc: call Dump
 * @tc.type: FUNC
 * @tc.require: I6O5T3
 */
HWTEST_F(DistributedSchedServiceTest, Dump001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest Dump001 start" << std::endl;
    int32_t fd = 1;
    const std::vector<std::u16string> args;
    const wptr<IRemoteObject> remote;
    int32_t missionId = 0;
    bool resultCode = ERR_OK;
    int32_t ret = DistributedSchedService::GetInstance().Dump(fd, args);
    DistributedSchedService::GetInstance().NotifyContinuationCallbackResult(missionId, resultCode);
    DistributedSchedService::GetInstance().ProcessFormMgrDied(remote);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest Dump001 end" << std::endl;
}

/**
 * @tc.name: Dump002
 * @tc.desc: call Dump
 * @tc.type: FUNC
 * @tc.require: I6O5T3
 */
HWTEST_F(DistributedSchedServiceTest, Dump002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest Dump002 start" << std::endl;
    int32_t fd = 0;
    const std::vector<std::u16string> args;
    const std::string deviceId;
    int32_t ret = DistributedSchedService::GetInstance().Dump(fd, args);
    DistributedSchedService::GetInstance().DeviceOnlineNotify(deviceId);
    DistributedSchedService::GetInstance().DeviceOfflineNotify(deviceId);
    EXPECT_EQ(ret, DMS_WRITE_FILE_FAILED_ERR);
    DTEST_LOG << "DistributedSchedServiceTest Dump002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility001
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteAbility001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility001 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t requestCode = 0;
    uint32_t accessToken = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility002
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteAbility002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility002 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 1;
    int32_t requestCode = 0;
    uint32_t accessToken = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility003
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteAbility003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility003 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t requestCode = 1;
    uint32_t accessToken = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility003 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility004
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteAbility004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility004 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t requestCode = 0;
    uint32_t accessToken = 1;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility004 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility005
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteAbility005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility005 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 1;
    int32_t requestCode = 1;
    uint32_t accessToken = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility005 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility006
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, StartRemoteAbility006, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility006 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 1;
    int32_t requestCode = 1;
    uint32_t accessToken = 1;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest StartRemoteAbility006 end" << std::endl;
}


/**
 * @tc.name: CheckDistributedConnectLocked001
 * @tc.desc: call CheckDistributedConnectLocked
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, CheckDistributedConnectLocked001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest CheckDistributedConnectLocked001 start" << std::endl;
    int32_t uid = IPCSkeleton::GetCallingUid();
    CallerInfo callerInfo;
    callerInfo.uid = uid;
    int32_t ret = DistributedSchedService::GetInstance().CheckDistributedConnectLocked(callerInfo);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceTest CheckDistributedConnectLocked001 end" << std::endl;
}

/**
 * @tc.name: CheckDistributedConnectLocked002
 * @tc.desc: call CheckDistributedConnectLocked
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, CheckDistributedConnectLocked002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest CheckDistributedConnectLocked002 start" << std::endl;
    int32_t uid = -1;
    CallerInfo callerInfo;
    callerInfo.uid = uid;
    int32_t ret = DistributedSchedService::GetInstance().CheckDistributedConnectLocked(callerInfo);
    EXPECT_EQ(ret, BIND_ABILITY_UID_INVALID_ERR);
    DTEST_LOG << "DistributedSchedServiceTest CheckDistributedConnectLocked002 end" << std::endl;
}


/**
 * @tc.name: ConnectRemoteAbility001
 * @tc.desc: connect remote ability with right uid and pid
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, ConnectRemoteAbility001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ConnectRemoteAbility001 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("123_remote_device_id", "ohos.demo.bundleName", "abilityName");
    const sptr<IRemoteObject> connect;
    int32_t ret = DistributedSchedService::GetInstance().ConnectRemoteAbility(want, connect, 1, 1, 1);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ConnectRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: ConnectRemoteAbility002
 * @tc.desc: connect remote ability with empty deviceId.
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, ConnectRemoteAbility002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest ConnectRemoteAbility002 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    const sptr<IRemoteObject> connect;
    int32_t ret = DistributedSchedService::GetInstance().ConnectRemoteAbility(want, connect, 1, 1, 1);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest ConnectRemoteAbility002 end" << std::endl;
}

/**
 * @tc.name: TryConnectRemoteAbility001
 * @tc.desc: call TryConnectRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, TryConnectRemoteAbility001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest TryConnectRemoteAbility001 start" << std::endl;
    std::string remoteDeviceId = "remoteDeviceId";
    OHOS::AAFwk::Want want;
    want.SetElementName(remoteDeviceId, "ohos.demo.bundleName", "abilityName");
    sptr<IRemoteObject> connect;
    CallerInfo callerInfo;
    int32_t ret = DistributedSchedService::GetInstance().TryConnectRemoteAbility(want, connect, callerInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest TryConnectRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: TryConnectRemoteAbility002
 * @tc.desc: call TryConnectRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceTest, TryConnectRemoteAbility002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest TryConnectRemoteAbility002 start" << std::endl;
    std::string remoteDeviceId = "remoteDeviceId";
    OHOS::AAFwk::Want want;
    want.SetElementName(remoteDeviceId, "ohos.demo.bundleName", "abilityName");
    sptr<IRemoteObject> connect;
    CallerInfo callerInfo;
    int32_t ret = DistributedSchedService::GetInstance().TryConnectRemoteAbility(want, connect, callerInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest TryConnectRemoteAbility002 end" << std::endl;
}

/**
 * @tc.name: StopRemoteExtensionAbility_001
 * @tc.desc: StopRemoteExtensionAbility with uninitialized params, return INVALID_PARAMETERS_ERR.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StopRemoteExtensionAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StopRemoteExtensionAbility_001 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceTest StopRemoteExtensionAbility_001 end" << std::endl;
}

/**
 * @tc.name: StopRemoteExtensionAbility_002
 * @tc.desc: StopRemoteExtensionAbility with empty want's deviceId, return INVALID_PARAMETERS_ERR.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StopRemoteExtensionAbility_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StopRemoteExtensionAbility_002 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    uint32_t accessToken = 0;
    int32_t extensionType = 3;
    AppExecFwk::ElementName element("abcdefg123456", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    EXPECT_EQ(DistributedSchedService::GetInstance().StopRemoteExtensionAbility(want, callerUid, accessToken,
        extensionType), INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest StopRemoteExtensionAbility_002 end" << std::endl;
}

/**
 * @tc.name: StopExtensionAbilityFromRemote_001
 * @tc.desc: StopExtensionAbilityFromRemote with uninitialized params, return INVALID_REMOTE_PARAMETERS_ERR.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StopExtensionAbilityFromRemote_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StopExtensionAbilityFromRemote_001 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
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
        accountInfo, extensionType), DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedServiceTest StopExtensionAbilityFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: StopExtensionAbilityFromRemote_002
 * @tc.desc: StopExtensionAbilityFromRemote with empty want's deviceId, return DMS_PERMISSION_DENIED.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StopExtensionAbilityFromRemote_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StopExtensionAbilityFromRemote_002 start" << std::endl;
    AAFwk::Want remoteWant;
    AppExecFwk::ElementName element("abcdefg123456", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    remoteWant.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    int32_t extensionType = 3;
    EXPECT_EQ(DistributedSchedService::GetInstance().StopExtensionAbilityFromRemote(remoteWant, callerInfo,
        accountInfo, extensionType), INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceTest StopExtensionAbilityFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: StopExtensionAbilityFromRemote_003
 * @tc.desc: StopExtensionAbilityFromRemote with empty want's deviceId, return INVALID_REMOTE_PARAMETERS_ERR.
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceTest, StopExtensionAbilityFromRemote_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceTest StopExtensionAbilityFromRemote_003 start" << std::endl;
    sptr<IDistributedSched> proxy = GetDms();
    if (proxy == nullptr) {
        return;
    }
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
    DTEST_LOG << "DistributedSchedServiceTest StopExtensionAbilityFromRemote_003 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS