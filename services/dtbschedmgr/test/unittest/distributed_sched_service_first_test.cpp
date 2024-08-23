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
#include "dms_constant.h"
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
using namespace Constants;
namespace {
    const string LOCAL_DEVICEID = "192.168.43.100";
    const string REMOTE_DEVICEID = "255.255.255.255";
    const std::u16string DEVICE_ID = u"192.168.43.100";
    const std::u16string DEVICE_ID_NULL = u"";
    constexpr int32_t SESSION_ID = 123;
    const std::string DMS_MISSION_ID = "dmsMissionId";
    constexpr int32_t MISSION_ID = 1;
    const std::string DMS_SRC_NETWORK_ID = "dmsSrcNetworkId";
    const string ABILITY_NAME = "com.ohos.permissionmanager.MainAbility";
    const string BUNDLE_NAME = "com.ohos.permissionmanager";
    const string DMS_IS_CALLER_BACKGROUND = "dmsIsCallerBackGround";
    const string DMS_VERSION_ID = "dmsVersion";
    constexpr int32_t SLEEP_TIME = 1000;
}

class DistributedSchedServiceFirstTest : public testing::Test {
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

void DistributedSchedServiceFirstTest::SetUpTestCase()
{
    if (!DistributedSchedUtil::LoadDistributedSchedService()) {
        DTEST_LOG << "DistributedSchedServiceFirstTest::SetUpTestCase LoadDistributedSchedService failed" << std::endl;
    }
    const std::string pkgName = "DBinderBus_" + std::to_string(getprocpid());
    std::shared_ptr<DmInitCallback> initCallback_ = std::make_shared<DeviceInitCallBack>();
    DeviceManager::GetInstance().InitDeviceManager(pkgName, initCallback_);
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
}

void DistributedSchedServiceFirstTest::TearDownTestCase()
{}

void DistributedSchedServiceFirstTest::SetUp()
{
    DistributedSchedUtil::MockPermission();
}

void DistributedSchedServiceFirstTest::TearDown()
{}

void DistributedSchedServiceFirstTest::DeviceInitCallBack::OnRemoteDied()
{}

sptr<IDistributedSched> DistributedSchedServiceFirstTest::GetDms()
{
    if (proxy_ != nullptr) {
        return proxy_;
    }
    auto sm = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    EXPECT_TRUE(sm != nullptr);
    if (sm == nullptr) {
        DTEST_LOG << "DistributedSchedServiceFirstTest sm is nullptr" << std::endl;
        return nullptr;
    }
    DTEST_LOG << "DistributedSchedServiceFirstTest sm is not nullptr" << std::endl;
    auto distributedObject = sm->GetSystemAbility(DISTRIBUTED_SCHED_SA_ID);
    proxy_ = iface_cast<IDistributedSched>(distributedObject);
    if (proxy_ == nullptr) {
        DTEST_LOG << "DistributedSchedServiceFirstTest DistributedSched is nullptr" << std::endl;
    } else {
        DTEST_LOG << "DistributedSchedServiceFirstTest DistributedSched is not nullptr" << std::endl;
    }
    return proxy_;
}

sptr<IRemoteObject> DistributedSchedServiceFirstTest::GetDSchedService() const
{
    sptr<IRemoteObject> dsched(new MockDistributedSched());
    return dsched;
}

void DistributedSchedServiceFirstTest::GetAbilityInfo(const std::string& package, const std::string& name,
    const std::string& bundleName, const std::string& deviceId, OHOS::AppExecFwk::AbilityInfo& abilityInfo)
{
    abilityInfo.bundleName = bundleName;
    abilityInfo.deviceId = deviceId;
}

/**
 * @tc.name: Dump001
 * @tc.desc: call Dump
 * @tc.type: FUNC
 * @tc.require: I6O5T3
 */
HWTEST_F(DistributedSchedServiceFirstTest, Dump001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest Dump001 start" << std::endl;
    int32_t fd = 1;
    const std::vector<std::u16string> args;
    const wptr<IRemoteObject> remote;
    int32_t missionId = 0;
    bool resultCode = ERR_OK;
    int32_t ret = DistributedSchedService::GetInstance().Dump(fd, args);
    DistributedSchedService::GetInstance().NotifyContinuationCallbackResult(missionId, resultCode);
    DistributedSchedService::GetInstance().ProcessFormMgrDied(remote);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DistributedSchedServiceFirstTest Dump001 end" << std::endl;
}

/**
 * @tc.name: Dump002
 * @tc.desc: call Dump
 * @tc.type: FUNC
 * @tc.require: I6O5T3
 */
HWTEST_F(DistributedSchedServiceFirstTest, Dump002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest Dump002 start" << std::endl;
    int32_t fd = 0;
    const std::vector<std::u16string> args;
    const std::string deviceId;
    int32_t ret = DistributedSchedService::GetInstance().Dump(fd, args);
    DistributedSchedService::GetInstance().DeviceOnlineNotify(deviceId);
    DistributedSchedService::GetInstance().DeviceOfflineNotify(deviceId);
    EXPECT_EQ(ret, DMS_WRITE_FILE_FAILED_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest Dump002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility_001
 * @tc.desc: call StartRemoteAbility with illegal params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteAbility_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility_001 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility_002
 * @tc.desc: call StartRemoteAbility with dms with wrong deviceId and local deviceId
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteAbility_002, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility_002 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility_002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility_003
 * @tc.desc: call StartRemoteAbility with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteAbility_003, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility_003 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility_003 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility_004
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteAbility_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility_004 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility_004 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility001
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteAbility001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility001 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t requestCode = 0;
    uint32_t accessToken = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility002
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteAbility002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility002 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 1;
    int32_t requestCode = 0;
    uint32_t accessToken = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility003
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteAbility003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility003 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t requestCode = 1;
    uint32_t accessToken = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility003 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility004
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteAbility004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility004 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t requestCode = 0;
    uint32_t accessToken = 1;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility004 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility005
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteAbility005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility005 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 1;
    int32_t requestCode = 1;
    uint32_t accessToken = 0;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility005 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbility006
 * @tc.desc: call StartRemoteAbility
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteAbility006, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility006 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 1;
    int32_t requestCode = 1;
    uint32_t accessToken = 1;
    int32_t ret = DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbility006 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemote_001
 * @tc.desc: call StartAbilityFromRemote with illegal param
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartAbilityFromRemote_001, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityFromRemote_001 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityFromRemote_001 end" << std::endl;
}

#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
/**
 * @tc.name: StartRemoteShareForm_002
 * @tc.desc: call StartAbilityFromRemote with dms
 * @tc.type: FUNC
 * @tc.require: I76THI
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteShareForm_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteShareForm_002 start" << std::endl;

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

    /**
    * @tc.steps: step1. call StartAbilityFromRemote when remoteDeviceId is valid.
    */
    const std::string remoteDeviceId = "123456";
    const OHOS::AppExecFwk::FormShareInfo formShareInfo {};
    int32_t result = DistributedSchedService::GetInstance().StartRemoteShareForm(remoteDeviceId, formShareInfo);
    EXPECT_EQ(result, GET_REMOTE_DMS_FAIL);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteShareForm_002 end" << std::endl;
}
#endif

/**
 * @tc.name: StartAbilityFromRemote_003
 * @tc.desc: call StartAbilityFromRemote with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartAbilityFromRemote_003, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityFromRemote_003 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityFromRemote_003 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemote_004
 * @tc.desc: call StartAbilityFromRemote
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartAbilityFromRemote_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityFromRemote_004 start" << std::endl;
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
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityFromRemote_004 end" << std::endl;
}

/**
 * @tc.name: StartAbilityFromRemote_005
 * @tc.desc: test StartAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartAbilityFromRemote_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityFromRemote_005 start" << std::endl;

    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    int32_t missionId = MISSION_ID;
    bool isSuccess = false;
    DistributedSchedService::GetInstance().NotifyContinuationCallbackResult(missionId, isSuccess);

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
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityFromRemote_005 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_001
 * @tc.desc: call SendResultFromRemote with illegal param
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, SendResultFromRemote_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_001 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_002
 * @tc.desc: call SendResultFromRemote with dms
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, SendResultFromRemote_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_002 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_003
 * @tc.desc: call SendResultFromRemote
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, SendResultFromRemote_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_003 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest RemoveContinuationTimeout_001 start" << std::endl;
    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    int32_t missionId = MISSION_ID;
    DistributedSchedService::GetInstance().RemoveContinuationTimeout(missionId);
    DTEST_LOG << "DistributedSchedServiceFirstTest RemoveContinuationTimeout_001 end" << std::endl;

    int result = DistributedSchedService::GetInstance().SendResultFromRemote(want, 0, callerInfo, accountInfo, 0);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(static_cast<int>(INVALID_REMOTE_PARAMETERS_ERR), result);
    /**
     * @tc.steps: step2. call RemoteConnectAbilityMappingLocked when connect == nullptr;
     */
    DistributedSchedService::GetInstance().RemoteConnectAbilityMappingLocked(nullptr,
        localDeviceId, localDeviceId, element, callerInfo, TargetComponent::HARMONY_COMPONENT);
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_003 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_004
 * @tc.desc: test SendResultFromRemote
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceFirstTest, SendResultFromRemote_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_004 start" << std::endl;

    if (DistributedSchedService::GetInstance().dschedContinuation_ == nullptr) {
        DistributedSchedService::GetInstance().dschedContinuation_ = std::make_shared<DSchedContinuation>();
    }
    int32_t missionId = MISSION_ID;
    bool resultCode = ERR_OK;
    DistributedSchedService::GetInstance().NotifyContinuationCallbackResult(missionId, resultCode);

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
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_004 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_005
 * @tc.desc: test SendResultFromRemote
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, SendResultFromRemote_005, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_005 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_005 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_006
 * @tc.desc: test SendResultFromRemote
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, SendResultFromRemote_006, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_006 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_006 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_007
 * @tc.desc: test SendResultFromRemote
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, SendResultFromRemote_007, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_007 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_007 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemote_008
 * @tc.desc: test SendResultFromRemote
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, SendResultFromRemote_008, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_008 start" << std::endl;
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
    DTEST_LOG << "DistributedSchedServiceFirstTest SendResultFromRemote_008 end" << std::endl;
}

/**
 * @tc.name: ContinueMission_001
 * @tc.desc: call ContinueMission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, ContinueMission_001, TestSize.Level1)
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
HWTEST_F(DistributedSchedServiceFirstTest, ContinueMission_002, TestSize.Level1)
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
 * @tc.name: ContinueMission_003
 * @tc.desc: call ContinueMission
 * @tc.type: FUNC
 * @tc.require: I7F8KH
 */
HWTEST_F(DistributedSchedServiceFirstTest, ContinueMission_003, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest ContinueMission_003 start" << std::endl;

    WantParams wantParams;
    auto callback = GetDSchedService();
    std::string bundleName = BUNDLE_NAME;

    /**
     * @tc.steps: step1. test ContinueMission when srcDeviceId is empty;
     */
    int32_t result = DistributedSchedService::GetInstance().ContinueMission(
        "", "string", BUNDLE_NAME, callback, wantParams);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    /**
     * @tc.steps: step2. test ContinueMission when dstDeviceId is empty;
     */
    result = DistributedSchedService::GetInstance().ContinueMission(
        "string", "", bundleName, callback, wantParams);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    /**
     * @tc.steps: step3. test ContinueMission when callback is empty;
     */
    result = DistributedSchedService::GetInstance().ContinueMission(
        "string", "string", bundleName, nullptr, wantParams);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DSchedContinuationTest ContinueMission_003 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_001
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartContinuation_001, TestSize.Level1)
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
HWTEST_F(DistributedSchedServiceFirstTest, StartContinuation_002, TestSize.Level1)
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
HWTEST_F(DistributedSchedServiceFirstTest, StartContinuation_003, TestSize.Level3)
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
HWTEST_F(DistributedSchedServiceFirstTest, StartContinuation_004, TestSize.Level3)
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
    EXPECT_EQ(static_cast<int>(INVALID_PARAMETERS_ERR), ret);
    DTEST_LOG << "DSchedContinuationTest StartContinuation_004 end" << std::endl;
}

/**
 * @tc.name: StartContinuation_005
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 * @tc.require: I6O5T3
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartContinuation_005, TestSize.Level3)
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
HWTEST_F(DistributedSchedServiceFirstTest, StartContinuation_006, TestSize.Level3)
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
HWTEST_F(DistributedSchedServiceFirstTest, StartContinuation_007, TestSize.Level3)
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
 * @tc.name: StartContinuation_008
 * @tc.desc: call StartContinuation
 * @tc.type: FUNC
 * @tc.type: I6O5T3
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartContinuation_008, TestSize.Level3)
{
    DTEST_LOG << "DSchedContinuationTest StartContinuation_008 start" << std::endl;
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
    DTEST_LOG << "DSchedContinuationTest StartContinuation_008 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteContinuation_001
 * @tc.desc: call NotifyCompleteContinuation
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceFirstTest, NotifyCompleteContinuation_001, TestSize.Level1)
{
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteContinuation_001 start" << std::endl;
    bool isSuccess = false;
    DistributedSchedService::GetInstance().NotifyCompleteContinuation(DEVICE_ID, SESSION_ID, isSuccess);
    DTEST_LOG << "DSchedContinuationTest NotifyCompleteContinuation_001 end" << std::endl;
}

/**
 * @tc.name: ConnectRemoteAbility001
 * @tc.desc: connect remote ability with right uid and pid
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, ConnectRemoteAbility001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest ConnectRemoteAbility001 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("123_remote_device_id", "ohos.demo.bundleName", "abilityName");
    const sptr<IRemoteObject> connect = nullptr;
    int32_t ret = DistributedSchedService::GetInstance().ConnectRemoteAbility(want, connect, 1, 1, 1);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest ConnectRemoteAbility001 end" << std::endl;
}

/**
 * @tc.name: ConnectRemoteAbility002
 * @tc.desc: connect remote ability with empty deviceId.
 * @tc.type: FUNC
 * @tc.require: I6P0I9
 */
HWTEST_F(DistributedSchedServiceFirstTest, ConnectRemoteAbility002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest ConnectRemoteAbility002 start" << std::endl;
    OHOS::AAFwk::Want want;
    want.SetElementName("", "ohos.demo.bundleName", "abilityName");
    const sptr<IRemoteObject> connect = nullptr;
    int32_t ret = DistributedSchedService::GetInstance().ConnectRemoteAbility(want, connect, 1, 1, 1);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest ConnectRemoteAbility002 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemote_001
 * @tc.desc: test ConnectAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceFirstTest, ConnectAbilityFromRemote_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest ConnectAbilityFromRemote_001 start" << std::endl;
    AAFwk::Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    sptr<IRemoteObject> connect = nullptr;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t ret = DistributedSchedService::GetInstance().ConnectAbilityFromRemote(want,
        abilityInfo, connect, callerInfo, accountInfo);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest ConnectAbilityFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemote_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceFirstTest, ConnectAbilityFromRemote_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest ConnectAbilityFromRemote_002 start" << std::endl;
    AAFwk::Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t ret = DistributedSchedService::GetInstance().ConnectAbilityFromRemote(want,
        abilityInfo, connect, callerInfo, accountInfo);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest ConnectAbilityFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemote_003
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceFirstTest, ConnectAbilityFromRemote_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest ConnectAbilityFromRemote_003 start" << std::endl;
    AAFwk::Want want;
    AppExecFwk::AbilityInfo abilityInfo;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    callerInfo.callerType = CALLER_TYPE_HARMONY;
    int32_t ret = DistributedSchedService::GetInstance().ConnectAbilityFromRemote(want,
        abilityInfo, connect, callerInfo, accountInfo);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest ConnectAbilityFromRemote_003 end" << std::endl;
}

/**
 * @tc.name: NotifyProcessDiedFromRemote_001
 * @tc.desc: call NotifyProcessDiedFromRemote when sourceDeviceId == sourceDeviceId.
 * @tc.type: FUNC
 * @tc.require: I76THI
 */
HWTEST_F(DistributedSchedServiceFirstTest, NotifyProcessDiedFromRemote_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest NotifyProcessDiedFromRemote_001 start" << std::endl;

    sptr<IDistributedSched> proxy = GetDms();

    AAFwk::Want want;
    AppExecFwk::ElementName element("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    AppExecFwk::AbilityInfo abilityInfo;
    GetAbilityInfo("com.ohos.distributedmusicplayer", "com.ohos.distributedmusicplayer.MainAbility",
        "com.ohos.distributedmusicplayer", "192.168.43.100", abilityInfo);
    CallerInfo callerInfo1;
    callerInfo1.uid = 0;
    callerInfo1.sourceDeviceId = "255.255.255.255";
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = 1;
    accountInfo.groupIdList.push_back("123456");

    int result1 = DistributedSchedService::GetInstance().StartAbilityFromRemote(want,
        abilityInfo, 0, callerInfo1, accountInfo);
    DTEST_LOG << "result1:" << result1 << std::endl;

    AppExecFwk::ElementName element2("", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbilityService");
    want.SetElement(element2);
    GetAbilityInfo("com.ohos.distributedmusicplayer", "com.ohos.distributedmusicplayer.MainAbilityService",
        "com.ohos.distributedmusicplayer", "192.168.43.100", abilityInfo);
    int result2 = DistributedSchedService::GetInstance().StartAbilityFromRemote(want,
        abilityInfo, 0, callerInfo1, accountInfo);

    /**
    * @tc.steps: step1. call NotifyProcessDiedFromRemote when sourceDeviceId == sourceDeviceId.
    */
    sptr<IRemoteObject> connect(new MockDistributedSched());
    ConnectInfo connectInfo;
    connectInfo.callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    connectInfo.callerInfo.uid = 0;
    connectInfo.callerInfo.pid = 0;
    connectInfo.callerInfo.callerType = 0;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().connectLock_);
        DistributedSchedService::GetInstance().calleeMap_[connect] = connectInfo;
    }
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = LOCAL_DEVICEID;
    callerInfo.uid = 0;
    callerInfo.pid = 0;
    callerInfo.callerType = 0;
    int32_t result = DistributedSchedService::GetInstance().NotifyProcessDiedFromRemote(callerInfo);
    EXPECT_EQ(result, ERR_OK);
    /**
    * @tc.steps: step2. call NotifyProcessDiedFromRemote when sourceDeviceId != sourceDeviceId.
    */
    callerInfo.sourceDeviceId = REMOTE_DEVICEID;
    result = DistributedSchedService::GetInstance().NotifyProcessDiedFromRemote(callerInfo);
    EXPECT_EQ(result, ERR_OK);

    /**
    * @tc.steps: step3. call ProcessFreeInstallOffline when dmsCallbackTask_ is not empty.
    */
    DistributedSchedService::GetInstance().dmsCallbackTask_ = make_shared<DmsCallbackTask>();
    DistributedSchedService::GetInstance().ProcessCalleeOffline("deviceId");
    DTEST_LOG << "DistributedSchedServiceFirstTest NotifyProcessDiedFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: StartAbilityByCallFromRemote_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartAbilityByCallFromRemote_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityByCallFromRemote_001 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.third.hiworld.example",
        "bmsThirdBundle");
    want.SetElement(element);
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    sptr<IRemoteObject> connect(new MockDistributedSched());
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
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityByCallFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: StartAbilityByCallFromRemote_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 * @tc.require: issueI5T6GJ
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartAbilityByCallFromRemote_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityByCallFromRemote_002 start" << std::endl;
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
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityByCallFromRemote_002 end" << std::endl;
}

/**
 * @tc.name: StartAbilityByCallFromRemote_003
 * @tc.desc: call StartAbilityByCallFromRemote
 * @tc.type: FUNC
 * @tc.require: I6YLV1
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartAbilityByCallFromRemote_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityByCallFromRemote_003 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.third.hiworld.example",
        "bmsThirdBundle");
    want.SetElement(element);
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    CallerInfo callerInfo;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms("com.third.hiworld.example", callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = localDeviceId;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    sptr<IRemoteObject> callbackWrapper(new AbilityConnectionWrapperStub(connect, localDeviceId));
    ConnectInfo connectInfo {callerInfo, callbackWrapper, want.GetElement()};
    DistributedSchedService::GetInstance().calleeMap_[connect] = connectInfo;
    int ret = DistributedSchedService::GetInstance().StartAbilityByCallFromRemote(want, connect,
        callerInfo, accountInfo);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityByCallFromRemote_003 end" << std::endl;
}

/**
 * @tc.name: StartAbilityByCallFromRemote_004
 * @tc.desc: call StartAbilityByCallFromRemote
 * @tc.type: FUNC
 * @tc.require: I6YLV1
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartAbilityByCallFromRemote_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityByCallFromRemote_004 start" << std::endl;
    AAFwk::Want want;
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    AppExecFwk::ElementName element(localDeviceId, "com.third.hiworld.example",
        "bmsThirdBundle");
    want.SetElement(element);
    want.SetParam(DMS_IS_CALLER_BACKGROUND, false);
    CallerInfo callerInfo;
    bool result = BundleManagerInternal::GetCallerAppIdFromBms("com.third.hiworld.example", callerInfo.callerAppId);
    EXPECT_EQ(result, true);
    callerInfo.extraInfoJson[DMS_VERSION_ID] = DMS_VERSION;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    callerInfo.uid = 0;
    callerInfo.sourceDeviceId = localDeviceId;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    int ret = DistributedSchedService::GetInstance().StartAbilityByCallFromRemote(want, connect,
        callerInfo, accountInfo);
    EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartAbilityByCallFromRemote_004 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityByCall_001
 * @tc.desc: call StartRemoteAbilityByCall
 * @tc.type: FUNC
 * @tc.require: I76THI
 */
HWTEST_F(DistributedSchedServiceFirstTest, StartRemoteAbilityByCall_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbilityByCall_001 start" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t callerPid = 0;
    uint32_t accessToken = 0;
    AppExecFwk::ElementName element("remoteDeviceId", "com.ohos.distributedmusicplayer",
        "com.ohos.distributedmusicplayer.MainAbility");
    want.SetElement(element);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    int32_t result = DistributedSchedService::GetInstance().StartRemoteAbilityByCall(want,
        connect, callerUid, callerPid, accessToken);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest StartRemoteAbilityByCall_001 end" << std::endl;
}

/**
 * @tc.name: ReleaseAbilityFromRemote_001
 * @tc.desc: call ReleaseAbilityFromRemote
 * @tc.type: FUNC
 * @tc.require: I76THI
 */
HWTEST_F(DistributedSchedServiceFirstTest, ReleaseAbilityFromRemote_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest ReleaseAbilityFromRemote_001 start" << std::endl;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    AAFwk::Want want;
    AppExecFwk::ElementName element;
    CallerInfo callerInfo;
    /**
    * @tc.steps: step1. call ReleaseAbilityFromRemote when callerInfo.sourceDeviceId is empty.
    * @tc.expected: step1. ReleaseAbilityFromRemote return INVALID_REMOTE_PARAMETERS_ERR
    */
    int32_t result = DistributedSchedService::GetInstance().ReleaseAbilityFromRemote(connect, element, callerInfo);
    EXPECT_EQ(result, INVALID_REMOTE_PARAMETERS_ERR);
    /**
    * @tc.steps: step2. call ReleaseAbilityFromRemote when localDeviceId == callerInfo.sourceDeviceId.
    * @tc.expected: step2. ReleaseAbilityFromRemote return INVALID_REMOTE_PARAMETERS_ERR
    */
    std::string localDeviceId;
    DtbschedmgrDeviceInfoStorage::GetInstance().GetLocalDeviceId(localDeviceId);
    callerInfo.sourceDeviceId = localDeviceId;
    result = DistributedSchedService::GetInstance().ReleaseAbilityFromRemote(connect, element, callerInfo);
    EXPECT_EQ(result, INVALID_REMOTE_PARAMETERS_ERR);
    /**
    * @tc.steps: step3. call ReleaseAbilityFromRemote when itConnect == calleeMap_.end().
    * @tc.expected: step3. ReleaseAbilityFromRemote return INVALID_REMOTE_PARAMETERS_ERR
    */
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().calleeLock_);
        DistributedSchedService::GetInstance().calleeMap_.clear();
    }
    callerInfo.sourceDeviceId = "sourceDeviceId";
    result = DistributedSchedService::GetInstance().ReleaseAbilityFromRemote(connect, element, callerInfo);
    EXPECT_EQ(result, INVALID_REMOTE_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedServiceFirstTest ReleaseAbilityFromRemote_001 end" << std::endl;
}

/**
 * @tc.name: ReleaseAbilityFromRemote_002
 * @tc.desc: call ReleaseAbilityFromRemote when itConnect != calleeMap_.end().
 * @tc.type: FUNC
 * @tc.require: I76THI
 */
HWTEST_F(DistributedSchedServiceFirstTest, ReleaseAbilityFromRemote_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedServiceFirstTest ReleaseAbilityFromRemote_002 start" << std::endl;
    /**
    * @tc.steps: step1. call ReleaseAbilityFromRemote when itConnect != calleeMap_.end().
    */
    sptr<IRemoteObject> connect(new MockDistributedSched());
    AAFwk::Want want;
    AppExecFwk::ElementName element;
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = "sourceDeviceId";
    ConnectInfo connectInfo;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().calleeLock_);
        DistributedSchedService::GetInstance().calleeMap_[connect] = connectInfo;
    }
    int32_t result = DistributedSchedService::GetInstance().ReleaseAbilityFromRemote(connect, element, callerInfo);
    EXPECT_NE(result, ERR_OK);
    /**
    * @tc.steps: step2. call ProcessConnectDied when connectSessionsList is empty.
    */
    std::list<ConnectAbilitySession> sessionsList;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().distributedLock_);
        DistributedSchedService::GetInstance().distributedConnectAbilityMap_[connect] = sessionsList;
    }
    DistributedSchedService::GetInstance().ProcessConnectDied(connect);
    /**
    * @tc.steps: step3. call ProcessConnectDied when sessionsList is empty.
    */
    DistributedSchedService::GetInstance().ProcessConnectDied(connect);
    DTEST_LOG << "DistributedSchedServiceFirstTest ReleaseAbilityFromRemote_002 end" << std::endl;
}
}
}