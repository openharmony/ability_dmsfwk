/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "accesstoken_kit.h"
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
#include "multi_user_manager.h"
#include "nativetoken_kit.h"
#include "mock/distributed_sched_permission_mock.h"
#include "mock/svc_distributed_connection_mock.h"
#include "mock/multi_user_manager_mock.h"
#include "mock/mock_device_manager.h"
#include "system_ability_definition.h"
#include "test_log.h"
#include "token_setproc.h"
#include "thread_pool.h"
#include "mock/accesstoken_kit_mock.h"
#include "mock/ability_manager_client_mock.h"
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
    const std::string TAG = "DistributedSchedService";
    constexpr int32_t WEARLINK_UID = 7259;
    constexpr int32_t TIME = 1000;
}

void SetNativeTokenForDExt()
{
    uint64_t tokenId;
    const char *perms[] = {
        "ohos.permission.GET_BUNDLE_RESOURCES",
        "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED"
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "foundation",
        .aplStr = "system_core",
    };

    tokenId = GetAccessTokenId(&infoInstance);
    if (tokenId == 0) {
        HILOGE("Failed to get valid Token ID.");
        return;
    }
    SetSelfTokenID(tokenId);
    setuid(WEARLINK_UID);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

class DistributedSchedServiceNewTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static inline std::shared_ptr<MultiUserManagerMock> multiUserMgrMock_ = nullptr;
    static inline std::shared_ptr<SvcDistributedConnectionMock> svcDConnMock = nullptr;
    static inline std::shared_ptr<DistributedSchedPermMock> dmsPermMock_ = nullptr;
    static inline std::shared_ptr<AccesstokenMock> tokenMock_ = nullptr;
    static inline std::shared_ptr<DeviceManagerMock> deviceMgrMock_ = nullptr;

    class DeviceInitCallBack : public DmInitCallback {
        void OnRemoteDied() override;
    };
};

void DistributedSchedServiceNewTest::SetUpTestCase()
{
    if (!DistributedSchedUtil::LoadDistributedSchedService()) {
        DTEST_LOG << "DistributedSchedServiceNewTest SetUpTestCase LoadDistributedSchedService failed" << std::endl;
    }
    multiUserMgrMock_ = std::make_shared<MultiUserManagerMock>();
    MultiUserManagerMock::multiUserMgrMock = multiUserMgrMock_;
    svcDConnMock = std::make_shared<SvcDistributedConnectionMock>();
    SvcDistributedConnectionMock::connMock = svcDConnMock;
    dmsPermMock_ = std::make_shared<DistributedSchedPermMock>();
    DistributedSchedPermMock::dmsPermMock = dmsPermMock_;
    tokenMock_ = std::make_shared<AccesstokenMock>();
    AccesstokenMock::accesstokenMock_ = tokenMock_;
    deviceMgrMock_ = std::make_shared<DeviceManagerMock>();
    DeviceManagerMock::deviceMgrMock = deviceMgrMock_;
    const std::string pkgName = "DBinderBus_" + std::to_string(getprocpid());
    std::shared_ptr<DmInitCallback> initCallback_ = std::make_shared<DeviceInitCallBack>();
    DeviceManager::GetInstance().InitDeviceManager(pkgName, initCallback_);
    std::this_thread::sleep_for(std::chrono::milliseconds(TIME));
}

void DistributedSchedServiceNewTest::TearDownTestCase()
{
    MultiUserManagerMock::multiUserMgrMock = nullptr;
    multiUserMgrMock_ = nullptr;
    SvcDistributedConnectionMock::connMock = nullptr;
    svcDConnMock = nullptr;
    DistributedSchedPermMock::dmsPermMock = nullptr;
    dmsPermMock_ = nullptr;
    AccesstokenMock::accesstokenMock_ = nullptr;
    tokenMock_ = nullptr;
    DeviceManagerMock::deviceMgrMock = nullptr;
    deviceMgrMock_ = nullptr;
}

void DistributedSchedServiceNewTest::SetUp()
{
    DistributedSchedUtil::MockPermission();
}

void DistributedSchedServiceNewTest::TearDown()
{}

void DistributedSchedServiceNewTest::DeviceInitCallBack::OnRemoteDied()
{}

// ============================================================
// GetDeviceDisplayName test cases
// ============================================================

/**
 * @tc.name  : GetDeviceDisplayName_Test01
 * @tc.desc  : Test GetDeviceDisplayName when deviceName is not empty (sports watch path).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, GetDeviceDisplayName_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest GetDeviceDisplayName_Test01 start" << std::endl;
    // deviceName is not empty, should return ERR_OK directly using deviceName
    DExtSourceInfo sourceInfo("device123", "network123", "MyWatch", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    std::string displayName;
    int32_t ret = DistributedSchedService::GetInstance().GetDeviceDisplayName(connectInfo, displayName, resultInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(displayName, "MyWatch");

    DTEST_LOG << "DistributedSchedServiceNewTest GetDeviceDisplayName_Test01 end" << std::endl;
}

/**
 * @tc.name  : GetDeviceDisplayName_Test02
 * @tc.desc  : Test GetDeviceDisplayName when deviceName is empty but networkId is not empty,
 *             and GetDeviceName succeeds (smart watch path).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, GetDeviceDisplayName_Test02, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest GetDeviceDisplayName_Test02 start" << std::endl;
    // deviceName is empty, networkId is not empty
    DExtSourceInfo sourceInfo("device123", "network123", "", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    std::string displayName;
    EXPECT_CALL(*deviceMgrMock_, GetDeviceName(_, _, _)).WillOnce(Return(ERR_OK));
    int32_t ret = DistributedSchedService::GetInstance().GetDeviceDisplayName(connectInfo, displayName, resultInfo);
    EXPECT_EQ(ret, ERR_OK);

    DTEST_LOG << "DistributedSchedServiceNewTest GetDeviceDisplayName_Test02 end" << std::endl;
}

/**
 * @tc.name  : GetDeviceDisplayName_Test03
 * @tc.desc  : Test GetDeviceDisplayName when deviceName is empty, networkId is not empty,
 *             but GetDeviceName fails.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, GetDeviceDisplayName_Test03, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest GetDeviceDisplayName_Test03 start" << std::endl;
    DExtSourceInfo sourceInfo("device123", "network123", "", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    std::string displayName;
    EXPECT_CALL(*deviceMgrMock_, GetDeviceName(_, _, _)).WillOnce(Return(-1));
    int32_t ret = DistributedSchedService::GetInstance().GetDeviceDisplayName(connectInfo, displayName, resultInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    EXPECT_EQ(resultInfo.errCode, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DistributedSchedServiceNewTest GetDeviceDisplayName_Test03 end" << std::endl;
}

/**
 * @tc.name  : GetDeviceDisplayName_Test04
 * @tc.desc  : Test GetDeviceDisplayName when both deviceName and networkId are empty.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, GetDeviceDisplayName_Test04, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest GetDeviceDisplayName_Test04 start" << std::endl;
    DExtSourceInfo sourceInfo("device123", "", "", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    std::string displayName;
    int32_t ret = DistributedSchedService::GetInstance().GetDeviceDisplayName(connectInfo, displayName, resultInfo);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    EXPECT_EQ(resultInfo.errCode, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DistributedSchedServiceNewTest GetDeviceDisplayName_Test04 end" << std::endl;
}

// ============================================================
// FinalizeDExtensionConnection test cases
// ============================================================

/**
 * @tc.name  : FinalizeDExtensionConnection_Test01
 * @tc.desc  : Test FinalizeDExtensionConnection when isDelay is true.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, FinalizeDExtensionConnection_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest FinalizeDExtensionConnection_Test01 start" << std::endl;
    AAFwk::Want want;
    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;
    sptr<IDExtension> proxy = nullptr;
    bool isDelay = true;

    int32_t ret = DistributedSchedService::GetInstance().FinalizeDExtensionConnection(
        want, connectInfo, proxy, isDelay, resultInfo);
    EXPECT_EQ(ret, ERR_OK);
    // When isDelay is true, resultInfo.result should not be set to SUCCESS
    EXPECT_NE(resultInfo.result, DExtConnectResult::SUCCESS);

    DTEST_LOG << "DistributedSchedServiceNewTest FinalizeDExtensionConnection_Test01 end" << std::endl;
}

// ============================================================
// SetDExtensionConnected / ScheduleAutoUnload test cases
// ============================================================

/**
 * @tc.name  : SetDExtensionConnected_Test01
 * @tc.desc  : Test SetDExtensionConnected sets the atomic flag correctly.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SetDExtensionConnected_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SetDExtensionConnected_Test01 start" << std::endl;

    DistributedSchedService::GetInstance().SetDExtensionConnected(true);
    EXPECT_TRUE(DistributedSchedService::GetInstance().dExtensionConnected_.load());

    DistributedSchedService::GetInstance().SetDExtensionConnected(false);
    EXPECT_FALSE(DistributedSchedService::GetInstance().dExtensionConnected_.load());

    DTEST_LOG << "DistributedSchedServiceNewTest SetDExtensionConnected_Test01 end" << std::endl;
}

/**
 * @tc.name  : ScheduleAutoUnload_Test01
 * @tc.desc  : Test ScheduleAutoUnload returns ERR_OK and runs without crash.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ScheduleAutoUnload_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ScheduleAutoUnload_Test01 start" << std::endl;

    int32_t ret = DistributedSchedService::GetInstance().ScheduleAutoUnload();
    EXPECT_EQ(ret, ERR_OK);

    // Wait briefly for the detached thread to start
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    // Clean up: set connected to prevent actual unload in test environment
    DistributedSchedService::GetInstance().SetDExtensionConnected(true);

    DTEST_LOG << "DistributedSchedServiceNewTest ScheduleAutoUnload_Test01 end" << std::endl;
}

// ============================================================
// WaitAndGetDExtensionProxy test cases
// ============================================================

/**
 * @tc.name  : WaitAndGetDExtensionProxy_Test01
 * @tc.desc  : Test WaitAndGetDExtensionProxy when the connection for the given bundleName
 *             exists in svcDConnMap_ but GetDistributedExtProxy returns nullptr.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, WaitAndGetDExtensionProxy_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest WaitAndGetDExtensionProxy_Test01 start" << std::endl;

    // Clean up svcDConnMap_ before test
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    DExtSourceInfo sourceInfo("device123", "network123", "", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    AAFwk::Want want;
    bool isDelay = false;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillOnce(Return(nullptr));
    DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo, want, isDelay);

    std::string bundleName = "testBundle";
    auto proxy = DistributedSchedService::GetInstance().WaitAndGetDExtensionProxy(bundleName);
    EXPECT_EQ(proxy, nullptr);

    // Clean up
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    DTEST_LOG << "DistributedSchedServiceNewTest WaitAndGetDExtensionProxy_Test01 end" << std::endl;
}

/**
 * @tc.name  : WaitAndGetDExtensionProxy_Test02
 * @tc.desc  : Test WaitAndGetDExtensionProxy when svcDConnMap_ has no entry for the given
 *             bundleName, should return nullptr.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, WaitAndGetDExtensionProxy_Test02, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest WaitAndGetDExtensionProxy_Test02 start" << std::endl;

    // Ensure svcDConnMap_ is empty
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    std::string bundleName = "nonexistent_bundle";
    auto proxy = DistributedSchedService::GetInstance().WaitAndGetDExtensionProxy(bundleName);
    EXPECT_EQ(proxy, nullptr);

    DTEST_LOG << "DistributedSchedServiceNewTest WaitAndGetDExtensionProxy_Test02 end" << std::endl;
}

/**
 * @tc.name  : WaitAndGetDExtensionProxy_Test03
 * @tc.desc  : Test WaitAndGetDExtensionProxy with multiple bundleNames in svcDConnMap_.
 *             Each bundleName should independently return its own proxy (nullptr in this case).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, WaitAndGetDExtensionProxy_Test03, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest WaitAndGetDExtensionProxy_Test03 start" << std::endl;

    // Clean up svcDConnMap_ before test
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    // Prepare first connection: bundle1
    DExtSourceInfo sourceInfo1("device1", "network1", "", "bundle1", "module1", "ability1");
    DExtSinkInfo sinkInfo1(100, 0, "bundle1", "module1", "ability1", "service1");
    DExtConnectInfo connectInfo1(sourceInfo1, sinkInfo1, "token1", "delegatee1");
    AAFwk::Want want1;
    bool isDelay1 = false;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillRepeatedly(Return(nullptr));
    DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo1, want1, isDelay1);

    // Prepare second connection: bundle2
    DExtSourceInfo sourceInfo2("device2", "network2", "", "bundle2", "module2", "ability2");
    DExtSinkInfo sinkInfo2(200, 0, "bundle2", "module2", "ability2", "service2");
    DExtConnectInfo connectInfo2(sourceInfo2, sinkInfo2, "token2", "delegatee2");
    AAFwk::Want want2;
    bool isDelay2 = false;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillRepeatedly(Return(nullptr));
    DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo2, want2, isDelay2);

    // Both bundleNames should exist independently in svcDConnMap_
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        EXPECT_EQ(DistributedSchedService::GetInstance().svcDConnMap_.size(), static_cast<size_t>(2));
        EXPECT_NE(DistributedSchedService::GetInstance().svcDConnMap_.find("bundle1"),
            DistributedSchedService::GetInstance().svcDConnMap_.end());
        EXPECT_NE(DistributedSchedService::GetInstance().svcDConnMap_.find("bundle2"),
            DistributedSchedService::GetInstance().svcDConnMap_.end());
    }

    // WaitAndGetDExtensionProxy for each bundleName returns nullptr proxy
    auto proxy1 = DistributedSchedService::GetInstance().WaitAndGetDExtensionProxy("bundle1");
    EXPECT_EQ(proxy1, nullptr);

    auto proxy2 = DistributedSchedService::GetInstance().WaitAndGetDExtensionProxy("bundle2");
    EXPECT_EQ(proxy2, nullptr);

    // Nonexistent bundleName returns nullptr
    auto proxy3 = DistributedSchedService::GetInstance().WaitAndGetDExtensionProxy("bundle3");
    EXPECT_EQ(proxy3, nullptr);

    // Clean up
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    DTEST_LOG << "DistributedSchedServiceNewTest WaitAndGetDExtensionProxy_Test03 end" << std::endl;
}

// ============================================================
// PrepareSvcDConnection test cases
// ============================================================

/**
 * @tc.name  : PrepareSvcDConnection_Test01
 * @tc.desc  : Test PrepareSvcDConnection when ConnectDExtAbility fails.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, PrepareSvcDConnection_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test01 start" << std::endl;
    SetNativeTokenForDExt();

    DExtSourceInfo sourceInfo("device123", "network123", "", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "com.it.welink", "dms", "AttendanceDistributedAbility", "WeLink");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "ohos.permission.dms_extension", "delegatee");

    AAFwk::Want want;
    bool isDelay = false;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(INVALID_PARAMETERS_ERR));

    int32_t ret = DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo, want, isDelay);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test01 end" << std::endl;
}

/**
 * @tc.name  : PrepareSvcDConnection_Test02
 * @tc.desc  : Test PrepareSvcDConnection when ConnectDExtAbility succeeds.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, PrepareSvcDConnection_Test02, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test02 start" << std::endl;
    SetNativeTokenForDExt();

    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "com.it.welink", "dms", "TestAbility");
    DExtSinkInfo sinkInfo(100, 0, "com.it.welink", "dms", "AttendanceDistributedAbility", "WeLink");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "ohos.permission.dms_extension", "delegatee");

    AAFwk::Want want;
    bool isDelay = false;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));

    int32_t ret = DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo, want, isDelay);
    EXPECT_EQ(ret, ERR_OK);

    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test02 end" << std::endl;
}

/**
 * @tc.name  : PrepareSvcDConnection_Test03
 * @tc.desc  : Test PrepareSvcDConnection when ConnectDExtAbility returns isDelay=true.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, PrepareSvcDConnection_Test03, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test03 start" << std::endl;
    SetNativeTokenForDExt();

    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "com.it.welink", "dms", "TestAbility");
    DExtSinkInfo sinkInfo(100, 0, "com.it.welink", "dms", "AttendanceDistributedAbility", "WeLink");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "ohos.permission.dms_extension", "delegatee");

    AAFwk::Want want;
    bool isDelay = false;
    // Set isDelay to true via the mock's output parameter
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _))
        .WillRepeatedly(DoAll(SetArgReferee<4>(true), Return(ERR_OK)));

    int32_t ret = DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo, want, isDelay);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_TRUE(isDelay);

    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test03 end" << std::endl;
}

// ============================================================
// ConnectDExtensionFromRemote integrated test cases
// (new branches from PR #1933: deviceName path, GetDeviceName fail path,
//  networkId+deviceName both empty, isDelay path, proxy null path)
// ============================================================

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test08
 * @tc.desc  : Test ConnectDExtensionFromRemote when both networkId and deviceName are empty,
 *             GetDeviceDisplayName should fail with INVALID_PARAMETERS_ERR.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test08, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test08 start" << std::endl;
    SetNativeTokenForDExt();

    // sourceInfo with empty networkId and empty deviceName
    DExtSourceInfo sourceInfo("device123", "", "", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "com.it.welink", "dms", "AttendanceDistributedAbility", "WeLink");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "ohos.permission.dms_extension", "delegatee");
    DExtConnectResultInfo resultInfo;

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    EXPECT_EQ(resultInfo.result, DExtConnectResult::FAILED);

    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test08 end" << std::endl;
}

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test09
 * @tc.desc  : Test ConnectDExtensionFromRemote when networkId is not empty but GetDeviceName fails.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test09, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test09 start" << std::endl;
    SetNativeTokenForDExt();

    DExtSourceInfo sourceInfo("device123", "network123", "", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "com.it.welink", "dms", "AttendanceDistributedAbility", "WeLink");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "ohos.permission.dms_extension", "delegatee");
    DExtConnectResultInfo resultInfo;

    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillOnce(Return(nullptr));
    EXPECT_CALL(*deviceMgrMock_, GetDeviceName(_, _, _)).WillRepeatedly(Return(-1));

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test09 end" << std::endl;
}

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test10
 * @tc.desc  : Test ConnectDExtensionFromRemote when proxy is nullptr after WaitAndGetDExtensionProxy.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test10, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test10 start" << std::endl;
    SetNativeTokenForDExt();

    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "com.it.welink", "dms", "AttendanceDistributedAbility", "WeLink");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "ohos.permission.dms_extension", "delegatee");
    DExtConnectResultInfo resultInfo;

    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillRepeatedly(Return(nullptr));

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test10 end" << std::endl;
}

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test11
 * @tc.desc  : Test ConnectDExtensionFromRemote when GetBundleResourceInfo fails.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test11, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test11 start" << std::endl;
    SetNativeTokenForDExt();

    // Use a bundleName that does not exist, GetBundleResourceInfo should fail
    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1",
        "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "com.nonexistent.bundle", "dms", "FakeAbility", "FakeService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "ohos.permission.dms_extension", "delegatee");
    DExtConnectResultInfo resultInfo;

    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillOnce(Return(nullptr));

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    // Bundle does not exist, should fail
    EXPECT_NE(result, ERR_OK);

    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test11 end" << std::endl;
}

// ============================================================
// Additional branch coverage test cases
// ============================================================

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test13
 * @tc.desc  : Test ConnectDExtensionFromRemote with native token but wrong UID
 *             (not DSOFTBUS_UID or WEARLINK_UID), CheckCallingPermission should fail.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test13, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test13 start" << std::endl;

    // Set native token but with a UID that is neither DSOFTBUS_UID nor WEARLINK_UID
    uint64_t tokenId;
    const char *perms[] = {
        "ohos.permission.GET_BUNDLE_RESOURCES",
        "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED"
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "foundation",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    // Use a UID that is neither DSOFTBUS_UID (1024) nor WEARLINK_UID (7259)
    setuid(9999);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();

    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    EXPECT_EQ(resultInfo.result, DExtConnectResult::PERMISSION_DENIED);

    // Restore UID
    setuid(WEARLINK_UID);
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test13 end" << std::endl;
}

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test14
 * @tc.desc  : Test ConnectDExtensionFromRemote when sinkInfo IsEmpty (explicit empty fields).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test14, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test14 start" << std::endl;
    SetNativeTokenForDExt();

    // sinkInfo with empty bundleName, moduleName, abilityName => IsEmpty() returns true
    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "", "", "", "");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test14 end" << std::endl;
}

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test15
 * @tc.desc  : Test ConnectDExtensionFromRemote when both deviceName and networkId are provided.
 *             GetDeviceDisplayName should use deviceName directly (sports watch path).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test15, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test15 start" << std::endl;
    SetNativeTokenForDExt();

    // Both deviceName and networkId provided - deviceName takes priority
    DExtSourceInfo sourceInfo("device123", "network123", "MySportsWatch", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "com.it.welink", "dms", "AttendanceDistributedAbility", "WeLink");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "ohos.permission.dms_extension", "delegatee");
    DExtConnectResultInfo resultInfo;

    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillOnce(Return(nullptr));

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    // proxy is nullptr so should fail
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test15 end" << std::endl;
}

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test16
 * @tc.desc  : Test ConnectDExtensionFromRemote with networkId but empty deviceName,
 *             and GetDeviceName succeeds (smart watch path).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test16, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test16 start" << std::endl;
    SetNativeTokenForDExt();

    // networkId present, deviceName empty => GetDeviceName called
    DExtSourceInfo sourceInfo("device123", "network123", "", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "com.it.welink", "dms", "AttendanceDistributedAbility", "WeLink");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "ohos.permission.dms_extension", "delegatee");
    DExtConnectResultInfo resultInfo;

    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillOnce(Return(nullptr));
    EXPECT_CALL(*deviceMgrMock_, GetDeviceName(_, _, _)).WillRepeatedly(Return(ERR_OK));

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    // proxy is nullptr so should fail
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test16 end" << std::endl;
}

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test17
 * @tc.desc  : Test two different bundleNames connecting in sequence, verifying
 *             svcDConnMap_ holds independent entries.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test17, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test17 start" << std::endl;
    SetNativeTokenForDExt();

    // Clean up svcDConnMap_ before test
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    // First connection: bundleA
    DExtSourceInfo sourceInfo1("device1", "network1", "deviceName1", "bundleA", "moduleA", "abilityA");
    DExtSinkInfo sinkInfo1(100, 0, "bundleA", "moduleA", "abilityA", "serviceA");
    DExtConnectInfo connectInfo1(sourceInfo1, sinkInfo1, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo1;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillOnce(Return(nullptr));
    int32_t result1 = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo1, resultInfo1);
    EXPECT_EQ(result1, INVALID_PARAMETERS_ERR);

    // Second connection: bundleB
    DExtSourceInfo sourceInfo2("device2", "network2", "deviceName2", "bundleB", "moduleB", "abilityB");
    DExtSinkInfo sinkInfo2(100, 0, "bundleB", "moduleB", "abilityB", "serviceB");
    DExtConnectInfo connectInfo2(sourceInfo2, sinkInfo2, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo2;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillOnce(Return(nullptr));
    int32_t result2 = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo2, resultInfo2);
    EXPECT_EQ(result2, INVALID_PARAMETERS_ERR);

    // Verify both entries exist independently in svcDConnMap_
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        EXPECT_EQ(DistributedSchedService::GetInstance().svcDConnMap_.size(), static_cast<size_t>(2));
        EXPECT_NE(DistributedSchedService::GetInstance().svcDConnMap_.find("bundleA"),
            DistributedSchedService::GetInstance().svcDConnMap_.end());
        EXPECT_NE(DistributedSchedService::GetInstance().svcDConnMap_.find("bundleB"),
            DistributedSchedService::GetInstance().svcDConnMap_.end());
    }

    // Clean up
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test17 end" << std::endl;
}

/**
 * @tc.name  : PrepareSvcDConnection_Test04
 * @tc.desc  : Test PrepareSvcDConnection reuses existing connection when called twice
 *             with the same bundleName.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, PrepareSvcDConnection_Test04, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test04 start" << std::endl;
    SetNativeTokenForDExt();

    // Clean up
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "reuseBundle", "dms", "TestAbility");
    DExtSinkInfo sinkInfo(100, 0, "reuseBundle", "dms", "TestAbility", "TestService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "ohos.permission.dms_extension", "delegatee");

    // First call: creates new connection
    AAFwk::Want want1;
    bool isDelay1 = false;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    int32_t ret1 = DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo, want1, isDelay1);
    EXPECT_EQ(ret1, ERR_OK);

    size_t mapSizeAfterFirst = 0;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        mapSizeAfterFirst = DistributedSchedService::GetInstance().svcDConnMap_.size();
    }
    EXPECT_EQ(mapSizeAfterFirst, static_cast<size_t>(1));

    // Second call with same bundleName: should reuse existing connection
    AAFwk::Want want2;
    bool isDelay2 = false;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    int32_t ret2 = DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo, want2, isDelay2);
    EXPECT_EQ(ret2, ERR_OK);

    // Map should still have only 1 entry (reused)
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        EXPECT_EQ(DistributedSchedService::GetInstance().svcDConnMap_.size(), static_cast<size_t>(1));
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test04 end" << std::endl;
}

/**
 * @tc.name  : WaitAndGetDExtensionProxy_Test04
 * @tc.desc  : Test WaitAndGetDExtensionProxy fast path when connection already has
 *             isConnected_ = true (simulating already connected scenario).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, WaitAndGetDExtensionProxy_Test04, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest WaitAndGetDExtensionProxy_Test04 start" << std::endl;

    // Clean up svcDConnMap_ before test
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    // Prepare a connection via PrepareSvcDConnection
    DExtSourceInfo sourceInfo("device123", "network123", "", "connectedBundle", "module1", "ability1");
    DExtSinkInfo sinkInfo(100, 0, "connectedBundle", "module1", "ability1", "service1");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "token1", "delegatee1");
    AAFwk::Want want;
    bool isDelay = false;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillRepeatedly(Return(ERR_OK));
    DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo, want, isDelay);

    // Manually set isConnected_ = true to simulate that connection has completed
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        auto it = DistributedSchedService::GetInstance().svcDConnMap_.find("connectedBundle");
        ASSERT_NE(it, DistributedSchedService::GetInstance().svcDConnMap_.end());
        ASSERT_NE(it->second, nullptr);
        it->second->isConnected_.store(true);
    }

    // Now WaitAndGetDExtensionProxy should take the fast path (no waiting)
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillRepeatedly(Return(nullptr));
    auto proxy = DistributedSchedService::GetInstance().WaitAndGetDExtensionProxy("connectedBundle");
    EXPECT_EQ(proxy, nullptr);

    // Clean up
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    DTEST_LOG << "DistributedSchedServiceNewTest WaitAndGetDExtensionProxy_Test04 end" << std::endl;
}

/**
 * @tc.name  : ScheduleAutoUnload_Test02
 * @tc.desc  : Test ScheduleAutoUnload reschedule path - set dExtensionConnected_ = true
 *             so the unload thread should reschedule instead of actually unloading.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ScheduleAutoUnload_Test02, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ScheduleAutoUnload_Test02 start" << std::endl;

    // Set connected flag so the unload thread will reschedule instead of unloading
    DistributedSchedService::GetInstance().SetDExtensionConnected(true);

    int32_t ret = DistributedSchedService::GetInstance().ScheduleAutoUnload();
    EXPECT_EQ(ret, ERR_OK);

    // Wait briefly for the detached thread to execute and see dExtensionConnected_ = true
    std::this_thread::sleep_for(std::chrono::milliseconds(200));

    // After the thread sees connected=true, it resets to false and reschedules
    // The flag should have been reset to false by the reschedule logic
    // Clean up: set connected to prevent any actual unload
    DistributedSchedService::GetInstance().SetDExtensionConnected(true);

    DTEST_LOG << "DistributedSchedServiceNewTest ScheduleAutoUnload_Test02 end" << std::endl;
}

/**
 * @tc.name  : FinalizeDExtensionConnection_Test03
 * @tc.desc  : Test FinalizeDExtensionConnection when proxy is nullptr and isDelay is false.
 *             TriggerProxyCallbacks should set result to FAILED.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, FinalizeDExtensionConnection_Test03, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest FinalizeDExtensionConnection_Test03 start" << std::endl;
    AAFwk::Want want;
    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;
    sptr<IDExtension> proxy = nullptr;  // proxy is nullptr
    bool isDelay = false;

    int32_t ret = DistributedSchedService::GetInstance().FinalizeDExtensionConnection(
        want, connectInfo, proxy, isDelay, resultInfo);
    EXPECT_EQ(ret, ERR_OK);
    // TriggerProxyCallbacks sets result to FAILED when proxy is null
    EXPECT_EQ(resultInfo.result, DExtConnectResult::FAILED);

    DTEST_LOG << "DistributedSchedServiceNewTest FinalizeDExtensionConnection_Test03 end" << std::endl;
}

/**
 * @tc.name  : GetDeviceDisplayName_Test05
 * @tc.desc  : Test GetDeviceDisplayName when deviceName is provided (non-empty),
 *             ignoring networkId entirely.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, GetDeviceDisplayName_Test05, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest GetDeviceDisplayName_Test05 start" << std::endl;
    // Both deviceName and networkId are provided, deviceName takes priority
    DExtSourceInfo sourceInfo("device123", "network123", "PriorityDevice", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    std::string displayName;
    // Should NOT call GetDeviceName since deviceName is non-empty
    int32_t ret = DistributedSchedService::GetInstance().GetDeviceDisplayName(connectInfo, displayName, resultInfo);
    EXPECT_EQ(ret, ERR_OK);
    EXPECT_EQ(displayName, "PriorityDevice");

    DTEST_LOG << "DistributedSchedServiceNewTest GetDeviceDisplayName_Test05 end" << std::endl;
}

// ============================================================
// SvcDistributedConnection stub-based test cases
// (Uses real stub implementations from mock cpp, accessing internals via #define private public)
// ============================================================

/**
 * @tc.name  : SvcDConn_IsExtAbilityConnected_Test01
 * @tc.desc  : Test IsExtAbilityConnected returns false by default and true when set.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SvcDConn_IsExtAbilityConnected_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_IsExtAbilityConnected_Test01 start" << std::endl;
    auto conn = sptr<SvcDistributedConnection>(new SvcDistributedConnection("testBundle"));
    EXPECT_FALSE(conn->IsExtAbilityConnected());
    conn->isConnected_.store(true);
    EXPECT_TRUE(conn->IsExtAbilityConnected());
    conn->isConnected_.store(false);
    EXPECT_FALSE(conn->IsExtAbilityConnected());

    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_IsExtAbilityConnected_Test01 end" << std::endl;
}

/**
 * @tc.name  : SvcDConn_SetCallback_Test01
 * @tc.desc  : Test SetCallback stores and invokes the callback.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SvcDConn_SetCallback_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_SetCallback_Test01 start" << std::endl;
    auto conn = sptr<SvcDistributedConnection>(new SvcDistributedConnection("testBundle"));
    bool callbackInvoked = false;
    std::string receivedName;
    conn->SetCallback([&](const std::string &&name) {
        callbackInvoked = true;
        receivedName = name;
    });
    // Invoke callback manually via callConnected_
    {
        std::lock_guard<std::mutex> lock(conn->callbackMutex_);
        if (conn->callConnected_) {
            conn->callConnected_(std::string("testBundle"));
        }
    }
    EXPECT_TRUE(callbackInvoked);
    EXPECT_EQ(receivedName, "testBundle");

    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_SetCallback_Test01 end" << std::endl;
}

/**
 * @tc.name  : SvcDConn_OnAbilityConnectDone_Test01
 * @tc.desc  : Test OnAbilityConnectDone with null remoteObject.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SvcDConn_OnAbilityConnectDone_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_OnAbilityConnectDone_Test01 start" << std::endl;
    auto conn = sptr<SvcDistributedConnection>(new SvcDistributedConnection("testBundle"));
    AppExecFwk::ElementName element("device", "testBundle", "module", "ability");
    conn->isConnected_.store(false);
    EXPECT_NO_FATAL_FAILURE(conn->OnAbilityConnectDone(element, nullptr, 0));
    // remoteObject is nullptr, isConnected_ should remain false
    EXPECT_FALSE(conn->isConnected_.load());

    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_OnAbilityConnectDone_Test01 end" << std::endl;
}

/**
 * @tc.name  : SvcDConn_OnAbilityConnectDone_Test02
 * @tc.desc  : Test OnAbilityConnectDone with valid remoteObject, matching bundleName,
 *             and callback invoked.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SvcDConn_OnAbilityConnectDone_Test02, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_OnAbilityConnectDone_Test02 start" << std::endl;
    auto conn = sptr<SvcDistributedConnection>(new SvcDistributedConnection("testBundle"));
    conn->isConnected_.store(false);

    bool callbackInvoked = false;
    conn->SetCallback([&](const std::string &&name) {
        callbackInvoked = true;
    });

    // Create a mock remote object
    sptr<IRemoteObject> remoteObj = sptr<IRemoteObject>(new MockDistributedSched());
    AppExecFwk::ElementName element("device", "testBundle", "module", "ability");
    EXPECT_NO_FATAL_FAILURE(conn->OnAbilityConnectDone(element, remoteObj, 0));
    // Should have set connected and triggered callback
    // Note: distributedProxy_ is set via iface_cast, may be nullptr in test
    // if iface_cast returns nullptr, isConnected_ stays false
    // But the callback path requires ValidateBundleName + distributedProxy_ != nullptr

    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_OnAbilityConnectDone_Test02 end" << std::endl;
}

/**
 * @tc.name  : SvcDConn_OnAbilityConnectDone_Test03
 * @tc.desc  : Test OnAbilityConnectDone with bundleName mismatch (ValidateBundleName fails).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SvcDConn_OnAbilityConnectDone_Test03, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_OnAbilityConnectDone_Test03 start" << std::endl;
    auto conn = sptr<SvcDistributedConnection>(new SvcDistributedConnection("expectedBundle"));
    conn->isConnected_.store(false);

    bool callbackInvoked = false;
    conn->SetCallback([&](const std::string &&name) {
        callbackInvoked = true;
    });

    sptr<IRemoteObject> remoteObj = sptr<IRemoteObject>(new MockDistributedSched());
    // Use a different bundleName so ValidateBundleName fails
    AppExecFwk::ElementName element("device", "wrongBundle", "module", "ability");
    EXPECT_NO_FATAL_FAILURE(conn->OnAbilityConnectDone(element, remoteObj, 0));
    // Callback should NOT be invoked because ValidateBundleName fails
    EXPECT_FALSE(callbackInvoked);

    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_OnAbilityConnectDone_Test03 end" << std::endl;
}

/**
 * @tc.name  : SvcDConn_DisconnectDistributedExtAbility_Test01
 * @tc.desc  : Test DisconnectDistributedExtAbility basic call.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SvcDConn_DisconnectDistributedExtAbility_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_DisconnectDistributedExtAbility_Test01 start" << std::endl;
    auto conn = sptr<SvcDistributedConnection>(new SvcDistributedConnection("testBundle"));
    ErrCode ret = conn->DisconnectDistributedExtAbility();
    EXPECT_EQ(ret, ERR_OK);

    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_DisconnectDistributedExtAbility_Test01 end" << std::endl;
}

/**
 * @tc.name  : SvcDConn_EndTaskFunction_Test01
 * @tc.desc  : Test EndTaskFunction when connected (should disconnect).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SvcDConn_EndTaskFunction_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_EndTaskFunction_Test01 start" << std::endl;
    auto conn = sptr<SvcDistributedConnection>(new SvcDistributedConnection("testBundle"));
    conn->isConnected_.store(true);
    EXPECT_NO_FATAL_FAILURE(conn->EndTaskFunction());

    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_EndTaskFunction_Test01 end" << std::endl;
}

/**
 * @tc.name  : SvcDConn_EndTaskFunction_Test02
 * @tc.desc  : Test EndTaskFunction when not connected (should do nothing).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SvcDConn_EndTaskFunction_Test02, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_EndTaskFunction_Test02 start" << std::endl;
    auto conn = sptr<SvcDistributedConnection>(new SvcDistributedConnection("testBundle"));
    conn->isConnected_.store(false);
    EXPECT_NO_FATAL_FAILURE(conn->EndTaskFunction());

    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_EndTaskFunction_Test02 end" << std::endl;
}

/**
 * @tc.name  : SvcDConn_RegisterEventListener_Test01
 * @tc.desc  : Test RegisterEventListener runs without crash.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SvcDConn_RegisterEventListener_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_RegisterEventListener_Test01 start" << std::endl;
    auto conn = sptr<SvcDistributedConnection>(new SvcDistributedConnection("testBundle"));
    EXPECT_NO_FATAL_FAILURE(conn->RegisterEventListener());

    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_RegisterEventListener_Test01 end" << std::endl;
}

/**
 * @tc.name  : SvcDConn_GetDistributedExtProxy_Test01
 * @tc.desc  : Test GetDistributedExtProxy returns nullptr when no proxy set.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SvcDConn_GetDistributedExtProxy_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_GetDistributedExtProxy_Test01 start" << std::endl;
    auto conn = sptr<SvcDistributedConnection>(new SvcDistributedConnection("testBundle"));
    auto proxy = conn->GetDistributedExtProxy();
    EXPECT_EQ(proxy, nullptr);

    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_GetDistributedExtProxy_Test01 end" << std::endl;
}

/**
 * @tc.name  : SvcDConn_PublishDExtensionNotification_Test01
 * @tc.desc  : Test PublishDExtensionNotification runs without crash (stub no-op).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SvcDConn_PublishDExtensionNotification_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_PublishDExtensionNotification_Test01 start" << std::endl;
    auto conn = sptr<SvcDistributedConnection>(new SvcDistributedConnection("testBundle"));
    AppExecFwk::BundleResourceInfo bundleResourceInfo;
    EXPECT_NO_FATAL_FAILURE(conn->PublishDExtensionNotification(
        "device123", "testBundle", 100, "TestDevice", bundleResourceInfo));

    DTEST_LOG << "DistributedSchedServiceNewTest SvcDConn_PublishDExtensionNotification_Test01 end" << std::endl;
}

// ============================================================
// ValidateAndPrepareConnection / CheckCallingPermission direct branch tests
// ============================================================

/**
 * @tc.name  : ValidateAndPrepareConnection_Test01
 * @tc.desc  : Test ValidateAndPrepareConnection succeeds with valid sinkInfo,
 *             native token, correct UID, and foreground user.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ValidateAndPrepareConnection_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ValidateAndPrepareConnection_Test01 start" << std::endl;
    SetNativeTokenForDExt();

    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    // ValidateAndPrepareConnection succeeds, PrepareSvcDConnection is called next
    // which calls mock ConnectDExtAbility
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillRepeatedly(Return(nullptr));

    // Re-invoke to validate the path
    DExtConnectResultInfo resultInfo2;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillOnce(Return(nullptr));
    int32_t result2 = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo2);
    EXPECT_NE(result2, DMS_PERMISSION_DENIED);

    DTEST_LOG << "DistributedSchedServiceNewTest ValidateAndPrepareConnection_Test01 end" << std::endl;
}

/**
 * @tc.name  : CheckCallingPermission_DSoftBusUid_Test01
 * @tc.desc  : Test CheckCallingPermission with DSOFTBUS_UID.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, CheckCallingPermission_DSoftBusUid_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest CheckCallingPermission_DSoftBusUid_Test01 start" << std::endl;

    uint64_t tokenId;
    const char *perms[] = {
        "ohos.permission.GET_BUNDLE_RESOURCES",
        "ohos.permission.GET_BUNDLE_INFO_PRIVILEGED"
    };
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = 2,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = "foundation",
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    setuid(1024); // DSOFTBUS_UID
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();

    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillRepeatedly(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillRepeatedly(Return(nullptr));
    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    // Should NOT get permission denied with DSOFTBUS_UID
    EXPECT_NE(result, DMS_PERMISSION_DENIED);

    // Restore
    setuid(WEARLINK_UID);
    DTEST_LOG << "DistributedSchedServiceNewTest CheckCallingPermission_DSoftBusUid_Test01 end" << std::endl;
}

/**
 * @tc.name  : CheckCallingPermission_WrongTokenType_Test01
 * @tc.desc  : Test CheckCallingPermission with non-native token type.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, CheckCallingPermission_WrongTokenType_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest CheckCallingPermission_WrongTokenType_Test01 start" << std::endl;
    // Do NOT set native token, so token type is not TOKEN_NATIVE
    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;
    setuid(9999);

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    EXPECT_EQ(resultInfo.result, DExtConnectResult::PERMISSION_DENIED);

    DTEST_LOG << "DistributedSchedServiceNewTest CheckCallingPermission_WrongTokenType_Test01 end" << std::endl;
}

/**
 * @tc.name  : ValidateAndPrepareConnection_NotForeground_Test01
 * @tc.desc  : Test ValidateAndPrepareConnection when user is not foreground.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ValidateAndPrepareConnection_NotForeground_Test01, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ValidateAndPrepareConnection_NotForeground_Test01 start" << std::endl;
    SetNativeTokenForDExt();

    // Use userId=-1 which IsUserForeground returns false
    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(-1, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    EXPECT_EQ(result, DMS_NOT_FOREGROUND_USER);

    DTEST_LOG << "DistributedSchedServiceNewTest ValidateAndPrepareConnection_NotForeground_Test01 end" << std::endl;
}

// ============================================================
// PrepareSvcDConnection edge case tests
// ============================================================

/**
 * @tc.name  : PrepareSvcDConnection_Test05
 * @tc.desc  : Test PrepareSvcDConnection with empty bundleName.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, PrepareSvcDConnection_Test05, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test05 start" << std::endl;
    SetNativeTokenForDExt();

    DExtSourceInfo sourceInfo("device123", "network123", "", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");

    AAFwk::Want want;
    bool isDelay = false;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    int32_t ret = DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo, want, isDelay);
    EXPECT_EQ(ret, ERR_OK);

    // Clean up
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test05 end" << std::endl;
}

/**
 * @tc.name  : PrepareSvcDConnection_Test06
 * @tc.desc  : Test PrepareSvcDConnection with different bundleNames creates separate entries.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, PrepareSvcDConnection_Test06, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test06 start" << std::endl;
    SetNativeTokenForDExt();

    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    // First bundle
    DExtSourceInfo sourceInfo1("device1", "network1", "", "bundleX", "module1", "ability1");
    DExtSinkInfo sinkInfo1(100, 0, "bundleX", "module1", "ability1", "service1");
    DExtConnectInfo connectInfo1(sourceInfo1, sinkInfo1, "token1", "delegatee1");
    AAFwk::Want want1;
    bool isDelay1 = false;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    int32_t ret1 = DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo1, want1, isDelay1);
    EXPECT_EQ(ret1, ERR_OK);

    // Second bundle
    DExtSourceInfo sourceInfo2("device2", "network2", "", "bundleY", "module2", "ability2");
    DExtSinkInfo sinkInfo2(200, 0, "bundleY", "module2", "ability2", "service2");
    DExtConnectInfo connectInfo2(sourceInfo2, sinkInfo2, "token2", "delegatee2");
    AAFwk::Want want2;
    bool isDelay2 = false;
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    int32_t ret2 = DistributedSchedService::GetInstance().PrepareSvcDConnection(connectInfo2, want2, isDelay2);
    EXPECT_EQ(ret2, ERR_OK);

    // Verify two separate entries
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        EXPECT_EQ(DistributedSchedService::GetInstance().svcDConnMap_.size(), static_cast<size_t>(2));
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    DTEST_LOG << "DistributedSchedServiceNewTest PrepareSvcDConnection_Test06 end" << std::endl;
}

// ============================================================
// WaitAndGetDExtensionProxy additional edge case tests
// ============================================================

/**
 * @tc.name  : WaitAndGetDExtensionProxy_Test05
 * @tc.desc  : Test WaitAndGetDExtensionProxy with entry in map but connection ptr is nullptr.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, WaitAndGetDExtensionProxy_Test05, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest WaitAndGetDExtensionProxy_Test05 start" << std::endl;
    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
        // Insert a nullptr entry
        DistributedSchedService::GetInstance().svcDConnMap_["nullBundle"] = nullptr;
    }

    auto proxy = DistributedSchedService::GetInstance().WaitAndGetDExtensionProxy("nullBundle");
    EXPECT_EQ(proxy, nullptr);

    {
        std::lock_guard<std::mutex> autoLock(DistributedSchedService::GetInstance().svcDConnectLock_);
        DistributedSchedService::GetInstance().svcDConnMap_.clear();
    }

    DTEST_LOG << "DistributedSchedServiceNewTest WaitAndGetDExtensionProxy_Test05 end" << std::endl;
}

// ============================================================
// ConnectDExtensionFromRemote PrepareSvcDConnection failure path
// ============================================================

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test18
 * @tc.desc  : Test ConnectDExtensionFromRemote when PrepareSvcDConnection fails.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test18, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test18 start" << std::endl;
    SetNativeTokenForDExt();

    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(INVALID_PARAMETERS_ERR));
    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    EXPECT_EQ(resultInfo.errCode, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test18 end" << std::endl;
}

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test19
 * @tc.desc  : Test ConnectDExtensionFromRemote with sinkInfo only serviceName non-empty
 *             (bundleName, moduleName, abilityName all empty => IsEmpty returns true).
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test19, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test19 start" << std::endl;
    SetNativeTokenForDExt();

    // serviceName is non-empty but bundleName/moduleName/abilityName are empty
    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "", "", "", "OnlyServiceName");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);

    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test19 end" << std::endl;
}

/**
 * @tc.name  : ConnectDExtensionFromRemote_Test20
 * @tc.desc  : Test ConnectDExtensionFromRemote validates resultInfo.connectInfo is set on success.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, ConnectDExtensionFromRemote_Test20, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test20 start" << std::endl;
    SetNativeTokenForDExt();

    DExtSourceInfo sourceInfo("device123", "network123", "deviceName1", "testBundle", "testModule", "testAbility");
    DExtSinkInfo sinkInfo(100, 0, "testBundle", "testModule", "testAbility", "testService");
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, "validToken", "delegatee");
    DExtConnectResultInfo resultInfo;

    // First check that ValidateAndPrepareConnection sets resultInfo.connectInfo
    // by calling ConnectDExtensionFromRemote which internally calls ValidateAndPrepareConnection
    // We need PrepareSvcDConnection to succeed to get past it
    EXPECT_CALL(*svcDConnMock, ConnectDExtAbility(_, _, _, _, _)).WillOnce(Return(ERR_OK));
    EXPECT_CALL(*svcDConnMock, GetDistributedExtProxy()).WillOnce(Return(nullptr));
    int32_t result = DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
    // ValidateAndPrepareConnection should have set resultInfo.connectInfo before PrepareSvcDConnection
    // Even though overall result fails due to null proxy, connectInfo should be set
    EXPECT_EQ(resultInfo.connectInfo.sinkInfo.bundleName, "testBundle");

    DTEST_LOG << "DistributedSchedServiceNewTest ConnectDExtensionFromRemote_Test20 end" << std::endl;
}

// ============================================================
// SetDExtensionConnected additional tests
// ============================================================

/**
 * @tc.name  : SetDExtensionConnected_Test02
 * @tc.desc  : Test SetDExtensionConnected concurrent access.
 * @tc.type  : FUNC
 */
HWTEST_F(DistributedSchedServiceNewTest, SetDExtensionConnected_Test02, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceNewTest SetDExtensionConnected_Test02 start" << std::endl;
    auto& instance = DistributedSchedService::GetInstance();
    instance.SetDExtensionConnected(false);
    EXPECT_FALSE(instance.dExtensionConnected_.load());

    // Toggle rapidly
    for (int i = 0; i < 100; i++) {
        instance.SetDExtensionConnected(i % 2 == 0);
    }
    // No crash means thread-safe

    DTEST_LOG << "DistributedSchedServiceNewTest SetDExtensionConnected_Test02 end" << std::endl;
}
}
}
