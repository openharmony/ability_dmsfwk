/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "mission/dsched_sync_e2e.h"
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
    const string LOCAL_DEVICEID = "192.168.43.100";
    const string REMOTE_DEVICEID = "123";
    const std::u16string DEVICE_ID = u"192.168.43.100";
    const std::u16string DEVICE_ID_NULL = u"";
    constexpr int32_t SESSION_ID = 123;
    const std::string DMS_MISSION_ID = "dmsMissionId";
    constexpr int32_t MISSION_ID = 1;
    const std::string DMS_SRC_NETWORK_ID = "dmsSrcNetworkId";
    const string ABILITY_NAME = "com.ohos.permissionmanager.MainAbility";
    const string BUNDLE_NAME = "com.ohos.permissionmanager";
    const string BUNDLE_NAME_2 = "com.example.testapp";
    const string DMS_IS_CALLER_BACKGROUND = "dmsIsCallerBackGround";
    const string DMS_VERSION_ID = "dmsVersion";
    constexpr int32_t SLEEP_TIME = 1000;
    constexpr int32_t WEARLINK_UID = 7259;
    constexpr int32_t COLLABORATION_SERVICE = 0;
    constexpr int32_t TEST_ACCOUNT_ID = 100;
}

class DistributedSchedServiceMDMTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DistributedSchedServiceMDMTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedSchedServiceMDMTest::SetUpTestCase" << std::endl;
}

void DistributedSchedServiceMDMTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedSchedServiceMDMTest::TearDownTestCase" << std::endl;
}

void DistributedSchedServiceMDMTest::SetUp()
{
    DistributedSchedUtil::MockPermission();
    DTEST_LOG << "DistributedSchedServiceMDMTest::SetUp" << std::endl;
}

void DistributedSchedServiceMDMTest::TearDown()
{
    DTEST_LOG << "DistributedSchedServiceMDMTest::TearDown" << std::endl;
}

/**
 * @tc.name: GetBundleNameFromConnectAbilityMapTest_001
 * @tc.desc: test GetBundleNameFromConnectAbilityMap with null connect
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, GetBundleNameFromConnectAbilityMapTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest GetBundleNameFromConnectAbilityMapTest_001 start" << std::endl;
    
    DistributedSchedService service;
    sptr<IRemoteObject> connect = nullptr;
    
    std::string bundleName = service.GetBundleNameFromConnectAbilityMap(connect);
    EXPECT_TRUE(bundleName.empty());
    
    DTEST_LOG << "DistributedSchedServiceMDMTest GetBundleNameFromConnectAbilityMapTest_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityMDMTest_001
 * @tc.desc: test StartRemoteAbility with MDM control enabled and no exemption
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, StartRemoteAbilityMDMTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest StartRemoteAbilityMDMTest_001 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(true);
    
    int32_t result = service.StartRemoteAbility(want, 100, 0, 0, 0);
    EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest StartRemoteAbilityMDMTest_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteAbilityMDMTest_002
 * @tc.desc: test StartRemoteAbility with MDM control disabled
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, StartRemoteAbilityMDMTest_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest StartRemoteAbilityMDMTest_002 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    int32_t result = service.StartRemoteAbility(want, 100, 0, 0, 0);
    EXPECT_NE(result, ERR_CAPABILITY_NOT_SUPPORT);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest StartRemoteAbilityMDMTest_002 end" << std::endl;
}

/**
 * @tc.name: ReleaseRemoteAbilityMDMTest_001
 * @tc.desc: test ReleaseRemoteAbility with MDM control enabled and no exemption
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, ReleaseRemoteAbilityMDMTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest ReleaseRemoteAbilityMDMTest_001 start" << std::endl;
    
    DistributedSchedService service;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(true);
    
    int32_t result = service.ReleaseRemoteAbility(nullptr, element);
    EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest ReleaseRemoteAbilityMDMTest_001 end" << std::endl;
}

/**
 * @tc.name: ReleaseRemoteAbilityMDMTest_002
 * @tc.desc: test ReleaseRemoteAbility with MDM control disabled
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, ReleaseRemoteAbilityMDMTest_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest ReleaseRemoteAbilityMDMTest_002 start" << std::endl;
    
    DistributedSchedService service;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    int32_t result = service.ReleaseRemoteAbility(nullptr, element);
    EXPECT_NE(result, ERR_CAPABILITY_NOT_SUPPORT);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest ReleaseRemoteAbilityMDMTest_002 end" << std::endl;
}

/**
 * @tc.name: StartRemoteFreeInstallMDMTest_001
 * @tc.desc: test StartRemoteFreeInstall with MDM control enabled and no exemption
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, StartRemoteFreeInstallMDMTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest StartRemoteFreeInstallMDMTest_001 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(true);
    
    int32_t result = service.StartRemoteFreeInstall(want, 100, 0, 0, nullptr);
    EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest StartRemoteFreeInstallMDMTest_001 end" << std::endl;
}

/**
 * @tc.name: StartRemoteFreeInstallMDMTest_002
 * @tc.desc: test StartRemoteFreeInstall with MDM control disabled
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, StartRemoteFreeInstallMDMTest_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest StartRemoteFreeInstallMDMTest_002 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    int32_t result = service.StartRemoteFreeInstall(want, 100, 0, 0, nullptr);
    EXPECT_NE(result, ERR_CAPABILITY_NOT_SUPPORT);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest StartRemoteFreeInstallMDMTest_002 end" << std::endl;
}

/**
 * @tc.name: StopRemoteExtensionAbilityMDMTest_001
 * @tc.desc: test StopRemoteExtensionAbility with MDM control enabled and no exemption
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, StopRemoteExtensionAbilityMDMTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest StopRemoteExtensionAbilityMDMTest_001 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(true);
    
    int32_t result = service.StopRemoteExtensionAbility(want, 100, 0, 0);
    EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest StopRemoteExtensionAbilityMDMTest_001 end" << std::endl;
}

/**
 * @tc.name: StopRemoteExtensionAbilityMDMTest_002
 * @tc.desc: test StopRemoteExtensionAbility with MDM control disabled
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, StopRemoteExtensionAbilityMDMTest_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest StopRemoteExtensionAbilityMDMTest_002 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    int32_t result = service.StopRemoteExtensionAbility(want, 100, 0, 0);
    EXPECT_NE(result, ERR_CAPABILITY_NOT_SUPPORT);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest StopRemoteExtensionAbilityMDMTest_002 end" << std::endl;
}

/**
 * @tc.name: MDMControlIntegrationTest_001
 * @tc.desc: test MDM control with state toggling
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, MDMControlIntegrationTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_001 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    for (int i = 0; i < 10; i++) {
        bool enableMDM = (i % 2 == 0);
        DmsKvSyncE2E::GetInstance()->SetMdmControl(enableMDM);
        
        int32_t result = service.StartRemoteAbility(want, 100, 0, 0, 0);
        
        if (enableMDM) {
            EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
        } else {
            EXPECT_NE(result, ERR_CAPABILITY_NOT_SUPPORT);
        }
    }
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_001 end" << std::endl;
}

/**
 * @tc.name: MDMControlIntegrationTest_002
 * @tc.desc: test MDM control with different bundle names
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, MDMControlIntegrationTest_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_002 start" << std::endl;
    
    DistributedSchedService service;
    
    std::vector<std::string> bundleNames = {
        BUNDLE_NAME,
        BUNDLE_NAME_2,
        "com.ohos.systemui",
        "com.ohos.launcher",
        "com.example.testapp"
    };
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(true);
    
    for (const auto& bundleName : bundleNames) {
        Want want;
        ElementName element(bundleName, ABILITY_NAME, "ability");
        want.SetElement(element);
        
        int32_t result = service.StartRemoteAbility(want, 100, 0, 0, 0);
        EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
    }
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_002 end" << std::endl;
}

/**
 * @tc.name: MDMControlIntegrationTest_003
 * @tc.desc: test MDM control with account ID changes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, MDMControlIntegrationTest_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_003 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(true);
    
    for (int32_t accountId = 0; accountId < 10; accountId++) {
        int32_t result = service.StartRemoteAbility(want, 100, 0, 0, 0);
        EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
    }
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_003 end" << std::endl;
}

/**
 * @tc.name: MDMControlIntegrationTest_004
 * @tc.desc: test MDM control with service type variations
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, MDMControlIntegrationTest_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_004 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(true);
    
    for (int32_t serviceType = 0; serviceType < 10; serviceType++) {
        int32_t result = service.StartRemoteAbility(want, 100, 0, 0, 0);
        EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
    }
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_004 end" << std::endl;
}

/**
 * @tc.name: MDMControlIntegrationTest_005
 * @tc.desc: test MDM control with boundary values
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, MDMControlIntegrationTest_005, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_005 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(true);
    
    int32_t result1 = service.StartRemoteAbility(want, INT32_MIN, 0, 0, 0);
    EXPECT_EQ(result1, ERR_CAPABILITY_NOT_SUPPORT);
    
    int32_t result2 = service.StartRemoteAbility(want, INT32_MAX, 0, 0, 0);
    EXPECT_EQ(result2, ERR_CAPABILITY_NOT_SUPPORT);
    
    int32_t result3 = service.StartRemoteAbility(want, 0, INT32_MIN, 0, 0);
    EXPECT_EQ(result3, ERR_CAPABILITY_NOT_SUPPORT);
    
    int32_t result4 = service.StartRemoteAbility(want, 0, INT32_MAX, 0, 0);
    EXPECT_EQ(result4, ERR_CAPABILITY_NOT_SUPPORT);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_005 end" << std::endl;
}

/**
 * @tc.name: MDMControlIntegrationTest_006
 * @tc.desc: test MDM control with null parameters
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, MDMControlIntegrationTest_006, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_006 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(true);
    
    int32_t result1 = service.ReleaseRemoteAbility(nullptr, element);
    EXPECT_EQ(result1, ERR_CAPABILITY_NOT_SUPPORT);
    
    int32_t result2 = service.StartRemoteFreeInstall(want, 100, 0, 0, nullptr);
    EXPECT_EQ(result2, ERR_CAPABILITY_NOT_SUPPORT);
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_006 end" << std::endl;
}

/**
 * @tc.name: MDMControlIntegrationTest_007
 * @tc.desc: test MDM control performance with rapid state changes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedServiceMDMTest, MDMControlIntegrationTest_007, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_007 start" << std::endl;
    
    DistributedSchedService service;
    Want want;
    ElementName element(BUNDLE_NAME, ABILITY_NAME, "ability");
    want.SetElement(element);
    
    for (int i = 0; i < 100; i++) {
        bool enableMDM = (i % 2 == 0);
        DmsKvSyncE2E::GetInstance()->SetMdmControl(enableMDM);
        
        int32_t result = service.StartRemoteAbility(want, 100, 0, 0, 0);
        
        if (enableMDM) {
            EXPECT_EQ(result, ERR_CAPABILITY_NOT_SUPPORT);
        } else {
            EXPECT_NE(result, ERR_CAPABILITY_NOT_SUPPORT);
        }
    }
    
    DmsKvSyncE2E::GetInstance()->SetMdmControl(false);
    
    DTEST_LOG << "DistributedSchedServiceMDMTest MDMControlIntegrationTest_007 end" << std::endl;
}

} // namespace DistributedSchedule
} // namespace OHOS