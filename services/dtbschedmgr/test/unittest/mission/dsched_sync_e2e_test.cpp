/*
 * Copyright (c) 2024-2026 Huawei Device Co., Ltd.
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

#include "dsched_sync_e2e_test.h"

#include <thread>
#include "distributed_sched_test_util.h"
#include "dtbschedmgr_device_info_storage.h"
#include "test_log.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS::DistributedKv;
using namespace OHOS::DistributedHardware;
namespace {
const std::string BASEDIR = "/data/service/el1/public/database/DistributedSchedule";
constexpr int32_t TASK_ID_1 = 11;
constexpr int32_t TASK_ID_2 = 12;
constexpr size_t BYTESTREAM_LENGTH = 100;
constexpr uint8_t ONE_BYTE = '6';
constexpr int32_t TEST_ACCOUNT_ID = 100;
constexpr int32_t INVALID_ACCOUNT_BUNDLE_ID = -1;
}

void DmsKvSyncE2ETest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DmsKvSyncE2ETest::SetUpTestCase" << std::endl;
}

void DmsKvSyncE2ETest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DmsKvSyncE2ETest::TearDownTestCase" << std::endl;
}

void DmsKvSyncE2ETest::SetUp()
{
    DistributedSchedUtil::MockPermission();
    dmsKvSyncE2E_ = std::make_shared<DmsKvSyncE2E>();
    DTEST_LOG << "DmsKvSyncE2ETest::SetUp" << std::endl;
}

void DmsKvSyncE2ETest::TearDown()
{
    DTEST_LOG << "DmsKvSyncE2ETest::TearDown" << std::endl;
}


std::shared_ptr<DmsKvSyncE2E> DmsKvSyncE2ETest::GetDmsKvSyncE2E()
{
    if (dmsKvSyncE2E_ == nullptr) {
        dmsKvSyncE2E_ = std::make_unique<DmsKvSyncE2E>();
    }
    return dmsKvSyncE2E_;
}

/**
 * @tc.name: PushAndPullDataTest_001
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, PushAndPullDataTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest PushAndPullDataTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_.clear();
        bool ret = dmsKvSyncE2E_->GetInstance()->PushAndPullData();
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DmsKvSyncE2ETest PushAndPullDataTest_001 end" << std::endl;
}

/**
 * @tc.name: PushAndPullDataTest_002
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, PushAndPullDataTest_002, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest PushAndPullDataTest_002 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        const std::string networkId = "123";
        bool ret = dmsKvSyncE2E_->GetInstance()->PushAndPullData(networkId);
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DmsKvSyncE2ETest PushAndPullDataTest_002 end" << std::endl;
}

/**
 * @tc.name: PushAndPullDataTest_003
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, PushAndPullDataTest_003, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest PushAndPullDataTest_003 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        auto deviceInfo = std::make_shared<DmsDeviceInfo>("", 0, "");
        auto deviceInfo1 = std::make_shared<DmsDeviceInfo>("", 1, "");
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_["deviceInfo"] = deviceInfo;
        DtbschedmgrDeviceInfoStorage::GetInstance().remoteDevices_["deviceInfo1"] = deviceInfo1;
        bool ret = dmsKvSyncE2E_->GetInstance()->PushAndPullData();
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DmsKvSyncE2ETest PushAndPullDataTest_003 end" << std::endl;
}

/**
 * @tc.name: SetDeviceCfgTest_001
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, SetDeviceCfgTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest SetDeviceCfgTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetDeviceCfg();
    }
    DTEST_LOG << "DmsKvSyncE2ETest SetDeviceCfgTest_001 end" << std::endl;
}

/**
 * @tc.name: CheckDeviceCfgTest_001
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, CheckDeviceCfgTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest CheckDeviceCfgTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        bool ret = dmsKvSyncE2E_->GetInstance()->CheckDeviceCfg();
    }
    DTEST_LOG << "DmsKvSyncE2ETest CheckDeviceCfgTest_001 end" << std::endl;
}

/**
 * @tc.name: CheckCtrlRuleTest_001
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, CheckCtrlRuleTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest CheckCtrlRuleTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->CheckCtrlRule();
    }
    DTEST_LOG << "DmsKvSyncE2ETest CheckCtrlRuleTest_001 end" << std::endl;
}

/**
 * @tc.name: CheckBundleContinueConfigTest_001
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, CheckBundleContinueConfigTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest CheckBundleContinueConfigTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        const std::string bundleName = "123";
        dmsKvSyncE2E_->GetInstance()->whiteList_.clear();
        bool ret = dmsKvSyncE2E_->GetInstance()->CheckBundleContinueConfig(bundleName);
        EXPECT_EQ(ret, false);

        dmsKvSyncE2E_->GetInstance()->whiteList_.clear();
        dmsKvSyncE2E_->GetInstance()->whiteList_.push_back(bundleName);
        dmsKvSyncE2E_->GetInstance()->whiteList_.push_back(bundleName);
        ret = dmsKvSyncE2E_->GetInstance()->CheckBundleContinueConfig(bundleName);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest CheckBundleContinueConfigTest_001 end" << std::endl;
}

/**
 * @tc.name: IsValidPath_001
 * @tc.desc: test IsValidPath
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsValidPath_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest CheckCtrlRuleTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        std::string inFilePath = "";
        std::string realFilePath;
        bool ret = dmsKvSyncE2E_->GetInstance()->IsValidPath(inFilePath, realFilePath);
        EXPECT_EQ(ret, false);

        inFilePath = "inFilePath";
        ret = dmsKvSyncE2E_->GetInstance()->IsValidPath(inFilePath, realFilePath);
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsValidPath_001 end" << std::endl;
}

/**
 * @tc.name: UpdateWhiteListTest_001
 * @tc.desc: test UpdateWhiteList
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, UpdateWhiteListTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest UpdateWhiteListTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        const std::string cfgJsonStr = "cfgJsonStr";
        bool ret = dmsKvSyncE2E_->GetInstance()->UpdateWhiteList(cfgJsonStr);
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DmsKvSyncE2ETest UpdateWhiteListTest_001 end" << std::endl;
}

/**
 * @tc.name: CheckKvStoreTest_001
 * @tc.desc: test CheckKvStore
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, CheckKvStoreTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest CheckKvStoreTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->kvStorePtr_ = nullptr;
        bool ret = dmsKvSyncE2E_->GetInstance()->CheckKvStore();
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest CheckKvStoreTest_001 end" << std::endl;
}

/**
 * @tc.name: CheckMDMCtrlRuleTest_001
 * @tc.desc: test insert CheckMDMCtrlRule
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, CheckMDMCtrlRuleTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest CheckMDMCtrlRuleTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    std::string bundleName = "bundleName";
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->isMDMControl_ = true;
        bool ret = dmsKvSyncE2E_->GetInstance()->CheckMDMCtrlRule(bundleName);
        EXPECT_EQ(ret, true);

        dmsKvSyncE2E_->GetInstance()->isMDMControl_ = false;
        ret = dmsKvSyncE2E_->GetInstance()->CheckMDMCtrlRule(bundleName);
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DmsKvSyncE2ETest CheckMDMCtrlRuleTest_001 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_001
 * @tc.desc: test IsMDMControlWithExemption with empty bundle name
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    std::string bundleName = "";
    int32_t serviceType = COLLABORATION_SERVICE;
    int32_t accountId = TEST_ACCOUNT_ID;
    
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_001 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_002
 * @tc.desc: test IsMDMControlWithExemption with valid bundle name but no exemption
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_002, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_002 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    std::string bundleName = "com.example.testapp";
    int32_t serviceType = COLLABORATION_SERVICE;
    int32_t accountId = TEST_ACCOUNT_ID;
    
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_002 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_004
 * @tc.desc: test IsMDMControlWithExemption with different service types
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_004, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_004 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    std::string bundleName = "com.example.testapp";
    int32_t accountId = TEST_ACCOUNT_ID;
    
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        
        for (int32_t serviceType = 0; serviceType < 10; serviceType++) {
            bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
            EXPECT_EQ(ret, true);
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_004 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_005
 * @tc.desc: test IsMDMControlWithExemption with different account IDs
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_005, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_005 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    std::string bundleName = "com.example.testapp";
    int32_t serviceType = COLLABORATION_SERVICE;
    
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        
        for (int32_t accountId = 0; accountId < 10; accountId++) {
            bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
            EXPECT_EQ(ret, true);
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_005 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_006
 * @tc.desc: test IsMDMControlWithExemption with special bundle names
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_006, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_006 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    int32_t serviceType = COLLABORATION_SERVICE;
    int32_t accountId = TEST_ACCOUNT_ID;
    
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        
        std::vector<std::string> specialBundleNames = {
            "com.ohos.systemui",
            "com.ohos.launcher",
            "com.ohos.settings",
            "com.example.app.with.very.long.name",
            "com.example.app-with-dashes",
            "com.example.app_with_underscores",
            "123.456.789"
        };
        
        for (const auto& bundleName : specialBundleNames) {
            bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
            EXPECT_EQ(ret, true);
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_006 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_007
 * @tc.desc: test IsMDMControlWithExemption with negative account ID
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_007, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_007 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    std::string bundleName = "com.example.testapp";
    int32_t serviceType = COLLABORATION_SERVICE;
    int32_t accountId = INVALID_ACCOUNT_BUNDLE_ID;
    
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_007 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_008
 * @tc.desc: test IsMDMControlWithExemption with very large account ID
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_008, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_008 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    std::string bundleName = "com.example.testapp";
    int32_t serviceType = COLLABORATION_SERVICE;
    int32_t accountId = INT32_MAX;
    
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_008 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_009
 * @tc.desc: test IsMDMControlWithExemption with negative service type
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_009, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_009 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    std::string bundleName = "com.example.testapp";
    int32_t serviceType = -1;
    int32_t accountId = TEST_ACCOUNT_ID;
    
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_009 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_010
 * @tc.desc: test IsMDMControlWithExemption with very large service type
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_010, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_010 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    std::string bundleName = "com.example.testapp";
    int32_t serviceType = INT32_MAX;
    int32_t accountId = TEST_ACCOUNT_ID;
    
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_010 end" << std::endl;
}

/**
 * @tc.name: GetActiveAccountIdTest_001
 * @tc.desc: test GetActiveAccountId basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetActiveAccountIdTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetActiveAccountIdTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        int32_t accountId = dmsKvSyncE2E_->GetInstance()->GetActiveAccountId();
        EXPECT_GE(accountId, 0);
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetActiveAccountIdTest_001 end" << std::endl;
}

/**
 * @tc.name: GetActiveAccountIdTest_002
 * @tc.desc: test GetActiveAccountId multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetActiveAccountIdTest_002, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetActiveAccountIdTest_002 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        int32_t accountId1 = dmsKvSyncE2E_->GetInstance()->GetActiveAccountId();
        int32_t accountId2 = dmsKvSyncE2E_->GetInstance()->GetActiveAccountId();
        int32_t accountId3 = dmsKvSyncE2E_->GetInstance()->GetActiveAccountId();
        
        EXPECT_GE(accountId1, 0);
        EXPECT_GE(accountId2, 0);
        EXPECT_GE(accountId3, 0);
        EXPECT_EQ(accountId1, accountId2);
        EXPECT_EQ(accountId2, accountId3);
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetActiveAccountIdTest_002 end" << std::endl;
}

/**
 * @tc.name: GetActiveAccountIdTest_003
 * @tc.desc: test GetActiveAccountId with different MDM control states
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetActiveAccountIdTest_003, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetActiveAccountIdTest_003 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(false);
        int32_t accountId1 = dmsKvSyncE2E_->GetInstance()->GetActiveAccountId();
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        int32_t accountId2 = dmsKvSyncE2E_->GetInstance()->GetActiveAccountId();
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(false);
        int32_t accountId3 = dmsKvSyncE2E_->GetInstance()->GetActiveAccountId();
        
        EXPECT_GE(accountId1, 0);
        EXPECT_GE(accountId2, 0);
        EXPECT_GE(accountId3, 0);
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetActiveAccountIdTest_003 end" << std::endl;
}

/**
 * @tc.name: GetAllowedDistributeAbilityConnBundlesStubTest_001
 * @tc.desc: test GetAllowedDistributeAbilityConnBundlesStub with collaboration service
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetAllowedDistributeAbilityConnBundlesStubTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        AAFwk::Want admin;
        int32_t serviceType = COLLABORATION_SERVICE;
        int32_t accountId = TEST_ACCOUNT_ID;
        
        std::vector<std::string> result = dmsKvSyncE2E_->GetInstance()->GetAllowedDistributeAbilityConnBundlesStub(
            admin, serviceType, accountId);
        EXPECT_TRUE(result.empty());
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_001 end" << std::endl;
}

/**
 * @tc.name: GetAllowedDistributeAbilityConnBundlesStubTest_002
 * @tc.desc: test GetAllowedDistributeAbilityConnBundlesStub with different service types
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetAllowedDistributeAbilityConnBundlesStubTest_002, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_002 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        AAFwk::Want admin;
        int32_t accountId = TEST_ACCOUNT_ID;
        
        for (int32_t serviceType = 0; serviceType < 10; serviceType++) {
            std::vector<std::string> result = dmsKvSyncE2E_->GetInstance()->GetAllowedDistributeAbilityConnBundlesStub(
                admin, serviceType, accountId);
            EXPECT_TRUE(result.empty());
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_002 end" << std::endl;
}

/**
 * @tc.name: GetAllowedDistributeAbilityConnBundlesStubTest_003
 * @tc.desc: test GetAllowedDistributeAbilityConnBundlesStub with different account IDs
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetAllowedDistributeAbilityConnBundlesStubTest_003, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_003 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        AAFwk::Want admin;
        int32_t serviceType = COLLABORATION_SERVICE;
        
        for (int32_t accountId = 0; accountId < 10; accountId++) {
            std::vector<std::string> result = dmsKvSyncE2E_->GetInstance()->GetAllowedDistributeAbilityConnBundlesStub(
                admin, serviceType, accountId);
            EXPECT_TRUE(result.empty());
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_003 end" << std::endl;
}

/**
 * @tc.name: GetAllowedDistributeAbilityConnBundlesStubTest_004
 * @tc.desc: test GetAllowedDistributeAbilityConnBundlesStub with negative account ID
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetAllowedDistributeAbilityConnBundlesStubTest_004, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_004 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        AAFwk::Want admin;
        int32_t serviceType = COLLABORATION_SERVICE;
        int32_t accountId = INVALID_ACCOUNT_BUNDLE_ID;
        
        std::vector<std::string> result = dmsKvSyncE2E_->GetInstance()->GetAllowedDistributeAbilityConnBundlesStub(
            admin, serviceType, accountId);
        EXPECT_TRUE(result.empty());
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_004 end" << std::endl;
}

/**
 * @tc.name: GetAllowedDistributeAbilityConnBundlesStubTest_005
 * @tc.desc: test GetAllowedDistributeAbilityConnBundlesStub with very large account ID
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetAllowedDistributeAbilityConnBundlesStubTest_005, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_005 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        AAFwk::Want admin;
        int32_t serviceType = COLLABORATION_SERVICE;
        int32_t accountId = INT32_MAX;
        
        std::vector<std::string> result = dmsKvSyncE2E_->GetInstance()->GetAllowedDistributeAbilityConnBundlesStub(
            admin, serviceType, accountId);
        EXPECT_TRUE(result.empty());
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_005 end" << std::endl;
}

/**
 * @tc.name: GetAllowedDistributeAbilityConnBundlesStubTest_006
 * @tc.desc: test GetAllowedDistributeAbilityConnBundlesStub with negative service type
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetAllowedDistributeAbilityConnBundlesStubTest_006, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_006 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        AAFwk::Want admin;
        int32_t serviceType = -1;
        int32_t accountId = TEST_ACCOUNT_ID;
        
        std::vector<std::string> result = dmsKvSyncE2E_->GetInstance()->GetAllowedDistributeAbilityConnBundlesStub(
            admin, serviceType, accountId);
        EXPECT_TRUE(result.empty());
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_006 end" << std::endl;
}

/**
 * @tc.name: GetAllowedDistributeAbilityConnBundlesStubTest_007
 * @tc.desc: test GetAllowedDistributeAbilityConnBundlesStub with very large service type
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetAllowedDistributeAbilityConnBundlesStubTest_007, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_007 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        AAFwk::Want admin;
        int32_t serviceType = INT32_MAX;
        int32_t accountId = TEST_ACCOUNT_ID;
        
        std::vector<std::string> result = dmsKvSyncE2E_->GetInstance()->GetAllowedDistributeAbilityConnBundlesStub(
            admin, serviceType, accountId);
        EXPECT_TRUE(result.empty());
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_007 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlTest_001
 * @tc.desc: test IsMDMControl basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(false);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControl();
        EXPECT_EQ(ret, false);
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        ret = dmsKvSyncE2E_->GetInstance()->IsMDMControl();
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlTest_001 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlTest_002
 * @tc.desc: test IsMDMControl with multiple state changes
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlTest_002, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlTest_002 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        for (int i = 0; i < 10; i++) {
            dmsKvSyncE2E_->GetInstance()->SetMdmControl(i % 2 == 0);
            bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControl();
            EXPECT_EQ(ret, i % 2 == 0);
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlTest_002 end" << std::endl;
}

/**
 * @tc.name: QueryMDMControlTest_001
 * @tc.desc: test QueryMDMControl basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, QueryMDMControlTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest QueryMDMControlTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        bool ret = dmsKvSyncE2E_->GetInstance()->QueryMDMControl();
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DmsKvSyncE2ETest QueryMDMControlTest_001 end" << std::endl;
}

/**
 * @tc.name: SetMdmControlTest_001
 * @tc.desc: test SetMdmControl basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, SetMdmControlTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest SetMdmControlTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        EXPECT_EQ(dmsKvSyncE2E_->GetInstance()->IsMDMControl(), true);
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(false);
        EXPECT_EQ(dmsKvSyncE2E_->GetInstance()->IsMDMControl(), false);
    }
    DTEST_LOG << "DmsKvSyncE2ETest SetMdmControlTest_001 end" << std::endl;
}

/**
 * @tc.name: SetMdmControlTest_002
 * @tc.desc: test SetMdmControl with repeated same values
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, SetMdmControlTest_002, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest SetMdmControlTest_002 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        EXPECT_EQ(dmsKvSyncE2E_->GetInstance()->IsMDMControl(), true);
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(false);
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(false);
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(false);
        EXPECT_EQ(dmsKvSyncE2E_->GetInstance()->IsMDMControl(), false);
    }
    DTEST_LOG << "DmsKvSyncE2ETest SetMdmControlTest_002 end" << std::endl;
}

/**
 * @tc.name: SubscriptionAccountTest_001
 * @tc.desc: test SubscriptionAccount basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, SubscriptionAccountTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest SubscriptionAccountTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SubscriptionAccount();
    }
    DTEST_LOG << "DmsKvSyncE2ETest SubscriptionAccountTest_001 end" << std::endl;
}

/**
 * @tc.name: UnsubscriptionAccountTest_001
 * @tc.desc: test UnsubscriptionAccount basic functionality
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, UnsubscriptionAccountTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest UnsubscriptionAccountTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->UnsubscriptionAccount();
    }
    DTEST_LOG << "DmsKvSyncE2ETest UnsubscriptionAccountTest_001 end" << std::endl;
}

/**
 * @tc.name: SubscriptionUnsubscriptionAccountTest_001
 * @tc.desc: test SubscriptionAccount and UnsubscriptionAccount sequence
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, SubscriptionUnsubscriptionAccountTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest SubscriptionUnsubscriptionAccountTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->SubscriptionAccount();
        dmsKvSyncE2E_->GetInstance()->UnsubscriptionAccount();
    }
    DTEST_LOG << "DmsKvSyncE2ETest SubscriptionUnsubscriptionAccountTest_001 end" << std::endl;
}

/**
 * @tc.name: CheckMDMCtrlRuleTest_002
 * @tc.desc: test CheckMDMCtrlRule with various bundle names
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, CheckMDMCtrlRuleTest_002, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest CheckMDMCtrlRuleTest_002 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        std::vector<std::string> bundleNames = {
            "com.example.app1",
            "com.example.app2",
            "com.ohos.system",
            "com.test.bundle"
        };
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        for (const auto& bundleName : bundleNames) {
            bool ret = dmsKvSyncE2E_->GetInstance()->CheckMDMCtrlRule(bundleName);
            EXPECT_EQ(ret, true);
        }
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(false);
        for (const auto& bundleName : bundleNames) {
            bool ret = dmsKvSyncE2E_->GetInstance()->CheckMDMCtrlRule(bundleName);
            EXPECT_EQ(ret, false);
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest CheckMDMCtrlRuleTest_002 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_011
 * @tc.desc: test IsMDMControlWithExemption edge case with maximum length string bundle name
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_011, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_011 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        std::string longBundleName(256, 'a');
        int32_t serviceType = COLLABORATION_SERVICE;
        int32_t accountId = TEST_ACCOUNT_ID;
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(longBundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_011 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_012
 * @tc.desc: test IsMDMControlWithExemption with unicode characters in bundle name
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_012, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_012 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        std::string unicodeBundleName = "com.example.测试应用";
        int32_t serviceType = COLLABORATION_SERVICE;
        int32_t accountId = TEST_ACCOUNT_ID;
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(unicodeBundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_012 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_013
 * @tc.desc: test IsMDMControlWithExemption performance with multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_013, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_013 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        std::string bundleName = "com.example.testapp";
        int32_t serviceType = COLLABORATION_SERVICE;
        int32_t accountId = TEST_ACCOUNT_ID;
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        
        for (int i = 0; i < 100; i++) {
            bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
            EXPECT_EQ(ret, true);
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_013 end" << std::endl;
}

/**
 * @tc.name: GetActiveAccountIdTest_004
 * @tc.desc: test GetActiveAccountId performance with multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetActiveAccountIdTest_004, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetActiveAccountIdTest_004 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        int32_t expectedAccountId = dmsKvSyncE2E_->GetInstance()->GetActiveAccountId();
        
        for (int i = 0; i < 100; i++) {
            int32_t accountId = dmsKvSyncE2E_->GetInstance()->GetActiveAccountId();
            EXPECT_EQ(accountId, expectedAccountId);
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetActiveAccountIdTest_004 end" << std::endl;
}

/**
 * @tc.name: GetAllowedDistributeAbilityConnBundlesStubTest_008
 * @tc.desc: test GetAllowedDistributeAbilityConnBundlesStub performance with multiple calls
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, GetAllowedDistributeAbilityConnBundlesStubTest_008, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_008 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        AAFwk::Want admin;
        int32_t serviceType = COLLABORATION_SERVICE;
        int32_t accountId = TEST_ACCOUNT_ID;
        
        for (int i = 0; i < 100; i++) {
            std::vector<std::string> result = dmsKvSyncE2E_->GetInstance()->GetAllowedDistributeAbilityConnBundlesStub(
                admin, serviceType, accountId);
            EXPECT_TRUE(result.empty());
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest GetAllowedDistributeAbilityConnBundlesStubTest_008 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_014
 * @tc.desc: test IsMDMControlWithExemption with zero account ID
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_014, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_014 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        std::string bundleName = "com.example.testapp";
        int32_t serviceType = COLLABORATION_SERVICE;
        int32_t accountId = 0;
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_014 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_015
 * @tc.desc: test IsMDMControlWithExemption with zero service type
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_015, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_015 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        std::string bundleName = "com.example.testapp";
        int32_t serviceType = 0;
        int32_t accountId = TEST_ACCOUNT_ID;
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_015 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_016
 * @tc.desc: test IsMDMControlWithExemption with boundary account ID values
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_016, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_016 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        std::string bundleName = "com.example.testapp";
        int32_t serviceType = COLLABORATION_SERVICE;
        
        std::vector<int32_t> boundaryAccountIds = {INT32_MIN, -1, 0, 1, INT32_MAX - 1, INT32_MAX};
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        for (int32_t accountId : boundaryAccountIds) {
            bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
            EXPECT_EQ(ret, true);
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_016 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_017
 * @tc.desc: test IsMDMControlWithExemption with boundary service type values
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_017, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_017 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        std::string bundleName = "com.example.testapp";
        int32_t accountId = TEST_ACCOUNT_ID;
        
        std::vector<int32_t> boundaryServiceTypes = {INT32_MIN, -1, 0, 1, INT32_MAX - 1, INT32_MAX};
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        for (int32_t serviceType : boundaryServiceTypes) {
            bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
            EXPECT_EQ(ret, true);
        }
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_017 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_019
 * @tc.desc: test IsMDMControlWithExemption with null-like bundle name characters
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_019, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_019 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        std::string bundleName = "com.example.test\0app";
        int32_t serviceType = COLLABORATION_SERVICE;
        int32_t accountId = TEST_ACCOUNT_ID;
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_019 end" << std::endl;
}

/**
 * @tc.name: IsMDMControlWithExemptionTest_020
 * @tc.desc: test IsMDMControlWithExemption with special characters in bundle name
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsMDMControlWithExemptionTest_020, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_020 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        std::string bundleName = "com.example.test@app#1";
        int32_t serviceType = COLLABORATION_SERVICE;
        int32_t accountId = TEST_ACCOUNT_ID;
        
        dmsKvSyncE2E_->GetInstance()->SetMdmControl(true);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsMDMControlWithExemption(bundleName, serviceType, accountId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsMDMControlWithExemptionTest_020 end" << std::endl;
}

} // namespace DistributedSchedule
} // namespace OHOS