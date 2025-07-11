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
 * @tc.name: CheckCtrlRuleTest_002
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, CheckCtrlRuleTest_002, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest CheckCtrlRuleTest_002 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        dmsKvSyncE2E_->GetInstance()->isForbidSendAndRecv_ = true;
        bool ret = dmsKvSyncE2E_->GetInstance()->CheckCtrlRule();
        EXPECT_EQ(ret, true);
        
        dmsKvSyncE2E_->GetInstance()->isCfgDevices_ = true;
        ret = dmsKvSyncE2E_->GetInstance()->CheckCtrlRule();
        EXPECT_EQ(ret, false);
        
        dmsKvSyncE2E_->GetInstance()->isForbidSendAndRecv_ = false;
        ret = dmsKvSyncE2E_->GetInstance()->CheckCtrlRule();
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest CheckCtrlRuleTest_002 end" << std::endl;
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
        dmsKvSyncE2E_->GetInstance()->isCfgDevices_ = false;
        bool ret = dmsKvSyncE2E_->GetInstance()->CheckBundleContinueConfig(bundleName);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest CheckBundleContinueConfigTest_001 end" << std::endl;
}

/**
 * @tc.name: CheckBundleContinueConfigTest_002
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, CheckBundleContinueConfigTest_002, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest CheckBundleContinueConfigTest_002 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        const std::string bundleName = "123";
        dmsKvSyncE2E_->GetInstance()->isCfgDevices_ = true;
        dmsKvSyncE2E_->GetInstance()->whiteList_.clear();
        bool ret = dmsKvSyncE2E_->GetInstance()->CheckBundleContinueConfig(bundleName);
        EXPECT_EQ(ret, false);

        dmsKvSyncE2E_->GetInstance()->isCfgDevices_ = true;
        dmsKvSyncE2E_->GetInstance()->whiteList_.clear();
        dmsKvSyncE2E_->GetInstance()->whiteList_.push_back(bundleName);
        dmsKvSyncE2E_->GetInstance()->whiteList_.push_back(bundleName);
        ret = dmsKvSyncE2E_->GetInstance()->CheckBundleContinueConfig(bundleName);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest CheckBundleContinueConfigTest_002 end" << std::endl;
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
} // namespace DistributedSchedule
} // namespace OHOS
