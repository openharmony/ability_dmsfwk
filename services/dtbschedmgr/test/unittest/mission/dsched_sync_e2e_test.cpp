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
 * @tc.name: SetSyncRecordTest_001
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, SetSyncRecordTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest SetSyncRecordTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        const std::string networkId = "123";
        dmsKvSyncE2E_->GetInstance()->SetSyncRecord(networkId);
    }
    DTEST_LOG << "DmsKvSyncE2ETest SetSyncRecordTest_001 end" << std::endl;
}

/**
 * @tc.name: ClearSyncRecordTest_001
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, ClearSyncRecordTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest ClearSyncRecordTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        const std::string networkId = "123";
        dmsKvSyncE2E_->GetInstance()->ClearSyncRecord(networkId);
    }
    DTEST_LOG << "DmsKvSyncE2ETest ClearSyncRecordTest_001 end" << std::endl;
}

/**
 * @tc.name: IsSynchronizedTest_001
 * @tc.desc: test insert DmsKvSyncE2E
 * @tc.type: FUNC
 */
HWTEST_F(DmsKvSyncE2ETest, IsSynchronizedTest_001, TestSize.Level1)
{
    DTEST_LOG << "DmsKvSyncE2ETest IsSynchronizedTest_001 start" << std::endl;
    ASSERT_NE(dmsKvSyncE2E_, nullptr);
    auto dmsKvSyncE2E = GetDmsKvSyncE2E();
    EXPECT_NE(dmsKvSyncE2E, nullptr);
    if (dmsKvSyncE2E != nullptr) {
        const std::string networkId = "123";
        dmsKvSyncE2E_->GetInstance()->SetSyncRecord(networkId);
        bool ret = dmsKvSyncE2E_->GetInstance()->IsSynchronized(networkId);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest IsSynchronizedTest_001 end" << std::endl;
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
        bool ret = dmsKvSyncE2E_->GetInstance()->CheckBundleContinueConfig(bundleName);
        EXPECT_EQ(ret, true);
    }
    DTEST_LOG << "DmsKvSyncE2ETest CheckBundleContinueConfigTest_001 end" << std::endl;
}

} // namespace DistributedSchedule
} // namespace OHOS
