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

#include "distributed_bm_storage_test.h"

#include <thread>
#include "distributed_sched_util.h"
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
constexpr int32_t TASK_ID_1 = 11;
constexpr int32_t TASK_ID_2 = 12;
constexpr size_t BYTESTREAM_LENGTH = 100;
constexpr uint8_t ONE_BYTE = '6';
}

void DistributedBmStorageTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedBmStorageTest::SetUpTestCase" << std::endl;
}

void DistributedBmStorageTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedBmStorageTest::TearDownTestCase" << std::endl;
}

void DistributedBmStorageTest::SetUp()
{
    DistributedSchedUtil::MockPermission();
    dmsBmStorage_ = std::make_shared<DmsBmStorage>();
    DTEST_LOG << "DistributedBmStorageTest::SetUp" << std::endl;
}

void DistributedBmStorageTest::TearDown()
{
    DTEST_LOG << "DistributedBmStorageTest::TearDown" << std::endl;
}


std::shared_ptr<DmsBmStorage> DistributedBmStorageTest::GetDmsBmStorage()
{
    if (dmsBmStorage_ == nullptr) {
        dmsBmStorage_ = std::make_unique<DmsBmStorage>();
    }
    return dmsBmStorage_;
}

/**
 * @tc.name: InitTest_001
 * @tc.desc: test init DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, SaveStorageDistributeInfo_001, TestSize.Level0)
{
    DTEST_LOG << "DistributedBmStorageTest SaveStorageDistributeInfo_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        const std::string bundleName = "NonexistentName";
        bool ret = dmsBmStorage_->GetInstance()->SaveStorageDistributeInfo(bundleName);
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DistributedBmStorageTest SaveStorageDistributeInfo_001 end" << std::endl;
}

/**
 * @tc.name: DeleteStorageDistributeInfoTest_001
 * @tc.desc: test insert DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, DeleteStorageDistributeInfoTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest DeleteStorageDistributeInfoTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        const std::string bundleName = "NonexistentName";
        bool ret = dmsBmStorage_->GetInstance()->SaveStorageDistributeInfo(bundleName);
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DistributedBmStorageTest DeleteStorageDistributeInfoTest_001 end" << std::endl;
}

/**
 * @tc.name: GetStorageDistributeInfo_001
 * @tc.desc: test insert DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, GetStorageDistributeInfo_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest GetStorageDistributeInfo_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        const std::string bundleName = "NonexistentName";
        int32_t userId = 0;
        DmsBundleInfo info;
        bool ret = dmsBmStorage_->GetInstance()->GetStorageDistributeInfo("", bundleName, info);
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DistributedBmStorageTest GetStorageDistributeInfo_001 end" << std::endl;
}

/**
 * @tc.name: GetDistributedBundleNameTest_001
 * @tc.desc: test insert DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, GetDistributedBundleNameTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest GetDistributedBundleNameTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        std::string bundleName = "";
        int32_t userId = 0;
        bool ret = dmsBmStorage_->GetInstance()->GetDistributedBundleName("", userId, bundleName);
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DistributedBmStorageTest GetDistributedBundleNameTest_001 end" << std::endl;
}

/**
 * @tc.name: GetBundleIdTest_001
 * @tc.desc: test delete DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, GetBundleIdTest_001, TestSize.Level0)
{
    DTEST_LOG << "DistributedBmStorageTest GetBundleIdTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        const std::string &bundleName = "NonexistentName";
        uint16_t accessTokenId = 0;
        bool ret = dmsBmStorage_->GetInstance()->GetBundleNameId(bundleName, accessTokenId);
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DistributedBmStorageTest GetBundleIdTest_001 end" << std::endl;
}

/**
 * @tc.name: UpdateDistributedDataTest_001
 * @tc.desc: test delete DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, UpdateDistributedDataTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest UpdateDistributedDataTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        dmsBmStorage_->GetInstance()->UpdateDistributedData();
    }
    DTEST_LOG << "DistributedBmStorageTest UpdateDistributedDataTest_001 end" << std::endl;
}

/**
 * @tc.name: PullOtherDistributedDataTest_001
 * @tc.desc: test delete DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, PullOtherDistributedDataTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest PullOtherDistributedDataTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        int32_t userId = 0;
        int32_t ret = dmsBmStorage_->GetInstance()->PullOtherDistributedData();
        EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    }
    DTEST_LOG << "DistributedBmStorageTest PullOtherDistributedDataTest_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS