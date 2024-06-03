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

void DistributedBmStorageTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DistributedBmStorageTest::SetUpTestCase" << std::endl;
}

void DistributedBmStorageTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
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
        uint16_t bundleNameId = 0;
        bool ret = dmsBmStorage_->GetInstance()->GetBundleNameId(bundleName, bundleNameId);
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
 * @tc.name: CloudSyncTest_001
 * @tc.desc: test delete DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, CloudSyncTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest CloudSyncTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        dmsBmStorage_->GetInstance()->CloudSync();
    }
    DTEST_LOG << "DistributedBmStorageTest CloudSyncTest_001 end" << std::endl;
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
        std::vector<std::string> networkIdList = DtbschedmgrDeviceInfoStorage::GetInstance().GetNetworkIdList();
        int32_t ret = dmsBmStorage_->GetInstance()->PullOtherDistributedData(networkIdList);
        EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    }
    DTEST_LOG << "DistributedBmStorageTest PullOtherDistributedDataTest_001 end" << std::endl;
}

/**
 * @tc.name: PushOtherDistributedDataDataTest_001
 * @tc.desc: test delete DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, PushOtherDistributedDataDataTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest PushOtherDistributedDataDataTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        std::vector<std::string> networkIdList = DtbschedmgrDeviceInfoStorage::GetInstance().GetNetworkIdList();
        int32_t ret = dmsBmStorage_->GetInstance()->PushOtherDistributedData(networkIdList);
        EXPECT_EQ(ret, INVALID_REMOTE_PARAMETERS_ERR);
    }
    DTEST_LOG << "DistributedBmStorageTest PushOtherDistributedDataDataTest_001 end" << std::endl;
}

/**
 * @tc.name: GetBundleMgrTest_001
 * @tc.desc: test delete DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, GetBundleMgrTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest GetBundleMgrTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        auto bundleMgr = dmsBmStorage_->GetInstance()->GetBundleMgr();
        EXPECT_NE(bundleMgr, nullptr);
    }
    DTEST_LOG << "DistributedBmStorageTest GetBundleMgrTest_001 end" << std::endl;
}

/**
 * @tc.name: GetContinueTypeTest_001
 * @tc.desc: test delete DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, GetContinueTypeTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest GetContinueTypeTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        std::string networkId;
        std::string bundleName;
        uint8_t continueTypeId = 0;
        std::string ret = dmsBmStorage_->GetInstance()->GetContinueType(networkId, bundleName, continueTypeId);
        EXPECT_EQ(ret, "");
    }
    DTEST_LOG << "DistributedBmStorageTest GetContinueTypeTest_001 end" << std::endl;
}

/**
 * @tc.name: GetAbilityNameTest_001
 * @tc.desc: test delete DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, GetAbilityNameTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest GetAbilityNameTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        std::string networkId;
        std::string bundleName;
        std::string continueType;
        std::string ret = dmsBmStorage_->GetInstance()->GetAbilityName(networkId, bundleName, continueType);
        EXPECT_EQ(ret, "");
    }
    DTEST_LOG << "DistributedBmStorageTest GetAbilityNameTest_001 end" << std::endl;
}

/**
 * @tc.name: GetContinueTypeIdTest_001
 * @tc.desc: test delete DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, GetContinueTypeIdTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest GetContinueTypeIdTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        std::string bundleName;
        std::string abilityName;
        uint8_t continueTypeId = 0;
        bool ret = dmsBmStorage_->GetInstance()->GetContinueTypeId(bundleName, abilityName, continueTypeId);
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DistributedBmStorageTest GetContinueTypeIdTest_001 end" << std::endl;
}

/**
 * @tc.name: GetContinueEventInfoTest_001
 * @tc.desc: test delete DistributedBmStorage
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBmStorageTest, GetContinueEventInfoTest_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedBmStorageTest GetContinueEventInfoTest_001 start" << std::endl;
    auto distributedDataStorage = GetDmsBmStorage();
    EXPECT_NE(distributedDataStorage, nullptr);
    if (distributedDataStorage != nullptr) {
        std::string networkId;
        std::string bundleName;
        std::string continueType;
        ContinueEventInfo continueEventInfo;
        bool ret = dmsBmStorage_->GetInstance()->GetContinueEventInfo(networkId, bundleName,
            continueType, continueEventInfo);
        EXPECT_EQ(ret, false);
    }
    DTEST_LOG << "DistributedBmStorageTest GetContinueEventInfoTest_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS