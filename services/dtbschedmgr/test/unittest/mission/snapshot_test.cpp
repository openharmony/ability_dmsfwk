/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "snapshot_test.h"
#define private public
#include "mission/snapshot.h"
#undef private
#include "parcel_helper.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "Snapshot";
constexpr size_t TEST_PARCEL_WRITE_VALUE = 1;
}
void SnapshotTest::SetUpTestCase()
{
}

void SnapshotTest::TearDownTestCase()
{
}

void SnapshotTest::SetUp()
{
}

void SnapshotTest::TearDown()
{
}

/**
 * @tc.name: testWriteToParcel001
 * @tc.desc: write data to parcel
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(SnapshotTest, testWriteToParcel001, TestSize.Level1)
{
    Snapshot snapshot;
    MessageParcel data;
    auto ret = snapshot.WriteToParcel(data);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: testWriteToParcel002
 * @tc.desc: test WriteToParcel when rect_ is not nullptr
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testWriteToParcel002, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testWriteToParcel002 start" << std::endl;
    Snapshot snapshot;
    MessageParcel data;
    snapshot.rect_ = std::make_unique<Rect>(0, 0, 0, 0);
    bool ret = snapshot.WriteToParcel(data);
    EXPECT_TRUE(ret);
    DTEST_LOG << "SnapshotTest testWriteToParcel002 end" << std::endl;
}

/**
 * @tc.name: testWriteToParcel003
 * @tc.desc: test WriteToParcel when windowBounds_ is not nullptr
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testWriteToParcel003, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testWriteToParcel003 start" << std::endl;
    Snapshot snapshot;
    MessageParcel data;
    snapshot.rect_ = std::make_unique<Rect>(0, 0, 0, 0);
    snapshot.windowBounds_ = std::make_unique<Rect>(0, 0, 0, 0);
    bool ret = snapshot.WriteToParcel(data);
    EXPECT_TRUE(ret);
    DTEST_LOG << "SnapshotTest testWriteToParcel003 end" << std::endl;
}

/**
 * @tc.name: testWriteToParcel004
 * @tc.desc: test WriteToParcel when pixelMap_ is not nullptr
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testWriteToParcel004, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testWriteToParcel004 start" << std::endl;
    Snapshot snapshot;
    MessageParcel data;
    snapshot.rect_ = std::make_unique<Rect>(0, 0, 0, 0);
    snapshot.windowBounds_ = std::make_unique<Rect>(0, 0, 0, 0);
    uint8_t buffer = (uint8_t)TEST_PARCEL_WRITE_VALUE;
    snapshot.pixelMap_ = snapshot.CreatePixelMap(&buffer, TEST_PARCEL_WRITE_VALUE);
    /**
     * @tc.steps: step1. WriteToParcel when pixelMap_ is not nullptr
     */
    bool ret = snapshot.WriteToParcel(data);
    EXPECT_TRUE(ret);
    /**
     * @tc.steps: step2. FillSnapShot
     */
    std::unique_ptr<Snapshot> snapShotReturn = snapshot.FillSnapShot(data);
    EXPECT_NE(nullptr, snapShotReturn);
    /**
     * @tc.steps: step3. CreatePixelMap when buffer == nullptr
     */
    std::unique_ptr<Media::PixelMap> pixelMap = snapshot.CreatePixelMap(nullptr, TEST_PARCEL_WRITE_VALUE);
    EXPECT_EQ(nullptr, pixelMap);
    DTEST_LOG << "SnapshotTest testWriteToParcel004 end" << std::endl;
}

/**
 * @tc.name: testFillSnapShot001
 * @tc.desc: fill up a snapshot
 * @tc.type: FUNC
* @tc.require: I5O2P9
 */
HWTEST_F(SnapshotTest, testFillSnapShot001, TestSize.Level1)
{
    Snapshot snapshot;
    MessageParcel data;
    auto ret = snapshot.FillSnapShot(data);
    EXPECT_EQ(ret, nullptr);
}

/**
 * @tc.name: testWriteSnapshotInfo001
 * @tc.desc: write a snapshot info
 * @tc.type: FUNC
* @tc.require: I5O2P9
 */
HWTEST_F(SnapshotTest, testWriteSnapshotInfo001, TestSize.Level1)
{
    Snapshot snapshot;
    MessageParcel data;
    auto ret = snapshot.WriteSnapshotInfo(data);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: testCreate001
 * @tc.desc: test Create when buffer is nullptr
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testCreate001, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testCreate001 start" << std::endl;
    Snapshot snapshot;
    std::vector<uint8_t> data;
    /**
     * @tc.steps: step1. Create when data is empty;
     */
    std::unique_ptr<Snapshot> ret = snapshot.Create(data);
    EXPECT_EQ(nullptr, ret);
    /**
     * @tc.steps: step2. Create when data is not empty;
     */
    data.emplace_back(1);
    EXPECT_EQ(nullptr, ret);
    DTEST_LOG << "SnapshotTest testCreate001 end" << std::endl;
}

/**
 * @tc.name: testGetCreatedTime001
 * @tc.desc: test GetCreatedTime
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testGetCreatedTime001, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testGetCreatedTime001 start" << std::endl;
    Snapshot snapshot;
    int64_t ret = snapshot.GetCreatedTime();
    EXPECT_EQ(0, ret);
    DTEST_LOG << "SnapshotTest testGetCreatedTime001 end" << std::endl;
}

/**
 * @tc.name: testGetLastAccessTime001
 * @tc.desc: test GetLastAccessTime
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testGetLastAccessTime001, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testGetCreatedTime001 start" << std::endl;
    Snapshot snapshot;
    int64_t ret = snapshot.GetLastAccessTime();
    EXPECT_EQ(0, ret);
    DTEST_LOG << "SnapshotTest testGetLastAccessTime001 end" << std::endl;
}

/**
 * @tc.name: testUpdateLastAccessTime001
 * @tc.desc: test UpdateLastAccessTime
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testUpdateLastAccessTime001, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testUpdateLastAccessTime001 start" << std::endl;
    Snapshot snapshot;
    snapshot.UpdateLastAccessTime(TEST_PARCEL_WRITE_VALUE);
    EXPECT_EQ((int64_t)TEST_PARCEL_WRITE_VALUE, snapshot.lastAccessTime_);
    DTEST_LOG << "SnapshotTest testUpdateLastAccessTime001 end" << std::endl;
}
} // DistributedSchedule
} // namespace OHOS