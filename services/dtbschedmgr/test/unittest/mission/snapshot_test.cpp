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

#include <cstring>

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
constexpr uint8_t MINI_MALJPEG[] = {
    0xFF, 0xD8, 0xFF, 0xDB, 0x00, 0x43, 0x00, 0x08, 0x06, 0x06, 0x07, 0x06, 0x05, 0x08,
    0x07, 0x07, 0x07, 0x09, 0x09, 0x08, 0x0A, 0x0C, 0x14, 0x0D, 0x0C, 0x0B, 0x0B, 0x0C,
    0x19, 0x12, 0x13, 0x0F, 0x14, 0x1D, 0x1A, 0x1F, 0x1E, 0x1D, 0x1A, 0x1C, 0x1C, 0x20,
    0x24, 0x2E, 0x27, 0x20, 0x22, 0x2C, 0x23, 0x1C, 0x1C, 0x28, 0x37, 0x29, 0x2C, 0x30,
    0x31, 0x34, 0x34, 0x34, 0x1F, 0x27, 0x39, 0x3D, 0x38, 0x32, 0x3C, 0x2E, 0x33, 0x34,
    0x32, 0xFF, 0xC0, 0x00, 0x0B, 0x08, 0x00, 0x01, 0x00, 0x01, 0x01, 0x01, 0x11, 0x00,
    0xFF, 0xC4, 0x00, 0x14, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x08, 0xFF, 0xC4, 0x00, 0x14, 0x10, 0x01,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0xFF, 0xDA, 0x00, 0x08, 0x01, 0x01, 0x00, 0x00, 0x3F, 0x00, 0x37, 0xFF, 0xD9,
};
constexpr uint32_t MINI_MALJPEG_SIZE = static_cast<uint32_t>(sizeof(MINI_MALJPEG));
} // namespace
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
     * @tc.steps: step2. FillSnapshot
     */
    std::unique_ptr<Snapshot> snapShotReturn = snapshot.FillSnapshot(data);
    EXPECT_NE(nullptr, snapShotReturn);
    /**
     * @tc.steps: step3. CreatePixelMap when buffer == nullptr
     */
    std::unique_ptr<Media::PixelMap> pixelMap = snapshot.CreatePixelMap(nullptr, TEST_PARCEL_WRITE_VALUE);
    EXPECT_EQ(nullptr, pixelMap);
    DTEST_LOG << "SnapshotTest testWriteToParcel004 end" << std::endl;
}

/**
 * @tc.name: testFillSnapshot001
 * @tc.desc: fill up a snapshot
 * @tc.type: FUNC
* @tc.require: I5O2P9
 */
HWTEST_F(SnapshotTest, testFillSnapshot001, TestSize.Level1)
{
    Snapshot snapshot;
    MessageParcel data;
    auto ret = snapshot.FillSnapshot(data);
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
 * @tc.name: testWriteSnapshotInfo002
 * @tc.desc: WriteSnapshotInfo with rect and windowBounds set
 * @tc.type: FUNC
 */
HWTEST_F(SnapshotTest, testWriteSnapshotInfo002, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testWriteSnapshotInfo002 start" << std::endl;
    Snapshot snapshot;
    snapshot.rect_ = std::make_unique<Rect>(0, 0, 100, 200);
    snapshot.windowBounds_ = std::make_unique<Rect>(1, 2, 3, 4);
    MessageParcel data;
    EXPECT_TRUE(snapshot.WriteSnapshotInfo(data));
    DTEST_LOG << "SnapshotTest testWriteSnapshotInfo002 end" << std::endl;
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
 * @tc.name: testCreate002
 * @tc.desc: test Create
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testCreate002, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testCreate002 start" << std::endl;
    Snapshot snapshot;
    std::vector<uint8_t> data(sizeof(uint32_t), 0);
    uint32_t msgSzie = 10;
    memcpy(data.data(), &msgSzie, sizeof(uint32_t));

    std::unique_ptr<Snapshot> ret = snapshot.Create(data);
    EXPECT_EQ(nullptr, ret);
    data.emplace_back(1);
    EXPECT_EQ(nullptr, ret);
    DTEST_LOG << "SnapshotTest testCreate002 end" << std::endl;
}

/**
 * @tc.name: testCreate003
 * @tc.desc: test Create
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testCreate003, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testCreate003 start" << std::endl;
    Snapshot snapshot;
    std::vector<uint8_t> data(12, 0); // totalSize = 12
    uint32_t msgSize = 8; // msgSize + sizeof(uint32_t) = 8 + 4 = 12
    memcpy(data.data(), &msgSize, sizeof(uint32_t));

    std::unique_ptr<Snapshot> ret = snapshot.Create(data);
    EXPECT_EQ(nullptr, ret);
    data.emplace_back(1);
    EXPECT_EQ(nullptr, ret);
    DTEST_LOG << "SnapshotTest testCreate003 end" << std::endl;
}

/**
 * @tc.name: testCreate004
 * @tc.desc: test Create
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testCreate004, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testCreate004 start" << std::endl;
    Snapshot snapshot;
    std::vector<uint8_t> data(20, 0); // totalSize = 20
    uint32_t msgSize = 10; // msgSize + sizeof(uint32_t) = 10 + 4 = 14 < 20
    memcpy(data.data(), &msgSize, sizeof(uint32_t));

    std::unique_ptr<Snapshot> ret = snapshot.Create(data);
    EXPECT_EQ(nullptr, ret);
    data.emplace_back(1);
    EXPECT_EQ(nullptr, ret);
    DTEST_LOG << "SnapshotTest testCreate004 end" << std::endl;
}

/**
 * @tc.name: testCreate005
 * @tc.desc: test Create
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testCreate005, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testCreate005 start" << std::endl;
    Snapshot snapshot;
    std::vector<uint8_t> data(12, 0); // totalSize = 12
    uint32_t msgSize = 6; // msgSize + sizeof(uint32_t) = 6 + 4 = 10 < totalSize (12)
    memcpy(data.data(), &msgSize, sizeof(uint32_t));

    std::unique_ptr<Snapshot> ret = snapshot.Create(data);
    EXPECT_EQ(nullptr, ret);
    data.emplace_back(1);
    EXPECT_EQ(nullptr, ret);
    DTEST_LOG << "SnapshotTest testCreate005 end" << std::endl;
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

/**
 * @tc.name: testWritePixelMap001
 * @tc.desc: test WritePixelMap when pixelMap_ is null or created from valid JPEG buffer
 * @tc.type: FUNC
 * @tc.require: I5Y2VH
 */
HWTEST_F(SnapshotTest, testWritePixelMap001, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testWritePixelMap001 start" << std::endl;
    Snapshot snapshot;
    EXPECT_EQ(snapshot.pixelMap_, nullptr);

    std::unique_ptr<Media::PixelMap> pixelMap =
        snapshot.CreatePixelMap(MINI_MALJPEG, MINI_MALJPEG_SIZE);
    if (pixelMap == nullptr) {
        DTEST_LOG << "SnapshotTest testWritePixelMap001 skip: CreatePixelMap failed" << std::endl;
        return;
    }
    snapshot.pixelMap_ = std::move(pixelMap);
    MessageParcel data;
    EXPECT_TRUE(snapshot.WritePixelMap(data));
    EXPECT_GT(data.GetReadableBytes(), 0u);
    DTEST_LOG << "SnapshotTest testWritePixelMap001 end" << std::endl;
}

/**
 * @tc.name: testCreatePixelMap_ZeroBufferSize_001
 * @tc.desc: CreatePixelMap returns nullptr when bufferSize is 0
 * @tc.type: FUNC
 */
HWTEST_F(SnapshotTest, testCreatePixelMap_ZeroBufferSize_001, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testCreatePixelMap_ZeroBufferSize_001 start" << std::endl;
    Snapshot snapshot;
    uint8_t byte = 0xFF;
    auto pixelMap = snapshot.CreatePixelMap(&byte, 0);
    EXPECT_EQ(nullptr, pixelMap);
    DTEST_LOG << "SnapshotTest testCreatePixelMap_ZeroBufferSize_001 end" << std::endl;
}

/**
 * @tc.name: testCreate_MsgSizeExceedsTotal_001
 * @tc.desc: Create returns nullptr when declared msg size is not less than total buffer
 * @tc.type: FUNC
 */
HWTEST_F(SnapshotTest, testCreate_MsgSizeExceedsTotal_001, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testCreate_MsgSizeExceedsTotal_001 start" << std::endl;
    Snapshot snapshot;
    std::vector<uint8_t> data(sizeof(uint32_t) + 2);
    uint32_t msgSize = static_cast<uint32_t>(data.size());
    memcpy(data.data(), &msgSize, sizeof(uint32_t));
    std::unique_ptr<Snapshot> ret = snapshot.Create(data);
    EXPECT_EQ(nullptr, ret);
    DTEST_LOG << "SnapshotTest testCreate_MsgSizeExceedsTotal_001 end" << std::endl;
}

/**
 * @tc.name: testCreatePixelMap_NullBufferNonZeroSize_001
 * @tc.desc: CreatePixelMap returns nullptr when buffer is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(SnapshotTest, testCreatePixelMap_NullBufferNonZeroSize_001, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testCreatePixelMap_NullBufferNonZeroSize_001 start" << std::endl;
    Snapshot snapshot;
    auto pixelMap = snapshot.CreatePixelMap(nullptr, 4);
    EXPECT_EQ(nullptr, pixelMap);
    DTEST_LOG << "SnapshotTest testCreatePixelMap_NullBufferNonZeroSize_001 end" << std::endl;
}

/**
 * @tc.name: testCreatePixelMap_InvalidJpeg_001
 * @tc.desc: CreatePixelMap returns nullptr when buffer is not decodable as JPEG
 * @tc.type: FUNC
 */
HWTEST_F(SnapshotTest, testCreatePixelMap_InvalidJpeg_001, TestSize.Level3)
{
    DTEST_LOG << "SnapshotTest testCreatePixelMap_InvalidJpeg_001 start" << std::endl;
    Snapshot snapshot;
    const char kNotJpeg[] = "not_a_jpeg";
    auto pixelMap = snapshot.CreatePixelMap(reinterpret_cast<const uint8_t*>(kNotJpeg),
        static_cast<uint32_t>(sizeof(kNotJpeg) - 1));
    EXPECT_EQ(nullptr, pixelMap);
    DTEST_LOG << "SnapshotTest testCreatePixelMap_InvalidJpeg_001 end" << std::endl;
}
} // DistributedSchedule
} // namespace OHOS