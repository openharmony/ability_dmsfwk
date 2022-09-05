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

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
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
} // DistributedSchedule
} // namespace OHOS