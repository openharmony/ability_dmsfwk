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

#include "distributed_mission_info_test.h"
#define private public
#include "mission/distributed_mission_info.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
void DistributedMissionInfoTest::SetUpTestCase()
{
}

void DistributedMissionInfoTest::TearDownTestCase()
{
}

void DistributedMissionInfoTest::SetUp()
{
}

void DistributedMissionInfoTest::TearDown()
{
}

/**
 * @tc.name: testMarshalling001
 * @tc.desc: write data to parcel
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testMarshalling001, TestSize.Level1)
{
    DstbMissionInfo dstbMissionInfo;
    Parcel data;
    auto ret = dstbMissionInfo.Marshalling(data);
    EXPECT_EQ(ret, true);
}

/**
 * @tc.name: testToString001
 * @tc.desc: print a missionInfo
 * @tc.type: FUNC
 * @tc.require: I5O2P9
 */
HWTEST_F(DistributedMissionInfoTest, testToString001, TestSize.Level1)
{
    DstbMissionInfo dstbMissionInfo;
    auto ret = dstbMissionInfo.ToString();
    EXPECT_NE(ret, "");
}
} // DistributedSchedule
} // namespace OHOS