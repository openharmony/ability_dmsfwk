/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "gtest/gtest.h"

#include <thread>

#include "dtbschedmgr_device_info_storage.h"

using namespace std;
using namespace testing;
using namespace testing::ext;

namespace {
const std::string NETWORKID = "1234568";
constexpr int32_t SLEEP_TIME = 2000;
}

namespace OHOS {
namespace DistributedSchedule {
class DMSNetworkAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void DMSNetworkAdapterTest::SetUpTestCase()
{
}

void DMSNetworkAdapterTest::TearDownTestCase()
{
}

void DMSNetworkAdapterTest::SetUp()
{
}

void DMSNetworkAdapterTest::TearDown()
{
}

/**
 * @tc.name: testGetUdidByNetworkId001
 * @tc.desc: testGetUdidByNetworkId empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUdidByNetworkId001, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUdidByNetworkId("");
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: testGetUdidByNetworkId002
 * @tc.desc: testGetUdidByNetworkId not empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUdidByNetworkId002, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(NETWORKID);
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: testGetUuidByNetworkId001
 * @tc.desc: testGetUuidByNetworkId empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUuidByNetworkId001, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUuidByNetworkId("");
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: testGetUuidByNetworkId001
 * @tc.desc: testGetUuidByNetworkId not empty
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUuidByNetworkId002, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUuidByNetworkId(NETWORKID);
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: Init
 * @tc.desc: testInit
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testInit001, TestSize.Level3)
{
    DnetworkAdapter::GetInstance()->Init();
    bool res = DtbschedmgrDeviceInfoStorage::GetInstance().Init();
    std::this_thread::sleep_for(std::chrono::milliseconds(SLEEP_TIME));
    EXPECT_EQ(res, true);
}

/**
 * @tc.name: testGetUdidByNetworkId003
 * @tc.desc: testGetUdidByNetworkId not empty with init
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUdidByNetworkId003, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUdidByNetworkId(NETWORKID);
    EXPECT_EQ(res, "");
}

/**
 * @tc.name: testGetUuidByNetworkId003
 * @tc.desc: testGetUuidByNetworkId not empty with init
 * @tc.type: FUNC
 */
HWTEST_F(DMSNetworkAdapterTest, testGetUuidByNetworkId003, TestSize.Level3)
{
    std::string res = DnetworkAdapter::GetInstance()->GetUuidByNetworkId(NETWORKID);
    EXPECT_EQ(res, "");
}
} // namespace DistributedSchedule
} // namespace OHOS