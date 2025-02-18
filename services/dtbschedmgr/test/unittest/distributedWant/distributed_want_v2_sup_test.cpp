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

#include <gtest/gtest.h>

#include "string_wrapper.h"
#include "base_obj.h"
#include "bool_wrapper.h"
#include "int_wrapper.h"
#include "float_wrapper.h"
#include "long_wrapper.h"
#include "array_wrapper.h"

#include "distributed_operation.h"
#include "distributed_want_v2.h"
#include "want.h"
#include "want_params.h"

using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS;
using OHOS::Parcel;
using OHOS::AppExecFwk::ElementName;

namespace OHOS {
namespace DistributedSchedule {
class DistributedWantV2SupTest : public testing::Test {
public:
    DistributedWantV2SupTest()
    {}
    ~DistributedWantV2SupTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DistributedWantV2SupTest::SetUpTestCase(void)
{}

void DistributedWantV2SupTest::TearDownTestCase(void)
{}

void DistributedWantV2SupTest::SetUp(void)
{
}

void DistributedWantV2SupTest::TearDown(void)
{}

/**
 * @tc.number: DistributedSchedule_DistributedWantV2_CanReadFromJson_0100
 * @tc.name: distributedwantV2
 * @tc.desc: Verifying CanReadFromJson to distributedwantV2.
 */
HWTEST_F(DistributedWantV2SupTest, DistributedSchedule_DistributedWantV2_CanReadFromJson_0100,
    Function | MediumTest | Level3)
{
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    nlohmann::json wantJson;
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["deviceId"] = 1;
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["bundleName"] = 1;
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["abilityName"] = 1;
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["uri"] = 1;
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["type"] = 1;
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["flags"] = "test";
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["action"] = 1;
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["parameters"] = 1;
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["entities"] = 1;
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));
}

/**
 * @tc.number: DistributedSchedule_DistributedWantV2_CanReadFromJson_0200
 * @tc.name: distributedwantV2
 * @tc.desc: Verifying CanReadFromJson to distributedwantV2.
 */
HWTEST_F(DistributedWantV2SupTest, DistributedSchedule_DistributedWantV2_CanReadFromJson_0200,
    Function | MediumTest | Level3)
{
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    nlohmann::json wantJson;
    wantJson["deviceId"] = "deviceId";
    wantJson["bundleName"] = 1;
    wantJson["abilityName"] = 1;
    wantJson["uri"] = 1;
    wantJson["type"] = 1;
    wantJson["flags"] = "test";
    wantJson["action"] = 1;
    wantJson["parameters"] = 1;
    wantJson["entities"] = 1;
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["bundleName"] = "bundleName";
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["abilityName"] = "abilityName";
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["uri"] = "uri";
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["type"] = "type";
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["flags"] = 1u;
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["action"] = "action";
    EXPECT_FALSE(dwant->CanReadFromJson(wantJson));

    wantJson["parameters"] = "parameters";
    EXPECT_TRUE(dwant->CanReadFromJson(wantJson));
}

/**
 * @tc.number: DistributedSchedule_DistributedWantV2_ReadFromJson_0100
 * @tc.name: distributedwantV2
 * @tc.desc: Verifying ReadFromJson to distributedwantV2.
 */
HWTEST_F(DistributedWantV2SupTest, DistributedSchedule_DistributedWantV2_ReadFromJson_0100,
    Function | MediumTest | Level3)
{
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    nlohmann::json wantJson;
    EXPECT_FALSE(dwant->ReadFromJson(wantJson));

    wantJson["deviceId"] = "deviceId";
    wantJson["bundleName"] = "bundleName";
    wantJson["abilityName"] = "abilityName";
    wantJson["uri"] = "uri";
    wantJson["type"] = "type";
    wantJson["flags"] = 1u;
    wantJson["action"] = "action";
    wantJson["parameters"] = "parameters";
    nlohmann::json testJson;
    wantJson["entities"] = testJson;
    EXPECT_TRUE(dwant->ReadFromJson(wantJson));

    wantJson["entities"].emplace_back("test");
    EXPECT_TRUE(dwant->ReadFromJson(wantJson));
}

/**
 * @tc.number: DistributedSchedule_DistributedWantV2_FromString_0100
 * @tc.name: distributedwantV2
 * @tc.desc: Verifying FromString to distributedwantV2.
 */
HWTEST_F(DistributedWantV2SupTest, DistributedSchedule_DistributedWantV2_FromString_0100,
    Function | MediumTest | Level3)
{
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    std::string test;
    EXPECT_EQ(dwant->FromString(test), nullptr);

    test = "test";
    EXPECT_EQ(dwant->FromString(test), nullptr);

    nlohmann::json wantJson;
    wantJson["test"] = "test";
    test = wantJson.dump();
    EXPECT_EQ(dwant->FromString(test), nullptr);

    wantJson.clear();
    wantJson["deviceId"] = "deviceId";
    wantJson["bundleName"] = "bundleName";
    wantJson["abilityName"] = "abilityName";
    wantJson["uri"] = "uri";
    wantJson["type"] = "type";
    wantJson["flags"] = 1u;
    wantJson["action"] = "action";
    wantJson["parameters"] = "parameters";
    nlohmann::json testJson;
    testJson.emplace_back("test");
    wantJson["entities"] = testJson;

    test = wantJson.dump();
    EXPECT_NE(dwant->FromString(test), nullptr);
}
}
}