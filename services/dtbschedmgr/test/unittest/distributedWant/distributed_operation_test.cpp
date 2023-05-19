/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#define private public
#define protected public
#include "distributed_operation.h"
#include "distributed_operation_builder.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::DistributedSchedule;
using OHOS::Parcel;
using Uri = OHOS::Uri;
class DistributedOperationBaseTest : public testing::Test {
public:
    DistributedOperationBaseTest()
    {}
    ~DistributedOperationBaseTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<DistributedOperationBuilder> operationbuilder_ = nullptr;
};

void DistributedOperationBaseTest::SetUpTestCase(void)
{}

void DistributedOperationBaseTest::TearDownTestCase(void)
{}

void DistributedOperationBaseTest::SetUp(void)
{
    operationbuilder_ = std::make_shared<DistributedOperationBuilder>();
}

void DistributedOperationBaseTest::TearDown(void)
{}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetAbilityName_0100
 * @tc.name: WithAbilityName/GetAbilityName.
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetAbilityName_0100, Function | MediumTest | Level3)
{
    std::string value = "enter";
    GTEST_LOG_(INFO) << "DmsFwk_DistributedOperation_GetAbilityName_0100 start";

    operationbuilder_->WithAbilityName(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    EXPECT_STREQ(value.c_str(), operation->GetAbilityName().c_str());

    GTEST_LOG_(INFO) << "DmsFwk_DistributedOperation_GetAbilityName_0100 end";
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetAbilityName_0200
 * @tc.name: WithAbilityName/GetAbilityName.
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetAbilityName_0200, Function | MediumTest | Level3)
{
    std::string value = "";
    operationbuilder_->WithAbilityName(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();

    EXPECT_STREQ(value.c_str(), operation->GetAbilityName().c_str());
}

/**
 * @tc.number:  DmsFwk_DistributedOperation_GetBundleName_0100
 * @tc.name: WithBundleName/GetBundleName
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetBundleName_0100, Function | MediumTest | Level3)
{
    std::string value = "value";
    operationbuilder_->WithBundleName(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    EXPECT_STREQ(value.c_str(), operation->GetBundleName().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetBundleName_0200
 * @tc.name: WithBundleName/GetBundleName
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetBundleName_0200, Function | MediumTest | Level3)
{
    std::string value = "";
    operationbuilder_->WithBundleName(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    EXPECT_STREQ(value.c_str(), operation->GetBundleName().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetDeviceId_0100
 * @tc.name: WithDeviceId/GetDeviceId
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetDeviceId_0100, Function | MediumTest | Level3)
{
    std::string value = "value";
    operationbuilder_->WithDeviceId(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    EXPECT_STREQ(value.c_str(), operation->GetDeviceId().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetDeviceId_0200
 * @tc.name: WithDeviceId/GetDeviceId
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetDeviceId_0200, Function | MediumTest | Level3)
{
    std::string value = "";
    operationbuilder_->WithDeviceId(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    EXPECT_STREQ(value.c_str(), operation->GetDeviceId().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetAction_0100
 * @tc.name: WithAction/GetAction
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetAction_0100, Function | MediumTest | Level3)
{
    std::string value = "value";
    operationbuilder_->WithAction(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    EXPECT_STREQ(value.c_str(), operation->GetAction().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetAction_0200
 * @tc.name: WithAction/GetAction
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetAction_0200, Function | MediumTest | Level3)
{
    std::string value = "";
    operationbuilder_->WithAction(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    EXPECT_STREQ(value.c_str(), operation->GetAction().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetEntities_0100
 * @tc.name: WithEntities/GetEntities
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetEntities_0100, Function | MediumTest | Level3)
{
    std::vector<std::string> value;
    value.push_back("string1");
    operationbuilder_->WithEntities(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();

    std::vector<std::string> revValue = operation->GetEntities();

    if (value.size() > 0 && revValue.size() > 0) {
        EXPECT_STREQ(value.at(0).c_str(), operation->GetEntities().at(0).c_str());
    } else {
        EXPECT_EQ(true, revValue.size() > 0);
    }
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetEntities_0200
 * @tc.name: WithEntities/GetEntities
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetEntities_0200, Function | MediumTest | Level3)
{
    std::vector<std::string> value;
    operationbuilder_->WithEntities(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    EXPECT_EQ(true, operation->GetEntities().size() == 0);
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetFlags_0100
 * @tc.name: WithFlags/GetFlags
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetFlags_0100, Function | MediumTest | Level3)
{
    unsigned int value = 1;
    operationbuilder_->WithFlags(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    EXPECT_EQ(value, operation->GetFlags());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetFlags_0200
 * @tc.name: WithFlags/GetFlags
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetFlags_0200, Function | MediumTest | Level3)
{
    unsigned int value = 0;
    operationbuilder_->WithFlags(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    EXPECT_EQ(value, operation->GetFlags());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetUri_0100
 * @tc.name: WithUri/GetUri
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetUri_0100, Function | MediumTest | Level3)
{
    std::string value = "scheme://authority/path1/path2/path3?id = 1&name = mingming&old#fragment";
    OHOS::Uri uri(value);
    operationbuilder_->WithUri(uri);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();

    EXPECT_EQ(uri, operation->GetUri());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetUri_0200
 * @tc.name: WithUri/GetUri
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetUri_0200, Function | MediumTest | Level3)
{
    std::string value = "";
    OHOS::Uri uri(value);
    operationbuilder_->WithUri(uri);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    EXPECT_EQ(uri, operation->GetUri());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_build_0100
 * @tc.name: build
 * @tc.desc: Verify that the parameters are correct.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_build_0100, Function | MediumTest | Level3)
{
    std::string value = "value";
    OHOS::Uri uri(value);
    std::vector<std::string> columns;
    columns.push_back("string1");
    operationbuilder_->WithUri(uri);
    operationbuilder_->WithAction(value);
    operationbuilder_->WithEntities(columns);
    operationbuilder_->WithDeviceId(value);
    operationbuilder_->WithBundleName(value);
    operationbuilder_->WithAbilityName(value);

    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();

    EXPECT_EQ(uri, operation->GetUri());
    EXPECT_STREQ(value.c_str(), operation->GetAction().c_str());

    std::vector<std::string> revValue = operation->GetEntities();

    if (columns.size() > 0 && revValue.size() > 0) {
        EXPECT_STREQ(columns.at(0).c_str(), operation->GetEntities().at(0).c_str());
    } else {
        EXPECT_EQ(true, revValue.size() > 0);
    }
    EXPECT_STREQ(value.c_str(), operation->GetDeviceId().c_str());
    EXPECT_STREQ(value.c_str(), operation->GetBundleName().c_str());
    EXPECT_STREQ(value.c_str(), operation->GetAbilityName().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Marshalling_0100
 * @tc.name: Marshalling/Unmarshalling
 * @tc.desc: Validation serialization.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Marshalling_0100, Function | MediumTest | Level3)
{
    std::string value = "value";
    OHOS::Uri uri(value);
    std::vector<std::string> columns;
    columns.push_back("string1");
    operationbuilder_->WithUri(uri);
    operationbuilder_->WithAction(value);
    operationbuilder_->WithEntities(columns);
    operationbuilder_->WithDeviceId(value);
    operationbuilder_->WithBundleName(value);
    operationbuilder_->WithAbilityName(value);

    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    Parcel in;
    operation->Marshalling(in);

    DistributedOperation* pOperation = operation->Unmarshalling(in);
    if (pOperation != nullptr) {
        EXPECT_EQ(true, *pOperation == *(operation.get()));
    } else {
        EXPECT_EQ(true, pOperation != nullptr);
    }
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Operator_0100
 * @tc.name: Operator
 * @tc.desc: Verify string overload.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Operator_0100, Function | MediumTest | Level3)
{
    DistributedOperation operation_;
    std::string value = "value";
    OHOS::Uri uri(value);
    std::vector<std::string> columns;
    columns.push_back("string1");
    operationbuilder_->WithUri(uri);
    operationbuilder_->WithAction(value);
    operationbuilder_->WithEntities(columns);
    operationbuilder_->WithDeviceId(value);
    operationbuilder_->WithBundleName(value);
    operationbuilder_->WithAbilityName(value);

    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    operation_ = *(operation.get());

    EXPECT_EQ(true, operation_ == *(operation.get()));
}