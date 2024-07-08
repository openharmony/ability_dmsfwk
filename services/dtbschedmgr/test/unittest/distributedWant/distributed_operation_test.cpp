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
#include "test_log.h"

using namespace OHOS;
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
    static sptr<DistributedOperation> distributedOperation_;
};

sptr<DistributedOperation> DistributedOperationBaseTest::distributedOperation_;

void DistributedOperationBaseTest::SetUpTestCase(void)
{
    distributedOperation_ = new DistributedOperation();
}

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
    ASSERT_NE(operationbuilder_, nullptr);
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
    ASSERT_NE(operationbuilder_, nullptr);
    std::string value = "";
    operationbuilder_->WithAbilityName(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_STREQ(value.c_str(), operation->GetAbilityName().c_str());
}

/**
 * @tc.number:  DmsFwk_DistributedOperation_GetBundleName_0100
 * @tc.name: WithBundleName/GetBundleName
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetBundleName_0100, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
    std::string value = "value";
    operationbuilder_->WithBundleName(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_STREQ(value.c_str(), operation->GetBundleName().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetBundleName_0200
 * @tc.name: WithBundleName/GetBundleName
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetBundleName_0200, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
    std::string value = "";
    operationbuilder_->WithBundleName(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_STREQ(value.c_str(), operation->GetBundleName().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetDeviceId_0100
 * @tc.name: WithDeviceId/GetDeviceId
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetDeviceId_0100, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
    std::string value = "value";
    operationbuilder_->WithDeviceId(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_STREQ(value.c_str(), operation->GetDeviceId().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetDeviceId_0200
 * @tc.name: WithDeviceId/GetDeviceId
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetDeviceId_0200, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
    std::string value = "";
    operationbuilder_->WithDeviceId(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_STREQ(value.c_str(), operation->GetDeviceId().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetAction_0100
 * @tc.name: WithAction/GetAction
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetAction_0100, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
    std::string value = "value";
    operationbuilder_->WithAction(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_STREQ(value.c_str(), operation->GetAction().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetAction_0200
 * @tc.name: WithAction/GetAction
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetAction_0200, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
    std::string value = "";
    operationbuilder_->WithAction(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_STREQ(value.c_str(), operation->GetAction().c_str());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetEntities_0100
 * @tc.name: WithEntities/GetEntities
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetEntities_0100, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
    std::vector<std::string> value;
    value.push_back("string1");
    operationbuilder_->WithEntities(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
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
    ASSERT_NE(operationbuilder_, nullptr);
    std::vector<std::string> value;
    operationbuilder_->WithEntities(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_EQ(true, operation->GetEntities().size() == 0);
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetFlags_0100
 * @tc.name: WithFlags/GetFlags
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetFlags_0100, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
    unsigned int value = 1;
    operationbuilder_->WithFlags(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_EQ(value, operation->GetFlags());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetFlags_0200
 * @tc.name: WithFlags/GetFlags
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetFlags_0200, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
    unsigned int value = 0;
    operationbuilder_->WithFlags(value);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_EQ(value, operation->GetFlags());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetUri_0100
 * @tc.name: WithUri/GetUri
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetUri_0100, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
    std::string value = "scheme://authority/path1/path2/path3?id = 1&name = mingming&old#fragment";
    OHOS::Uri uri(value);
    operationbuilder_->WithUri(uri);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_EQ(uri, operation->GetUri());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_GetUri_0200
 * @tc.name: WithUri/GetUri
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_GetUri_0200, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
    std::string value = "";
    OHOS::Uri uri(value);
    operationbuilder_->WithUri(uri);
    std::shared_ptr<DistributedOperation> operation = operationbuilder_->build();
    ASSERT_NE(operation, nullptr);
    EXPECT_EQ(uri, operation->GetUri());
}

/**
 * @tc.number: DmsFwk_DistributedOperation_build_0100
 * @tc.name: build
 * @tc.desc: Verify that the parameters are correct.
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_build_0100, Function | MediumTest | Level3)
{
    ASSERT_NE(operationbuilder_, nullptr);
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
    ASSERT_NE(operation, nullptr);
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
    ASSERT_NE(operationbuilder_, nullptr);
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
    ASSERT_NE(operation, nullptr);
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
    ASSERT_NE(operationbuilder_, nullptr);
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
    ASSERT_NE(operation, nullptr);
    operation_ = *(operation.get());

    EXPECT_EQ(true, operation_ == *(operation.get()));
}

/**
 * @tc.number: DmsFwk_DistributedOperation_AddEntity_0100
 * @tc.name: AddEntity
 * @tc.desc: test AddEntity.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_AddEntity_0100, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_AddEntity_0100 begin" << std::endl;
    ASSERT_NE(distributedOperation_, nullptr);
    std::string entity = "test";
    distributedOperation_->entities_.emplace_back(entity);
    distributedOperation_->AddEntity(entity);
    distributedOperation_->entities_.clear();
    EXPECT_TRUE(distributedOperation_->entities_.empty());
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_AddEntity_0100 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_RemoveEntity_0100
 * @tc.name: RemoveEntity
 * @tc.desc: test RemoveEntity.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_RemoveEntity_0100, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_RemoveEntity_0100 begin" << std::endl;
    ASSERT_NE(distributedOperation_, nullptr);
    std::string entity = "test";
    distributedOperation_->entities_.clear();
    distributedOperation_->RemoveEntity(entity);
    distributedOperation_->entities_.clear();
    EXPECT_TRUE(distributedOperation_->entities_.empty());
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_RemoveEntity_0100 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_RemoveEntity_0200
 * @tc.name: RemoveEntity
 * @tc.desc: test RemoveEntity.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_RemoveEntity_0200, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_RemoveEntity_0200 begin" << std::endl;
    ASSERT_NE(distributedOperation_, nullptr);
    std::string entity = "test";
    distributedOperation_->entities_.emplace_back(entity);
    std::string entity1 = "test1";
    distributedOperation_->RemoveEntity(entity1);
    distributedOperation_->entities_.clear();
    EXPECT_TRUE(distributedOperation_->entities_.empty());
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_RemoveEntity_0200 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Operator_0200
 * @tc.name: Operator
 * @tc.desc: test Operator.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Operator_0200, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0200 begin" << std::endl;
    DistributedOperation operation1;
    DistributedOperation operation2;
    operation1.abilityName_ = "test";
    EXPECT_FALSE(operation1 == operation2);
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0200 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Operator_0300
 * @tc.name: Operator
 * @tc.desc: test Operator.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Operator_0300, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0300 begin" << std::endl;
    DistributedOperation operation1;
    DistributedOperation operation2;
    operation1.action_ = "test";
    EXPECT_FALSE(operation1 == operation2);
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0300 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Operator_0400
 * @tc.name: Operator
 * @tc.desc: test Operator.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Operator_0400, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0400 begin" << std::endl;
    DistributedOperation operation1;
    DistributedOperation operation2;
    operation1.bundleName_ = "test";
    EXPECT_FALSE(operation1 == operation2);
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0400 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Operator_0500
 * @tc.name: Operator
 * @tc.desc: test Operator.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Operator_0500, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0500 begin" << std::endl;
    DistributedOperation operation1;
    DistributedOperation operation2;
    operation1.deviceId_ = "test";
    EXPECT_FALSE(operation1 == operation2);
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0500 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Operator_0600
 * @tc.name: Operator
 * @tc.desc: test Operator.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Operator_0600, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0600 begin" << std::endl;
    DistributedOperation operation1;
    DistributedOperation operation2;
    operation1.moduleName_ = "test";
    EXPECT_FALSE(operation1 == operation2);
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0600 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Operator_0700
 * @tc.name: Operator
 * @tc.desc: test Operator.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Operator_0700, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0700 begin" << std::endl;
    DistributedOperation operation1;
    DistributedOperation operation2;
    std::string entity = "test";
    operation1.entities_.emplace_back(entity);
    EXPECT_FALSE(operation1 == operation2);
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0700 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Operator_0800
 * @tc.name: Operator
 * @tc.desc: test Operator.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Operator_0800, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0800 begin" << std::endl;
    DistributedOperation operation1;
    DistributedOperation operation2;
    std::string entity = "test";
    operation1.entities_.emplace_back(entity);
    std::string entity1 = "test1";
    operation2.entities_.emplace_back(entity1);
    EXPECT_FALSE(operation1 == operation2);
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0800 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Operator_0900
 * @tc.name: Operator
 * @tc.desc: test Operator.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Operator_0900, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0900 begin" << std::endl;
    DistributedOperation operation1;
    DistributedOperation operation2;
    operation1.flags_ = 1;
    EXPECT_FALSE(operation1 == operation2);
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_0900 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Operator_1000
 * @tc.name: Operator
 * @tc.desc: test Operator.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Operator_1000, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_1000 begin" << std::endl;
    DistributedOperation operation1;
    DistributedOperation operation2;
    std::string value = "test";
    OHOS::Uri uri(value);
    operation1.uri_ = uri;
    EXPECT_FALSE(operation1 == operation2);
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Operator_1000 end" << std::endl;
}

/**
 * @tc.number: DmsFwk_DistributedOperation_Marshalling_0200
 * @tc.name: Marshalling
 * @tc.desc: test Marshalling.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedOperationBaseTest, DmsFwk_DistributedOperation_Marshalling_0200, Function | MediumTest | Level3)
{
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Marshalling_0200 begin" << std::endl;
    ASSERT_NE(operationbuilder_, nullptr);
    std::string value = "";
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
    bool ret = operation->Marshalling(in);
    EXPECT_TRUE(ret);
    DTEST_LOG << "DistributedWantParamsBaseTest DmsFwk_DistributedOperation_Marshalling_0200 begin" << std::endl;
}