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

/**
 * @tc.number: GetLowerCaseScheme_test_001
 * @tc.name: GetLowerCaseScheme
 * @tc.desc: Test GetLowerCaseScheme.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedWantV2SupTest, GetLowerCaseScheme_test_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetLowerCaseScheme_test_001 start";
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    std::string strUri = "";
    Uri uri(strUri);
    Want want;
    auto rlt = dwant->GetLowerCaseScheme(uri);
    EXPECT_EQ(rlt, uri);
    GTEST_LOG_(INFO) << "GetLowerCaseScheme_test_001 end";
}

/**
 * @tc.number: GetLowerCaseScheme_test_002
 * @tc.name: GetLowerCaseScheme
 * @tc.desc: Test GetLowerCaseScheme.
 * @tc.require: I77HFZ
 */
HWTEST_F(DistributedWantV2SupTest, GetLowerCaseScheme_test_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetLowerCaseScheme_test_002 start";
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    std::string strUri = "?Test;action;end";
    Uri uri(strUri);
    Want want;
    auto rlt = dwant->GetLowerCaseScheme(uri);
    EXPECT_EQ(rlt, uri);
    GTEST_LOG_(INFO) << "GetLowerCaseScheme_test_002 end";
}

/**
 * @tc.number: GetLowerCaseScheme_test_004
 * @tc.name: GetLowerCaseScheme
 * @tc.desc: Test GetLowerCaseScheme.
 */
HWTEST_F(DistributedWantV2SupTest, GetLowerCaseScheme_test_004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetLowerCaseScheme_test_004 start";
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    Uri lowerCaseUri("http://TEST.COM");
    Uri result = dwant->GetLowerCaseScheme(lowerCaseUri);
    EXPECT_EQ(result, lowerCaseUri);
    GTEST_LOG_(INFO) << "GetLowerCaseScheme_test_004 end";
}

/**
 * @tc.number: GetLowerCaseScheme_test_005
 * @tc.name: GetLowerCaseScheme
 * @tc.desc: Test GetLowerCaseScheme.
 */
HWTEST_F(DistributedWantV2SupTest, GetLowerCaseScheme_test_005, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetLowerCaseScheme_test_005 start";
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    Uri uri("HTTP://TEST.COM?Test");
    Uri lowerCaseUri("http://TEST.COM?Test");
    Uri result = dwant->GetLowerCaseScheme(uri);
    EXPECT_EQ(result, lowerCaseUri);
    GTEST_LOG_(INFO) << "GetLowerCaseScheme_test_005 end";
}

/**
 * @tc.number: GetParmFail_test_001
 * @tc.name: GetParmFail
 * @tc.desc: Test GetParmFail.
 */
HWTEST_F(DistributedWantV2SupTest, GetParmFail_test_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetParmFail_test_005 start";
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    auto str = dwant->GetType();
    EXPECT_TRUE(str.empty());

    bool defaultValue = false;
    auto flag = dwant->GetBoolParam("test", defaultValue);
    EXPECT_EQ(flag, defaultValue);
    EXPECT_EQ(dwant->GetByteParam("test", 0), 0);
    EXPECT_EQ(dwant->GetCharParam("test", 'a'), 'a');
    EXPECT_EQ(dwant->GetIntParam("test", 10), 10);
    EXPECT_EQ(dwant->GetDoubleParam("test", 20), 20);
    EXPECT_EQ(dwant->GetFloatParam("test", 5.0), 5.0);
    EXPECT_EQ(dwant->GetLongParam("test", 30), 30);
    EXPECT_EQ(dwant->GetShortParam("test", 1), 1);
    EXPECT_EQ(dwant->GetStringParam("test"), "");
    GTEST_LOG_(INFO) << "GetParmFail_test_001 end";
}

/**
 * @tc.number: GetParmFail_test_002
 * @tc.name: GetParmFail
 * @tc.desc: Test GetParmFail.
 */
HWTEST_F(DistributedWantV2SupTest, GetParmFail_test_002, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetParmFail_test_002 start";
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    auto flagArray = dwant->GetBoolArrayParam("test");
    EXPECT_TRUE(flagArray.empty());
    auto byteArray = dwant->GetByteArrayParam("test");
    EXPECT_TRUE(byteArray.empty());
    auto charArray = dwant->GetCharArrayParam("test");
    EXPECT_TRUE(charArray.empty());
    auto intArray = dwant->GetIntArrayParam("test");
    EXPECT_TRUE(intArray.empty());
    auto doubleArray = dwant->GetDoubleArrayParam("test");
    EXPECT_TRUE(doubleArray.empty());
    auto floatArray = dwant->GetFloatArrayParam("test");
    EXPECT_TRUE(floatArray.empty());
    auto longArray = dwant->GetLongArrayParam("test");
    EXPECT_TRUE(longArray.empty());
    auto shortArray = dwant->GetShortArrayParam("test");
    EXPECT_TRUE(shortArray.empty());
    auto strArray = dwant->GetStringArrayParam("test");
    EXPECT_TRUE(strArray.empty());
    GTEST_LOG_(INFO) << "GetParmFail_test_002 end";
}

/**
 * @tc.number: GetParmFail_test_003
 * @tc.name: GetParmFail
 * @tc.desc: Test GetParmFail.
 */
HWTEST_F(DistributedWantV2SupTest, GetParmFail_test_003, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetParmFail_test_003 start";
    std::vector<int> value{0, 1, 2, 3, 4, 5};
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    dwant->SetParam("test", value);
    auto flagArray = dwant->GetBoolArrayParam("test");
    EXPECT_TRUE(flagArray.empty());
    auto byteArray = dwant->GetByteArrayParam("test");
    EXPECT_TRUE(byteArray.empty());
    auto charArray = dwant->GetCharArrayParam("test");
    EXPECT_TRUE(charArray.empty());
    auto intArray = dwant->GetIntArrayParam("test");
    EXPECT_EQ(intArray, value);
    auto doubleArray = dwant->GetDoubleArrayParam("test");
    EXPECT_TRUE(doubleArray.empty());
    auto floatArray = dwant->GetFloatArrayParam("test");
    EXPECT_TRUE(floatArray.empty());
    auto longArray = dwant->GetLongArrayParam("test");
    EXPECT_TRUE(longArray.empty());
    auto shortArray = dwant->GetShortArrayParam("test");
    EXPECT_TRUE(shortArray.empty());
    auto strArray = dwant->GetStringArrayParam("test");
    EXPECT_TRUE(strArray.empty());
    GTEST_LOG_(INFO) << "GetParmFail_test_003 end";
}

/**
 * @tc.number: GetParmFail_test_004
 * @tc.name: GetParmFail
 * @tc.desc: Test GetParmFail.
 */
HWTEST_F(DistributedWantV2SupTest, GetParmFail_test_004, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetParmFail_test_004 start";
    std::vector<std::string> value{"1000", "10001", "10002", "test", "10004x", "10005"};
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    dwant->SetParam("test", value);
    auto intArray = dwant->GetIntArrayParam("test");
    EXPECT_TRUE(intArray.empty());
    std::vector<long> valueLong{1000, 10001, 10002, 10005};
    auto longArray = dwant->GetLongArrayParam("test");
    EXPECT_EQ(longArray, valueLong);
    auto strArray = dwant->GetStringArrayParam("test");
    EXPECT_EQ(strArray, value);
    GTEST_LOG_(INFO) << "GetParmFail_test_004 end";
}

/**
 * @tc.number: GetLongParam_test_001
 * @tc.name: GetLongParam
 * @tc.desc: Test GetLongParam.
 */
HWTEST_F(DistributedWantV2SupTest, GetLongParam_test_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "GetLongParam_test_001 start";
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    std::string value = "1000x";
    dwant->SetParam("test", value);
    value = "10004";
    dwant->SetParam("test1", value);
    auto rlt = dwant->GetLongParam("test", 2);
    EXPECT_EQ(rlt, 2);
    rlt = dwant->GetLongParam("test1", 2);
    EXPECT_EQ(rlt, 10004);
    GTEST_LOG_(INFO) << "GetLongParam_test_001 end";
}

/**
 * @tc.number: MarshallingWriteUri_test_001
 * @tc.name: MarshallingWriteUri
 * @tc.desc: Test MarshallingWriteUri.
 */
HWTEST_F(DistributedWantV2SupTest, MarshallingWriteUri_test_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MarshallingWriteUri_test_001 start";
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    std::string uri = "file://huawei.com.a/test";
    dwant->SetUri(uri);
    Parcel parcel;
    EXPECT_TRUE(dwant->MarshallingWriteUri(parcel));
    GTEST_LOG_(INFO) << "MarshallingWriteUri_test_001 end";
}

/**
 * @tc.number: MarshallingWriteEntities_test_001
 * @tc.name: MarshallingWriteEntities
 * @tc.desc: Test MarshallingWriteEntities.
 */
HWTEST_F(DistributedWantV2SupTest, MarshallingWriteEntities_test_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "MarshallingWriteEntities_test_001 start";
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    Parcel parcel;
    EXPECT_TRUE(dwant->MarshallingWriteEntities(parcel));
    EXPECT_TRUE(dwant->MarshallingWriteElement(parcel));

    std::string uri = "test";
    std::string deviceId = "deviceId";
    std::string bundleName = "bundleName";
    std::string abilityName = "abilityName";
    dwant->AddEntity(uri);
    dwant->SetElementName(deviceId, bundleName, abilityName);
    EXPECT_TRUE(dwant->MarshallingWriteEntities(parcel));
    EXPECT_TRUE(dwant->MarshallingWriteElement(parcel));
    GTEST_LOG_(INFO) << "MarshallingWriteUri_test_001 end";
}

/**
 * @tc.number: ReadUriFromParcel_test_001
 * @tc.name: ReadUriFromParcel
 * @tc.desc: Test ReadUriFromParcel.
 */
HWTEST_F(DistributedWantV2SupTest, ReadUriFromParcel_test_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ReadUriFromParcel_test_001 start";
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    Parcel parcel;
    EXPECT_FALSE(dwant->ReadUriFromParcel(parcel));
    
    ASSERT_TRUE(parcel.WriteInt32(0));
    EXPECT_TRUE(dwant->ReadUriFromParcel(parcel));

    ASSERT_TRUE(parcel.WriteInt32(DistributedWantV2::VALUE_OBJECT));
    EXPECT_TRUE(dwant->ReadUriFromParcel(parcel));
    EXPECT_EQ(dwant->GetUriString(), "");
    
    std::string testUri = "file://huawei.com.a/test";
    ASSERT_TRUE(parcel.WriteInt32(DistributedWantV2::VALUE_OBJECT));
    ASSERT_TRUE(parcel.WriteString16(Str8ToStr16(testUri)));
    EXPECT_TRUE(dwant->ReadUriFromParcel(parcel));
    EXPECT_EQ(dwant->GetUriString(), testUri);
    GTEST_LOG_(INFO) << "ReadUriFromParcel_test_001 end";
}

/**
 * @tc.number: ReadFromParcel_test_001
 * @tc.name: ReadFromParcel
 * @tc.desc: Test ReadFromParcel.
 */
HWTEST_F(DistributedWantV2SupTest, ReadFromParcel_test_001, TestSize.Level3)
{
    GTEST_LOG_(INFO) << "ReadFromParcel_test_001 start";
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    Parcel parcel;
    ASSERT_TRUE(parcel.WriteString16(Str8ToStr16("action")));
    EXPECT_FALSE(dwant->ReadFromParcel(parcel));
    
    ASSERT_TRUE(parcel.WriteString16(Str8ToStr16("action")));
    ASSERT_TRUE(parcel.WriteInt32(0));
    EXPECT_FALSE(dwant->ReadFromParcel(parcel));

    ASSERT_TRUE(parcel.WriteString16(Str8ToStr16("action")));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteInt32(0));
    EXPECT_FALSE(dwant->ReadFromParcel(parcel));

    ASSERT_TRUE(parcel.WriteString16(Str8ToStr16("action")));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteUint32(100));
    EXPECT_FALSE(dwant->ReadFromParcel(parcel));
    GTEST_LOG_(INFO) << "ReadFromParcel_test_001 end";
}

/**
 * @tc.number: ReadFromParcel_test_002
 * @tc.name: ReadFromParcel
 * @tc.desc: Test ReadFromParcel.
 */
HWTEST_F(DistributedWantV2SupTest, ReadFromParcel_test_002, TestSize.Level3)
{
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    Parcel parcel;
    ASSERT_TRUE(parcel.WriteString16(Str8ToStr16("action")));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteUint32(100));
    ASSERT_TRUE(parcel.WriteInt32(0));
    EXPECT_FALSE(dwant->ReadFromParcel(parcel));

    ASSERT_TRUE(parcel.WriteString16(Str8ToStr16("action")));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteUint32(100));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteInt32(0));
    EXPECT_TRUE(dwant->ReadFromParcel(parcel));

    ASSERT_TRUE(parcel.WriteString16(Str8ToStr16("action")));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteUint32(100));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteInt32(0));
    ASSERT_TRUE(parcel.WriteString16(Str8ToStr16("bundleName")));
    EXPECT_TRUE(dwant->ReadFromParcel(parcel));
    GTEST_LOG_(INFO) << "ReadFromParcel_test_002 end";
}
}
}