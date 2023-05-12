/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "base_object.h"
#include "bool_wrapper.h"
#include "int_wrapper.h"
#include "float_wrapper.h"
#include "long_wrapper.h"
#include "array_wrapper.h"

#define private public
#define protected public
#include "distributed_operation.h"
#include "distributed_want.h"
#include "want.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS;
using OHOS::Parcel;
using OHOS::AppExecFwk::ElementName;

namespace OHOS {
namespace DistributedSchedule {
class DistributedWantBaseTest : public testing::Test {
public:
    DistributedWantBaseTest()
    {}
    ~DistributedWantBaseTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::string boolType = "bool";
    std::string boolArrayType = "boolArray";
    std::string byteType = "byte";
    std::string byteArrayType = "byteArray";
    std::string charType = "char";
    std::string charArrayType = "charArray";
    std::string shortType = "short";
    std::string shortArrayType = "shortArray";
    std::string intType = "int";
    std::string intArrayType = "intArray";
    std::string longType = "long";
    std::string longArrayType = "longArray";
    std::string floatType = "float";
    std::string floatArrayType = "floatArray";
    std::string doubleType = "double";
    std::string doubleArrayType = "doubleArray";
    std::string stringType = "string";
    std::string stringArrayType = "stringArray";
};


void DistributedWantBaseTest::SetUpTestCase(void)
{}

void DistributedWantBaseTest::TearDownTestCase(void)
{}

void DistributedWantBaseTest::SetUp(void)
{}

void DistributedWantBaseTest::TearDown(void)
{}

/**
 * @tc.number: AaExecFwk_DistributedWant_Convert_0100
 * @tc.name: distributedwant
 * @tc.desc: Verifying successful conversion of want to distributedwant.
 */
HWTEST_F(DistributedWantBaseTest, AaExecFwk_DistributedWant_Convert_0100, Function | MediumTest | Level1)
{
    Want want;
    std::string description = "liuuy";
    want.SetType(description);
    want.SetFlags(16);
    want.SetElementName("deviceID", "com.bundle.com", "com.bundle.com.ability");
    want.SetUri("wantUri");
    want.SetAction("Action");
    want.AddEntity("Entity1");
    want.SetParam(boolType, true);
    std::vector<bool> bv;
    bv.emplace_back(true);
    bv.emplace_back(false);
    want.SetParam(boolArrayType, bv);
    want.SetParam(byteType, 1);
    std::vector<byte> byv;
    byv.emplace_back(2);
    byv.emplace_back(3);
    want.SetParam(byteArrayType, byv);
    want.SetParam(charType, 6);
    std::vector<zchar> chv;
    chv.emplace_back('\n');
    chv.emplace_back('p');
    chv.emplace_back('i');
    want.SetParam(charArrayType, chv);
    want.SetParam(shortType, 444);
    std::vector<short> shv;
    shv.emplace_back(111);
    shv.emplace_back(222);
    shv.emplace_back(333);
    want.SetParam(shortArrayType, shv);
    want.SetParam(intType, 1111);
    std::vector<int> inv;
    inv.emplace_back(1111);
    inv.emplace_back(2222);
    inv.emplace_back(3333);
    inv.emplace_back(4444);
    want.SetParam(intArrayType, inv);
    want.SetParam(longType, 12345);
    std::vector<long> lgv;
    lgv.emplace_back(1111);
    lgv.emplace_back(2222);
    lgv.emplace_back(3333);
    lgv.emplace_back(4444);
    want.SetParam(longArrayType, lgv);
    want.SetParam(floatType, 1.1);
    std::vector<float> ftv;
    ftv.emplace_back(1111.1);
    ftv.emplace_back(2222.2);
    ftv.emplace_back(3333.3);
    ftv.emplace_back(4444.4);
    want.SetParam(floatArrayType, ftv);
    want.SetParam(doubleType, 1.11);
    std::vector<double> dbv;
    dbv.emplace_back(1111.11);
    dbv.emplace_back(2222.22);
    dbv.emplace_back(3333.33);
    dbv.emplace_back(4444.44);
    want.SetParam(doubleArrayType, dbv);
    want.SetParam(stringType, std::string("string..."));
    std::vector<std::string> strv;
    strv.emplace_back("1111.11");
    strv.emplace_back("2222.22");
    want.SetParam(stringArrayType, strv);
    DistributedWant dstbWant(want);
    EXPECT_STREQ(want.GetType().c_str(), dstbWant.GetType().c_str());
    EXPECT_STREQ(want.GetElement().GetDeviceID().c_str(), dstbWant.GetElement().GetDeviceID().c_str());
    EXPECT_STREQ(want.GetElement().GetBundleName().c_str(), dstbWant.GetElement().GetBundleName().c_str());
    EXPECT_STREQ(want.GetElement().GetAbilityName().c_str(), dstbWant.GetElement().GetAbilityName().c_str());
    EXPECT_EQ(want.GetFlags(), dstbWant.GetFlags());
    EXPECT_STREQ(want.GetUriString().c_str(), dstbWant.GetUriString().c_str());
    EXPECT_STREQ(want.GetAction().c_str(), dstbWant.GetAction().c_str());
    EXPECT_EQ(want.GetEntities().size(), dstbWant.GetEntities().size());
    EXPECT_EQ(want.GetBoolParam(boolType, false), dstbWant.GetBoolParam(boolType, true));
    EXPECT_EQ(want.GetBoolArrayParam(boolArrayType).size(), dstbWant.GetBoolArrayParam(boolArrayType).size());
    EXPECT_EQ(want.GetByteParam(byteType, 0), dstbWant.GetByteParam(byteType, 0));
    EXPECT_EQ(want.GetByteArrayParam(byteArrayType).size(), dstbWant.GetByteArrayParam(byteArrayType).size());
    EXPECT_EQ(want.GetCharParam(charType, 0), dstbWant.GetCharParam(charType, 0));
    EXPECT_EQ(want.GetCharArrayParam(charArrayType).size(), dstbWant.GetCharArrayParam(charArrayType).size());
    EXPECT_EQ(want.GetShortParam(shortType, 0), dstbWant.GetShortParam(shortType, 0));
    EXPECT_EQ(want.GetShortArrayParam(shortArrayType).size(), dstbWant.GetShortArrayParam(shortArrayType).size());
    EXPECT_EQ(want.GetIntParam(intType, 0), dstbWant.GetIntParam(intType, 0));
    EXPECT_EQ(want.GetIntArrayParam(intArrayType).size(), dstbWant.GetIntArrayParam(intArrayType).size());
    EXPECT_EQ(want.GetLongParam(longType, 0), dstbWant.GetLongParam(longType, 0));
    EXPECT_EQ(want.GetLongArrayParam(longArrayType).size(), dstbWant.GetLongArrayParam(longArrayType).size());
    EXPECT_EQ(want.GetFloatParam(floatType, 0), dstbWant.GetFloatParam(floatType, 0));
    EXPECT_EQ(want.GetFloatArrayParam(floatArrayType).size(), dstbWant.GetFloatArrayParam(floatArrayType).size());
    EXPECT_EQ(want.GetDoubleParam(doubleType, 0), dstbWant.GetDoubleParam(doubleType, 0));
    EXPECT_EQ(want.GetDoubleArrayParam(doubleArrayType).size(), dstbWant.GetDoubleArrayParam(doubleArrayType).size());
    EXPECT_STREQ(want.GetStringParam(stringType).c_str(), dstbWant.GetStringParam(stringType).c_str());
    EXPECT_EQ(want.GetStringArrayParam(stringArrayType).size(), dstbWant.GetStringArrayParam(stringArrayType).size());
}

/**
 * @tc.number: AaFwk_Want_Action_0100
 * @tc.name: ToWant
 * @tc.desc: Verifying successful conversion of distributedwant to want.
 */
HWTEST_F(DistributedWantBaseTest, AaExecFwk_DistributedWant_Convert_0200, Function | MediumTest | Level1)
{
    std::shared_ptr<DistributedWant> dwant = std::make_shared<DistributedWant>();
    std::string description = "liuuy";
    dwant->SetType(description);
    dwant->SetFlags(16);
    dwant->SetElementName("deviceID", "com.bundle.com", "com.bundle.com.ability");
    dwant->SetUri("wantUri");
    dwant->SetAction("Action");
    dwant->AddEntity("Entity1");
    dwant->SetParam(boolType, true);
    std::vector<bool> bv;
    bv.emplace_back(true);
    bv.emplace_back(false);
    dwant->SetParam(boolArrayType, bv);
    dwant->SetParam(byteType, 1);
    std::vector<byte> byv;
    byv.emplace_back(2);
    byv.emplace_back(3);
    dwant->SetParam(byteArrayType, byv);
    dwant->SetParam(charType, 6);
    std::vector<zchar> chv;
    chv.emplace_back('\n');
    chv.emplace_back('p');
    chv.emplace_back('i');
    dwant->SetParam(charArrayType, chv);
    dwant->SetParam(shortType, 444);
    std::vector<short> shv;
    shv.emplace_back(111);
    shv.emplace_back(222);
    shv.emplace_back(333);
    dwant->SetParam(shortArrayType, shv);
    dwant->SetParam(intType, 1111);
    std::vector<int> inv;
    inv.emplace_back(1111);
    inv.emplace_back(2222);
    inv.emplace_back(3333);
    inv.emplace_back(4444);
    dwant->SetParam(intArrayType, inv);
    dwant->SetParam(longType, 12345);
    std::vector<long> lgv;
    lgv.emplace_back(1111);
    lgv.emplace_back(2222);
    lgv.emplace_back(3333);
    lgv.emplace_back(4444);
    dwant->SetParam(longArrayType, lgv);
    dwant->SetParam(floatType, 1.1);
    std::vector<float> ftv;
    ftv.emplace_back(1111.1);
    ftv.emplace_back(2222.2);
    ftv.emplace_back(3333.3);
    ftv.emplace_back(4444.4);
    dwant->SetParam(floatArrayType, ftv);
    dwant->SetParam(doubleType, 1.11);
    std::vector<double> dbv;
    dbv.emplace_back(1111.11);
    dbv.emplace_back(2222.22);
    dbv.emplace_back(3333.33);
    dbv.emplace_back(4444.44);
    dwant->SetParam(doubleArrayType, dbv);
    dwant->SetParam(stringType, std::string("string..."));
    std::vector<std::string> strv;
    strv.emplace_back("1111.11");
    strv.emplace_back("2222.22");
    dwant->SetParam(stringArrayType, strv);
    std::shared_ptr<Want> want = dwant->ToWant();
    EXPECT_STREQ(want->GetAction().c_str(), dwant->GetAction().c_str());
    EXPECT_STREQ(want->GetElement().GetDeviceID().c_str(), dwant->GetElement().GetDeviceID().c_str());
    EXPECT_STREQ(want->GetElement().GetBundleName().c_str(), dwant->GetElement().GetBundleName().c_str());
    EXPECT_STREQ(want->GetElement().GetAbilityName().c_str(), dwant->GetElement().GetAbilityName().c_str());
    EXPECT_EQ(want->GetFlags(), dwant->GetFlags());
    EXPECT_STREQ(want->GetUriString().c_str(), dwant->GetUriString().c_str());
    EXPECT_STREQ(want->GetAction().c_str(), dwant->GetAction().c_str());
    EXPECT_EQ(want->GetEntities().size(), dwant->GetEntities().size());
    EXPECT_EQ(want->GetBoolParam(boolType, false), dwant->GetBoolParam(boolType, true));
    EXPECT_EQ(want->GetBoolArrayParam(boolArrayType).size(), dwant->GetBoolArrayParam(boolArrayType).size());
    EXPECT_EQ(want->GetByteParam(byteType, 0), dwant->GetByteParam(byteType, 0));
    EXPECT_EQ(want->GetByteArrayParam(byteArrayType).size(), dwant->GetByteArrayParam(byteArrayType).size());
    EXPECT_EQ(want->GetCharParam(charType, 0), dwant->GetCharParam(charType, 0));
    EXPECT_EQ(want->GetCharArrayParam(charArrayType).size(), dwant->GetCharArrayParam(charArrayType).size());
    EXPECT_EQ(want->GetShortParam(shortType, 0), dwant->GetShortParam(shortType, 0));
    EXPECT_EQ(want->GetShortArrayParam(shortArrayType).size(), dwant->GetShortArrayParam(shortArrayType).size());
    EXPECT_EQ(want->GetIntParam(intType, 0), dwant->GetIntParam(intType, 0));
    EXPECT_EQ(want->GetIntArrayParam(intArrayType).size(), dwant->GetIntArrayParam(intArrayType).size());
    EXPECT_EQ(want->GetLongParam(longType, 0), dwant->GetLongParam(longType, 0));
    EXPECT_EQ(want->GetLongArrayParam(longArrayType).size(), dwant->GetLongArrayParam(longArrayType).size());
    EXPECT_EQ(want->GetFloatParam(floatType, 0), dwant->GetFloatParam(floatType, 0));
    EXPECT_EQ(want->GetFloatArrayParam(floatArrayType).size(), dwant->GetFloatArrayParam(floatArrayType).size());
    EXPECT_EQ(want->GetDoubleParam(doubleType, 0), dwant->GetDoubleParam(doubleType, 0));
    EXPECT_EQ(want->GetDoubleArrayParam(doubleArrayType).size(), dwant->GetDoubleArrayParam(doubleArrayType).size());
    EXPECT_STREQ(want->GetStringParam(stringType).c_str(), dwant->GetStringParam(stringType).c_str());
    EXPECT_EQ(want->GetStringArrayParam(stringArrayType).size(), dwant->GetStringArrayParam(stringArrayType).size());
}
}  // namespace AAFwk
}  // namespace OHOS