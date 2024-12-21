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

#define private public
#define protected public
#include "distributed_operation.h"
#include "distributed_want_v2.h"
#include "want.h"
#include "want_params.h"
#undef private
#undef protected

using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS;
using OHOS::Parcel;
using OHOS::AppExecFwk::ElementName;

namespace OHOS {
namespace DistributedSchedule {
class DistributedWantV2BaseTest : public testing::Test {
public:
    DistributedWantV2BaseTest()
    {}
    ~DistributedWantV2BaseTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();

    std::shared_ptr<DistributedWantV2> want_ = nullptr;

    void CompareWant(const std::shared_ptr<DistributedWantV2> &want1,
        const std::shared_ptr<DistributedWantV2> &want2) const;
    bool CompareWant(const std::shared_ptr<DistributedWantV2> &want1,
        const std::shared_ptr<DistributedWantV2> &want2, std::map<std::string, std::string> &keys) const;
    bool CompareWantOthers(const std::shared_ptr<DistributedWantV2>& want1,
        const std::shared_ptr<DistributedWantV2>& want2, std::map<std::string, std::string>::iterator it) const;
    bool CompareWantNumber(const std::shared_ptr<DistributedWantV2>& want1,
        const std::shared_ptr<DistributedWantV2>& want2, std::map<std::string, std::string>::iterator it) const;
    bool CompareWantArray(const std::shared_ptr<DistributedWantV2>& want1,
        const std::shared_ptr<DistributedWantV2>& want2, std::map<std::string, std::string>::iterator it) const;
    void SendParcelTest(const std::shared_ptr<DistributedWantV2> &want,
        std::map<std::string, std::string> &keys) const;
    void AddBoolParams(DistributedWantV2 &want,
        std::map<std::string, std::string> &keys, int loop, unsigned int flag) const;
    void AddByteParams(DistributedWantV2 &want,
        std::map<std::string, std::string> &keys, int loop, unsigned int flag) const;
    void AddCharParams(DistributedWantV2 &want,
        std::map<std::string, std::string> &keys, int loop, unsigned int flag) const;
    void AddShortParams(DistributedWantV2 &want,
        std::map<std::string, std::string> &keys, int loop, unsigned int flag) const;
    void AddIntParams(DistributedWantV2 &want,
        std::map<std::string, std::string> &keys, int loop, unsigned int flag) const;
    void AddLongParams(DistributedWantV2 &want,
        std::map<std::string, std::string> &keys, int loop, unsigned int flag) const;
    void AddFloatParams(DistributedWantV2 &want,
        std::map<std::string, std::string> &keys, int loop, unsigned int flag) const;
    void AddDoubleParams(DistributedWantV2 &want,
        std::map<std::string, std::string> &keys, int loop, unsigned int flag) const;
    void AddStringParams(DistributedWantV2 &want,
        std::map<std::string, std::string> &keys, int loop, unsigned int flag) const;
    void TestStringForParseUri(std::string uri,
        std::string keyString, std::size_t &length, std::string valueStringOrigin);
    void TestFloatForParseUri(std::string uri,
        std::string keyFloat, std::size_t &length, float valueFloatOrigin);
    void TestFloatArrayForParseUri(std::string uri,
        std::string keyFloatArray, std::size_t &length, std::vector<float> valueFloatArrayOrigin);
    void TestStringArrayForParseUri(std::string uri,
        std::string keyStringArray, std::size_t &length, std::vector<std::string> valueStringArrayOrigin);

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

    static const std::string URI_STRING_HEAD;
    static const std::string URI_STRING_END;
};

void DistributedWantV2BaseTest::SetUpTestCase(void)
{}

void DistributedWantV2BaseTest::TearDownTestCase(void)
{}

void DistributedWantV2BaseTest::SetUp(void)
{
    want_ = std::make_shared<DistributedWantV2>();
}

void DistributedWantV2BaseTest::TearDown(void)
{}

template<typename T>
bool CompareArrayData(const std::vector<T> &arr1, const std::vector<T> &arr2)
{
    if (arr1.size() != arr2.size()) {
        return false;
    }
    for (std::uint32_t i = 0; i < arr1.size(); i++) {
        if (arr1[i] != arr2[i]) {
            return false;
        }
    }
    return true;
};

enum Type { FLAG_TEST_SINGLE = 0x01, FLAG_TEST_ARRAY, FLAG_TEST_BOTH };
const std::string DistributedWantV2BaseTest::URI_STRING_HEAD("#Intent;");
const std::string DistributedWantV2BaseTest::URI_STRING_END(";end");

/**
 * @tc.number: DistributedSchedule_DistributedWantV2_Convert_0100
 * @tc.name: distributedwantV2
 * @tc.desc: Verifying successful conversion of want to distributedwantV2.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedSchedule_DistributedWantV2_Convert_0100, Function | MediumTest | Level3)
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
    want.SetParam(byteType, 1);
    want.SetParam(charType, 6);
    want.SetParam(shortType, 444);
    want.SetParam(intType, 1111);
    want.SetParam(longType, 12345);
    want.SetParam(floatType, 1.1);
    want.SetParam(doubleType, 1.11);
    want.SetParam(stringType, std::string("string..."));
    std::vector<double> dbv;
    dbv.emplace_back(1111.11);
    dbv.emplace_back(2222.22);
    dbv.emplace_back(3333.33);
    dbv.emplace_back(4444.44);
    want.SetParam(doubleArrayType, dbv);
    std::vector<std::string> strv;
    strv.emplace_back("1111.11");
    strv.emplace_back("2222.22");
    want.SetParam(stringArrayType, strv);
    DistributedWantV2 dstbWant(want);
    EXPECT_STREQ(want.GetType().c_str(), dstbWant.GetType().c_str());
    EXPECT_STREQ(want.GetElement().GetDeviceID().c_str(), dstbWant.GetElement().GetDeviceID().c_str());
    EXPECT_STREQ(want.GetElement().GetBundleName().c_str(), dstbWant.GetElement().GetBundleName().c_str());
    EXPECT_STREQ(want.GetElement().GetAbilityName().c_str(), dstbWant.GetElement().GetAbilityName().c_str());
    EXPECT_EQ(want.GetFlags(), dstbWant.GetFlags());
    EXPECT_STREQ(want.GetUriString().c_str(), dstbWant.GetUriString().c_str());
    EXPECT_STREQ(want.GetAction().c_str(), dstbWant.GetAction().c_str());
    EXPECT_EQ(want.GetEntities().size(), dstbWant.GetEntities().size());
    EXPECT_EQ(want.GetBoolParam(boolType, false), dstbWant.GetBoolParam(boolType, true));
    EXPECT_EQ(want.GetByteParam(byteType, 0), dstbWant.GetByteParam(byteType, 0));
    EXPECT_EQ(want.GetCharParam(charType, 0), dstbWant.GetCharParam(charType, 0));
    EXPECT_EQ(want.GetShortParam(shortType, 0), dstbWant.GetShortParam(shortType, 0));
    EXPECT_EQ(want.GetIntParam(intType, 0), dstbWant.GetIntParam(intType, 0));
    EXPECT_EQ(want.GetLongParam(longType, 0), dstbWant.GetLongParam(longType, 0));
    EXPECT_EQ(want.GetFloatParam(floatType, 0), dstbWant.GetFloatParam(floatType, 0));
    EXPECT_EQ(want.GetDoubleParam(doubleType, 0), dstbWant.GetDoubleParam(doubleType, 0));
    EXPECT_STREQ(want.GetStringParam(stringType).c_str(), dstbWant.GetStringParam(stringType).c_str());
    EXPECT_EQ(want.GetDoubleArrayParam(doubleArrayType).size(), dstbWant.GetDoubleArrayParam(doubleArrayType).size());
    EXPECT_EQ(want.GetStringArrayParam(stringArrayType).size(), dstbWant.GetStringArrayParam(stringArrayType).size());
}

/**
 * @tc.number: DistributedSchedule_DistributedWantV2_Convert_0101
 * @tc.name: distributedwantV2
 * @tc.desc: Verifying successful conversion of want to distributedwantV2.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedSchedule_DistributedWantV2_Convert_0101, Function | MediumTest | Level3)
{
    Want want;
    std::vector<bool> bv;
    bv.emplace_back(true);
    bv.emplace_back(false);
    want.SetParam(boolArrayType, bv);
    std::vector<byte> byv;
    byv.emplace_back(2);
    byv.emplace_back(3);
    want.SetParam(byteArrayType, byv);
    std::vector<zchar> chv;
    chv.emplace_back('\n');
    chv.emplace_back('p');
    chv.emplace_back('i');
    want.SetParam(charArrayType, chv);
    std::vector<short> shv;
    shv.emplace_back(111);
    shv.emplace_back(222);
    shv.emplace_back(333);
    want.SetParam(shortArrayType, shv);
    std::vector<int> inv;
    inv.emplace_back(1111);
    inv.emplace_back(2222);
    inv.emplace_back(3333);
    inv.emplace_back(4444);
    want.SetParam(intArrayType, inv);
    std::vector<long> lgv;
    lgv.emplace_back(1111);
    lgv.emplace_back(2222);
    lgv.emplace_back(3333);
    lgv.emplace_back(4444);
    want.SetParam(longArrayType, lgv);
    std::vector<float> ftv;
    ftv.emplace_back(1111.1);
    ftv.emplace_back(2222.2);
    ftv.emplace_back(3333.3);
    ftv.emplace_back(4444.4);
    want.SetParam(floatArrayType, ftv);
    DistributedWantV2 dstbWant(want);
    EXPECT_EQ(want.GetBoolArrayParam(boolArrayType).size(), dstbWant.GetBoolArrayParam(boolArrayType).size());
    EXPECT_EQ(want.GetByteArrayParam(byteArrayType).size(), dstbWant.GetByteArrayParam(byteArrayType).size());
    EXPECT_EQ(want.GetCharArrayParam(charArrayType).size(), dstbWant.GetCharArrayParam(charArrayType).size());
    EXPECT_EQ(want.GetShortArrayParam(shortArrayType).size(), dstbWant.GetShortArrayParam(shortArrayType).size());
    EXPECT_EQ(want.GetIntArrayParam(intArrayType).size(), dstbWant.GetIntArrayParam(intArrayType).size());
    EXPECT_EQ(want.GetLongArrayParam(longArrayType).size(), dstbWant.GetLongArrayParam(longArrayType).size());
    EXPECT_EQ(want.GetFloatArrayParam(floatArrayType).size(), dstbWant.GetFloatArrayParam(floatArrayType).size());
}

/**
 * @tc.number: DistributedSchedule_DistributedWantV2_Convert_0200
 * @tc.name: ToWant
 * @tc.desc: Verifying successful conversion of distributedwantV2 to want.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedSchedule_Distributedwant_Convert_0200, Function | MediumTest | Level3)
{
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    std::string description = "liuuy";
    dwant->SetType(description);
    dwant->SetFlags(16);
    dwant->SetElementName("deviceID", "com.bundle.com", "com.bundle.com.ability");
    dwant->SetUri("wantUri");
    dwant->SetAction("Action");
    dwant->AddEntity("Entity1");
    dwant->SetParam(boolType, true);
    dwant->SetParam(byteType, 1);
    dwant->SetParam(charType, 6);
    dwant->SetParam(shortType, 444);
    dwant->SetParam(intType, 1111);
    dwant->SetParam(longType, 12345);
    dwant->SetParam(floatType, 1.1);
    dwant->SetParam(doubleType, 1.11);
    dwant->SetParam(stringType, std::string("string..."));
    std::vector<double> dbv;
    dbv.emplace_back(1111.11);
    dbv.emplace_back(2222.22);
    dbv.emplace_back(3333.33);
    dbv.emplace_back(4444.44);
    dwant->SetParam(doubleArrayType, dbv);
    std::vector<std::string> strv;
    strv.emplace_back("1111.11");
    strv.emplace_back("2222.22");
    dwant->SetParam(stringArrayType, strv);
    std::shared_ptr<Want> want = dwant->ToWant();
    EXPECT_STREQ(want->GetType().c_str(), dwant->GetType().c_str());
    EXPECT_STREQ(want->GetElement().GetDeviceID().c_str(), dwant->GetElement().GetDeviceID().c_str());
    EXPECT_STREQ(want->GetElement().GetBundleName().c_str(), dwant->GetElement().GetBundleName().c_str());
    EXPECT_STREQ(want->GetElement().GetAbilityName().c_str(), dwant->GetElement().GetAbilityName().c_str());
    EXPECT_EQ(want->GetFlags(), dwant->GetFlags());
    EXPECT_STREQ(want->GetUriString().c_str(), dwant->GetUriString().c_str());
    EXPECT_STREQ(want->GetAction().c_str(), dwant->GetAction().c_str());
    EXPECT_EQ(want->GetEntities().size(), dwant->GetEntities().size());
    EXPECT_EQ(want->GetBoolParam(boolType, false), dwant->GetBoolParam(boolType, true));
    EXPECT_EQ(want->GetByteParam(byteType, 0), dwant->GetByteParam(byteType, 0));
    EXPECT_EQ(want->GetCharParam(charType, 0), dwant->GetCharParam(charType, 0));
    EXPECT_EQ(want->GetShortParam(shortType, 0), dwant->GetShortParam(shortType, 0));
    EXPECT_EQ(want->GetIntParam(intType, 0), dwant->GetIntParam(intType, 0));
    EXPECT_EQ(want->GetLongParam(longType, 0), dwant->GetLongParam(longType, 0));
    EXPECT_EQ(want->GetFloatParam(floatType, 0), dwant->GetFloatParam(floatType, 0));
    EXPECT_EQ(want->GetDoubleParam(doubleType, 0), dwant->GetDoubleParam(doubleType, 0));
    EXPECT_STREQ(want->GetStringParam(stringType).c_str(), dwant->GetStringParam(stringType).c_str());
    EXPECT_EQ(want->GetDoubleArrayParam(doubleArrayType).size(), dwant->GetDoubleArrayParam(doubleArrayType).size());
    EXPECT_EQ(want->GetStringArrayParam(stringArrayType).size(), dwant->GetStringArrayParam(stringArrayType).size());
}

/**
 * @tc.number: DistributedSchedule_DistributedWantV2_Convert_0201
 * @tc.name: ToWant
 * @tc.desc: Verifying successful conversion of distributedwantV2 to want.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedSchedule_Distributedwant_Convert_0201, Function | MediumTest | Level3)
{
    std::shared_ptr<DistributedWantV2> dwant = std::make_shared<DistributedWantV2>();
    ASSERT_NE(dwant, nullptr);
    std::vector<bool> bv;
    bv.emplace_back(true);
    bv.emplace_back(false);
    dwant->SetParam(boolArrayType, bv);
    std::vector<byte> byv;
    byv.emplace_back(2);
    byv.emplace_back(3);
    dwant->SetParam(byteArrayType, byv);
    std::vector<zchar> chv;
    chv.emplace_back('\n');
    chv.emplace_back('p');
    chv.emplace_back('i');
    dwant->SetParam(charArrayType, chv);
    std::vector<short> shv;
    shv.emplace_back(111);
    shv.emplace_back(222);
    shv.emplace_back(333);
    dwant->SetParam(shortArrayType, shv);
    std::vector<int> inv;
    inv.emplace_back(1111);
    inv.emplace_back(2222);
    inv.emplace_back(3333);
    inv.emplace_back(4444);
    dwant->SetParam(intArrayType, inv);
    std::vector<long> lgv;
    lgv.emplace_back(1111);
    lgv.emplace_back(2222);
    lgv.emplace_back(3333);
    lgv.emplace_back(4444);
    dwant->SetParam(longArrayType, lgv);
    std::vector<float> ftv;
    ftv.emplace_back(1111.1);
    ftv.emplace_back(2222.2);
    ftv.emplace_back(3333.3);
    ftv.emplace_back(4444.4);
    dwant->SetParam(floatArrayType, ftv);
    std::shared_ptr<Want> want = dwant->ToWant();
    EXPECT_EQ(want->GetBoolArrayParam(boolArrayType).size(), dwant->GetBoolArrayParam(boolArrayType).size());
    EXPECT_EQ(want->GetByteArrayParam(byteArrayType).size(), dwant->GetByteArrayParam(byteArrayType).size());
    EXPECT_EQ(want->GetCharArrayParam(charArrayType).size(), dwant->GetCharArrayParam(charArrayType).size());
    EXPECT_EQ(want->GetShortArrayParam(shortArrayType).size(), dwant->GetShortArrayParam(shortArrayType).size());
    EXPECT_EQ(want->GetIntArrayParam(intArrayType).size(), dwant->GetIntArrayParam(intArrayType).size());
    EXPECT_EQ(want->GetLongArrayParam(longArrayType).size(), dwant->GetLongArrayParam(longArrayType).size());
    EXPECT_EQ(want->GetFloatArrayParam(floatArrayType).size(), dwant->GetFloatArrayParam(floatArrayType).size());
}

/**
 * @tc.number: DistributedScheduleWant_Type_0100
 * @tc.name: SetType/GetType
 * @tc.desc: Validate when normally entering a string
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Type_0100, Function | MediumTest | Level3)
{
    if (want_ != nullptr) {
        std::string description = "liuuy";
        want_->SetType(description);
        EXPECT_STREQ(description.c_str(), want_->GetType().c_str());
    }
}

/**
 * @tc.number: DistributedScheduleWant_Action_0100
 * @tc.name: SetAction/GetAction
 * @tc.desc: Validate when normally entering a string
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Action_0100, Function | MediumTest | Level3)
{
    if (want_ != nullptr) {
        std::string actiondescription = "liuuy";
        want_->SetAction(actiondescription);
        EXPECT_STREQ(actiondescription.c_str(), want_->GetAction().c_str());
    }
}

/**
 * @tc.number: DistributedScheduleWant_Bundle_0100
 * @tc.name: SetBundle/GetBundle
 * @tc.desc: Validate when normally entering a string
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Bundle_0100, Function | MediumTest | Level3)
{
    if (want_ != nullptr) {
        std::string bundleName = "liuuy";
        want_->SetBundle(bundleName);
        EXPECT_STREQ(bundleName.c_str(), want_->GetBundle().c_str());
    }
}

/**
 * @tc.number: DistributedScheduleWant_Parcelable_0100
 * @tc.name: Marshalling/Unmarshalling
 * @tc.desc: marshalling Want, and then check result.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Parcelable_0100, Function | MediumTest | Level3)
{
    std::shared_ptr<DistributedWantV2> WantIn_ = std::make_shared<DistributedWantV2>();
    ASSERT_NE(nullptr, WantIn_);

    WantIn_->SetAction("12345");
    WantIn_->SetFlags(123);
    WantIn_->AddEntity("12345");
    AAFwk::WantParams wantParams;
    std::string keyStr = "12345667";
    bool valueBool = true;
    wantParams.SetParam(keyStr, Boolean::Box(valueBool));
    WantIn_->SetParams(wantParams);
    OHOS::AppExecFwk::ElementName element;
    element.SetAbilityName("12345");
    element.SetBundleName("12345");
    element.SetDeviceID("12345");
    WantIn_->SetElement(element);
    WantIn_->SetType("12345");

    Parcel in;
    size_t pos1 = in.GetWritePosition();
    bool result = WantIn_->Marshalling(in);
    size_t pos2 = in.GetWritePosition();
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << " Marshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;

    pos1 = in.GetWritePosition();
    result = WantIn_->Marshalling(in);
    pos2 = in.GetWritePosition();
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << " Marshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;

    pos1 = in.GetReadPosition();
    std::shared_ptr<DistributedWantV2> WantOut_(DistributedWantV2::Unmarshalling(in));
    if (WantOut_ != nullptr) {
        pos2 = in.GetReadPosition();
        CompareWant(WantIn_, WantOut_);
        EXPECT_EQ(valueBool, Boolean::Unbox(IBoolean::Query(WantOut_->GetParams().GetParam(keyStr))));
        GTEST_LOG_(INFO) << " Unmarshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;
    }

    pos1 = in.GetReadPosition();
    std::shared_ptr<DistributedWantV2> WantOut2_(DistributedWantV2::Unmarshalling(in));
    if (WantOut2_ != nullptr) {
        pos2 = in.GetReadPosition();
        CompareWant(WantIn_, WantOut2_);
        EXPECT_EQ(valueBool, Boolean::Unbox(IBoolean::Query(WantOut2_->GetParams().GetParam(keyStr))));
        GTEST_LOG_(INFO) << " Unmarshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;
    }
}
/**
 * @tc.number: DistributedScheduleWant_Parcelable_0200
 * @tc.name: Marshalling/Unmarshalling
 * @tc.desc: marshalling Want, and then check result.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Parcelable_0200, Function | MediumTest | Level3)
{
    std::shared_ptr<DistributedWantV2> WantIn_ = std::make_shared<DistributedWantV2>();
    ASSERT_NE(nullptr, WantIn_);
    WantIn_->SetAction("@#￥#3243adsafdf_中文");
    WantIn_->SetFlags(123);
    WantIn_->AddEntity("@#￥#3243adsafdf_中文");
    AAFwk::WantParams wantParams;
    std::string keyStr = "@#￥#3243adsafdf_中文";
    std::string valueStr = "123";
    wantParams.SetParam(keyStr, String::Box(valueStr));
    WantIn_->SetParams(wantParams);
    OHOS::AppExecFwk::ElementName element;
    element.SetAbilityName("@#￥#3243adsafdf_中文");
    element.SetBundleName("@#￥#3243adsafdf_中文");
    element.SetDeviceID("@#￥#3243adsafdf_中文");
    WantIn_->SetElement(element);
    WantIn_->SetType("@#￥#3243adsafdf_中文");
    size_t pos1;
    size_t pos2;
    bool result = false;
    Parcel in;
    pos1 = in.GetWritePosition();
    result = WantIn_->Marshalling(in);
    pos2 = in.GetWritePosition();
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "Marshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;
    pos1 = in.GetWritePosition();
    result = WantIn_->Marshalling(in);
    pos2 = in.GetWritePosition();
    EXPECT_EQ(result, true);
    pos1 = in.GetReadPosition();
    std::shared_ptr<DistributedWantV2> WantOut_(DistributedWantV2::Unmarshalling(in));
    if (WantOut_ != nullptr) {
        pos2 = in.GetReadPosition();
        CompareWant(WantIn_, WantOut_);
        std::string outString(String::Unbox(IString::Query(WantOut_->GetParams().GetParam(keyStr))));
        EXPECT_STREQ(valueStr.c_str(), outString.c_str());
        GTEST_LOG_(INFO) << "Unmarshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;
    }
    pos1 = in.GetReadPosition();
    std::shared_ptr<DistributedWantV2> WantOut2_(DistributedWantV2::Unmarshalling(in));
    if (WantOut2_ != nullptr) {
        pos2 = in.GetReadPosition();
        CompareWant(WantIn_, WantOut2_);
        std::string outString2(String::Unbox(IString::Query(WantOut2_->GetParams().GetParam(keyStr))));
        EXPECT_STREQ(valueStr.c_str(), outString2.c_str());
    }
}

/**
 * @tc.number: DistributedScheduleWant_Parcelable_0300
 * @tc.name: Marshalling/Unmarshalling
 * @tc.desc: marshalling Want, and then check result.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Parcelable_0300, Function | MediumTest | Level3)
{
    std::shared_ptr<DistributedWantV2> WantIn_ = std::make_shared<DistributedWantV2>();
    ASSERT_NE(nullptr, WantIn_);

    WantIn_->SetAction("");
    WantIn_->SetFlags(123);
    WantIn_->AddEntity("");
    AAFwk::WantParams wantParams;
    std::string keyStr = "";
    int valueInt = 123;
    wantParams.SetParam(keyStr, Integer::Box(valueInt));
    WantIn_->SetParams(wantParams);
    OHOS::AppExecFwk::ElementName element;
    element.SetAbilityName("");
    element.SetBundleName("");
    element.SetDeviceID("");
    WantIn_->SetElement(element);
    WantIn_->SetType("");

    size_t pos1;
    size_t pos2;
    bool result = false;

    Parcel in;
    pos1 = in.GetWritePosition();
    result = WantIn_->Marshalling(in);
    pos2 = in.GetWritePosition();
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "Marshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;

    pos1 = in.GetWritePosition();
    result = WantIn_->Marshalling(in);
    pos2 = in.GetWritePosition();
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "Marshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;

    pos1 = in.GetReadPosition();
    std::shared_ptr<DistributedWantV2> WantOut_(DistributedWantV2::Unmarshalling(in));
    if (WantOut_ != nullptr) {
        pos2 = in.GetReadPosition();
        CompareWant(WantIn_, WantOut_);
        EXPECT_EQ(valueInt, Integer::Unbox(IInteger::Query(WantOut_->GetParams().GetParam(keyStr))));
        GTEST_LOG_(INFO) << "Unmarshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;
    }

    pos1 = in.GetReadPosition();
    std::shared_ptr<DistributedWantV2> WantOut2_(DistributedWantV2::Unmarshalling(in));
    if (WantOut2_ != nullptr) {
        pos2 = in.GetReadPosition();
        CompareWant(WantIn_, WantOut2_);
        EXPECT_EQ(valueInt, Integer::Unbox(IInteger::Query(WantOut2_->GetParams().GetParam(keyStr))));
        GTEST_LOG_(INFO) << "Unmarshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;
    }
}

/**
 * @tc.number: DistributedScheduleWant_Parcelable_0400
 * @tc.name: Marshalling/Unmarshalling
 * @tc.desc: marshalling Want, and then check result.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Parcelable_0400, Function | MediumTest | Level3)
{
    std::shared_ptr<DistributedWantV2> WantIn_ = std::make_shared<DistributedWantV2>();
    ASSERT_NE(nullptr, WantIn_);

    WantIn_->SetAction("12345");
    WantIn_->SetFlags(123);
    WantIn_->AddEntity("12345");
    WantIn_->AddEntity("@#￥#3243adsafdf_中文");
    WantIn_->AddEntity("");
    AAFwk::WantParams wantParams;
    std::string keyStr = "12345667";
    std::string valueString = "123";
    wantParams.SetParam(keyStr, String::Box(valueString));
    WantIn_->SetParams(wantParams);
    OHOS::AppExecFwk::ElementName element;
    element.SetAbilityName("12345");
    element.SetBundleName("12345");
    element.SetDeviceID("12345");
    WantIn_->SetElement(element);
    WantIn_->SetType("12345");

    Parcel in;
    size_t pos1 = in.GetWritePosition();
    bool result = WantIn_->Marshalling(in);
    size_t pos2 = in.GetWritePosition();
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "Marshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;

    pos1 = in.GetWritePosition();
    result = WantIn_->Marshalling(in);
    pos2 = in.GetWritePosition();
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "Marshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;

    pos1 = in.GetReadPosition();
    std::shared_ptr<DistributedWantV2> WantOut_(DistributedWantV2::Unmarshalling(in));
    if (WantOut_ != nullptr) {
        pos2 = in.GetReadPosition();
        CompareWant(WantIn_, WantOut_);
        EXPECT_EQ(valueString, String::Unbox(IString::Query(WantOut_->GetParams().GetParam(keyStr))));
        GTEST_LOG_(INFO) << "Unmarshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;
    }

    pos1 = in.GetReadPosition();
    std::shared_ptr<DistributedWantV2> WantOut2_(DistributedWantV2::Unmarshalling(in));
    if (WantOut2_ != nullptr) {
        pos2 = in.GetReadPosition();
        CompareWant(WantIn_, WantOut2_);
        EXPECT_EQ(valueString, String::Unbox(IString::Query(WantOut2_->GetParams().GetParam(keyStr))));
        GTEST_LOG_(INFO) << "Unmarshalling: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;
    }
}

/**
 * @tc.number: DistributedScheduleWant_Parcelable_0500
 * @tc.name: Marshalling/Unmarshalling
 * @tc.desc: marshalling Want, and then check result.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Parcelable_0500, Function | MediumTest | Level3)
{
    GTEST_LOG_(INFO) << "DistributedScheduleWant_Parcelable_0500 start";
    std::shared_ptr<DistributedWantV2> WantIn_ = std::make_shared<DistributedWantV2>();
    ASSERT_NE(nullptr, WantIn_);

    WantIn_->AddEntity("system.test.entity");

    OHOS::AppExecFwk::ElementName element;
    element.SetAbilityName("system.test.abilityname");
    element.SetBundleName("system.test.bundlename");
    element.SetDeviceID("system.test.deviceid");
    WantIn_->SetElement(element);

    AAFwk::WantParams wantParams;
    std::string keyStr = "system.test.wantparams.key";
    std::string MIMEKEY = "mime-type";
    wantParams.SetParam(MIMEKEY, String::Box("system.test.uritype"));

    std::string valueString = "system.wantparams.value.content.test";
    wantParams.SetParam(keyStr, String::Box(valueString));
    WantIn_->SetParams(wantParams);

    Parcel in;
    bool result = false;
    result = WantIn_->Marshalling(in);
    EXPECT_EQ(result, true);
    std::shared_ptr<DistributedWantV2> WantOut_(DistributedWantV2::Unmarshalling(in));
    if (WantOut_ != nullptr) {

        bool hasentity = WantOut_->HasEntity("system.test.entity");
        GTEST_LOG_(INFO) << "WantOut_->HasEntity(system.test.entity)" << hasentity;
        EXPECT_EQ(hasentity, true);

        WantOut_->RemoveEntity(std::string("system.test.entity"));
        hasentity = WantOut_->HasEntity(std::string("system.test.entity"));
        GTEST_LOG_(INFO) << "WantOut_->RemoveEntity(system.test.entity)" << hasentity;
        EXPECT_EQ(hasentity, false);

        std::string outtype = WantOut_->GetType();
        GTEST_LOG_(INFO) << "WantOut_->GetType()" << outtype.c_str();
        EXPECT_STREQ(outtype.c_str(), std::string("system.test.uritype").c_str());

        element = WantOut_->GetElement();
        GTEST_LOG_(INFO) << "element.GetAbilityName().c_str(): " << element.GetAbilityName().c_str();
        EXPECT_STREQ(element.GetAbilityName().c_str(), std::string("system.test.abilityname").c_str());

        GTEST_LOG_(INFO) << "element->GetBundleName().c_str(): " << element.GetBundleName().c_str();
        EXPECT_STREQ(element.GetBundleName().c_str(), std::string("system.test.bundlename").c_str());

        EXPECT_STREQ(element.GetDeviceID().c_str(), std::string("system.test.deviceid").c_str());

        std::string param_content = WantOut_->GetStringParam(keyStr);
        GTEST_LOG_(INFO) << "WantOut_->GetStringParam(keyStr): " << param_content.c_str();

        GTEST_LOG_(INFO) << "DistributedScheduleWant_Parcelable_005 end";
    }
}

/**
 * @tc.number: DistributedScheduleWant_Parcelable_0501
 * @tc.name: Marshalling/Unmarshalling
 * @tc.desc: marshalling Want, and then check result.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Parcelable_0501, Function | MediumTest | Level3)
{
    GTEST_LOG_(INFO) << "DistributedScheduleWant_Parcelable_0501 start";
    std::shared_ptr<DistributedWantV2> WantIn_ = std::make_shared<DistributedWantV2>();
    ASSERT_NE(nullptr, WantIn_);

    WantIn_->SetAction("system.test.action");

    std::vector<bool> boolArrayValue = {true, false, true};
    WantIn_->SetParam(std::string("bool_arraykey"), boolArrayValue);

    std::vector<byte> byteArrayValue = {'?', 'a', '\\'};
    WantIn_->SetParam(std::string("byte_arraykey"), byteArrayValue);

    std::vector<zchar> charArrayValue = {U'e', U'l', U'l', U'o'};
    WantIn_->SetParam(std::string("char_arraykey"), charArrayValue);

    std::vector<std::string> stringArrayValue = {"stringtest1", "string@test2", "string@!#test2"};
    WantIn_->SetParam(std::string("string_arraykey"), stringArrayValue);

    DistributedWantV2 wantCopy(*WantIn_);
    std::vector<std::string> teststringArrayValue1 = WantIn_->GetStringArrayParam(std::string("string_arraykey"));
    std::vector<std::string> teststringArrayValue2 = wantCopy.GetStringArrayParam(std::string("string_arraykey"));
    bool copyarraycompare = CompareArrayData<std::string>(teststringArrayValue1, teststringArrayValue1);
    EXPECT_EQ(copyarraycompare, true);
    std::string str = (copyarraycompare == true) ? "true" : "false";
    GTEST_LOG_(INFO) << "copyarraycompare=" << str.c_str();

    Parcel in;
    bool result = false;
    result = WantIn_->Marshalling(in);
    EXPECT_EQ(result, true);
    std::shared_ptr<DistributedWantV2> WantOut_(DistributedWantV2::Unmarshalling(in));
    if (WantOut_ != nullptr) {
        GTEST_LOG_(INFO) << "WantOut_->GetAction().c_str(): " << WantOut_->GetAction().c_str();
        EXPECT_STREQ(WantOut_->GetAction().c_str(), std::string("system.test.action").c_str());

        std::vector<bool> retboolArray;
        retboolArray = WantOut_->GetBoolArrayParam(std::string("bool_arraykey"));

        bool arraycompare = CompareArrayData<bool>(retboolArray, boolArrayValue);
        EXPECT_EQ(arraycompare, true);

        std::vector<byte> retbyteArrayValue;
        retbyteArrayValue = WantOut_->GetByteArrayParam(std::string("byte_arraykey"));
        arraycompare = CompareArrayData<byte>(retbyteArrayValue, byteArrayValue);
        EXPECT_EQ(arraycompare, true);

        std::vector<zchar> retcharArrayValue;
        retcharArrayValue = WantOut_->GetCharArrayParam(std::string("char_arraykey"));
        arraycompare = CompareArrayData<zchar>(retcharArrayValue, charArrayValue);
        EXPECT_EQ(arraycompare, true);

        std::vector<std::string> retstringArrayValue;
        retstringArrayValue = WantOut_->GetStringArrayParam(std::string("string_arraykey"));
        arraycompare = CompareArrayData<std::string>(retstringArrayValue, stringArrayValue);
        EXPECT_EQ(arraycompare, true);
    }
}

/**
 * @tc.number: DistributedScheduleWant_Parcelable_0502
 * @tc.name: Marshalling/Unmarshalling
 * @tc.desc: marshalling Want, and then check result.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Parcelable_0502, Function | MediumTest | Level3)
{
    GTEST_LOG_(INFO) << "DistributedScheduleWant_Parcelable_0502 start";
    std::shared_ptr<DistributedWantV2> WantIn_ = std::make_shared<DistributedWantV2>();
    ASSERT_NE(nullptr, WantIn_);

    WantIn_->SetFlags(64);

    std::vector<short> shortArrayValue = {-1, 0, 1};
    WantIn_->SetParam(std::string("short_arraykey"), shortArrayValue);

    std::vector<int> intArrayValue = {-10, 0, 10};
    WantIn_->SetParam(std::string("int_arraykey"), intArrayValue);

    std::vector<long> longArrayValue = {-100, 0, 100};
    WantIn_->SetParam(std::string("long_arraykey"), longArrayValue);

    std::vector<float> floatArrayValue = {-100.1, 0.1, 100.1};
    WantIn_->SetParam(std::string("float_arraykey"), floatArrayValue);

    std::vector<double> doubleArrayValue = {-1000.1, 0.1, 1000.1};
    WantIn_->SetParam(std::string("double_arraykey"), doubleArrayValue);

    Parcel in;
    bool result = false;
    result = WantIn_->Marshalling(in);
    EXPECT_EQ(result, true);
    std::shared_ptr<DistributedWantV2> WantOut_(DistributedWantV2::Unmarshalling(in));
    if (WantOut_ != nullptr) {
        int flags = WantOut_->GetFlags();
        GTEST_LOG_(INFO) << "WantOut_->GetFlags(): " << flags;
        EXPECT_EQ(static_cast<int>(flags), 64);

        std::vector<short> retshortArrayValue;
        retshortArrayValue = WantOut_->GetShortArrayParam(std::string("short_arraykey"));
        bool arraycompare = CompareArrayData<short>(retshortArrayValue, shortArrayValue);
        EXPECT_EQ(arraycompare, true);

        std::vector<int> retintArrayValue;
        retintArrayValue = WantOut_->GetIntArrayParam(std::string("int_arraykey"));
        arraycompare = CompareArrayData<int>(retintArrayValue, intArrayValue);
        EXPECT_EQ(arraycompare, true);

        std::vector<long> retlonArrayValue;
        retlonArrayValue = WantOut_->GetLongArrayParam(std::string("long_arraykey"));
        arraycompare = CompareArrayData<long>(retlonArrayValue, longArrayValue);
        EXPECT_EQ(arraycompare, true);

        std::vector<float> retfloatArrayValue;
        retfloatArrayValue = WantOut_->GetFloatArrayParam(std::string("float_arraykey"));
        arraycompare = CompareArrayData<float>(retfloatArrayValue, floatArrayValue);
        EXPECT_EQ(arraycompare, true);

        std::vector<double> retdoubleArrayValue;
        retdoubleArrayValue = WantOut_->GetDoubleArrayParam(std::string("double_arraykey"));
        arraycompare = CompareArrayData<double>(retdoubleArrayValue, doubleArrayValue);
        EXPECT_EQ(arraycompare, true);
    }
}

void DistributedWantV2BaseTest::CompareWant(const std::shared_ptr<DistributedWantV2>& want1,
    const std::shared_ptr<DistributedWantV2>& want2) const
{
    DistributedOperation opt1 = want1->GetOperation();
    DistributedOperation opt2 = want2->GetOperation();
    EXPECT_EQ(opt1.GetDeviceId(), opt2.GetDeviceId());
    EXPECT_EQ(opt1.GetBundleName(), opt2.GetBundleName());
    EXPECT_EQ(opt1.GetAbilityName(), opt2.GetAbilityName());

    EXPECT_EQ(want1->GetAction(), want2->GetAction());
    EXPECT_EQ(want1->GetFlags(), want2->GetFlags());
    EXPECT_EQ(want1->GetType(), want2->GetType());
    EXPECT_EQ(want1->CountEntities(), want2->CountEntities());

    int count = want1->CountEntities();
    std::vector<std::string> entities1 = want1->GetEntities();
    std::vector<std::string> entities2 = want2->GetEntities();
    for (int i = 0; i < count; i++) {
        EXPECT_EQ(entities1.at(i), entities2.at(i));
    }

    OHOS::AppExecFwk::ElementName element1 = want1->GetElement();
    OHOS::AppExecFwk::ElementName element2 = want2->GetElement();
    EXPECT_EQ(element1.GetURI(), element1.GetURI());

    std::set<std::string> key1;
    std::set<std::string> key2;
    key1 = want1->GetParams().KeySet();
    key2 = want2->GetParams().KeySet();
    EXPECT_EQ(key1.size(), key2.size());

    std::set<std::string>::iterator iter1 = key1.begin();
    std::set<std::string>::iterator iter2 = key2.begin();
    for (; (iter1 != key1.end() && iter2 != key2.end()); iter1++, iter2++) {
        EXPECT_EQ(*iter1, *iter2);
    }
}

bool DistributedWantV2BaseTest::CompareWant(const std::shared_ptr<DistributedWantV2>& want1,
    const std::shared_ptr<DistributedWantV2>& want2, std::map<std::string, std::string>& keys) const
{
    if (want1 == nullptr || want2 == nullptr) {
        return false;
    }
    EXPECT_STREQ(want1->GetAction().c_str(), want2->GetAction().c_str());
    EXPECT_EQ(want1->CountEntities(), want2->CountEntities());

    if (want1->CountEntities() != want2->CountEntities()) {
        return false;
    }

    int count = want1->CountEntities();

    std::vector<std::string> entities1 = want1->GetEntities();
    std::vector<std::string> entities2 = want2->GetEntities();
    for (int i = 0; i < count; i++) {
        EXPECT_EQ(entities1.at(i), entities2.at(i));
    }
    EXPECT_EQ(want1->GetFlags(), want2->GetFlags());
    EXPECT_EQ(want1->GetElement(), want2->GetElement());

    for (auto it = keys.begin(); it != keys.end(); it++) {
        if (!CompareWantNumber(want1, want2, it) && !CompareWantOthers(want1, want2, it) &&
            !CompareWantArray(want1, want2, it)) {};
    }

    return true;
}

bool DistributedWantV2BaseTest::CompareWantNumber(const std::shared_ptr<DistributedWantV2>& want1,
    const std::shared_ptr<DistributedWantV2>& want2, std::map<std::string, std::string>::iterator it) const
{
    if (it->second == shortType) {
        short default1 = 123;
        short default2 = 456;
        short v1 = want1->GetShortParam(it->first, default1);
        short v2 = want2->GetShortParam(it->first, default2);
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == intType) {
        int default1 = 1230000;
        int default2 = 4560000;
        int v1 = want1->GetIntParam(it->first, default1);
        int v2 = want2->GetIntParam(it->first, default2);
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == longType) {
        long default1 = 1e8;
        long default2 = 2e8;
        long v1 = want1->GetLongParam(it->first, default1);
        long v2 = want2->GetLongParam(it->first, default2);
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == floatType) {
        float default1 = 12.3;
        float default2 = 45.6;
        float v1 = want1->GetFloatParam(it->first, default1);
        float v2 = want2->GetFloatParam(it->first, default2);
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == doubleType) {
        double default1 = 12.3;
        double default2 = 45.6;
        double v1 = want1->GetDoubleParam(it->first, default1);
        double v2 = want2->GetDoubleParam(it->first, default2);
        EXPECT_EQ(v1, v2);
        return true;
    }
    return false;
}

bool DistributedWantV2BaseTest::CompareWantOthers(const std::shared_ptr<DistributedWantV2>& want1,
    const std::shared_ptr<DistributedWantV2>& want2, std::map<std::string, std::string>::iterator it) const
{
    if (it->second == boolType) {
        bool v1 = want1->GetBoolParam(it->first, false);
        bool v2 = want2->GetBoolParam(it->first, false);
        EXPECT_EQ(v1, v2);
        EXPECT_EQ(v1, true);
        return true;
    } else if (it->second == byteType) {
        byte v1 = want1->GetByteParam(it->first, 'j');
        byte v2 = want2->GetByteParam(it->first, 'k');
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == charType) {
        zchar v1 = want1->GetCharParam(it->first, 0x01AB);
        zchar v2 = want2->GetCharParam(it->first, 0x02CD);
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == stringType) {
        std::string v1 = want1->GetStringParam(it->first);
        std::string v2 = want2->GetStringParam(it->first);
        EXPECT_EQ(v1, v2);
        return true;
    }
    return false;
}

bool DistributedWantV2BaseTest::CompareWantArray(const std::shared_ptr<DistributedWantV2>& want1,
    const std::shared_ptr<DistributedWantV2>& want2, std::map<std::string, std::string>::iterator it) const
{
    if (it->second == boolArrayType) {
        std::vector<bool> v1 = want1->GetBoolArrayParam(it->first);
        std::vector<bool> v2 = want2->GetBoolArrayParam(it->first);
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == byteArrayType) {
        std::vector<byte> v1 = want1->GetByteArrayParam(it->first);
        std::vector<byte> v2 = want2->GetByteArrayParam(it->first);
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == charArrayType) {
        std::vector<zchar> v1 = want1->GetCharArrayParam(it->first);
        std::vector<zchar> v2 = want2->GetCharArrayParam(it->first);
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == shortArrayType) {
        std::vector<short> v1 = want1->GetShortArrayParam(it->first);
        std::vector<short> v2 = want2->GetShortArrayParam(it->first);
        EXPECT_EQ(v1, v2);
    } else if (it->second == intArrayType) {
        std::vector<int> v1 = want1->GetIntArrayParam(it->first);
        std::vector<int> v2 = want2->GetIntArrayParam(it->first);
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == longArrayType) {
        std::vector<long> v1 = want1->GetLongArrayParam(it->first);
        std::vector<long> v2 = want2->GetLongArrayParam(it->first);
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == floatArrayType) {
        std::vector<float> v1 = want1->GetFloatArrayParam(it->first);
        std::vector<float> v2 = want2->GetFloatArrayParam(it->first);
        EXPECT_EQ(v1, v2);
        return true;
    } else if (it->second == doubleArrayType) {
        std::vector<double> v1 = want1->GetDoubleArrayParam(it->first);
        std::vector<double> v2 = want2->GetDoubleArrayParam(it->first);
        EXPECT_EQ(v1, v2);
        return true;
    }  else if (it->second == stringArrayType) {
        std::vector<std::string> v1 = want1->GetStringArrayParam(it->first);
        std::vector<std::string> v2 = want2->GetStringArrayParam(it->first);
        EXPECT_EQ(v1, v2);
        return true;
    }
    return false;
}

void DistributedWantV2BaseTest::SendParcelTest(const std::shared_ptr<DistributedWantV2> &want,
    std::map<std::string, std::string> &keys) const
{
    size_t pos1;
    size_t pos2;
    Parcel data;
    bool result = false;

    pos1 = data.GetWritePosition();
    result = data.WriteParcelable(want.get());
    pos2 = data.GetWritePosition();
    EXPECT_EQ(result, true);
    GTEST_LOG_(INFO) << "SendParcelTest: pos1: " << pos1 << ", pos2: " << pos2 << ", result: " << result;

    std::shared_ptr<DistributedWantV2> wantNew(data.ReadParcelable<DistributedWantV2>());
    EXPECT_NE(wantNew, nullptr);

    if (wantNew != nullptr) {
        result = CompareWant(want, wantNew, keys);
        EXPECT_EQ(result, true);
    }
}

void DistributedWantV2BaseTest::AddBoolParams(DistributedWantV2& want,
    std::map<std::string, std::string>& keys, int loop, unsigned int flag) const
{
    std::string key;
    std::string boolKey = "boolKey";
    std::string boolArrayKey = "boolArrayKey";
    for (int i = 0; i < loop; i++) {
        if (flag & FLAG_TEST_SINGLE) {
            bool boolValue = true;
            keys[boolKey + std::to_string(i)] = boolType;
            want.SetParam(boolKey + std::to_string(i), boolValue);
        }

        if (flag & FLAG_TEST_ARRAY) {
            std::vector<bool> boolArrayValue = {true, false, true};
            keys[key] = boolArrayType;
            want.SetParam(key, boolArrayValue);
        }
    }
}

void DistributedWantV2BaseTest::AddByteParams(DistributedWantV2& want,
    std::map<std::string, std::string>& keys, int loop, unsigned int flag) const
{
    std::string key;
    std::string byteKey = "byteKey";
    std::string byteArrayKey = "byteArrayKey";
    for (int i = 0; i < loop; i++) {
        if (flag & FLAG_TEST_SINGLE) {
            byte byteValue = 'z';
            key = byteKey + std::to_string(i);
            keys[key] = byteType;
            want.SetParam(key, byteValue);
        }

        if (flag & FLAG_TEST_ARRAY) {
            std::vector<byte> byteArrayValue = {'?', 'a', '\\'};
            key = byteArrayKey + std::to_string(i);
            keys[key] = byteArrayType;
            want.SetParam(key, byteArrayValue);
        }
    }
}

void DistributedWantV2BaseTest::AddCharParams(DistributedWantV2& want,
    std::map<std::string, std::string>& keys, int loop, unsigned int flag) const
{
    std::string key;
    std::string charKey = "charKey";
    std::string charArrayKey = "charArrayKey";
    for (int i = 0; i < loop; i++) {
        if (flag & FLAG_TEST_SINGLE) {
            zchar charValue = U'h';
            key = charKey + std::to_string(i);
            keys[key] = charType;
            want.SetParam(key, charValue);
        }

        if (flag & FLAG_TEST_ARRAY) {
            std::vector<zchar> charArrayValue = {U'e', U'l', U'l', U'o'};
            key = charArrayKey + std::to_string(i);
            keys[key] = charArrayType;
            want.SetParam(key, charArrayValue);
        }
    }
}

void DistributedWantV2BaseTest::AddShortParams(DistributedWantV2& want,
    std::map<std::string, std::string>& keys, int loop, unsigned int flag) const
{
    std::string key;
    std::string shortKey = "shortKey";
    std::string shortArrayKey = "shortArrayKey";
    for (int i = 0; i < loop; i++) {
        if (flag & FLAG_TEST_SINGLE) {
            short shortValue = 1;
            key = shortKey + std::to_string(i);
            keys[key] = shortType;
            want.SetParam(key, shortValue);
        }

        if (flag & FLAG_TEST_ARRAY) {
            std::vector<short> shortArrayValue = {-1, 0, 1};
            key = shortArrayKey + std::to_string(i);
            keys[key] = shortArrayType;
            want.SetParam(key, shortArrayValue);
        }
    }
}

void DistributedWantV2BaseTest::AddIntParams(DistributedWantV2& want,
    std::map<std::string, std::string>& keys, int loop, unsigned int flag) const
{
    std::string key;
    std::string intKey = "intKey";
    std::string intArrayKey = "intArrayKey";
    for (int i = 0; i < loop; i++) {
        if (flag & FLAG_TEST_SINGLE) {
            int intValue = 10;
            key = intKey + std::to_string(i);
            keys[key] = intType;
            want.SetParam(key, intValue);
        }

        if (flag & FLAG_TEST_ARRAY) {
            std::vector<int> intArrayValue = {-10, 0, 10};
            key = intArrayKey + std::to_string(i);
            keys[key] = intArrayType;
            want.SetParam(key, intArrayValue);
        }
    }
}

void DistributedWantV2BaseTest::AddLongParams(DistributedWantV2& want,
    std::map<std::string, std::string>& keys, int loop, unsigned int flag) const
{
    std::string key;
    std::string longKey = "longKey";
    std::string longArrayKey = "longArrayKey";
    for (int i = 0; i < loop; i++) {
        if (flag & FLAG_TEST_SINGLE) {
            long longValue = 100L;
            key = longKey + std::to_string(i);
            keys[key] = longType;
            want.SetParam(key, longValue);
        }

        if (flag & FLAG_TEST_ARRAY) {
            std::vector<long> longArrayValue = {-100, 0, 100};
            key = longArrayKey + std::to_string(i);
            keys[key] = longArrayType;
            want.SetParam(key, longArrayValue);
        }
    }
}

void DistributedWantV2BaseTest::AddFloatParams(DistributedWantV2& want,
    std::map<std::string, std::string>& keys, int loop, unsigned int flag) const
{
    std::string key;
    std::string floatKey = "floatKey";
    std::string floatArrayKey = "floatArrayKey";
    for (int i = 0; i < loop; i++) {
        if (flag & FLAG_TEST_SINGLE) {
            float floatValue = 100.1f;
            key = floatKey + std::to_string(i);
            keys[key] = floatType;
            want.SetParam(key, floatValue);
        }

        if (flag & FLAG_TEST_ARRAY) {
            std::vector<float> floatArrayValue = {-100.1, 0.1, 100.1};
            key = floatArrayKey + std::to_string(i);
            keys[key] = floatArrayType;
            want.SetParam(key, floatArrayValue);
        }
    }
}

void DistributedWantV2BaseTest::AddDoubleParams(DistributedWantV2& want,
    std::map<std::string, std::string>& keys, int loop, unsigned int flag) const
{
    std::string key;
    std::string doubleKey = "doubleKey";
    std::string doubleArrayKey = "doubleArrayKey";
    for (int i = 0; i < loop; i++) {
        if (flag & FLAG_TEST_SINGLE) {
            double doubleValue = 1000.1;
            key = doubleKey + std::to_string(i);
            keys[key] = doubleType;
            want.SetParam(key, doubleValue);
        }

        if (flag & FLAG_TEST_ARRAY) {
            std::vector<double> doubleArrayValue = {-1000.1, 0.1, 1000.1};
            key = doubleArrayKey + std::to_string(i);
            keys[key] = doubleArrayType;
            want.SetParam(key, doubleArrayValue);
        }
    }
}

void DistributedWantV2BaseTest::AddStringParams(DistributedWantV2& want,
    std::map<std::string, std::string>& keys, int loop, unsigned int flag) const
{
    std::string key;
    std::string stringKey = "stringKey";
    std::string stringArrayKey = "stringArrayKey";
    for (int i = 0; i < loop; i++) {
        if (flag & FLAG_TEST_SINGLE) {
            std::string stringValue = "zzzz";
            key = stringKey + std::to_string(i);
            keys[key] = stringType;
            want.SetParam(key, stringValue);
        }

        if (flag & FLAG_TEST_ARRAY) {
            std::vector<std::string> stringArrayValue = {"??", "aa", "\\\\"};
            key = stringArrayKey + std::to_string(i);
            keys[key] = stringArrayType;
            want.SetParam(key, stringArrayValue);
        }
    }
}

void DistributedWantV2BaseTest::TestStringForParseUri(std::string uri,
    std::string keyString, std::size_t &length, std::string valueStringOrigin)
{
    std::size_t head = length;
    std::string search = String::SIGNATURE + std::string(".") + keyString + std::string("=");
    std::size_t result = uri.find(search);
    EXPECT_NE(result, std::string::npos);
    EXPECT_GE(result, head);
    length += search.length();
    if (result != std::string::npos) {
        std::size_t pos = result + search.length();
        std::size_t delims = uri.find(";", pos);
        if (delims != std::string::npos) {
            std::string substring = uri.substr(pos, delims - pos);
            std::string valueStringNew = String::Unbox(String::Parse(substring));
            EXPECT_EQ(valueStringNew, valueStringOrigin);
            length += substring.length() + 1;
        }
    }
}

void DistributedWantV2BaseTest::TestFloatForParseUri(std::string uri,
    std::string keyFloat, std::size_t &length, float valueFloatOrigin)
{
    std::size_t head = length;
    std::string search = Float::SIGNATURE + std::string(".") + keyFloat + std::string("=");
    std::size_t result = uri.find(search);
    EXPECT_NE(result, std::string::npos);
    EXPECT_GE(result, head);
    length += search.length();
    if (result != std::string::npos) {
        std::size_t pos = result + search.length();
        std::size_t delims = uri.find(";", pos);
        if (delims != std::string::npos) {
            std::string substring = uri.substr(pos, delims - pos);
            float valueFloatNew = Float::Unbox(Float::Parse(substring));
            EXPECT_EQ(valueFloatNew, valueFloatOrigin);
            length += substring.length() + 1;
        }
    }
}

void DistributedWantV2BaseTest::TestFloatArrayForParseUri(std::string uri,
    std::string keyFloatArray, std::size_t &length, std::vector<float> valueFloatArrayOrigin)
{
    std::size_t head = length;
    std::string search = Array::SIGNATURE + std::string(".") + keyFloatArray + std::string("=");
    std::size_t result = uri.find(search);
    EXPECT_NE(result, std::string::npos);
    EXPECT_GE(result, head);
    length += search.length();
    if (result != std::string::npos) {
        std::size_t pos = result + search.length();
        std::size_t delims = uri.find(";", result);
        if (delims != std::string::npos) {
            std::string substring = uri.substr(pos, delims - pos);
            sptr<IArray> array = Array::Parse(substring);
            std::vector<float> valueFloatArrayNew;
            auto func = [&valueFloatArrayNew](
                            IInterface *object) { valueFloatArrayNew.push_back(Float::Unbox(IFloat::Query(object))); };
            Array::ForEach(array, func);
            EXPECT_EQ(valueFloatArrayNew, valueFloatArrayOrigin);
            length += substring.length() + 1;
        }
    }
}

void DistributedWantV2BaseTest::TestStringArrayForParseUri(std::string uri,
    std::string keyStringArray, std::size_t &length, std::vector<std::string> valueStringArrayOrigin)
{
    std::size_t head = length;
    std::string search = Array::SIGNATURE + std::string(".") + keyStringArray + std::string("=");
    std::size_t result = uri.find(search);
    EXPECT_NE(result, std::string::npos);
    EXPECT_GE(result, head);
    length += search.length();
    if (result != std::string::npos) {
        std::size_t pos = result + search.length();
        std::size_t delims = uri.find(";", result);
        if (delims != std::string::npos) {
            std::string substring = uri.substr(pos, delims - pos);
            sptr<IArray> array = Array::Parse(substring);
            std::vector<std::string> valueStringArrayNew;
            auto func = [&valueStringArrayNew](IInterface *object) {
                valueStringArrayNew.push_back(String::Unbox(IString::Query(object)));
            };
            Array::ForEach(array, func);
            EXPECT_EQ(valueStringArrayNew, valueStringArrayOrigin);
            length += substring.length() + 1;
        }
    }
}

/**
 * @tc.number: DistributedScheduleWant_Parcelable_0600
 * @tc.name: parcelable
 * @tc.desc: Verify parcelable.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Parcelable_0600, Function | MediumTest | Level3)
{
    std::string action = "want.action.test";
    unsigned int flag = 0x789;
    std::string entity = "want.entity.test";
    OHOS::AppExecFwk::ElementName element("bundlename", "appname", "abilityname");

    std::shared_ptr<DistributedWantV2> want = std::make_shared<DistributedWantV2>();
    if (want != nullptr) {
        want->SetAction(action);
        want->AddEntity(entity);
        want->AddFlags(flag);
        want->SetElement(element);

        std::map<std::string, std::string> keys;

        SendParcelTest(want, keys);
    }
}

/**
 * @tc.number: DistributedScheduleWant_Parcelable_0700
 * @tc.name: parcelable
 * @tc.desc: Verify parcelable.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Parcelable_0700, Function | MediumTest | Level3)
{
    std::string action = "want.action.test";
    unsigned int flag = 0x789;
    std::string entity = "want.entity.test";
    OHOS::AppExecFwk::ElementName element("bundlename", "appname", "abilityname");

    std::shared_ptr<DistributedWantV2> want = std::make_shared<DistributedWantV2>();
    if (want != nullptr) {
        want->SetAction(action);
        want->AddEntity(entity);
        want->AddFlags(flag);
        want->SetElement(element);

        int loop = 1;
        std::map<std::string, std::string> keys;

        AddByteParams(*(want.get()), keys, loop, FLAG_TEST_BOTH);
        AddCharParams(*(want.get()), keys, loop, FLAG_TEST_BOTH);
        AddShortParams(*(want.get()), keys, loop, FLAG_TEST_BOTH);
        AddIntParams(*(want.get()), keys, loop, FLAG_TEST_BOTH);
        AddLongParams(*(want.get()), keys, loop, FLAG_TEST_BOTH);
        AddFloatParams(*(want.get()), keys, loop, FLAG_TEST_BOTH);
        AddDoubleParams(*(want.get()), keys, loop, FLAG_TEST_BOTH);
        AddStringParams(*(want.get()), keys, loop, FLAG_TEST_BOTH);

        SendParcelTest(want, keys);
    }
}

/**
 * @tc.number: DistributedScheduleWant_Parcelable_0800
 * @tc.name: parcelable
 * @tc.desc: Verify parcelable.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Parcelable_0800, Function | MediumTest | Level3)
{
    std::string action = "want.action.test";
    unsigned int flag = 0x789;
    std::string entity = "want.entity.test";
    OHOS::AppExecFwk::ElementName element("bundlename", "appname", "abilityname");

    std::shared_ptr<DistributedWantV2> want = std::make_shared<DistributedWantV2>();
    if (want != nullptr) {
        want->SetAction(action);
        want->AddEntity(entity);
        want->AddFlags(flag);
        want->SetElement(element);
        std::map<std::string, std::string> keys;

        SendParcelTest(want, keys);
    }
}

/**
 * @tc.number:  DistributedScheduleWant_Flags_0100
 * @tc.name: SetFlags/AddFlags/GetFlags/RemoveFlags
 * @tc.desc: Verify SetFlags/AddFlags/GetFlags/RemoveFlags.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Flags_0100, Function | MediumTest | Level3)
{
    ASSERT_NE(want_, nullptr);
    int flags = 3;
    int returnsflags;
    int description = 8;

    want_->SetFlags(description);
    want_->AddFlags(flags);
    returnsflags = want_->GetFlags();
    EXPECT_EQ(11, returnsflags);

    want_->RemoveFlags(flags);
    returnsflags = want_->GetFlags();
    EXPECT_EQ(description, returnsflags);
}

/**
 * @tc.number:  DistributedScheduleWant_ClearWant_0100
 * @tc.name: ClearWant
 * @tc.desc: Verify ClearWant.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_ClearWant_0100, Function | MediumTest | Level3)
{
    ASSERT_NE(want_, nullptr);
    DistributedWantV2 want;
    ElementName elementName;
    std::string empty = "";
    want_->ClearWant(&want);

    EXPECT_EQ((uint)0, want_->GetFlags());
    EXPECT_EQ(empty, want_->GetType());
    EXPECT_EQ(empty, want_->GetAction());
    EXPECT_EQ(elementName, want_->GetElement());
    EXPECT_EQ((size_t)0, want_->GetEntities().size());
    EXPECT_EQ(0, want_->CountEntities());
}

/**
 * @tc.number:  DistributedScheduleWant_replaceParams_0100
 * @tc.name: replaceParams(wantParams)
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_replaceParams_0100, Function | MediumTest | Level3)
{
    ASSERT_NE(want_, nullptr);
    AAFwk::WantParams wantParams;
    std::string keyStr = "123";
    std::string valueStr = "123";
    wantParams.SetParam(keyStr, String::Box(valueStr));
    want_->ReplaceParams(wantParams);

    EXPECT_EQ(valueStr, String::Unbox(IString::Query(want_->GetParams().GetParam(keyStr))));
}

/**
 * @tc.number:  DistributedScheduleWant_setElement_0100
 * @tc.name:setElement / setElementName
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_setElement_0100, Function | MediumTest | Level3)
{
    ASSERT_NE(want_, nullptr);
    std::string valueStr1 = "xxxxx";
    std::string valueStr2 = "uaid";
    std::string valueStr3 = "uaygfi";

    OHOS::AppExecFwk::ElementName elementname1;
    OHOS::AppExecFwk::ElementName elementname2;
    OHOS::AppExecFwk::ElementName elementname3;
    ElementName elementname4;
    elementname1.SetAbilityName(valueStr1);
    elementname2.SetDeviceID(valueStr2);
    elementname3.SetBundleName(valueStr3);
    want_->SetElement(elementname1);
    EXPECT_EQ(valueStr1, want_->GetElement().GetAbilityName());

    want_->SetElement(elementname2);
    EXPECT_EQ(valueStr2, want_->GetElement().GetDeviceID());

    want_->SetElement(elementname3);
    EXPECT_EQ(valueStr3, want_->GetElement().GetBundleName());

    want_->SetElementName(valueStr3, valueStr1);
    EXPECT_EQ(valueStr1, want_->GetElement().GetAbilityName());
    EXPECT_EQ(valueStr3, want_->GetElement().GetBundleName());

    want_->SetElementName(valueStr2, valueStr3, valueStr1);
    EXPECT_EQ(valueStr1, want_->GetElement().GetAbilityName());
    EXPECT_EQ(valueStr2, want_->GetElement().GetDeviceID());
    EXPECT_EQ(valueStr3, want_->GetElement().GetBundleName());
}

/**
 * @tc.number:  DistributedScheduleWant_Action_0200
 * @tc.name:SetAction / GetAction
 * @tc.desc: Verify the function when the input string is empty.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Action_0200, Function | MediumTest | Level3)
{
    ASSERT_NE(want_, nullptr);
    std::string setValue;
    want_->SetAction(setValue);
    EXPECT_EQ(setValue, want_->GetAction());
}

/**
 * @tc.number:  DistributedScheduleWant_Action_0300
 * @tc.name:SetAction / GetAction
 * @tc.desc: Verify the function when the input string contains special characters.
 */
HWTEST_F(DistributedWantV2BaseTest, DistributedScheduleWant_Action_0300, Function | MediumTest | Level3)
{
    ASSERT_NE(want_, nullptr);
    std::string setValue("action.system.com");
    want_->SetAction(setValue);
    EXPECT_STREQ(setValue.c_str(), want_->GetAction().c_str());
}

using testByteType = std::tuple<std::string, std::string, byte, byte, byte>;
class DistributedWantV2ParametersBoolArrayTest : public testing::TestWithParam<testByteType> {
public:
    DistributedWantV2ParametersBoolArrayTest()
    {
        want_ = nullptr;
    }
    ~DistributedWantV2ParametersBoolArrayTest()
    {
        want_ = nullptr;
    }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<DistributedWantV2> want_;
};

void DistributedWantV2ParametersBoolArrayTest::SetUpTestCase(void)
{}

void DistributedWantV2ParametersBoolArrayTest::TearDownTestCase(void)
{}

void DistributedWantV2ParametersBoolArrayTest::SetUp(void)
{
    want_ = std::make_shared<DistributedWantV2>();
}

void DistributedWantV2ParametersBoolArrayTest::TearDown(void)
{}

/**
 * @tc.number:  DistributedScheduleWant_BoolArr_0100
 * @tc.name:SetBoolArrayParam/GetBoolArrayParam
 * @tc.desc: Verify when parameter change.
 */
HWTEST_P(DistributedWantV2ParametersBoolArrayTest,
    DistributedScheduleWant_BoolArr_0100, Function | MediumTest | Level3)
{
    std::string setKey = std::get<0>(GetParam());
    std::string getKey = std::get<1>(GetParam());
    byte setValue = std::get<2>(GetParam());
    byte defaultValue = std::get<3>(GetParam());
    byte result = std::get<4>(GetParam());
    want_->SetParam(setKey, setValue);
    EXPECT_EQ(result, want_->GetByteParam(getKey, defaultValue));
}

INSTANTIATE_TEST_SUITE_P(WantParametersBoolArrayTestCaseP, DistributedWantV2ParametersBoolArrayTest,
    testing::Values(testByteType("", "aa", '#', 'U', 'U'), testByteType("", "", 'N', 'K', 'N'),
        testByteType("1*中_aR", "aa", 'a', '%', '%'), testByteType("1*中_aR", "1*中_aR", 'a', 'z', 'a')));

using testBoolArrayType =
    std::tuple<std::string, std::string, std::vector<bool>, std::vector<bool>, std::vector<bool>>;
class DistributedWantV2BoolArrayParamTest : public testing::TestWithParam<testBoolArrayType> {
public:
    DistributedWantV2BoolArrayParamTest()
    {
        want_ = nullptr;
    }
    ~DistributedWantV2BoolArrayParamTest()
    {
        want_ = nullptr;
    }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
    std::shared_ptr<DistributedWantV2> want_;
};

void DistributedWantV2BoolArrayParamTest::SetUpTestCase(void)
{}

void DistributedWantV2BoolArrayParamTest::TearDownTestCase(void)
{}

void DistributedWantV2BoolArrayParamTest::SetUp(void)
{
    want_ = std::make_shared<DistributedWantV2>();
}

void DistributedWantV2BoolArrayParamTest::TearDown(void)
{}

/**
 * @tc.number:  DistributedScheduleWant_BoolArray_0200
 * @tc.name:SetBoolArrayParam/GetBoolArrayParam
 * @tc.desc: Verify when parameter change.
 */
HWTEST_P(DistributedWantV2BoolArrayParamTest, DistributedScheduleWant_BoolArray_0200, Function | MediumTest | Level3)
{
    ASSERT_NE(want_, nullptr);
    std::string setKey = std::get<0>(GetParam());
    std::string getKey = std::get<1>(GetParam());
    std::vector<bool> setValue = std::get<2>(GetParam());
    std::vector<bool> defaultValue = std::get<3>(GetParam());
    std::vector<bool> result = std::get<4>(GetParam());
    want_->SetParam(setKey, setValue);
    EXPECT_EQ(result, want_->GetBoolArrayParam(getKey));
}