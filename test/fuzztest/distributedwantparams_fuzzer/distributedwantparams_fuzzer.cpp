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

#include "distributedwantparams_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <iostream>

#include "array_wrapper.h"
#include "bool_wrapper.h"
#include "byte_wrapper.h"
#include "distributed_want_params.h"
#include "distributed_want_params_wrapper.h"
#include "double_wrapper.h"
#include "float_wrapper.h"
#include "int_wrapper.h"
#include "long_wrapper.h"
#include "securec.h"
#include "short_wrapper.h"
#include "string_wrapper.h"
#include "zchar_wrapper.h"

using namespace OHOS::AAFwk;
using namespace OHOS::DistributedSchedule;

namespace OHOS {
namespace {
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
constexpr int32_t POS_0 = 0;
constexpr int32_t POS_1 = 1;
constexpr int32_t POS_2 = 2;
constexpr int32_t POS_3 = 3;
constexpr int32_t OFFSET_24 = 24;
constexpr int32_t OFFSET_16 = 16;
constexpr int32_t OFFSET_8 = 8;
constexpr int32_t MID_HALF = 2;
constexpr size_t MAX_TEST_STRING_LEN = 32;

inline size_t CalculateMid(size_t size)
{
    return size / MID_HALF;
}
}
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[POS_0] << OFFSET_24) | (ptr[POS_1] << OFFSET_16) | (ptr[POS_2] << OFFSET_8) | ptr[POS_3];
}

bool DoSomethingInterestingWithMyApiDistributedWantParams001(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }

    DistributedWantParams wantOther;
    std::string key(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<DistributedWantParams> wantParams = std::make_shared<DistributedWantParams>(wantOther);
    sptr<AAFwk::IArray> array = new (std::nothrow) AAFwk::Array(0, DistributedSchedule::g_IID_IDistributedWantParams);
    wantParams->SetParam(key, array);
    IArray *iarray = IArray::Query(array);
    sptr<IArray> destAO = nullptr;
    wantParams->NewArrayData(iarray, destAO);
    sptr<IInterface> stringIt = String::Box(key);
    wantParams->Remove(key);
    wantParams->SetParam(key, stringIt);
    wantParams->KeySet();
    wantParams->HasParam(key);
    wantParams->IsEmpty();
    wantParams->GetParams();
    return true;
}

bool DoSomethingInterestingWithMyApiDistributedWantParams002(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }

    DistributedWantParams wantOther;
    std::shared_ptr<DistributedWantParams> wantParams = std::make_shared<DistributedWantParams>(wantOther);
    Parcel parcel;
    IArray* ao = nullptr;
    wantParams->WriteArrayToParcelChar(parcel, ao);
    wantParams->WriteArrayToParcelShort(parcel, ao);
    wantParams->WriteArrayToParcelString(parcel, ao);
    wantParams->WriteArrayToParcelBool(parcel, ao);
    wantParams->WriteArrayToParcelByte(parcel, ao);
    wantParams->WriteArrayToParcelInt(parcel, ao);
    wantParams->WriteArrayToParcelLong(parcel, ao);
    wantParams->WriteArrayToParcelFloat(parcel, ao);
    wantParams->WriteArrayToParcelDouble(parcel, ao);
    long longValue = static_cast<long>(GetU32Data(reinterpret_cast<const char*>(data)));
    sptr<IInterface> longIt = Long::Box(longValue);
    wantParams->WriteToParcelLong(parcel, longIt);
    float floatValue = static_cast<float>(GetU32Data(reinterpret_cast<const char*>(data)));
    sptr<IInterface> floatIt = Float::Box(floatValue);
    wantParams->WriteToParcelFloat(parcel, floatIt);

    sptr<IArray> array;
    wantParams->ReadFromParcelArrayChar(parcel, array);
    wantParams->ReadFromParcelArrayShort(parcel, array);
    wantParams->ReadFromParcelArrayString(parcel, array);
    wantParams->ReadFromParcelArrayBool(parcel, array);
    wantParams->ReadFromParcelArrayByte(parcel, array);
    wantParams->ReadFromParcelArrayInt(parcel, array);
    wantParams->ReadFromParcelArrayLong(parcel, array);
    wantParams->ReadFromParcelArrayFloat(parcel, array);
    wantParams->ReadFromParcelArrayDouble(parcel, array);
    std::string key(reinterpret_cast<const char*>(data), size);
    wantParams->ReadFromParcelLong(parcel, key);
    wantParams->ReadFromParcelFloat(parcel, key);

    wantParams->ReadArrayToParcel(parcel, GetU32Data(reinterpret_cast<const char*>(data)) % OFFSET_16, array);
    return true;
}

bool DoSomethingInterestingWithMyApiDistributedWant003(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }

    DistributedWantParams wantOther;
    std::shared_ptr<DistributedWantParams> wantParams = std::make_shared<DistributedWantParams>(wantOther);
    Parcel parcel;
    std::string key(reinterpret_cast<const char*>(data), size);
    int8_t byteValue = static_cast<int8_t>(GetU32Data(reinterpret_cast<const char*>(data)));
    sptr<IInterface> byteIt = Byte::Box(byteValue);
    wantParams->WriteToParcelByte(parcel, byteIt);
    sptr<IInterface> stringIt = String::Box(key);
    wantParams->WriteToParcelString(parcel, stringIt);
    bool boolValue = static_cast<bool>(GetU32Data(reinterpret_cast<const char*>(data)) > FOO_MAX_LEN);
    sptr<IInterface> boolIt = Boolean::Box(boolValue);
    wantParams->WriteToParcelBool(parcel, boolIt);
    char charValue = *data;
    sptr<IInterface> charIt = Char::Box(charValue);
    wantParams->WriteToParcelChar(parcel, charIt);
    short shortValue = static_cast<short>(GetU32Data(reinterpret_cast<const char*>(data)));
    sptr<IInterface> shortIt = Short::Box(shortValue);
    wantParams->WriteToParcelShort(parcel, shortIt);
    double doubleValue = static_cast<double>(GetU32Data(reinterpret_cast<const char*>(data)));
    sptr<IInterface> doubleIt = Double::Box(doubleValue);
    wantParams->WriteToParcelDouble(parcel, doubleIt);
    int32_t intValue = static_cast<int32_t>(GetU32Data(reinterpret_cast<const char*>(data)));
    sptr<IInterface> intIt = Integer::Box(intValue);
    wantParams->WriteToParcelInt(parcel, intIt);
    wantParams->WriteToParcelFD(parcel, wantOther);
    wantParams->WriteToParcelRemoteObject(parcel, wantOther);

    int type = static_cast<int>(GetU32Data(reinterpret_cast<const char*>(data)));
    wantParams->ReadFromParcelInt8(parcel, key);
    wantParams->ReadFromParcelString(parcel, key);
    wantParams->ReadFromParcelBool(parcel, key);
    wantParams->ReadFromParcelChar(parcel, key);
    wantParams->ReadFromParcelShort(parcel, key);
    wantParams->ReadFromParcelDouble(parcel, key);
    wantParams->ReadFromParcelInt(parcel, key);
    wantParams->ReadFromParcelFD(parcel, key);
    wantParams->ReadFromParcelRemoteObject(parcel, key);
    wantParams->ReadFromParcelWantParamWrapper(parcel, key, type);

    wantParams->WriteToParcelByte(parcel, byteIt);
    wantParams->ReadFromParcel(parcel);

    DistributedUnsupportedData uData;
    std::shared_ptr<DistributedUnsupportedData> unsupportedData = std::make_shared<DistributedUnsupportedData>(uData);
    wantParams->cachedUnsupportedData_.emplace_back(std::move(uData));
    wantParams->DoMarshalling(parcel);
    wantParams->cachedUnsupportedData_.clear();
    return true;
}

bool DoSomethingInterestingWithMyApiDistributedWantParams004(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }

    DistributedWantParams wantOther;
    std::shared_ptr<DistributedWantParams> wantParams = std::make_shared<DistributedWantParams>(wantOther);

    std::string value(reinterpret_cast<const char*>(data), size);
    sptr<IInterface> stringObj =
        DistributedWantParams::GetInterfaceByType(DistributedWantParams::VALUE_TYPE_STRING, value);
    wantParams->CompareInterface(stringObj, stringObj, DistributedWantParams::VALUE_TYPE_STRING);

    std::string keyStr = "12345667";
    wantParams->SetParam(keyStr, String::Box(value));
    Parcel in;
    wantParams->Marshalling(in);
    std::shared_ptr<DistributedWantParams> wantParamsNew(DistributedWantParams::Unmarshalling(in));

    wantParams->ToWantParams();
    return true;
}

bool DistributedWantParamWrapperEqualsFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }
    size_t mid = CalculateMid(size);

    DistributedWantParams wantOther;
    std::shared_ptr<DistributedWantParams> wantParams1 = std::make_shared<DistributedWantParams>(wantOther);
    std::string key1(reinterpret_cast<const char*>(data), mid);
    std::string value1(reinterpret_cast<const char*>(data + mid), size - mid);
    wantParams1->SetParam(key1, String::Box(value1));

    std::shared_ptr<DistributedWantParams> wantParams2 = std::make_shared<DistributedWantParams>(wantOther);
    std::string key2(reinterpret_cast<const char*>(data + mid), size - mid);
    std::string value2(reinterpret_cast<const char*>(data), mid);
    wantParams2->SetParam(key2, String::Box(value2));

    DistributedWantParamWrapper wrapper1(*wantParams1);
    DistributedWantParamWrapper wrapper2(*wantParams2);

    bool result = wrapper1.Equals(wrapper2);

    return result;
}

bool DistributedWantParamWrapperFindMatchingBraceFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }
    std::string inputStr(reinterpret_cast<const char*>(data), size);

    size_t startPos = size > 0 ? data[0] % size : 0;

    DistributedWantParams wantOther;
    std::shared_ptr<DistributedWantParams> wantParams = std::make_shared<DistributedWantParams>(wantOther);
    DistributedWantParamWrapper wrapper(*wantParams);
    size_t result = wrapper.FindMatchingBrace(inputStr, startPos);

    return result >= startPos && result <= inputStr.size();
}

bool DistributedWantParamWrapperBoxFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }
    size_t mid = CalculateMid(size);
    std::string key(reinterpret_cast<const char*>(data), mid);
    std::string value(reinterpret_cast<const char*>(data + mid), size - mid);

    DistributedWantParams wantParams;
    wantParams.SetParam(key, String::Box(value));
    auto boxedObject = DistributedWantParamWrapper::Box(std::move(wantParams));
    if (boxedObject == nullptr) {
        return false;
    }
    return true;
}

bool DistributedWantParamWrapperGerTypedIdFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return false;
    }
    std::string inputStr(reinterpret_cast<const char*>(data), size);

    size_t startPos = size > 0 ? data[0] % size : 0;

    DistributedWantParams wantOther;
    std::shared_ptr<DistributedWantParams> wantParams = std::make_shared<DistributedWantParams>(wantOther);
    DistributedWantParamWrapper wrapper(*wantParams);
    int typeId = wrapper.GerTypedId(inputStr, startPos);

    return typeId >= 0;
}

void DistributedWantParamQueryFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    size_t testSize = (size < MAX_TEST_STRING_LEN) ? size : MAX_TEST_STRING_LEN;
    std::string testStr(reinterpret_cast<const char*>(data), testSize);
    sptr<AAFwk::IInterface> iIt = String::Box(testStr);

    DistributedWantParams::ArrayQueryToStr(iIt);
    DistributedWantParams::DistributedWantParamsQueryToStr(iIt);
    DistributedWantParams::BooleanQueryEquals(iIt);
    DistributedWantParams::ByteQueryEquals(iIt);
    DistributedWantParams::CharQueryEquals(iIt);
    DistributedWantParams::ArrayQueryEquals(iIt);
    DistributedWantParams::DistributedWantParamsQueryEquals(iIt);
    DistributedWantParams::ShortQueryEquals(iIt);
    DistributedWantParams::IntegerQueryEquals(iIt);
    DistributedWantParams::LongQueryEquals(iIt);
    DistributedWantParams::FloatQueryEquals(iIt);
    DistributedWantParams::DoubleQueryEquals(iIt);
    DistributedWantParams::GetNumberDataType(iIt);
    DistributedWantParams::BooleanQueryToStr(iIt);
    DistributedWantParams::ByteQueryToStr(iIt);
    DistributedWantParams::CharQueryToStr(iIt);
    DistributedWantParams::ShortQueryToStr(iIt);
    DistributedWantParams::IntegerQueryToStr(iIt);
    DistributedWantParams::LongQueryToStr(iIt);
    DistributedWantParams::FloatQueryToStr(iIt);
    DistributedWantParams::DoubleQueryToStr(iIt);
}

void DistributedUnsupportedDataCopyAssignFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < U32_AT_SIZE) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    DistributedUnsupportedData lhs;
    DistributedUnsupportedData rhs;

    std::string keyStr = fdp.ConsumeRandomLengthString();
    rhs.key = std::u16string(keyStr.begin(), keyStr.end());
    rhs.type = fdp.ConsumeIntegral<int>();
    rhs.size = fdp.ConsumeIntegralInRange<int>(POS_1, FOO_MAX_LEN);
    rhs.buffer = new uint8_t[rhs.size];
    std::vector<uint8_t> buf = fdp.ConsumeBytes<uint8_t>(rhs.size);
    if (memcpy_s(rhs.buffer, rhs.size, buf.data(), buf.size()) != 0) {
        delete[] rhs.buffer;
        rhs.buffer = nullptr;
        return;
    }

    lhs = rhs;
}

void DistributedUnsupportedDataMoveAssignFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < U32_AT_SIZE) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    DistributedUnsupportedData lhs;
    DistributedUnsupportedData rhs;

    std::string keyStr = fdp.ConsumeRandomLengthString();
    rhs.key = std::u16string(keyStr.begin(), keyStr.end());
    rhs.type = fdp.ConsumeIntegral<int>();
    rhs.size = fdp.ConsumeIntegralInRange<int>(POS_1, FOO_MAX_LEN);
    rhs.buffer = new uint8_t[rhs.size];
    std::vector<uint8_t> buf = fdp.ConsumeBytes<uint8_t>(rhs.size);
    if (memcpy_s(rhs.buffer, rhs.size, buf.data(), buf.size()) != 0) {
        delete[] rhs.buffer;
        rhs.buffer = nullptr;
        return;
    }

    lhs = std::move(rhs);
}

}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyApiDistributedWantParams001(data, size);
    OHOS::DoSomethingInterestingWithMyApiDistributedWantParams002(data, size);
    OHOS::DoSomethingInterestingWithMyApiDistributedWant003(data, size);
    OHOS::DoSomethingInterestingWithMyApiDistributedWantParams004(data, size);
    OHOS::DistributedWantParamWrapperEqualsFuzzTest(data, size);
    OHOS::DistributedWantParamWrapperFindMatchingBraceFuzzTest(data, size);
    OHOS::DistributedWantParamWrapperBoxFuzzTest(data, size);
    OHOS::DistributedWantParamWrapperGerTypedIdFuzzTest(data, size);
    OHOS::DistributedWantParamQueryFuzzTest(data, size);
    OHOS::DistributedUnsupportedDataCopyAssignFuzzTest(data, size);
    OHOS::DistributedUnsupportedDataMoveAssignFuzzTest(data, size);
    return 0;
}
