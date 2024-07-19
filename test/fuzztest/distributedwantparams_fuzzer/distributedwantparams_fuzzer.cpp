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
#include <iostream>

#include "byte_wrapper.h"
#include "distributed_want_params.h"
#include "distributed_want_params_wrapper.h"
#include "double_wrapper.h"
#include "float_wrapper.h"
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
}
uint32_t GetU32Data(const char* ptr)
{
    // convert fuzz input data to an integer
    return (ptr[POS_0] << OFFSET_24) | (ptr[POS_1] << OFFSET_16) | (ptr[POS_2] << OFFSET_8) | ptr[POS_3];
}

bool DoSomethingInterestingWithMyAPI_DistributedWantParams_001(const char* data, size_t size)
{
    UnsupportedData other;
    std::shared_ptr<UnsupportedData> unsupportedData = std::make_shared<UnsupportedData>(other);
    DistributedWantParams wantOther;
    std::shared_ptr<DistributedWantParams> wantParams = std::make_shared<DistributedWantParams>(wantOther);
    std::string key(data, size);
    int8_t byteValue = static_cast<int8_t>(GetU32Data(data));
    sptr<IInterface> stringIt = String::Box(key);
    wantParams->SetParam(key, stringIt);
    wantParams->KeySet();
    wantParams->HasParam(key);
    wantParams->IsEmpty();
    Parcel parcel;
    sptr<IInterface> byteIt = Byte::Box(byteValue);
    wantParams->WriteToParcelByte(parcel, byteIt);
    return true;
}

bool DoSomethingInterestingWithMyAPI_DistributedWantParams_002(const char* data, size_t size)
{
    DistributedWantParams wantOther;
    std::shared_ptr<DistributedWantParams> wantParams = std::make_shared<DistributedWantParams>(wantOther);
    Parcel parcel;
    IArray* ao = nullptr;
    wantParams->WriteArrayToParcelChar(parcel, ao);
    wantParams->WriteArrayToParcelShort(parcel, ao);
    wantParams->WriteToParcelFD(parcel, wantOther);
    wantParams->WriteToParcelRemoteObject(parcel, wantOther);
    float floatValue = 0.0;
    sptr<IInterface> floatIt = Float::Box(floatValue);
    wantParams->WriteToParcelFloat(parcel, floatIt);
    sptr<IArray> array;
    wantParams->ReadFromParcelArrayChar(parcel, array);
    wantParams->ReadFromParcelArrayShort(parcel, array);
    std::string key(data, size);
    int type = static_cast<int>(GetU32Data(data));
    wantParams->ReadFromParcelWantParamWrapper(parcel, key, type);
    wantParams->ReadFromParcelFD(parcel, key);
    wantParams->ReadFromParcelRemoteObject(parcel, key);
    wantParams->ReadFromParcelFloat(parcel, key);
    return true;
}

bool DoSomethingInterestingWithMyAPI_DistributedWantParams_003(const char* data, size_t size)
{
    DistributedWantParams wantOther;
    std::shared_ptr<DistributedWantParams> wantParams = std::make_shared<DistributedWantParams>(wantOther);
    Parcel parcel;
    char charValue = *data;
    sptr<IInterface> charIt = Char::Box(charValue);
    wantParams->WriteToParcelChar(parcel, charIt);
    short shortValue = 0;
    sptr<IInterface> shortIt = Short::Box(shortValue);
    wantParams->WriteToParcelShort(parcel, shortIt);
    double doubleValue = 0.0;
    sptr<IInterface> doubleIt = Double::Box(doubleValue);
    wantParams->WriteToParcelDouble(parcel, doubleIt);
    IArray* ao = nullptr;
    wantParams->WriteArrayToParcelString(parcel, ao);
    wantParams->WriteArrayToParcelBool(parcel, ao);
    wantParams->WriteArrayToParcelByte(parcel, ao);
    wantParams->WriteArrayToParcelInt(parcel, ao);
    wantParams->WriteArrayToParcelLong(parcel, ao);
    wantParams->WriteArrayToParcelFloat(parcel, ao);
    wantParams->WriteArrayToParcelDouble(parcel, ao);
    return true;
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    /* Run your code on data */
    if (data == nullptr) {
        std::cout << "invalid data" << std::endl;
        return 0;
    }

    /* Validate the length of size */
    if (size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return 0;
    }

    char* ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }

    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, data, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }

    OHOS::DoSomethingInterestingWithMyAPI_DistributedWantParams_001(ch, size);
    OHOS::DoSomethingInterestingWithMyAPI_DistributedWantParams_002(ch, size);
    OHOS::DoSomethingInterestingWithMyAPI_DistributedWantParams_003(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}
