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

#include "distributedwant_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <iostream>

#include "bool_wrapper.h"
#include "distributed_want.h"
#include "securec.h"

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

bool DoSomethingInterestingWithMyAPI_DistributedWant_001(const char* data, size_t size)
{
    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    unsigned int flags = static_cast<unsigned int>(GetU32Data(data));
    want->SetFlags(flags);
    want->RemoveFlags(flags);
    want->AddFlags(flags);
    std::string entity(data, size);
    want->AddEntity(entity);
    want->HasEntity(entity);
    want->RemoveEntity(entity);
    std::string bundleName(data, size);
    want->SetBundle(bundleName);
    std::string deviceId(data, size);
    want->SetDeviceId(deviceId);
    want->SetElementName(bundleName, entity);
    want->SetElementName(deviceId, bundleName, entity);
    return true;
}

bool DoSomethingInterestingWithMyAPI_DistributedWant_002(const char* data, size_t size)
{
    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    std::string type(data, size);
    want->SetType(type);
    want->FormatType(type);
    Uri uri(type);
    want->SetUri(uri);
    want->SetUriAndType(uri, type);
    want->FormatUri(uri);
    want->FormatUri(type);
    char* charUri;
    want->WantParseUri(charUri);
    want->GetLowerCaseScheme(uri);
    want->FormatUriAndType(uri, type);
    want->FormatMimeType(type);

    std::string str(data, size);
    want->CheckParams(str);
    want->ParseUri(str);
    DistributedWant wantNew;
    want->WantToUri(wantNew);
    want->ToUri();
    want->GenerateUriString(str);
    want->ToUriStringInner(str);
    return true;
}

bool DoSomethingInterestingWithMyAPI_DistributedWant_003(const char* data, size_t size)
{
    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    want->CountEntities();
    DistributedWant *wantptr = nullptr;
    want->GetScheme();
    AppExecFwk::ElementName elementName;
    wantptr = want->MakeMainAbility(elementName);
    if (wantptr) {
        delete wantptr;
        wantptr = nullptr;
    }
    DistributedOperation operation;
    want->SetOperation(operation);
    wantptr = want->CloneOperation();
    if (wantptr) {
        delete wantptr;
        wantptr = nullptr;
    }
    std::string key(data, size);
    want->HasParameter(key);
    std::string content(data, size);
    std::string prop(data, size);
    std::string value(data, size);
    want->ParseContent(content, prop, value);
    std::string str(data, size);
    want->Decode(str);
    want->Encode(str);
    nlohmann::json wantJson;
    want->ReadFromJson(wantJson);
    return true;
}

bool DoSomethingInterestingWithMyAPI_DistributedWant_004(const char* data, size_t size)
{
    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    std::string key(data, size);
    sptr<IRemoteObject> remoteObject;
    want->SetParam(key, remoteObject);
    want->GetRemoteObject(key);
    std::vector<bool> boolValue;
    want->SetParam(key, boolValue);
    want->GetBoolArrayParam(key);
    byte byteValue = '\0';
    want->SetParam(key, byteValue);
    want->GetByteParam(key, byteValue);
    std::vector<byte> byteVector;
    want->SetParam(key, byteVector);
    want->GetByteArrayParam(key);
    zchar charValue = U'\0';
    want->SetParam(key, charValue);
    want->GetCharParam(key, charValue);
    want->GetParams();
    return true;
}

bool DoSomethingInterestingWithMyAPI_DistributedWant_005(const char* data, size_t size)
{
    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    std::string key(data, size);
    std::vector<zchar> charVector;
    want->SetParam(key, charVector);
    want->GetCharArrayParam(key);
    std::vector<int> intVector;
    want->SetParam(key, intVector);
    want->GetIntArrayParam(key);
    double doubleValue = 0.0;
    want->SetParam(key, doubleValue);
    want->GetDoubleParam(key, doubleValue);
    std::vector<double> doubleVector;
    want->SetParam(key, doubleVector);
    want->GetDoubleArrayParam(key);
    float floatValue = 0.0;
    want->SetParam(key, floatValue);
    want->GetFloatParam(key, floatValue);
    bool boolValue = true;
    want->SetParam(key, boolValue);
    want->GetBoolParam(key, boolValue);

    std::string wantStr = want->ToString();
    want->FromString(wantStr);
    return true;
}

bool DoSomethingInterestingWithMyAPI_DistributedWant_006(const char* data, size_t size)
{
    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    std::string key(data, size);
    std::vector<float> floatVector;
    want->SetParam(key, floatVector);
    want->GetFloatArrayParam(key);
    long longValue = 0;
    want->SetParam(key, longValue);
    want->GetShortParam(key, longValue);
    std::vector<long> longVector;
    want->SetParam(key, longVector);
    want->GetLongArrayParam(key);
    short shortValue = 0;
    want->SetParam(key, shortValue);
    want->GetShortParam(key, shortValue);
    std::vector<short> shortVector;
    want->SetParam(key, shortVector);
    want->GetShortArrayParam(key);
    std::string stringValue(data, size);
    want->SetParam(key, stringValue);
    want->GetStringParam(key);
    std::vector<std::string> stringVector;
    want->SetParam(key, stringVector);
    want->GetStringArrayParam(key);
    want->RemoveParam(key);

    bool boolValue = true;
    DistributedWantParams dWantParams;
    dWantParams.SetParam(key, Boolean::Box(boolValue));
    want->SetParams(dWantParams);
    want->ReplaceParams(dWantParams);
    DistributedWant dWant;
    want->ReplaceParams(dWant);
    want->ClearWant(&dWant);
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

    char* ch = reinterpret_cast<char *>(malloc(size + 1));
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

    OHOS::DoSomethingInterestingWithMyAPI_DistributedWant_001(ch, size);
    OHOS::DoSomethingInterestingWithMyAPI_DistributedWant_002(ch, size);
    OHOS::DoSomethingInterestingWithMyAPI_DistributedWant_003(ch, size);
    OHOS::DoSomethingInterestingWithMyAPI_DistributedWant_004(ch, size);
    OHOS::DoSomethingInterestingWithMyAPI_DistributedWant_005(ch, size);
    OHOS::DoSomethingInterestingWithMyAPI_DistributedWant_006(ch, size);
    free(ch);
    ch = nullptr;
    return 0;
}
