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
#include <fuzzer/FuzzedDataProvider.h>
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

bool DoSomethingInterestingWithMyApiDistributedWant001(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }

    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    unsigned int flags = static_cast<unsigned int>(GetU32Data(reinterpret_cast<const char*>(data)));
    want->SetFlags(flags);
    want->RemoveFlags(flags);
    want->AddFlags(flags);
    std::string entity(reinterpret_cast<const char*>(data), size);
    want->AddEntity(entity);
    want->HasEntity(entity);
    want->RemoveEntity(entity);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    want->SetBundle(bundleName);
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    want->SetDeviceId(deviceId);
    want->SetElementName(bundleName, entity);
    want->SetElementName(deviceId, bundleName, entity);
    return true;
}

bool DoSomethingInterestingWithMyApiDistributedWant002(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }

    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    std::string type(reinterpret_cast<const char*>(data), size);
    want->SetType(type);
    Uri uri(type);
    want->SetUri(uri);
    want->SetUriAndType(uri, type);
    want->FormatUri(uri);
    want->FormatUri(type);
    want->GetLowerCaseScheme(uri);
    return true;
}

bool DoSomethingInterestingWithMyApiDistributedWant003(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }

    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    want->CountEntities();
    want->GetScheme();
    DistributedOperation operation;
    want->SetOperation(operation);
    std::string key(reinterpret_cast<const char*>(data), size);
    want->HasParameter(key);
    std::string content(reinterpret_cast<const char*>(data), size);
    std::string prop(reinterpret_cast<const char*>(data), size);
    std::string value(reinterpret_cast<const char*>(data), size);
    std::string str(reinterpret_cast<const char*>(data), size);
    nlohmann::json wantJson;
    want->ReadFromJson(wantJson);
    return true;
}

bool DoSomethingInterestingWithMyApiDistributedWant004(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }

    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    std::string key(reinterpret_cast<const char*>(data), size);
    sptr<IRemoteObject> remoteObject;
    want->SetParam(key, remoteObject);
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

bool DoSomethingInterestingWithMyApiDistributedWant005(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }

    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    std::string key(reinterpret_cast<const char*>(data), size);
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
    return true;
}

bool DoSomethingInterestingWithMyApiDistributedWant006(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }

    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();
    std::string key(reinterpret_cast<const char*>(data), size);
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
    std::string stringValue(reinterpret_cast<const char*>(data), size);
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

void FuzzDistributedWantGetIntParam(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    DistributedWant want;

    std::string key = fdp.ConsumeRandomLengthString();
    int defaultValue = fdp.ConsumeIntegral<int>();

    if (fdp.ConsumeBool()) {
        int value = fdp.ConsumeIntegral<int>();
        want.SetParam(key, value);
    } else {
        std::string value = fdp.ConsumeRandomLengthString();
        want.SetParam(key, value);
    }
    want.GetIntParam(key, defaultValue);
}

void FuzzDistributedWantSetParamInt(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    DistributedWant want;

    std::string key = fdp.ConsumeRandomLengthString();
    int value = fdp.ConsumeIntegral<int>();
    want.SetParam(key, value);
    int defaultValue = 0;
    want.GetIntParam(key, defaultValue);
}

void FuzzDistributedWantGetLongParam(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    DistributedWant want;

    std::string key = fdp.ConsumeRandomLengthString();
    long defaultValue = fdp.ConsumeIntegral<long>();

    if (fdp.ConsumeBool()) {
        long value = fdp.ConsumeIntegral<long>();
        want.SetParam(key, value);
    } else {
        std::string value = fdp.ConsumeRandomLengthString();
        want.SetParam(key, value);
    }
    want.GetLongParam(key, defaultValue);
}

void FuzzDistributedWantSetParamLongLong(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    DistributedWant want;

    std::string key = fdp.ConsumeRandomLengthString();
    long long value = fdp.ConsumeIntegral<long long>();
    want.SetParam(key, value);

    long long defaultValue = 0;
    want.GetLongParam(key, defaultValue);
}

void FuzzDistributedWantGetOperation(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    DistributedWant want;

    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    want.SetElementName(deviceId, bundleName, abilityName);

    std::string action = fdp.ConsumeRandomLengthString();
    want.SetAction(action);

    unsigned int flags = fdp.ConsumeIntegral<unsigned int>();
    want.SetFlags(flags);
    want.GetOperation();
}

void FuzzDistributedWantOperationEquals(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    DistributedWant want1;
    DistributedWant want2;

    std::string deviceId1 = fdp.ConsumeRandomLengthString();
    std::string bundleName1 = fdp.ConsumeRandomLengthString();
    std::string abilityName1 = fdp.ConsumeRandomLengthString();
    want1.SetElementName(deviceId1, bundleName1, abilityName1);

    std::string deviceId2 = fdp.ConsumeRandomLengthString();
    std::string bundleName2 = fdp.ConsumeRandomLengthString();
    std::string abilityName2 = fdp.ConsumeRandomLengthString();
    want2.SetElementName(deviceId2, bundleName2, abilityName2);

    unsigned int flags1 = fdp.ConsumeIntegral<unsigned int>();
    unsigned int flags2 = fdp.ConsumeIntegral<unsigned int>();
    want1.SetFlags(flags1);
    want2.SetFlags(flags2);

    std::string action1 = fdp.ConsumeRandomLengthString();
    std::string action2 = fdp.ConsumeRandomLengthString();
    want1.SetAction(action1);
    want2.SetAction(action2);
    want1.OperationEquals(want2);
}

void FuzzDistributedWantSetUri(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    DistributedWant want;

    std::string uri = fdp.ConsumeRandomLengthString();
    want.SetUri(uri);
}

bool FuzzDistributedWantToJson(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }

    std::shared_ptr<DistributedWant> want = std::make_shared<DistributedWant>();

    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    std::string abilityName(reinterpret_cast<const char*>(data), size);
    want->SetElementName(deviceId, bundleName, abilityName);

    std::string action(reinterpret_cast<const char*>(data), size);
    want->SetAction(action);

    unsigned int flags = static_cast<unsigned int>(data[0]);
    want->SetFlags(flags);

    std::string type(reinterpret_cast<const char*>(data), size);
    want->SetType(type);

    std::string uri(reinterpret_cast<const char*>(data), size);
    want->SetUri(uri);

    std::vector<std::string> entities = { "entity1", "entity2", "entity3" };
    for (const auto& entity : entities) {
        want->AddEntity(entity);
    }

    want->ToJson();
    return true;
}

bool FuzzDistributedWantFromString(const uint8_t* data, size_t size)
{
    if (data == nullptr || size > OHOS::FOO_MAX_LEN || size < OHOS::U32_AT_SIZE) {
        return false;
    }
    std::string inputString(reinterpret_cast<const char*>(data), size);
    std::shared_ptr<DistributedWant> want(DistributedWant::FromString(inputString));
    return true;
}

void DistributedWantCopyCtorFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    Want want;
    want.SetAction(fdp.ConsumeRandomLengthString());
    want.SetBundle(fdp.ConsumeRandomLengthString());
    want.SetElement(AppExecFwk::ElementName(
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString()
    ));

    DistributedWant original(want);

    DistributedWant copy(original);
}

void DistributedWantAssignOperatorFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    Want want;
    want.SetAction(fdp.ConsumeRandomLengthString());
    want.SetBundle(fdp.ConsumeRandomLengthString());
    want.SetElement(AppExecFwk::ElementName(
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString()
    ));

    DistributedWant lhs(want);
    DistributedWant rhs(want);

    lhs = rhs;
}

void DistributedWantFromWantFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);

    Want want;
    want.SetAction(fdp.ConsumeRandomLengthString());
    want.SetBundle(fdp.ConsumeRandomLengthString());
    want.SetElement(AppExecFwk::ElementName(
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString()
    ));

    DistributedWant distributedWant(want);
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DoSomethingInterestingWithMyApiDistributedWant001(data, size);
    OHOS::DoSomethingInterestingWithMyApiDistributedWant002(data, size);
    OHOS::DoSomethingInterestingWithMyApiDistributedWant003(data, size);
    OHOS::DoSomethingInterestingWithMyApiDistributedWant004(data, size);
    OHOS::DoSomethingInterestingWithMyApiDistributedWant005(data, size);
    OHOS::DoSomethingInterestingWithMyApiDistributedWant006(data, size);
    OHOS::FuzzDistributedWantGetIntParam(data, size);
    OHOS::FuzzDistributedWantSetParamInt(data, size);
    OHOS::FuzzDistributedWantGetLongParam(data, size);
    OHOS::FuzzDistributedWantSetParamLongLong(data, size);
    OHOS::FuzzDistributedWantGetOperation(data, size);
    OHOS::FuzzDistributedWantOperationEquals(data, size);
    OHOS::FuzzDistributedWantSetUri(data, size);
    OHOS::FuzzDistributedWantToJson(data, size);
    OHOS::FuzzDistributedWantFromString(data, size);
    OHOS::DistributedWantCopyCtorFuzzTest(data, size);
    OHOS::DistributedWantAssignOperatorFuzzTest(data, size);
    OHOS::DistributedWantFromWantFuzzTest(data, size);
    return 0;
}
