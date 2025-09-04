/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "distributedoperation_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>
#include <fuzzer/FuzzedDataProvider.h>

#include "distributed_operation.h"

namespace OHOS {

void FuzzDistributedOperation(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }

    DistributedSchedule::DistributedOperation operation;

    operation.GetUri();

    FuzzedDataProvider fdp(data, size);
    std::string moduleName = fdp.ConsumeRandomLengthString();
    operation.SetModuleName(moduleName);
    operation.GetModuleName();

    Parcel parcel;
    operation.Marshalling(parcel);
    DistributedSchedule::DistributedOperation* unmarshalledOperation =
        DistributedSchedule::DistributedOperation::Unmarshalling(parcel);
    if (unmarshalledOperation != nullptr) {
        delete unmarshalledOperation;
        unmarshalledOperation = nullptr;
    }

    std::string str = fdp.ConsumeRandomLengthString();
    Parcel parcel_2;
    parcel_2.WriteBuffer(str.c_str(), str.size());
    parcel_2.RewindRead(0);
    operation.ReadFromParcel(parcel_2);

    DistributedSchedule::DistributedOperation operation_2(operation);

    if (operation_2 == operation) {
        return;
    }
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::FuzzDistributedOperation(data, size);
    return 0;
}
