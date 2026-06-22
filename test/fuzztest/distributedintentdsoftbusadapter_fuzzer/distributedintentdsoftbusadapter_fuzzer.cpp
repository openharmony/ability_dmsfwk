/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "distributedintentdsoftbusadapter_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "distributed_intent_dsoftbus_adapter.h"

namespace OHOS {
namespace DistributedSchedule {

void FuzzBindIntentSession(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string deviceId = fdp.ConsumeRandomLengthString();
    int32_t socketFd = 0;
    DistributedIntentDsoftbusAdapter::GetInstance().BindIntentSession(deviceId, socketFd);
    if (socketFd > 0) {
        DistributedIntentDsoftbusAdapter::GetInstance().UnbindIntentSession(socketFd);
    }
}

void FuzzUnbindIntentSession(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t socketFd = fdp.ConsumeIntegral<int32_t>();
    DistributedIntentDsoftbusAdapter::GetInstance().UnbindIntentSession(socketFd);
}

void FuzzSendIntentDataBySession(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t socketFd = fdp.ConsumeIntegral<int32_t>();
    uint32_t typeValue = fdp.ConsumeIntegral<uint32_t>();
    std::string payload = fdp.ConsumeRemainingBytesAsString();
    IntentDataType dataType = static_cast<IntentDataType>(typeValue);
    DistributedIntentDsoftbusAdapter::GetInstance().SendIntentDataBySession(socketFd, dataType, payload);
}

void FuzzGetSocketFdByDeviceId(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string deviceId = fdp.ConsumeRandomLengthString();
    DistributedIntentDsoftbusAdapter::GetInstance().GetSocketFdByDeviceId(deviceId);
}

void FuzzOnIntentBind(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::string peerDeviceId = fdp.ConsumeRandomLengthString();
    DistributedIntentDsoftbusAdapter::GetInstance().OnIntentBind(socket, peerDeviceId);
}

void FuzzOnIntentShutdown(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    DistributedIntentDsoftbusAdapter::GetInstance().OnIntentShutdown(socket);
}

void FuzzOnIntentBytes(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t socket = fdp.ConsumeIntegral<int32_t>();
    std::vector<uint8_t> bytes = fdp.ConsumeRemainingBytes<uint8_t>();
    const void* rawData = bytes.empty() ? nullptr : bytes.data();
    DistributedIntentDsoftbusAdapter::GetInstance().OnIntentBytes(socket, rawData, bytes.size());
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzBindIntentSession(data, size);
    OHOS::DistributedSchedule::FuzzUnbindIntentSession(data, size);
    OHOS::DistributedSchedule::FuzzSendIntentDataBySession(data, size);
    OHOS::DistributedSchedule::FuzzGetSocketFdByDeviceId(data, size);
    OHOS::DistributedSchedule::FuzzOnIntentBind(data, size);
    OHOS::DistributedSchedule::FuzzOnIntentShutdown(data, size);
    OHOS::DistributedSchedule::FuzzOnIntentBytes(data, size);
    return 0;
}
