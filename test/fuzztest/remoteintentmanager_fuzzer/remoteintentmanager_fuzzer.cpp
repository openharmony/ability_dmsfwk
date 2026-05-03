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

#include "remoteintentmanager_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "remote_intent_manager.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {

void FuzzDeserializeIntentData(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    std::string fuzzData(reinterpret_cast<const char*>(data), size);
    OHOS::AAFwk::Want want;
    IntentContext ctx;
    std::string resultMsg;
    RemoteIntentManager::GetInstance().DeserializeIntentData(fuzzData, want, ctx, resultMsg);
}

void FuzzSerializeResultData(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint64_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();
    uint64_t requestCode = fdp.ConsumeIntegral<uint64_t>();
    std::string outData;
    RemoteIntentManager::GetInstance().SerializeResultData(resultCode, "", requestCode, outData);
}

void FuzzOnIntentDataReceived(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(uint32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string srcDeviceId = fdp.ConsumeRandomLengthString(64);
    uint32_t typeValue = fdp.ConsumeIntegral<uint32_t>();
    int32_t socketFd = fdp.ConsumeIntegral<int32_t>();
    std::string payload = fdp.ConsumeRemainingBytesAsString();
    IntentDataType dataType = static_cast<IntentDataType>(typeValue);
    RemoteIntentManager::GetInstance().OnIntentDataReceived(srcDeviceId, dataType, payload, socketFd);
}

void FuzzHandleIntentExecute(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string srcDeviceId = fdp.ConsumeRandomLengthString(64);
    int32_t socketFd = fdp.ConsumeIntegral<int32_t>();
    std::string payload = fdp.ConsumeRemainingBytesAsString();
    RemoteIntentManager::GetInstance().HandleIntentExecute(srcDeviceId, payload, socketFd);
}

void FuzzHandleIntentResult(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string srcDeviceId = fdp.ConsumeRandomLengthString(64);
    int32_t socketFd = fdp.ConsumeIntegral<int32_t>();
    std::string payload = fdp.ConsumeRemainingBytesAsString();
    RemoteIntentManager::GetInstance().HandleIntentResult(srcDeviceId, payload, socketFd);
}

void FuzzHandleBusinessResult(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string srcDeviceId = fdp.ConsumeRandomLengthString(64);
    int32_t socketFd = fdp.ConsumeIntegral<int32_t>();
    std::string payload = fdp.ConsumeRemainingBytesAsString();
    RemoteIntentManager::GetInstance().HandleBusinessResult(srcDeviceId, payload, socketFd);
}

void FuzzCleanupSocketMapping(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string deviceId = fdp.ConsumeRandomLengthString(64);
    int32_t socketFd = fdp.ConsumeIntegral<int32_t>();
    RemoteIntentManager::GetInstance().CleanupSocketMapping(deviceId, socketFd);
}

void FuzzNotifyLinkDisconnected(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string deviceId = fdp.ConsumeRandomLengthString(64);
    int32_t reason = fdp.ConsumeIntegral<int32_t>();
    RemoteIntentManager::GetInstance().NotifyLinkDisconnected(deviceId, reason);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzDeserializeIntentData(data, size);
    OHOS::DistributedSchedule::FuzzSerializeResultData(data, size);
    OHOS::DistributedSchedule::FuzzOnIntentDataReceived(data, size);
    OHOS::DistributedSchedule::FuzzHandleIntentExecute(data, size);
    OHOS::DistributedSchedule::FuzzHandleIntentResult(data, size);
    OHOS::DistributedSchedule::FuzzHandleBusinessResult(data, size);
    OHOS::DistributedSchedule::FuzzCleanupSocketMapping(data, size);
    OHOS::DistributedSchedule::FuzzNotifyLinkDisconnected(data, size);
    return 0;
}
