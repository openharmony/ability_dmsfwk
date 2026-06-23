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

#include "distributedintentservice_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>

#include "distributed_sched_service.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {

namespace {
constexpr size_t FUZZ_STRING_MAX_LEN = 64;
}

void FuzzLoadIntentPlugin(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    DistributedSchedService::GetInstance().LoadIntentPlugin();
}

void FuzzEnsureIntentPluginLoaded(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    DistributedSchedService::GetInstance().EnsureIntentPluginLoaded();
}

void FuzzGetIntentPlugin(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    DistributedSchedService::GetInstance().GetIntentPlugin();
}

void FuzzStartRemoteIntent(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    want.SetElementName(fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN),
        fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN),
        fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN));
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = fdp.ConsumeIntegral<int32_t>();
    callerInfo.requestCode = fdp.ConsumeIntegral<uint64_t>();
    callerInfo.accessToken = fdp.ConsumeIntegral<uint32_t>();
    sptr<IRemoteObject> resultCallback = new IPCObjectStub(u"fuzz_intent_callback");
    DistributedSchedService::GetInstance().StartRemoteIntent(want, callerInfo, resultCallback);
}

void FuzzSendIntentResult(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    want.SetElementName(fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN),
        fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN),
        fdp.ConsumeRandomLengthString(FUZZ_STRING_MAX_LEN));
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = fdp.ConsumeIntegral<int32_t>();
    callerInfo.requestCode = fdp.ConsumeIntegral<uint64_t>();
    callerInfo.accessToken = fdp.ConsumeIntegral<uint32_t>();
    std::string msg = fdp.ConsumeRemainingBytesAsString();
    DistributedSchedService::GetInstance().SendIntentResult(want, callerInfo, msg);
}
} // namespace DistributedSchedule
} // namespace OHOS

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzLoadIntentPlugin(data, size);
    OHOS::DistributedSchedule::FuzzEnsureIntentPluginLoaded(data, size);
    OHOS::DistributedSchedule::FuzzGetIntentPlugin(data, size);
    OHOS::DistributedSchedule::FuzzStartRemoteIntent(data, size);
    OHOS::DistributedSchedule::FuzzSendIntentResult(data, size);
    return 0;
}
