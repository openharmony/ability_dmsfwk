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

#include "distributedintentservicestub_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "distributed_intent_service.h"
#include "distributedsched_ipc_interface_code.h"
#include "mock_fuzz_util.h"
#include "parcel_helper.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {

void FuzzStartRemoteIntentInner(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    uint64_t requestCode = fdp.ConsumeIntegral<uint64_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();
    uint32_t specifyTokenId = fdp.ConsumeIntegral<uint32_t>();

    MessageParcel parcelData;
    parcelData.WriteInterfaceToken(u"ohos.distributedschedule.accessToken");

    OHOS::AAFwk::Want want;
    want.SetElementName("fuzz_device", "com.example.fuzz", "FuzzAbility");
    want.SetParam("fuzz_key", std::string("fuzz_value"));
    parcelData.WriteParcelable(&want);

    parcelData.WriteString("fuzz_module");
    parcelData.WriteInt32(callerUid);
    parcelData.WriteUint64(requestCode);
    parcelData.WriteUint32(accessToken);
    parcelData.WriteUint32(specifyTokenId);

    sptr<IRemoteObject> callback = new IPCObjectStub(u"test_callback");
    parcelData.WriteRemoteObject(callback);

    MessageParcel reply;
    MessageOption option;
    DistributedIntentService intentService;
    uint32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT);
    intentService.OnRemoteRequest(code, parcelData, reply, option);
    FuzzUtil::MockPermission();
    intentService.OnRemoteRequest(code, parcelData, reply, option);
}

void FuzzSendIntentResultInner(const uint8_t* data, size_t size)
{
    if (data == nullptr || size == 0) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    uint64_t requestCode = fdp.ConsumeIntegral<uint64_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();
    uint32_t specifyTokenId = fdp.ConsumeIntegral<uint32_t>();
    std::string resultMsg = fdp.ConsumeRemainingBytesAsString();

    MessageParcel parcelData;
    parcelData.WriteInterfaceToken(u"ohos.distributedschedule.accessToken");

    OHOS::AAFwk::Want want;
    want.SetElementName("fuzz_device", "com.example.fuzz", "FuzzAbility");
    parcelData.WriteParcelable(&want);

    parcelData.WriteInt32(callerUid);
    parcelData.WriteUint64(requestCode);
    parcelData.WriteUint32(accessToken);
    parcelData.WriteUint32(specifyTokenId);
    parcelData.WriteString(resultMsg);

    MessageParcel reply;
    MessageOption option;
    DistributedIntentService intentService;
    uint32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT);
    intentService.OnRemoteRequest(code, parcelData, reply, option);
    FuzzUtil::MockPermission();
    intentService.OnRemoteRequest(code, parcelData, reply, option);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzStartRemoteIntentInner(data, size);
    OHOS::DistributedSchedule::FuzzSendIntentResultInner(data, size);
    return 0;
}
