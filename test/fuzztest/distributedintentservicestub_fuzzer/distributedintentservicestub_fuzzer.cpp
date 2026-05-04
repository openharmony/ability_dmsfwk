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

#include "distributed_sched_service.h"
#include "distributedsched_ipc_interface_code.h"
#include "mock_fuzz_util.h"
#include "parcel_helper.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {

void FuzzOnRemoteRequest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    uint32_t code = fdp.ConsumeIntegral<uint32_t>();
    std::vector<uint8_t> remaining = fdp.ConsumeRemainingBytes<uint8_t>();

    MessageParcel parcelData;
    parcelData.WriteInterfaceToken(u"ohos.distributedschedule.accessToken");

    if (!remaining.empty()) {
        parcelData.WriteBuffer(remaining.data(), remaining.size());
    }

    MessageParcel reply;
    MessageOption option;
    DistributedSchedService::GetInstance().OnRemoteRequest(code, parcelData, reply, option);
    FuzzUtil::MockPermission();
    DistributedSchedService::GetInstance().OnRemoteRequest(code, parcelData, reply, option);
}

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
    uint32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, parcelData, reply, option);
    FuzzUtil::MockPermission();
    DistributedSchedService::GetInstance().OnRemoteRequest(code, parcelData, reply, option);
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
    uint32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, parcelData, reply, option);
    FuzzUtil::MockPermission();
    DistributedSchedService::GetInstance().OnRemoteRequest(code, parcelData, reply, option);
}
}
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzOnRemoteRequest(data, size);
    OHOS::DistributedSchedule::FuzzStartRemoteIntentInner(data, size);
    OHOS::DistributedSchedule::FuzzSendIntentResultInner(data, size);
    return 0;
}
