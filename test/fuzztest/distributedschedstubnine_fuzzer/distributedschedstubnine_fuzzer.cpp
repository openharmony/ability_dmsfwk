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

#include "distributedschedstubnine_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <singleton.h>

#include "distributed_sched_interface.h"
#include "distributed_sched_service.h"
#include "distributed_sched_stub.h"
#include "distributedWant/distributed_want.h"
#include "mock_fuzz_util.h"
#include "mock_distributed_sched.h"
#include "parcel_helper.h"
#include "dms_continue_time_dumper.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedSchedFuzzTest";

void NotifyCloseCollabSessionInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    FuzzedDataProvider fdp(data, size);
    std::string tokenId = fdp.ConsumeRandomLengthString();
    dataParcel.WriteString(tokenId);
    DistributedSchedService::GetInstance().NotifyCloseCollabSessionInner(dataParcel, reply);
}

void GetSinkCollabVersionInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    FuzzedDataProvider fdp(data, size);
    int32_t collabSessionId = fdp.ConsumeIntegral<int32_t>();
    std::string sinkDeviceId = fdp.ConsumeRandomLengthString();
    std::string collabToken = fdp.ConsumeRandomLengthString();
    sptr<IRemoteObject> connect(new MockDistributedSched());
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, collabSessionId);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, sinkDeviceId);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, collabToken);
    dataParcel.WriteRemoteObject(connect);
    DistributedSchedService::GetInstance().GetSinkCollabVersionInner(dataParcel, reply);
}

void NotifyRejectReasonFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    FuzzedDataProvider fdp(data, size);
    std::string token = fdp.ConsumeRandomLengthString();
    std::string reason = fdp.ConsumeRandomLengthString();
    dataParcel.WriteString(token);
    dataParcel.WriteString(reason);
    DistributedSchedService::GetInstance().NotifyRejectReason(dataParcel, reply);
}

void NotifyCollabPrepareResultInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    FuzzedDataProvider fdp(data, size);
    std::string collabToken = fdp.ConsumeRandomLengthString();
    int32_t ret = fdp.ConsumeIntegral<int32_t>();
    int32_t sinkCollabSessionId = fdp.ConsumeIntegral<int32_t>();
    std::string sinkSocketName = fdp.ConsumeRandomLengthString();
    sptr<IRemoteObject> connect(new MockDistributedSched());
    dataParcel.WriteString(collabToken);
    dataParcel.WriteInt32(ret);
    dataParcel.WriteInt32(sinkCollabSessionId);
    dataParcel.WriteString(sinkSocketName);
    dataParcel.WriteRemoteObject(connect);
    DistributedSchedService::GetInstance().NotifyCollabPrepareResultInner(dataParcel, reply);
}

void NotifyStartAbilityResultInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    std::string collabToken = fdp.ConsumeRandomLengthString();
    int32_t ret = fdp.ConsumeIntegral<int32_t>();
    int32_t sinkPid = fdp.ConsumeIntegral<int32_t>();
    int32_t sinkUid = fdp.ConsumeIntegral<int32_t>();
    int32_t sinkAccessTokenId = fdp.ConsumeIntegral<int32_t>();

    MessageParcel dataParcel;
    MessageParcel reply;
    dataParcel.WriteString(collabToken);
    dataParcel.WriteInt32(ret);
    dataParcel.WriteInt32(sinkPid);
    dataParcel.WriteInt32(sinkUid);
    dataParcel.WriteInt32(sinkAccessTokenId);
    DistributedSchedService::GetInstance().NotifyStartAbilityResultInner(dataParcel, reply);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::NotifyCloseCollabSessionInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::GetSinkCollabVersionInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyRejectReasonFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyCollabPrepareResultInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyStartAbilityResultInnerFuzzTest(data, size);
    return 0;
}
