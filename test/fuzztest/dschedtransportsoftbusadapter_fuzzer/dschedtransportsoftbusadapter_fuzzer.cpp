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

#include "dschedtransportsoftbusadapter_fuzzer.h"

#include "dsched_transport_softbus_adapter.h"

namespace OHOS {
namespace DistributedSchedule {
void FuzzOnBind(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    std::string peerDeviceId(reinterpret_cast<const char*>(data), size);
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.OnBind(sessionId, peerDeviceId);
}

void FuzzOnShutdown(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    bool isSelfcalled = *(reinterpret_cast<const bool*>(data));
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.OnShutdown(sessionId, isSelfcalled);
}

void FuzzOnBytes(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    const void* newdata = reinterpret_cast<const void*>(data);
    int32_t dataLen = *(reinterpret_cast<const int32_t*>(data));
    DSchedTransportSoftbusAdapter dschedTransportSoftbusAdapter;
    dschedTransportSoftbusAdapter.OnBytes(sessionId, newdata, dataLen);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzOnBind(data, size);
    OHOS::DistributedSchedule::FuzzOnShutdown(data, size);
    OHOS::DistributedSchedule::FuzzOnBytes(data, size);
    return 0;
}
