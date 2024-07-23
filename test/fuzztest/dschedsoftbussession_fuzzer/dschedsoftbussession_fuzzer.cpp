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

#include "dschedsoftbussession_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dsched_data_buffer.h"
#include "dsched_softbus_session.h"

namespace OHOS {
namespace DistributedSchedule {
void FuzzOnBytesReceived(const uint8_t* data, size_t size)
{
    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(size);
    DSchedSoftbusSession dschedSoftbusSession;
    dschedSoftbusSession.OnBytesReceived(buffer);
    dschedSoftbusSession.OnConnect();
    dschedSoftbusSession.GetPeerDeviceId();
    int32_t dataType = *(reinterpret_cast<const int32_t*>(data));
    dschedSoftbusSession.SendData(buffer, dataType);
    dschedSoftbusSession.OnDisconnect();
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzOnBytesReceived(data, size);
    return 0;
}
