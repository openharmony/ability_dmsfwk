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
#include <securec.h>

#include "dsched_data_buffer.h"
#include "dsched_softbus_session.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
static const uint32_t DSCHED_MAX_BUFFER_SIZE = 80 * 1024 * 1024;
static const uint16_t BINARY_HEADER_FRAG_LEN = 49;
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

int32_t Get32Data(const uint8_t* ptr, size_t size)
{
    if (size > FOO_MAX_LEN || size < U32_AT_SIZE) {
        return 0;
    }
    char *ch = static_cast<char*>(malloc(size + 1));
    if (ch == nullptr) {
        return 0;
    }
    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, ptr, size) != EOK) {
        free(ch);
        ch = nullptr;
        return 0;
    }
    int32_t data = (ch[POS_0] << OFFSET_24) | (ch[POS_1] << OFFSET_16) | (ch[POS_2] << OFFSET_8) | ch[POS_3];
    free(ch);
    ch = nullptr;
    return data;
}

void FuzzOnBytesReceived(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < U32_AT_SIZE)) {
        return;
    }
    size_t intParam = static_cast<size_t>(Get32Data(data, size));
    intParam = intParam % (DSCHED_MAX_BUFFER_SIZE - BINARY_HEADER_FRAG_LEN);

    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(intParam);
    DSchedSoftbusSession dschedSoftbusSession;
    dschedSoftbusSession.OnBytesReceived(buffer);
    dschedSoftbusSession.OnConnect();
    dschedSoftbusSession.GetPeerDeviceId();
    int32_t dataType = Get32Data(data, size);
    dschedSoftbusSession.SendData(buffer, dataType);
    dschedSoftbusSession.OnDisconnect();
}

void FuzzAssembleNoFrag(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < U32_AT_SIZE)) {
        return;
    }
    size_t intParam = static_cast<size_t>(Get32Data(data, size));
    intParam = intParam % (DSCHED_MAX_BUFFER_SIZE - BINARY_HEADER_FRAG_LEN);

    std::shared_ptr<DSchedDataBuffer> buffer = std::make_shared<DSchedDataBuffer>(intParam);
    int32_t accountId = *(reinterpret_cast<const int32_t*>(data));
    DSchedSoftbusSession dschedSoftbusSession;
    dschedSoftbusSession.ResetAssembleFrag();

    dschedSoftbusSession.UnPackSendData(buffer, accountId);
    dschedSoftbusSession.UnPackStartEndData(buffer, accountId);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzOnBytesReceived(data, size);
    OHOS::DistributedSchedule::FuzzAssembleNoFrag(data, size);
    return 0;
}
