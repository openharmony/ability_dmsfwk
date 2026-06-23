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

#include "softbus_stub.h"
#include "distributed_intent_dsoftbus_adapter.h"
#include "session.h"
#include "socket.h"

namespace OHOS {
namespace DistributedSchedule {
static bool g_softbusMockEnabled = false;
static int32_t g_mockSocketFd = 10001;
static uint32_t g_mockMaxSendSize = 256;

void SetSoftbusMockEnabled(bool enabled)
{
    g_softbusMockEnabled = enabled;
}

void SetSoftbusMockSocketFd(int32_t fd)
{
    g_mockSocketFd = fd;
}

void SetSoftbusMockMaxSendSize(uint32_t size)
{
    g_mockMaxSendSize = size;
}
} // namespace DistributedSchedule
} // namespace OHOS

extern "C" {
int32_t Socket(SocketInfo info)
{
    (void)info;
    return OHOS::DistributedSchedule::g_softbusMockEnabled ?
        OHOS::DistributedSchedule::g_mockSocketFd : -1;
}

int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount,
    const ISocketListener* listener)
{
    (void)socket;
    (void)qos;
    (void)qosCount;
    (void)listener;
    return OHOS::DistributedSchedule::g_softbusMockEnabled ? 0 : -1;
}

int32_t SendBytes(int32_t socket, const void* data, uint32_t len)
{
    (void)socket;
    (void)data;
    (void)len;
    return OHOS::DistributedSchedule::g_softbusMockEnabled ? 0 : -1;
}

void Shutdown(int32_t socket)
{
    (void)socket;
}

int32_t GetSessionOption(int32_t socket, SessionOption option, void* value, uint32_t valueLen)
{
    (void)socket;
    (void)option;
    (void)valueLen;
    if (OHOS::DistributedSchedule::g_softbusMockEnabled && value != nullptr) {
        *static_cast<uint32_t*>(value) = OHOS::DistributedSchedule::g_mockMaxSendSize;
        return 0;
    }
    return -1;
}
}
