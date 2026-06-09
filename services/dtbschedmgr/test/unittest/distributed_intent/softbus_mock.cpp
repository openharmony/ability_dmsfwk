/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "softbus_mock.h"
#include "socket.h"

namespace OHOS {
namespace DistributedSchedule {

extern "C" {
int32_t Socket(SocketInfo info)
{
    if (ISoftbusInterface::softbusMock == nullptr) {
        return -1;
    }
    return ISoftbusInterface::softbusMock->Socket(info);
}

int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener* listener)
{
    if (ISoftbusInterface::softbusMock == nullptr) {
        return -1;
    }
    return ISoftbusInterface::softbusMock->Bind(socket, qos, qosCount, listener);
}

int32_t SendBytes(int32_t socket, const void* data, uint32_t len)
{
    if (ISoftbusInterface::softbusMock == nullptr) {
        return -1;
    }
    return ISoftbusInterface::softbusMock->SendBytes(socket, data, len);
}

void Shutdown(int32_t socket)
{
    if (ISoftbusInterface::softbusMock != nullptr) {
        ISoftbusInterface::softbusMock->Shutdown(socket);
    }
}

int32_t GetSessionOption(int32_t socket, SessionOption option, void* value, uint32_t valueLen)
{
    if (ISoftbusInterface::softbusMock == nullptr) {
        return -1;
    }
    return ISoftbusInterface::softbusMock->GetSessionOption(socket, option, value, valueLen);
}
}

} // namespace DistributedSchedule
} // namespace OHOS