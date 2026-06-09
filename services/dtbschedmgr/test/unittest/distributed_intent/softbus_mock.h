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

#ifndef SOFTBUS_MOCK_H
#define SOFTBUS_MOCK_H

#include <gmock/gmock.h>
#include <cstdint>
#include "socket.h"
#include "session.h"

namespace OHOS {
namespace DistributedSchedule {

class ISoftbusInterface {
public:
    virtual ~ISoftbusInterface() = default;
    virtual int32_t Socket(SocketInfo info) = 0;
    virtual int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener* listener) = 0;
    virtual int32_t SendBytes(int32_t socket, const void* data, uint32_t len) = 0;
    virtual void Shutdown(int32_t socket) = 0;
    virtual int32_t GetSessionOption(int32_t socket, SessionOption option,
        void* value, uint32_t valueLen) = 0;
public:
    static inline std::shared_ptr<ISoftbusInterface> softbusMock = nullptr;
};

class SoftbusMock : public ISoftbusInterface {
public:
    MOCK_METHOD(int32_t, Socket, (SocketInfo info), (override));
    MOCK_METHOD(int32_t, Bind, (int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener* listener), (override));
    MOCK_METHOD(int32_t, SendBytes, (int32_t socket, const void* data, uint32_t len), (override));
    MOCK_METHOD(void, Shutdown, (int32_t socket), (override));
    MOCK_METHOD(int32_t, GetSessionOption, (int32_t socket, SessionOption option,
        void* value, uint32_t valueLen), (override));
};

} // namespace DistributedSchedule
} // namespace OHOS
#endif // SOFTBUS_MOCK_H