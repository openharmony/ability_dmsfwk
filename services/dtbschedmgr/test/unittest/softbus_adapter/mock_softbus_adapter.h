/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_SOFTBUS_ADAPTER_TEST_H
#define MOCK_SOFTBUS_ADAPTER_TEST_H

#include <gmock/gmock.h>

#include "socket.h"
#include "session.h"

namespace OHOS {
namespace DistributedSchedule {
class MockInterface {
public:
    MockInterface() {};
    virtual ~MockInterface() {};

    virtual int32_t Socket(SocketInfo info) = 0;
    virtual int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener* listener) = 0;
    virtual int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener* listener) = 0;
    virtual int32_t SendBytes(int32_t socket, const void* data, uint32_t len) = 0;
    virtual void Shutdown(int32_t socket) = 0;
    virtual int GetSessionOption(int sessionId, SessionOption option, void* optionValue, uint32_t valueSize) = 0;
};

class SoftbusMock : public MockInterface {
public:
    SoftbusMock();
    ~SoftbusMock() override;

    static SoftbusMock& GetMock();

    MOCK_METHOD(int32_t, Socket, (SocketInfo info), (override));
    MOCK_METHOD(int32_t, Listen, (int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener* listener), (override));
    MOCK_METHOD(int32_t, Bind, (int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener* listener), (override));
    MOCK_METHOD(int32_t, SendBytes, (int32_t socket, const void* data, uint32_t len), (override));
    MOCK_METHOD(void, Shutdown, (int32_t socket), (override));
    MOCK_METHOD(int, GetSessionOption, (int sessionId, SessionOption option, void* optionValue,
        uint32_t valueSize), (override));

private:
    static SoftbusMock *gMock;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // MOCK_SOFTBUS_ADAPTER_TEST_H
