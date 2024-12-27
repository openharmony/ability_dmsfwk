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
#ifndef DISTRIBUTED_COLLAB_SOFTBUS_MOCK_TEST_H
#define DISTRIBUTED_COLLAB_SOFTBUS_MOCK_TEST_H
#include "socket.h"
#include "session.h"
#include <gmock/gmock.h>
#include <cstdint>
#include <vector>

namespace OHOS {
namespace DistributedCollab {
class MockInterface {
public:
    MockInterface() {};
    virtual ~MockInterface() {};

    virtual int32_t Socket(SocketInfo info) = 0;
    virtual int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener* listener) = 0;
    virtual int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener* listener) = 0;
    virtual int32_t BindAsync(int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener* listener) = 0;
    virtual int32_t SendBytes(int32_t socket, const void* data, uint32_t len) = 0;
    virtual int32_t SendMessage(int32_t socket, const void* data, uint32_t len) = 0;
    virtual int32_t SendStream(int32_t socket, const StreamData* data, const StreamData* ext,
        const StreamFrameInfo* param) = 0;
    virtual int32_t SendFile(int32_t socket, const char* sFileList[], const char* dFileList[], uint32_t fileCnt) = 0;
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
    MOCK_METHOD(int32_t, BindAsync, (int32_t socket, const QosTV qos[], uint32_t qosCount,
        const ISocketListener* listener), (override));
    MOCK_METHOD(int32_t, SendBytes, (int32_t socket, const void* data, uint32_t len), (override));
    MOCK_METHOD(int32_t, SendMessage, (int32_t socket, const void* data, uint32_t len), (override));
    MOCK_METHOD(int32_t, SendStream, (int32_t socket, const StreamData* data, const StreamData* ext,
        const StreamFrameInfo* param), (override));
    MOCK_METHOD(int32_t, SendFile, (int32_t socket, const char* sFileList[],
        const char* dFileList[], uint32_t fileCnt), (override));
    MOCK_METHOD(void, Shutdown, (int32_t socket), (override));
    MOCK_METHOD(int, GetSessionOption, (int sessionId, SessionOption option, void* optionValue,
        uint32_t valueSize), (override));
private:
    static SoftbusMock *gMock;
};

extern "C" {
    int32_t Socket(SocketInfo info);
    int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener* listener);
    int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener* listener);
    int32_t BindAsync(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener* listener);
    int32_t SendBytes(int32_t socket, const void* data, uint32_t len);
    int32_t SendMessage(int32_t socket, const void* data, uint32_t len);
    int32_t SendStream(int32_t socket, const StreamData* data, const StreamData* ext, const StreamFrameInfo* param);
    int32_t SendFile(int32_t socket, const char* sFileList[], const char* dFileList[], uint32_t fileCnt);
    void Shutdown(int32_t socket);
    int GetSessionOption(int sessionId, SessionOption option, void* optionValue, uint32_t valueSize);
}
}  // namespace DistributedCollab
}  // namespace OHOS
#endif