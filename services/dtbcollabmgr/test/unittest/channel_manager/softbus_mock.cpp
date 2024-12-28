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
#include "softbus_mock.h"

namespace OHOS {
namespace DistributedCollab {

SoftbusMock* SoftbusMock::gMock;

SoftbusMock::SoftbusMock()
{
    gMock = this;
}

SoftbusMock::~SoftbusMock()
{
    gMock = nullptr;
}

SoftbusMock& SoftbusMock::GetMock()
{
    return *gMock;
}

extern "C" {
    int32_t Socket(SocketInfo info)
    {
        return SoftbusMock::GetMock().Socket(info);
    }

    int32_t Listen(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener* listener)
    {
        return SoftbusMock::GetMock().Listen(socket, qos, qosCount, listener);
    }

    int32_t Bind(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener* listener)
    {
        return SoftbusMock::GetMock().Bind(socket, qos, qosCount, listener);
    }

    int32_t BindAsync(int32_t socket, const QosTV qos[], uint32_t qosCount, const ISocketListener* listener)
    {
        return SoftbusMock::GetMock().BindAsync(socket, qos, qosCount, listener);
    }

    int32_t SendBytes(int32_t socket, const void* data, uint32_t len)
    {
        return SoftbusMock::GetMock().SendBytes(socket, data, len);
    }

    int32_t SendMessage(int32_t socket, const void* data, uint32_t len)
    {
        return SoftbusMock::GetMock().SendMessage(socket, data, len);
    }

    int32_t SendStream(int32_t socket, const StreamData* data, const StreamData* ext, const StreamFrameInfo* param)
    {
        return SoftbusMock::GetMock().SendStream(socket, data, ext, param);
    }

    int32_t SendFile(int32_t socket, const char* sFileList[], const char* dFileList[], uint32_t fileCnt)
    {
        return SoftbusMock::GetMock().SendFile(socket, sFileList,
            dFileList, fileCnt);
    }

    void Shutdown(int32_t socket)
    {
        SoftbusMock::GetMock().Shutdown(socket);
    }

    int GetSessionOption(int sessionId, SessionOption option, void* optionValue, uint32_t valueSize)
    {
        return SoftbusMock::GetMock().GetSessionOption(sessionId,
            option, optionValue, valueSize);
    }
}
}  // namespace DistributedCollab
}  // namespace OHOS
