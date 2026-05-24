/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "distributed_intent_dsoftbus_adapter_mock.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

IMPLEMENT_SINGLE_INSTANCE(DistributedIntentDsoftbusAdapter);

DistributedIntentDsoftbusAdapter::DistributedIntentDsoftbusAdapter() {}
DistributedIntentDsoftbusAdapter::~DistributedIntentDsoftbusAdapter() {}

int32_t DistributedIntentDsoftbusAdapter::BindIntentSession(const std::string& deviceId, int32_t& socketFd)
{
    if (IDistributedIntentDsoftbusAdapter::adapterMock == nullptr) {
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    return IDistributedIntentDsoftbusAdapter::adapterMock->BindIntentSession(deviceId, socketFd);
}

int32_t DistributedIntentDsoftbusAdapter::SendIntentDataBySession(int32_t socketFd,
    IntentDataType dataType, const std::string& data)
{
    if (IDistributedIntentDsoftbusAdapter::adapterMock == nullptr) {
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    return IDistributedIntentDsoftbusAdapter::adapterMock->SendIntentDataBySession(socketFd, dataType, data);
}

void DistributedIntentDsoftbusAdapter::UnbindIntentSession(int32_t socketFd)
{
    if (IDistributedIntentDsoftbusAdapter::adapterMock != nullptr) {
        IDistributedIntentDsoftbusAdapter::adapterMock->UnbindIntentSession(socketFd);
    }
}

int32_t DistributedIntentDsoftbusAdapter::GetSocketFdByDeviceId(const std::string& deviceId)
{
    if (IDistributedIntentDsoftbusAdapter::adapterMock == nullptr) {
        return INVALID_SOCKET_FD;
    }
    return IDistributedIntentDsoftbusAdapter::adapterMock->GetSocketFdByDeviceId(deviceId);
}

void DistributedIntentDsoftbusAdapter::ShutdownDeviceSession(const std::string& deviceId)
{
    if (IDistributedIntentDsoftbusAdapter::adapterMock != nullptr) {
        IDistributedIntentDsoftbusAdapter::adapterMock->ShutdownDeviceSession(deviceId);
    }
}

void DistributedIntentDsoftbusAdapter::ForceCleanupDeviceSessions(const std::string& deviceId,
    std::vector<int32_t>& closedSockets)
{
    if (IDistributedIntentDsoftbusAdapter::adapterMock != nullptr) {
        IDistributedIntentDsoftbusAdapter::adapterMock->ForceCleanupDeviceSessions(deviceId, closedSockets);
    }
}

void DistributedIntentDsoftbusAdapter::OnIntentBind(int32_t socket, const std::string& peerDeviceId) {}
void DistributedIntentDsoftbusAdapter::OnIntentShutdown(int32_t socket) {}
void DistributedIntentDsoftbusAdapter::OnIntentBytes(int32_t socket, const void* data, uint32_t dataLen) {}

} // namespace DistributedSchedule
} // namespace OHOS