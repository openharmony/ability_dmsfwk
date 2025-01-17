/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dsched_transport_softbus_adapter_mock.h"

using namespace std;
using namespace OHOS::DistributedSchedule;

DSchedTransportSoftbusAdapter::DSchedTransportSoftbusAdapter()
{
}

DSchedTransportSoftbusAdapter::~DSchedTransportSoftbusAdapter()
{
}

int32_t DSchedTransportSoftbusAdapter::InitChannel()
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return 0;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->InitChannel();
}

int32_t DSchedTransportSoftbusAdapter::ConnectDevice(const std::string &peerDeviceId,
    int32_t &sessionId, DSchedServiceType type)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return 0;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->ConnectDevice(peerDeviceId, sessionId, type);
}

int32_t DSchedTransportSoftbusAdapter::ReleaseChannel()
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return 0;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->ReleaseChannel();
}

int32_t DSchedTransportSoftbusAdapter::SendData(int32_t sessionId, int32_t dataType,
    std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return 0;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->SendData(sessionId, dataType, dataBuffer);
}

int32_t DSchedTransportSoftbusAdapter::SendBytesBySoftbus(int32_t sessionId,
    std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return 0;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->SendBytesBySoftbus(sessionId, dataBuffer);
}

void DSchedTransportSoftbusAdapter::OnBind(int32_t sessionId, const std::string &peerDeviceId)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->OnBind(sessionId, peerDeviceId);
}

void DSchedTransportSoftbusAdapter::OnShutdown(int32_t sessionId, bool isSelfCalled)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->OnShutdown(sessionId, isSelfCalled);
}

void DSchedTransportSoftbusAdapter::OnBytes(int32_t sessionId, const void *data, uint32_t dataLen)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->OnBytes(sessionId, data, dataLen);
}

void DSchedTransportSoftbusAdapter::OnDataReady(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer,
    uint32_t dataType)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->OnDataReady(sessionId, dataBuffer, dataType);
}

void DSchedTransportSoftbusAdapter::RegisterListener(int32_t serviceType, std::shared_ptr<IDataListener> listener)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->RegisterListener(serviceType, listener);
}

void DSchedTransportSoftbusAdapter::UnregisterListener(int32_t serviceType, std::shared_ptr<IDataListener> listener)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->UnregisterListener(serviceType, listener);
}

void DSchedTransportSoftbusAdapter::SetCallingTokenId(int32_t callingTokenId)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->SetCallingTokenId(callingTokenId);
}

bool IDSchedTransportSoftbusAdapter::GetSessionIdByDeviceId(const std::string &peerDeviceId, int32_t &sessionId)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return false;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->GetSessionIdByDeviceId(peerDeviceId, sessionId);
}

bool DSchedTransportSoftbusAdapter::IsNeedAllConnect(DSchedServiceType type)
{
    if (IDSchedTransportSoftbusAdapter::adapterMock == nullptr) {
        return false;
    }
    return IDSchedTransportSoftbusAdapter::adapterMock->IsNeedAllConnect(type);
}
