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

#include "dsched_transport_softbus_adapter.h"

#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
IMPLEMENT_SINGLE_INSTANCE(DSchedTransportSoftbusAdapter);

DSchedTransportSoftbusAdapter::DSchedTransportSoftbusAdapter()
{
}

DSchedTransportSoftbusAdapter::~DSchedTransportSoftbusAdapter()
{
}

int32_t DSchedTransportSoftbusAdapter::InitChannel()
{
    return ERR_OK;
}

int32_t DSchedTransportSoftbusAdapter::ConnectDevice(std::string &peerDeviceId)
{
    return ERR_OK;
}

int32_t DSchedTransportSoftbusAdapter::SendData(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer)
{
    return ERR_OK;
}

int32_t DSchedTransportSoftbusAdapter::DisconnectDevice(std::string &peerDeviceId)
{
    return ERR_OK;
}

int32_t DSchedTransportSoftbusAdapter::ReleaseChannel()
{
    return ERR_OK;
}

void DSchedTransportSoftbusAdapter::RegisterListener(int32_t serviceType, std::shared_ptr<IDataListener> listener)
{
}
}  // namespace DistributedSchedule
}  // namespace OHOS