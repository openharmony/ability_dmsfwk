/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "softbus_adapter/softbus_adapter.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "SoftbusAdapter";
}

IMPLEMENT_SINGLE_INSTANCE(SoftbusAdapter);

int32_t SoftbusAdapter::SendSoftbusEvent(uint8_t* sendData, uint32_t sendDataLen)
{
    return 0;
}

int32_t SoftbusAdapter::StopSoftbusEvent()
{
    return 0;
}

void SoftbusAdapter::OnBroadCastRecv(std::string& networkId, uint8_t* data, uint32_t dataLen)
{
    return;
}

int32_t SoftbusAdapter::RegisterSoftbusEventListener(std::shared_ptr<SoftbusAdapterListener>& listener)
{
    return 0;
}

int32_t SoftbusAdapter::UnregisterSoftbusEventListener(std::shared_ptr<SoftbusAdapterListener>& listener)
{
    return 0;
}
} // namespace DistributedSchedule
} // namespace OHOS
