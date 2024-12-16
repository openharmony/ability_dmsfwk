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

#include "dtbschedmgr_log.h"
#include "softbus_adapter/softbus_adapter.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "SoftbusAdapter";
}

IMPLEMENT_SINGLE_INSTANCE(SoftbusAdapter);

void SoftbusAdapter::Init()
{
    HILOGI("%{public}s common called. ", __func__);
}

void SoftbusAdapter::UnInit()
{
    HILOGI("%{public}s common called. ", __func__);
}

int32_t SoftbusAdapter::SendSoftbusEvent(std::shared_ptr<DSchedDataBuffer> buffer)
{
    HILOGI("%{public}s common called. ", __func__);
    return 0;
}

int32_t SoftbusAdapter::StopSoftbusEvent()
{
    HILOGI("%{public}s common called. ", __func__);
    return 0;
}

void SoftbusAdapter::OnBroadCastRecv(std::string& networkId, uint8_t* data, uint32_t dataLen)
{
    HILOGI("%{public}s common called. ", __func__);
    return;
}

int32_t SoftbusAdapter::RegisterSoftbusEventListener(const std::shared_ptr<SoftbusAdapterListener>& listener)
{
    HILOGI("%{public}s common called. ", __func__);
    return 0;
}

int32_t SoftbusAdapter::UnregisterSoftbusEventListener(const std::shared_ptr<SoftbusAdapterListener>& listener)
{
    HILOGI("%{public}s common called. ", __func__);
    return 0;
}

void SoftbusAdapter::ReRegister()
{
    HILOGI("%{public}s common called. ", __func__);
    return;
}
} // namespace DistributedSchedule
} // namespace OHOS
