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
#include "broadcast.h"
#include "distributed_radar.h"
#include "dtbschedmgr_log.h"
#include "softbus_error_code.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "SoftbusAdapter";
}

IMPLEMENT_SINGLE_INSTANCE(SoftbusAdapter);

int32_t SoftbusAdapter::SendSoftbusEvent(uint8_t* sendData, uint32_t sendDataLen)
{
    HILOGI("SendSoftbusEvent pkgName: %{public}s.", pkgName_.c_str());
    EventData eventData;
    eventData.event = FOREGROUND_APP;
    eventData.freq = EVENT_HIGH_FREQ;
    eventData.data = sendData;
    eventData.dataLen = sendDataLen;
    int32_t ret = SendEvent(pkgName_.c_str(), BROADCAST_TARGET_AREA, &eventData);
    if (ret != SOFTBUS_OK) {
        HILOGE("SendEvent failed, ret:%{public}d.", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusAdapter::StopSoftbusEvent()
{
    HILOGI("StopSoftbusEvent pkgName: %{public}s.", pkgName_.c_str());
    int32_t ret = StopEvent(pkgName_.c_str(), BROADCAST_TARGET_AREA, FOREGROUND_APP);
    if (ret != SOFTBUS_OK) {
        HILOGE("StopEvent failed, ret:%{public}d.", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static void EventListenerReceived(const EventNotify *eventNotify)
{
    HILOGI("%{public}s called.", __func__);
    std::string networkId(eventNotify->senderNetworkId);
    SoftbusAdapter::GetInstance().OnBroadCastRecv(networkId, eventNotify->data, eventNotify->dataLen);
}

void SoftbusAdapter::OnBroadCastRecv(std::string& networkId, uint8_t* data, uint32_t dataLen)
{
    if (softbusAdapterListener_ != nullptr) {
        softbusAdapterListener_->OnDataRecv(networkId, data, dataLen);
    } else {
        HILOGE("softbusAdapterListener_ is nullptr");
    }
}

int32_t SoftbusAdapter::RegisterSoftbusEventListener(const std::shared_ptr<SoftbusAdapterListener>& listener)
{
    if (listener == nullptr) {
        HILOGE("Registering listener failed");
        return SOFTBUS_INVALID_PARAM;
    }
    softbusAdapterListener_ = listener;
    EventListener eventListener;
    eventListener.event = FOREGROUND_APP;
    eventListener.freq = EVENT_MID_FREQ;
    eventListener.deduplicate = true;
    eventListener.OnEventReceived = EventListenerReceived;
    HILOGI("RegisterSoftbusEventListener pkgName: %s.", pkgName_.c_str());
    int32_t ret = RegisterEventListener(pkgName_.c_str(), &eventListener);
    DmsRadar::GetInstance().RegisterSoftbusCallbackRes("RegisterSoftbusEventListener", ret);
    if (ret != SOFTBUS_OK) {
        HILOGE("RegisterSoftbusEventListener failed, ret:%d.", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t SoftbusAdapter::UnregisterSoftbusEventListener(const std::shared_ptr<SoftbusAdapterListener>& listener)
{
    if (listener == nullptr) {
        HILOGE("Unregistering listener failed");
        return SOFTBUS_INVALID_PARAM;
    }
    softbusAdapterListener_ = listener;
    EventListener eventListener;
    eventListener.event = FOREGROUND_APP;
    eventListener.freq = EVENT_MID_FREQ;
    eventListener.deduplicate = true;
    eventListener.OnEventReceived = EventListenerReceived;
    HILOGI("UnregisterSoftbusEventListener pkgName: %s.", pkgName_.c_str());
    int32_t ret = UnregisterEventListener(pkgName_.c_str(), &eventListener);
    if (ret != SOFTBUS_OK) {
        HILOGE("UnregisterSoftbusEventListener failed, ret:%d.", ret);
        return ret;
    }
    return SOFTBUS_OK;
}
} // namespace DistributedSchedule
} // namespace OHOS
