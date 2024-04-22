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

#ifndef OHOS_SOFTBUS_ADAPTER_H
#define OHOS_SOFTBUS_ADAPTER_H

#include <string>
#include "single_instance.h"
#include "softbus_adapter_listener.h"

namespace OHOS {
namespace DistributedSchedule {
class SoftbusAdapter {
public:
    DECLARE_SINGLE_INSTANCE_BASE(SoftbusAdapter);
public:
    int32_t SendSoftbusEvent(uint8_t* sendData, uint32_t sendDataLen);
    int32_t StopSoftbusEvent();
    int32_t RegisterSoftbusEventListener(const std::shared_ptr<SoftbusAdapterListener>& listener);
    int32_t UnregisterSoftbusEventListener(const std::shared_ptr<SoftbusAdapterListener>& listener);
    void OnBroadCastRecv(std::string& networkId, uint8_t* data, uint32_t dataLen);

private:
    SoftbusAdapter() {}
    std::shared_ptr<SoftbusAdapterListener> softbusAdapterListener_;
    std::string pkgName_ = "dms";
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif /* OHOS_SOFTBUS_ADAPTER_H */
