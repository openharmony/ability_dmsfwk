/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DMS_SOFTBUS_STRUCTURE_H
#define OHOS_DMS_SOFTBUS_STRUCTURE_H

#include "broadcast_struct.h"

namespace OHOS {
namespace DistributedSchedule {
typedef struct {
    int32_t (*SendSoftbusEvent)(EventData& eventData);
    int32_t (*StopSoftbusEvent)();
    int32_t (*RegisterSoftbusEventListener)(EventListener& eventListener);
    int32_t (*UnregisterSoftbusEventListener)(EventListener& eventListener);
    int32_t (*QueryValidQos)(const std::string &peerDeviceId, uint32_t &validQosCase);
} IDmsBroadcastAdapter;
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DMS_SOFTBUS_STRUCTURE_H
