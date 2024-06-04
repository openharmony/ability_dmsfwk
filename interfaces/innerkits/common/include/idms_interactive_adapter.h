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

#ifndef OHOS_IDMS_INTERACTIVE_ADAPTER_H
#define OHOS_IDMS_INTERACTIVE_ADAPTER_H

#include <string>

#include "caller_info.h"
#include "dm_device_info.h"
#include "message_parcel.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
typedef struct {
    int32_t (*StartRemoteAbilityAdapter)(const OHOS::AAFwk::Want& want, int32_t callerUid, int32_t requestCode,
        uint32_t accessToken);
    int32_t (*StartAbilityFromRemoteAdapter)(MessageParcel& data, MessageParcel& reply);

    int32_t (*StopAbilityFromRemoteAdapter)(MessageParcel& data, MessageParcel& reply);

    int32_t (*ConnectRemoteAbilityAdapter)(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect,
        int32_t callerUid, int32_t callerPid, uint32_t accessToken);
    int32_t (*ConnectAbilityFromRemoteAdapter)(MessageParcel& data, MessageParcel& reply);

    int32_t (*DisconnectRemoteAbilityAdapter)(const sptr<IRemoteObject>& connect, int32_t callerUid,
        uint32_t accessToken);
    int32_t (*DisconnectAbilityFromRemoteAdapter)(MessageParcel& data, MessageParcel& reply);

    int32_t (*NotifyAbilityLifecycleChangedFromRemoteAdapter)(MessageParcel& data, MessageParcel& reply);

    void (*OnDeviceOnlineEx)(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);
    void (*OnDeviceOfflineEx)(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);
    void (*OnDeviceInfoChangedEx)(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);
} IDmsInteractiveAdapter;
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_IDMS_INTERACTIVE_ADAPTER_H
