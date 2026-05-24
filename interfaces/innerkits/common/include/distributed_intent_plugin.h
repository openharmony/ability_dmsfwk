/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_DISTRIBUTED_INTENT_PLUGIN_H
#define OHOS_DISTRIBUTED_INTENT_PLUGIN_H

#include <cstdint>
#include <string>
#include "distributed_intent_provider.h"
#include "distributed_sched_types.h"
#include "intent_socket_listener.h"
#include "iremote_object.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {

class IIntentPlugin {
public:
    virtual ~IIntentPlugin() = default;

    virtual int32_t OnRemoteRequest(uint32_t code, MessageParcel& data,
        MessageParcel& reply, MessageOption& option) = 0;

    virtual IIntentSocketEventListener* GetSocketListener() = 0;

    virtual int32_t StartRemoteIntent(const AAFwk::Want& want,
        const IntentCallerInfo& callerInfo, const sptr<IRemoteObject>& resultCallback) = 0;

    virtual int32_t SendIntentResult(const AAFwk::Want& want,
        const IntentCallerInfo& callerInfo, const std::string& resultMsg) = 0;

    virtual void OnDeviceOffline(const std::string& networkId) = 0;
};

} // namespace DistributedSchedule
} // namespace OHOS

extern "C" __attribute__((visibility("default"))) void* CreateIntentPlugin(
    OHOS::DistributedSchedule::IIntentProvider* provider);

#endif // OHOS_DISTRIBUTED_INTENT_PLUGIN_H
