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

#ifndef OHOS_DISTRIBUTED_INTENT_SERVICE_INTERFACE_H
#define OHOS_DISTRIBUTED_INTENT_SERVICE_INTERFACE_H

#include <cstdint>
#include "iremote_broker.h"
#include "distributed_sched_types.h"
#include "distributedsched_ipc_interface_code.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {

class IDistributedIntentService : public OHOS::IRemoteBroker {
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"ohos.distributedschedule.IDistributedIntentService");

    virtual int32_t StartRemoteIntent(const OHOS::AAFwk::Want& want, const IntentCallerInfo& callerInfo,
        const sptr<IRemoteObject>& resultCallback)
    {
        return 0;
    }

    virtual int32_t SendIntentResult(const OHOS::AAFwk::Want& want,
        const IntentCallerInfo& callerInfo, const std::string& resultMsg)
    {
        return 0;
    }
};

} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_INTENT_SERVICE_INTERFACE_H
