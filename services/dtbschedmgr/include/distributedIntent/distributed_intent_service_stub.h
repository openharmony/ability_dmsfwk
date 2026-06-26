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

#ifndef OHOS_DISTRIBUTED_INTENT_SERVICE_STUB_H
#define OHOS_DISTRIBUTED_INTENT_SERVICE_STUB_H

#include <cstdint>
#include <map>
#include <mutex>
#include "distributed_intent_provider.h"
#include "distributed_intent_service_interface.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "nocopyable.h"

namespace OHOS {
namespace DistributedSchedule {

class DistributedIntentServiceStub : public IRemoteStub<IDistributedIntentService> {
public:
    DistributedIntentServiceStub();
    virtual ~DistributedIntentServiceStub() = default;

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data, MessageParcel& reply,
        MessageOption& option) override;
    int32_t StartRemoteIntent(const OHOS::AAFwk::Want& want, const IntentCallerInfo& callerInfo,
        const sptr<IRemoteObject>& resultCallback) override;
    int32_t SendIntentResult(const OHOS::AAFwk::Want& want,
        const IntentCallerInfo& callerInfo, const std::string& resultMsg) override;

    static void SetProvider(IIntentProvider* provider);
    static IIntentProvider* GetProvider();

private:
    DISALLOW_COPY_AND_MOVE(DistributedIntentServiceStub);
    using RequestHandler = int32_t (DistributedIntentServiceStub::*)(MessageParcel&, MessageParcel&);
    int32_t StartRemoteIntentInner(MessageParcel& data, MessageParcel& reply);
    int32_t SendIntentResultInner(MessageParcel& data, MessageParcel& reply);
    std::map<uint32_t, RequestHandler> requestHandlers_;
    static IIntentProvider* provider_;
    static std::mutex providerMutex_;
};

} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_INTENT_SERVICE_STUB_H
