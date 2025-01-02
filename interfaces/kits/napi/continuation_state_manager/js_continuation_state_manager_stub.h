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

#ifndef ABILITY_DMSFWK_JS_CONTINUATION_STATE_MANAGER_STUB_H
#define ABILITY_DMSFWK_JS_CONTINUATION_STATE_MANAGER_STUB_H

#include <memory>
#include "js_continuation_state_callback.h"
#include "base/continuationmgr_log.h"

#include "ipc_skeleton.h"
#include "iremote_stub.h"
#include "iremote_broker.h"
#include "native_engine/native_engine.h"
#include "napi_base_context.h"

namespace OHOS {
namespace DistributedSchedule {
class JsContinuationStateManagerStub : public IRemoteStub<IJsContinuationCallback> {
public:
    struct StateCallbackData {
        std::string bizType;
        int32_t missionId;
        std::string moduleName;
        std::string bundleName;
        std::string abilityName;
        napi_env env;
        napi_ref callbackRef;
    };

    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;
    int32_t ContinueStateCallback(MessageParcel &data, MessageParcel &reply) override;

public:
    StateCallbackData callbackData_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif //ABILITY_DMSFWK_JS_CONTINUATION_STATE_MANAGER_STUB_H
