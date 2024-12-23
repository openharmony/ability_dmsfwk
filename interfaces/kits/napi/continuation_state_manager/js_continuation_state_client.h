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

#ifndef ABILITY_DMSFWK_JS_CONTINUATION_STATE_CLIENT_H
#define ABILITY_DMSFWK_JS_CONTINUATION_STATE_CLIENT_H

#include "js_continuation_state_manager_stub.h"
#include "base/continuationmgr_log.h"
#include "iremote_broker.h"

namespace OHOS {
namespace DistributedSchedule {
class ContinuationStateClient {

public:
    int32_t RegisterContinueStateCallback(const sptr<JsContinuationStateManagerStub> stub);
    int32_t UnRegisterContinueStateCallback(const sptr<JsContinuationStateManagerStub> stub);

private:
    sptr<IRemoteObject> GetDmsProxy();
};
} // namespace DistributedSchedule
} // namespace OHOS

#endif //ABILITY_DMSFWK_JS_CONTINUATION_STATE_CLIENT_H
