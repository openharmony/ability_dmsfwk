/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef ANI_CONTINUE_MANAGER_H
#define ANI_CONTINUE_MANAGER_H

#include "ani_continue_manager_stub.h"
#include "ability_context.h"
#include "taihe/optional.hpp"
namespace OHOS {
namespace DistributedSchedule {
// using namespace OHOS::AbilityRuntime;
class AniContinueManager {
public:
    int32_t OnContinueStateCallback(uintptr_t context, uintptr_t opq);
    int32_t OffContinueStateCallback(uintptr_t context, ::taihe::optional_view<uintptr_t> opq);
    static std::shared_ptr<AniContinueManager> GetInstance();
private:
    sptr<AniContinuationStateManagerStub> CreateStub(uintptr_t context, uintptr_t opq, bool flag);
    bool GetAbilityContext(std::shared_ptr<AbilityRuntime::AbilityContext> &abilityContext, uintptr_t context);

public:
    std::recursive_mutex mutex_;
    std::map<std::string, sptr<AniContinuationStateManagerStub>> callbackStubs_;
};
}
}
#endif