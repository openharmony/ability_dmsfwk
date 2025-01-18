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

#include "distributed_extension_context_js.h"

#include "dtbschedmgr_log.h"
#include "js_extension_context.h"
#include "js_runtime.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedExtensionContextJS";

napi_value CreateDistributedExtensionContextJS(napi_env env, std::shared_ptr<DistributedExtensionContext> context)
{
    if (context == nullptr) {
        HILOGE("Failed to CreateDistributedExtensionContextJS, context is nullptr.");
        return nullptr;
    }
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = context->GetAbilityInfo();
    napi_value object = CreateJsExtensionContext(env, context, abilityInfo);
    if (object == nullptr) {
        HILOGE("Failed to CreateJsServiceExtensionContext, context is nullptr.");
        return nullptr;
    }
    std::unique_ptr<DistributedExtensionContextJS> jsContext =
        std::make_unique<DistributedExtensionContextJS>(context);
    napi_wrap(env, object, jsContext.release(), DistributedExtensionContextJS::Finalizer, nullptr, nullptr);
    return object;
}

void DistributedExtensionContextJS::Finalizer(napi_env env, void* data, void* hint)
{
    HILOGI("Finalizer Called.");
    std::unique_ptr<DistributedExtensionContextJS>(static_cast<DistributedExtensionContextJS*>(data));
}
}
}
