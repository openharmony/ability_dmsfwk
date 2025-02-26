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

#ifndef OHOS_DISTRIBUTED_EXTENSION_CONTEXT_JS_H
#define OHOS_DISTRIBUTED_EXTENSION_CONTEXT_JS_H

#include "distributed_extension_context.h"
#include "js_runtime_utils.h"

namespace OHOS {
namespace DistributedSchedule {
class DistributedExtensionContextJS final {
public:
    explicit DistributedExtensionContextJS(const std::shared_ptr<DistributedExtensionContext>& ct) : context(ct) {}
    ~DistributedExtensionContextJS() = default;

    static void Finalizer(napi_env env, void* data, void* hint);
private:
    std::weak_ptr<DistributedExtensionContext> context;
};

napi_value CreateDistributedExtensionContextJS(napi_env env, std::shared_ptr<DistributedExtensionContext> ct);
}
}

#endif // OHOS_DISTRIBUTED_EXTENSION_CONTEXT_JS_H
