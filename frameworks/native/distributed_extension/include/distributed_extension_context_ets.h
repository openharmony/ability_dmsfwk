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

#ifndef OHOS_ABILITY_RUNTIME_ETS_FORM_EXTENSION_CONTEXT_H
#define OHOS_ABILITY_RUNTIME_ETS_FORM_EXTENSION_CONTEXT_H

#include "ani.h"
#include "ability_connect_callback.h"
#include "event_handler.h"
#include "distributed_extension_context.h"
#include "ipc_skeleton.h"
#include "tokenid_kit.h"

namespace OHOS {
namespace DistributedSchedule {
ani_object CreateDistributedExtensionContextETS(ani_env *env, std::shared_ptr<DistributedExtensionContext> &context);
class DistributedExtensionContextETS {
public:
    explicit DistributedExtensionContextETS(std::shared_ptr<DistributedExtensionContext> context)
        : context_(std::move(context)) {}
    ~DistributedExtensionContextETS() = default;
    static void Finalizer(ani_env *env, ani_object obj);
    static DistributedExtensionContextETS *GetEtsAbilityContext(ani_env *env, ani_object obj);
    std::weak_ptr<DistributedExtensionContext> GetAbilityContext()
    {
        return context_;
    }
private:
    std::weak_ptr<DistributedExtensionContext> context_;
};

struct ETSConnectionKey {
    AAFwk::Want want;
    int64_t id;
};

struct ets_key_compare {
    bool operator()(const ETSConnectionKey &key1, const ETSConnectionKey &key2) const
    {
        return key1.id < key2.id;
    }
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_ABILITY_RUNTIME_ETS_FORM_EXTENSION_CONTEXT_H