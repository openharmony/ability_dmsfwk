/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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
ani_object CreateDistributedExtensionContextETS(ani_env *env,
    std::shared_ptr<DistributedExtensionContext> &context);

class DistributedExtensionContextETSConnection : public AbilityConnectCallback {
public:
    explicit DistributedExtensionContextETSConnection(ani_vm *etsVm);
    ~DistributedExtensionContextETSConnection();
    void OnAbilityConnectDone(const AppExecFwk::ElementName &element,
        const sptr<IRemoteObject> &remoteObject, int32_t resultCode) override;
    void OnAbilityDisconnectDone(const AppExecFwk::ElementName &element, int32_t resultCode) override;
    void CallEtsFailed(int32_t errorCode);
    void SetConnectionId(int32_t id);
    int32_t GetConnectionId() { return connectionId_; }
    void SetConnectionRef(ani_object connectOptionsObj);
    void RemoveConnectionObject();

private:
    ani_vm *etsVm_ = nullptr;
    int32_t connectionId_ = -1;
    ani_ref etsConnectionRef_ = nullptr;
};

class DistributedExtensionContextETS {
public:
    explicit DistributedExtensionContextETS(std::shared_ptr<DistributedExtensionContext> context)
        : context_(std::move(context)) {}
    ~DistributedExtensionContextETS() = default;

    static void Finalizer(ani_env *env, ani_object obj);
    static DistributedExtensionContextETS *GetEtsAbilityContext(ani_env *env, ani_object obj);
    static ani_long ConnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
        ani_object wantObj, ani_object connectOptionsObj);
    static void DisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
        ani_long connectId, ani_object callback);
    std::weak_ptr<DistributedExtensionContext> GetAbilityContext()
    {
        return context_;
    }

private:
    ani_long OnConnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
        ani_object wantObj, ani_object connectOptionsObj);
    void OnDisconnectServiceExtensionAbility(ani_env *env, ani_object aniObj,
        ani_long connectId, ani_object callback);
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
