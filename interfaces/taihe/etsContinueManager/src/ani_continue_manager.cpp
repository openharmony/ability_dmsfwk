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

#include "dtbschedmgr_log.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#include "ani_continue_manager.h"
#include "ani_continue_client.h"
#include "ani_base_context.h"
#include "ohos.app.ability.continueManager.ContinueResultInfo.ani.1.hpp"
#include "taihe/runtime.hpp"
#include "taihe/platform/ani.hpp"

namespace OHOS {
namespace DistributedSchedule {
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;
namespace {
    const std::string TAG = "AniContinuationStateManager";
    const std::string BIZTYPE_PREPARE_CONTINUE = "prepareContinue";
    const std::string CODE_KEY_NAME = "code";
    const std::string ERR_DMS_WORK_ABNORMALLY_MSG = "the system ability work abnormally.";
    const int32_t SUCCESS = 0;
}

int32_t AniContinueManager::OnContinueStateCallback(uintptr_t context, uintptr_t opq)
{
    sptr<DistributedSchedule::AniContinuationStateManagerStub> stub = CreateStub(context, opq, true);
    if (stub == nullptr || BIZTYPE_PREPARE_CONTINUE != stub->callbackData_.bizType) {
        HILOGE("ContinueStateCallbackOn Unsupported business type: %{public}s; need: %{public}s",
            stub == nullptr ? "" : stub->callbackData_.bizType.c_str(), BIZTYPE_PREPARE_CONTINUE.c_str());
        taihe::set_business_error(ERR_DMS_WORK_ABNORMALLY, ERR_DMS_WORK_ABNORMALLY_MSG.c_str());
        return ANI_ERROR;
    }

    std::string key = std::to_string(stub->callbackData_.missionId) + stub->callbackData_.bundleName +
        stub->callbackData_.moduleName + stub->callbackData_.abilityName;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        auto cacheStubEntry = callbackStubs_.find(key);
        if (cacheStubEntry == callbackStubs_.end() || cacheStubEntry->second == nullptr) {
            callbackStubs_[key] = stub;
        } else {
            ani_ref oldCallbackRef = callbackStubs_[key]->callbackData_.callbackRef;
            if (oldCallbackRef != nullptr) {
                stub->callbackData_.env.GlobalReference_Delete(oldCallbackRef);
            }
            callbackStubs_[key]->callbackData_.callbackRef = stub->callbackData_.callbackRef;
        }
    }

    AniContinuationStateClient client;
    int32_t result = client.RegisterContinueStateCallback(stub);
    if (result != ANI_OK) {
        HILOGE("RegisterContinueStateCallback fail {%{public}s} {%{public}s}",
            std::to_string(ERR_DMS_WORK_ABNORMALLY).c_str(), ERR_DMS_WORK_ABNORMALLY_MSG.c_str());
        taihe::set_business_error(ERR_DMS_WORK_ABNORMALLY, ERR_DMS_WORK_ABNORMALLY_MSG.c_str());
    }
    return result;
}

bool AniContinueManager::SendUnRegister(sptr<DistributedSchedule::AniContinuationStateManagerStub> &stub,
    uintptr_t context, ::taihe::optional_view<uintptr_t> opq, int32_t &result)
{
    uintptr_t tmp = 0;
    if (opq.has_value()) {
        tmp = opq.value();
    }
    stub = CreateStub(context, tmp, opq.has_value());
    if (stub == nullptr || BIZTYPE_PREPARE_CONTINUE != stub->callbackData_.bizType) {
        HILOGE("ContinueStateCallbackOff Unsupported business type: %{public}s; need: %{public}s",
            stub == nullptr ? "" : stub->callbackData_.bizType.c_str(), BIZTYPE_PREPARE_CONTINUE.c_str());
        return false;
    }
    
    AniContinuationStateClient client;
    result = client.UnRegisterContinueStateCallback(stub);

    std::string key = std::to_string(stub->callbackData_.missionId) + stub->callbackData_.bundleName +
        stub->callbackData_.moduleName + stub->callbackData_.abilityName;
    {
        std::lock_guard<std::recursive_mutex> lock(mutex_);
        if (result == ANI_OK) {
            callbackStubs_.erase(key);
        }
    }
    return true;
}

int32_t AniContinueManager::OffContinueStateCallback(uintptr_t context, ::taihe::optional_view<uintptr_t> opq)
{
    int32_t result = SUCCESS;
    sptr<DistributedSchedule::AniContinuationStateManagerStub> stub = nullptr;
    if (!SendUnRegister(stub, context, opq, result)) {
        taihe::set_business_error(ERR_DMS_WORK_ABNORMALLY, ERR_DMS_WORK_ABNORMALLY_MSG.c_str());
        return ANI_ERROR;
    }

    if (stub->callbackData_.callbackRef != nullptr) {
        std::vector<ani_ref> args;

        taihe::env_guard guard;
        ani_env *env = guard.get_env();
        if (env == nullptr) {
            HILOGE("env is nullptr!!!");
            return ERR_DMS_WORK_ABNORMALLY;
        }
        ohos::app::ability::continueManager::ContinueStateCode state =
            ohos::app::ability::continueManager::ContinueStateCode::key_t::SUCCESS;
        if (result != ANI_OK) {
            state = ohos::app::ability::continueManager::ContinueStateCode::key_t::SYSTEM_ERROR;
        }
        ohos::app::ability::continueManager::ContinueResultInfo info = {
            .resultState = state,
            .resultInfo = taihe::optional<taihe::string>(std::in_place_t{}, "")
        };
        ani_object param = taihe::into_ani<ohos::app::ability::continueManager::ContinueResultInfo>(env, info);
        args.push_back(reinterpret_cast<ani_ref>(param));
        ani_ref undefNull = nullptr;
        env->GetNull(@undefNull);
        args.push_back(undefNull);
        ani_fn_object onFn = reinterpret_cast<ani_fn_object>(stub->callbackData_.callbackRef);
        ani_ref result;
        if (env->FunctionalObject_Call(onFn, args.size(), args.data(), &result) != ANI_OK) {
            HILOGE("OnMessage functionalObject_Call failed");
        }
    }

    if (result != ANI_OK) {
        HILOGE("UnRegisterContinueStateCallback fail {%{public}s} {%{public}s}",
            std::to_string(ERR_DMS_WORK_ABNORMALLY).c_str(), ERR_DMS_WORK_ABNORMALLY_MSG.c_str());
        taihe::set_business_error(ERR_DMS_WORK_ABNORMALLY, ERR_DMS_WORK_ABNORMALLY_MSG.c_str());
        return result;
    }
    return ANI_OK;
}

sptr<AniContinuationStateManagerStub> AniContinueManager::CreateStub(uintptr_t context, uintptr_t opq, bool flag)
{
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext = nullptr;
    GetAbilityContext(abilityContext, context);
    if (abilityContext == nullptr) {
        HILOGD("get ability context failed");
        return nullptr;
    }
    ani_env *env = ::taihe::get_env();
    if (env == nullptr) {
        HILOGD("env is nullptr");
        return nullptr;
    }
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = abilityContext->GetAbilityInfo();
    if (abilityInfo == nullptr) {
        HILOGD("get ability fail");
        return nullptr;
    }
    AniContinuationStateManagerStub::StateCallbackData callbackData;
    callbackData.env = *env;
    callbackData.bundleName = abilityInfo->bundleName;
    callbackData.moduleName = abilityInfo->moduleName;
    callbackData.abilityName = abilityInfo->name;
    callbackData.bizType = BIZTYPE_PREPARE_CONTINUE;
    if (flag) {
        ani_ref callbackRef = nullptr;
        ani_object funObject = reinterpret_cast<ani_object>(opq);
        ani_status status = env->GlobalReference_Create(funObject, &callbackRef);
        if (status != ANI_OK) {
            HILOGE("create callback object failed, status = %{public}d", status);
            callbackRef = nullptr;
        }
        callbackData.callbackRef = callbackRef;
    }

    abilityContext->GetMissionId(callbackData.missionId);
    sptr<AniContinuationStateManagerStub> stub(new AniContinuationStateManagerStub());
    stub->callbackData_ = callbackData;
    return stub;
}

bool AniContinueManager::GetAbilityContext(std::shared_ptr<AbilityRuntime::AbilityContext> &abilityContext,
    uintptr_t context)
{
    ani_env *env = taihe::get_env();
    if (env == nullptr) {
        HILOGD("env is nullptr");
        return false;
    }

    ani_boolean stageMode = false;
    ani_object uiContext = reinterpret_cast<ani_object>(context);
    ani_status status = AbilityRuntime::IsStageContext(env, uiContext, stageMode);
    if (status != ANI_OK || !stageMode) {
        return false;
    }

    auto modeContext = AbilityRuntime::GetStageModeContext(env, uiContext);
    if (!modeContext) {
        HILOGD("get stageMode ability info failed");
        return false;
    }

    abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(modeContext);
    if (!abilityContext) {
        HILOGE("get stageMode ability context failed");
        return false;
    }
    return true;
}

std::shared_ptr<AniContinueManager> AniContinueManager::GetInstance()
{
    static std::shared_ptr<AniContinueManager> instance;
    if (instance == nullptr) {
        instance.reset(new AniContinueManager());
    }
    return instance;
}
} // namespace DistributedSchedule
} // namespace OHOS