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

#include "js_continuation_state_manager.h"
#include "js_continuation_state_client.h"

#include "napi_error_code.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;
namespace {
    const std::string TAG = "JsContinuationStateManager";
    const std::string BIZTYPE_PREPARE_CONTINUE = "prepareContinue";
    const int32_t ARG_INDEX_4_CALLBACK_FUNC = 2;
    const int32_t SUCCESS = 0;
    const int32_t FAILED = 1;
}

std::map<std::string, sptr<DistributedSchedule::JsContinuationStateManagerStub>> JsContinuationStateManager::jsContinuationStateManagerStubCache_;

napi_value JsContinuationStateManager::ContinueStateCallbackOn(napi_env env, napi_callback_info info)
{
    HILOGI("ContinueStateCallbackOn call");
    napi_value ret = nullptr;
    int32_t result = SUCCESS;
    sptr<DistributedSchedule::JsContinuationStateManagerStub> stub = CreateStub(env, info);
    if (stub == nullptr || BIZTYPE_PREPARE_CONTINUE != stub->callbackData_.bizType) {
        HILOGE("ContinueStateCallbackOn Unsupported business type: %{public}s; need: %{public}s",
               stub->callbackData_.bizType.c_str(), BIZTYPE_PREPARE_CONTINUE.c_str());
        result = FAILED;
        NAPI_CALL(env, napi_get_value_int32(env, ret, &result));
        return ret;
    }
    DistributedSchedule::ContinuationStateClient client;
    result = client.RegisterContinueStateCallback(stub);
    HILOGI("ContinueStateCallbackOn register callback result: %{public}d", result);
    NAPI_CALL(env, napi_get_value_int32(env, ret, &result));
    return ret;
}

napi_value JsContinuationStateManager::ContinueStateCallbackOff(napi_env env, napi_callback_info info)
{
    HILOGI("ContinueStateCallbackOff call");
    napi_value ret = nullptr;
    int32_t result = SUCCESS;
    sptr<DistributedSchedule::JsContinuationStateManagerStub> stub = CreateStub(env, info);
    if (stub == nullptr || BIZTYPE_PREPARE_CONTINUE != stub->callbackData_.bizType) {
        HILOGE("ContinueStateCallbackOff Unsupported business type: %{public}s; need: %{public}s",
               stub->callbackData_.bizType.c_str(), BIZTYPE_PREPARE_CONTINUE.c_str());
        result = FAILED;
        NAPI_CALL(env, napi_get_value_int32(env, ret, &result));
        return ret;
    }
    DistributedSchedule::ContinuationStateClient client;
    result = client.UnRegisterContinueStateCallback(stub);
    HILOGI("ContinueStateCallbackOff unregister callback result: %{public}d", result);
    NAPI_CALL(env, napi_get_value_int32(env, ret, &result));
    return ret;
}

sptr<DistributedSchedule::JsContinuationStateManagerStub> JsContinuationStateManager::CreateStub(
    napi_env env, napi_callback_info info)
{
    size_t argc = 3;
    napi_value args[3];
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, args, nullptr, nullptr));
    // this.context is 2ed parameter
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext = nullptr;
    GetAbilityContext(abilityContext, env, args[1]);
    if (abilityContext == nullptr) {
        HILOGE("get ability context failed");
        return nullptr;
    }
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = abilityContext->GetAbilityInfo();

    napi_valuetype valuetype;
    NAPI_CALL(env, napi_typeof(env, args[ARG_INDEX_4_CALLBACK_FUNC], &valuetype));
    if (valuetype != napi_function) {
        return nullptr;
    }
    napi_ref callbackRef = nullptr;
    napi_create_reference(env, args[ARG_INDEX_4_CALLBACK_FUNC], 1, &callbackRef);

    // 如果缓存存在，更新回调函数，不存在则创建stub
    std::string bundleName = abilityContext->GetBundleName();
    int32_t missionId;
    abilityContext->GetMissionId(missionId);
    std::string moduleName = abilityInfo->moduleName;
    std::string abilityName = abilityInfo->name;
    std::string key = std::to_string(missionId) + bundleName + moduleName + abilityName;
    auto cacheStubEntry = jsContinuationStateManagerStubCache_.find(key);
    if(cacheStubEntry == jsContinuationStateManagerStubCache_.end() || cacheStubEntry->second == nullptr){
        sptr<DistributedSchedule::JsContinuationStateManagerStub> stub(
                new DistributedSchedule::JsContinuationStateManagerStub());
        DistributedSchedule::JsContinuationStateManagerStub::StateCallbackData callbackData;
        size_t stringSize = 0;
        std::string type;
        napi_get_value_string_utf8(env, args[0], nullptr, 0, &stringSize);
        napi_get_value_string_utf8(env, args[0], &type[0], stringSize + 1, &stringSize);
        callbackData.bizType = type.c_str();
        callbackData.bundleName = abilityContext->GetBundleName();
        abilityContext->GetMissionId(callbackData.missionId);
        callbackData.moduleName = abilityInfo->moduleName;
        callbackData.abilityName = abilityInfo->name;
        callbackData.callbackRef = callbackRef;
        callbackData.env = env;
        stub->callbackData_ = callbackData;
        jsContinuationStateManagerStubCache_[key] = stub;
    }else{
        napi_ref oldCallbackRef = jsContinuationStateManagerStubCache_[key]->callbackData_.callbackRef;
        if (oldCallbackRef != nullptr) {
            napi_delete_reference(env, oldCallbackRef);
        }
        jsContinuationStateManagerStubCache_[key]->callbackData_.callbackRef = callbackRef;
    }
    return jsContinuationStateManagerStubCache_[key];
}

void JsContinuationStateManager::GetAbilityContext(
    std::shared_ptr<AbilityRuntime::AbilityContext> &abilityContext, napi_env env, napi_value context)
{
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, context, stageMode);
    if (status != napi_ok || !stageMode) {
        auto ability = OHOS::AbilityRuntime::GetCurrentAbility(env);
        if (!ability) {
            HILOGE("get ability info failed");
            return;
        }
        abilityContext = ability->GetAbilityContext();
        if (!abilityContext) {
            HILOGE("get ability context failed");
            return;
        }
    } else {
        auto modeContext = AbilityRuntime::GetStageModeContext(env, context);
        if (!modeContext) {
            HILOGE("get stageMode ability info failed");
            return;
        }
        abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(modeContext);
        if (!abilityContext) {
            HILOGE("get stageMode ability context failed");
            return;
        }
    }
}

napi_value JsContinueManagerInit(napi_env env, napi_value exportObj)
{
    static napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("on", JsContinuationStateManager::ContinueStateCallbackOn),
        DECLARE_NAPI_FUNCTION("off", JsContinuationStateManager::ContinueStateCallbackOff),
    };
    NAPI_CALL(env, napi_define_properties(env, exportObj, sizeof(desc) / sizeof(desc[0]), desc));
    return exportObj;
}

static napi_module continueManagerModule = {
    .nm_filename = "app/ability/libcontinuemanager_napi.so/continuemanager.js",
    .nm_register_func = OHOS::DistributedSchedule::JsContinueManagerInit,
    .nm_modname = "app.ability.continueManager",
};

extern "C" __attribute__((constructor)) void ContinuationStateManagerModuleRegister()
{
    napi_module_register(&continueManagerModule);
}
} // namespace DistributedSchedule
} // namespace OHOS