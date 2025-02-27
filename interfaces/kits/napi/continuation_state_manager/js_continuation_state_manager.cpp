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
    const std::string CODE_KEY_NAME = "code";
    const int32_t ARG_INDEX_4_CALLBACK_FUNC = 2;
    const int32_t SUCCESS = 0;
    const int32_t FAILED = 1;
    constexpr int32_t ARG_COUNT_THREE = 3;
    const int32_t CALLBACK_PARAMS_NUM = 2;
}

std::map<std::string, sptr<DistributedSchedule::JsContinuationStateManagerStub>>
    JsContinuationStateManager::callbackStubs_;

napi_value JsContinuationStateManager::ContinueStateCallbackOn(napi_env env, napi_callback_info info)
{
    HILOGI("ContinueStateCallbackOn call");
    napi_value ret = nullptr;
    int32_t result = SUCCESS;
    sptr<DistributedSchedule::JsContinuationStateManagerStub> stub = CreateStub(env, info);
    if (stub == nullptr || BIZTYPE_PREPARE_CONTINUE != stub->callbackData_.bizType) {
        HILOGE("ContinueStateCallbackOn Unsupported business type: %{public}s; need: %{public}s",
            stub->callbackData_.bizType.c_str(), BIZTYPE_PREPARE_CONTINUE.c_str());
        napi_throw(env, GenerateBusinessError(env, SYSTEM_WORK_ABNORMALLY, std::to_string(SYSTEM_WORK_ABNORMALLY)));
        result = FAILED;
        napi_get_value_int32(env, ret, &result);
        return ret;
    }

    std::string key = std::to_string(stub->callbackData_.missionId) + stub->callbackData_.bundleName +
            stub->callbackData_.moduleName + stub->callbackData_.abilityName;
    auto cacheStubEntry = callbackStubs_.find(key);
    if (cacheStubEntry == callbackStubs_.end() || cacheStubEntry->second == nullptr) {
        callbackStubs_[key] = stub;
    } else {
        napi_ref oldCallbackRef = callbackStubs_[key]->callbackData_.callbackRef;
        if (oldCallbackRef != nullptr) {
            napi_delete_reference(env, oldCallbackRef);
        }
        callbackStubs_[key]->callbackData_.callbackRef = stub->callbackData_.callbackRef;
    }

    DistributedSchedule::ContinuationStateClient client;
    result = client.RegisterContinueStateCallback(stub);
    HILOGI("ContinueStateCallbackOn register callback result: %{public}d", result);

    if (result != ERR_OK) {
        napi_throw(env, GenerateBusinessError(env, result, std::to_string(result)));
    }
    napi_get_value_int32(env, ret, &result);
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
        napi_throw(env, GenerateBusinessError(env, SYSTEM_WORK_ABNORMALLY, std::to_string(SYSTEM_WORK_ABNORMALLY)));
        result = FAILED;
        napi_get_value_int32(env, ret, &result);
        return ret;
    }

    DistributedSchedule::ContinuationStateClient client;
    result = client.UnRegisterContinueStateCallback(stub);
    HILOGI("ContinueStateCallbackOff unregister callback result: %{public}d", result);

    std::string key = std::to_string(stub->callbackData_.missionId) + stub->callbackData_.bundleName +
                      stub->callbackData_.moduleName + stub->callbackData_.abilityName;
    if (result == ERR_OK) {
        callbackStubs_.erase(key);
    }
    int32_t state = result;
    napi_value callback = nullptr;
    napi_get_reference_value(env, stub->callbackData_.callbackRef, &callback);
    napi_value undefined = nullptr;
    napi_get_undefined(env, &undefined);
    napi_value continueResultInfo;
    napi_create_object(env, &continueResultInfo);
    napi_value resultState;
    napi_create_int32(env, state, &resultState);
    napi_set_named_property(env, continueResultInfo, "resultState", resultState);
    napi_value resultInfo;
    napi_create_string_utf8(env, "", 0, &resultInfo);
    napi_set_named_property(env, continueResultInfo, "resultInfo", resultInfo);
    napi_value callbackResult[2] = {NULL, continueResultInfo};
    napi_call_function(env, undefined, callback, CALLBACK_PARAMS_NUM, callbackResult, nullptr);

    if (result != ERR_OK) {
        napi_throw(env, GenerateBusinessError(env, result, std::to_string(result)));
    }
    napi_get_value_int32(env, ret, &result);
    return ret;
}

sptr<DistributedSchedule::JsContinuationStateManagerStub> JsContinuationStateManager::CreateStub(
    napi_env env, napi_callback_info info)
{
    // get and check all params
    size_t argc = ARG_COUNT_THREE;
    napi_value args[ARG_COUNT_THREE];
    napi_get_cb_info(env, info, &argc, args, nullptr, nullptr);
    if (argc != ARG_COUNT_THREE) {
        HILOGE("Parameter error. The type of number of parameters must be 3");
        napi_throw(env, GenerateBusinessError(env, PARAMETER_CHECK_FAILED,
            "Parameter error. The type of number of parameters must be 3"));
        return nullptr;
    }
    // this.context is 2nd parameter
    std::shared_ptr<AbilityRuntime::AbilityContext> abilityContext = nullptr;
    GetAbilityContext(abilityContext, env, args[1]);
    if (abilityContext == nullptr) {
        HILOGE("get ability context failed");
        napi_throw(env, GenerateBusinessError(env, PARAMETER_CHECK_FAILED,
            "get ability context failed"));
        return nullptr;
    }
    std::shared_ptr<AppExecFwk::AbilityInfo> abilityInfo = abilityContext->GetAbilityInfo();
    napi_valuetype valuetype;
    napi_typeof(env, args[ARG_INDEX_4_CALLBACK_FUNC], &valuetype);
    if (valuetype != napi_function) {
        napi_throw(env, GenerateBusinessError(env, PARAMETER_CHECK_FAILED,
            "The third parameter must be an asynchronous function"));
        return nullptr;
    }

    DistributedSchedule::JsContinuationStateManagerStub::StateCallbackData callbackData;
    callbackData.env = env;
    callbackData.bundleName = abilityContext->GetBundleName();
    callbackData.moduleName = abilityInfo->moduleName;
    callbackData.abilityName = abilityInfo->name;

    size_t stringSize = 0;
    std::string type;
    napi_get_value_string_utf8(env, args[0], nullptr, 0, &stringSize);
    napi_get_value_string_utf8(env, args[0], &type[0], stringSize + 1, &stringSize);
    callbackData.bizType = type.c_str();

    napi_ref callbackRef = nullptr;
    napi_create_reference(env, args[ARG_INDEX_4_CALLBACK_FUNC], 1, &callbackRef);
    callbackData.callbackRef = callbackRef;

    abilityContext->GetMissionId(callbackData.missionId);

    sptr <DistributedSchedule::JsContinuationStateManagerStub> stub(
        new DistributedSchedule::JsContinuationStateManagerStub());
    stub->callbackData_ = callbackData;
    return stub;
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

napi_value JsContinuationStateManager::GenerateBusinessError(
    const napi_env &env, int32_t errCode, const std::string &errMsg)
{
    napi_value code = nullptr;
    napi_create_int32(env, errCode, &code);
    napi_value message = nullptr;
    napi_create_string_utf8(env, errMsg.c_str(), NAPI_AUTO_LENGTH, &message);
    napi_value businessError = nullptr;
    napi_create_error(env, nullptr, message, &businessError);
    napi_set_named_property(env, businessError, CODE_KEY_NAME.c_str(), code);
    return businessError;
}

napi_value JsContinuationStateManager::MakeContinueStateCodeEnumObject(napi_env env)
{
    napi_value object;
    env, napi_create_object(env, &object);
    MakeEnumItem(env, object, "SUCCESS", SUCCESS);
    MakeEnumItem(env, object, "SYSTEM_ERROR", FAILED);
    return object;
}

napi_status JsContinuationStateManager::MakeEnumItem(const napi_env &env, napi_value object, const char* name, int32_t value)
{
    napi_value itemName;
    napi_value itemValue;
    napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &itemName);
    napi_create_int32(env, value, &itemValue);
    napi_set_property(env, object, itemName, itemValue);
    return napi_ok;
}

napi_value JsContinueManagerInit(napi_env env, napi_value exportObj)
{
    napi_value continueStateCodeEnumObject = JsContinuationStateManager::MakeContinueStateCodeEnumObject(env);

    static napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("on", JsContinuationStateManager::ContinueStateCallbackOn),
        DECLARE_NAPI_FUNCTION("off", JsContinuationStateManager::ContinueStateCallbackOff),
        DECLARE_NAPI_PROPERTY("ContinueStateCode", continueStateCodeEnumObject),
    };
    napi_define_properties(env, exportObj, sizeof(desc) / sizeof(desc[0]), desc);
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