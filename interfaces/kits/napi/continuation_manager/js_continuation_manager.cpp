/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "js_continuation_manager.h"

#include <memory>

#include "base/continuationmgr_log.h"
#include "distributed_ability_manager_client.h"
#include "distributed_sched_utils.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"
#include "napi_error_code.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;
namespace {
const std::string TAG = "JsContinuationManager";
const std::string CODE_KEY_NAME = "code";
constexpr int32_t ERR_NOT_OK = -1;
constexpr int32_t ARG_COUNT_ONE = 1;
constexpr int32_t ARG_COUNT_TWO = 2;
constexpr int32_t ARG_COUNT_THREE = 3;
constexpr uint32_t MAX_JSPROCOUNT = 1000000;
constexpr int32_t ARG_COUNT_FOUR = 4;
}

void JsContinuationManager::Finalizer(napi_env env, void* data, void* hint)
{
    HILOGI("JsContinuationManager::Finalizer is called");
    JsContinuationManager* jsContinuationManager = static_cast<JsContinuationManager*>(data);
    if (jsContinuationManager != nullptr) {
        delete jsContinuationManager;
        jsContinuationManager = nullptr;
    }
}

napi_value JsContinuationManager::Register(napi_env env, napi_callback_info info)
{
    JsContinuationManager* me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnRegister(env, info) : nullptr;
}

napi_value JsContinuationManager::Unregister(napi_env env, napi_callback_info info)
{
    JsContinuationManager* me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnUnregister(env, info) : nullptr;
}

napi_value JsContinuationManager::RegisterDeviceSelectionCallback(napi_env env, napi_callback_info info)
{
    JsContinuationManager* me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnRegisterDeviceSelectionCallback(env, info) : nullptr;
}

napi_value JsContinuationManager::UnregisterDeviceSelectionCallback(napi_env env, napi_callback_info info)
{
    JsContinuationManager* me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnUnregisterDeviceSelectionCallback(env, info) : nullptr;
}

napi_value JsContinuationManager::UpdateConnectStatus(napi_env env, napi_callback_info info)
{
    JsContinuationManager *me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnUpdateConnectStatus(env, info) : nullptr;
}

napi_value JsContinuationManager::StartDeviceManager(napi_env env, napi_callback_info info)
{
    JsContinuationManager *me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnStartDeviceManager(env, info) : nullptr;
}

napi_value JsContinuationManager::InitDeviceConnectStateObject(napi_env env, napi_callback_info info)
{
    JsContinuationManager *me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnInitDeviceConnectStateObject(env, info) : nullptr;
}

napi_value JsContinuationManager::InitContinuationModeObject(napi_env env, napi_callback_info info)
{
    JsContinuationManager *me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnInitContinuationModeObject(env, info) : nullptr;
}

napi_value JsContinuationManager::RegisterContinuation(napi_env env, napi_callback_info info)
{
    JsContinuationManager* me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnRegisterContinuation(env, info) : nullptr;
}

napi_value JsContinuationManager::UnregisterContinuation(napi_env env, napi_callback_info info)
{
    JsContinuationManager* me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnUnregisterContinuation(env, info) : nullptr;
}

napi_value JsContinuationManager::UpdateContinuationState(napi_env env, napi_callback_info info)
{
    JsContinuationManager *me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnUpdateContinuationState(env, info) : nullptr;
}

napi_value JsContinuationManager::StartContinuationDeviceManager(napi_env env, napi_callback_info info)
{
    JsContinuationManager *me = CheckParamsAndGetThis<JsContinuationManager>(env, info);
    return (me != nullptr) ? me->OnStartContinuationDeviceManager(env, info) : nullptr;
}

napi_value JsContinuationManager::OnRegister(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    int32_t errCode = 0;
    size_t unwrapArgc = 0;
    size_t argc = ARG_COUNT_TWO;
    napi_value argv[ARG_COUNT_TWO] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    napi_valuetype valuetype = napi_valuetype::napi_undefined;
    if (argc > 0) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    }
    if (valuetype == napi_valuetype::napi_object) {
        HILOGI("register options is used.");
        if (!UnWrapContinuationExtraParams(env, argv[0], continuationExtraParams)) {
            HILOGE("Parse continuationExtraParams failed");
            errCode = ERR_NOT_OK;
        }
        unwrapArgc++;
    }
    NapiAsyncTask::CompleteCallback complete =
        [continuationExtraParams, unwrapArgc, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return;
        }

        if (errCode != 0) {
            task.Reject(env, CreateJsError(env, errCode, "Invalidate params."));
            napi_close_handle_scope(env, scope);
            return;
        }
        int32_t token = -1;
        int32_t ret = (unwrapArgc == 0) ? DistributedAbilityManagerClient::GetInstance().Register(nullptr, token) :
            DistributedAbilityManagerClient::GetInstance().Register(continuationExtraParams, token);
        if (ret == ERR_OK) {
            task.Resolve(env, CreateJsValue(env, token));
        } else {
            task.Reject(env, CreateJsError(env, ret, "Register failed."));
        }

        napi_close_handle_scope(env, scope);
    };

    napi_value lastParam = (argc <= unwrapArgc) ? nullptr : argv[unwrapArgc];
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("JsContinuationManager::OnRegister",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

std::string JsContinuationManager::GetErrorInforForRegisterContination(napi_env env, napi_callback_info info,
    size_t &unwrapArgc, std::shared_ptr<ContinuationExtraParams> &continuationExtraParams)
{
    size_t argc = ARG_COUNT_TWO;
    napi_value argv[ARG_COUNT_TWO] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc > ARG_COUNT_TWO) {
        return "Parameter error. The type of \"number of parameters\" must be less than 3";
    }
    napi_valuetype valuetype = napi_valuetype::napi_undefined;
    if (argc > 0) {
        NAPI_CALL(env, napi_typeof(env, argv[0], &valuetype));
    }
    if (valuetype == napi_valuetype::napi_object) {
        HILOGI("register options is used.");
        continuationExtraParams = std::make_shared<ContinuationExtraParams>();
        if (!UnWrapContinuationExtraParams(env, argv[0], continuationExtraParams)) {
            return "Parameter error. The type of \"options\" must be ContinuationExtraParams";
        }
        unwrapArgc++;
    }
    return std::string();
}

napi_value JsContinuationManager::OnRegisterContinuation(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    size_t unwrapArgc = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams;
    std::string errInfo = GetErrorInforForRegisterContination(env, info, unwrapArgc, continuationExtraParams);
    if (!errInfo.empty()) {
        HILOGE("%{public}s", errInfo.c_str());
        napi_throw(env, GenerateBusinessError(env, PARAMETER_CHECK_FAILED, errInfo));
        return CreateJsUndefined(env);
    }
    NapiAsyncTask::CompleteCallback complete =
        [this, continuationExtraParams, unwrapArgc](napi_env env, NapiAsyncTask &task, int32_t status) {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return;
        }

        int32_t token = -1;
        int32_t errCode = (unwrapArgc == 0) ? DistributedAbilityManagerClient::GetInstance().Register(nullptr, token) :
            DistributedAbilityManagerClient::GetInstance().Register(continuationExtraParams, token);
        if (errCode == ERR_OK) {
            task.Resolve(env, CreateJsValue(env, token));
        } else {
            errCode = ErrorCodeReturn(errCode);
            task.Reject(env, CreateJsError(env, errCode, ErrorMessageReturn(errCode)));
        }

        napi_close_handle_scope(env, scope);
    };
    size_t argc = ARG_COUNT_TWO;
    napi_value argv[ARG_COUNT_TWO] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    napi_value lastParam = (argc <= unwrapArgc) ? nullptr : argv[unwrapArgc];
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("JsContinuationManager::OnRegisterContinuation",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsContinuationManager::OnUnregister(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    int32_t errCode = 0;
    size_t argc = ARG_COUNT_TWO;
    napi_value argv[ARG_COUNT_TWO] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc == 0) {
        HILOGE("Params not match");
        errCode = ERR_NOT_OK;
    }
    int32_t token = -1;
    if (!errCode && !ConvertFromJsValue(env, argv[0], token)) {
        HILOGE("Parse token failed");
        errCode = ERR_NOT_OK;
    }

    NapiAsyncTask::CompleteCallback complete =
        [token, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return;
        }

        if (errCode != 0) {
            task.Reject(env, CreateJsError(env, errCode, "Invalidate params."));
            napi_close_handle_scope(env, scope);
            return;
        }
        int32_t ret = DistributedAbilityManagerClient::GetInstance().Unregister(token);
        if (ret == ERR_OK) {
            task.Resolve(env, CreateJsUndefined(env));
        } else {
            task.Reject(env, CreateJsError(env, ret, "Unregister failed."));
        }

        napi_close_handle_scope(env, scope);
    };

    napi_value lastParam = (argc <= ARG_COUNT_ONE) ? nullptr : argv[ARG_COUNT_ONE];
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("JsContinuationManager::OnUnregister",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsContinuationManager::OnUnregisterContinuation(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    int32_t token = -1;
    size_t argc = ARG_COUNT_TWO;
    napi_value argv[ARG_COUNT_TWO] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    std::string errInfo = [this, &env, &argc, argv, &token]() -> std::string {
        if (argc == 0 || argc > ARG_COUNT_TWO) {
            return "Parameter error. The type of \"number of parameters\" must be greater than 0 and less than 3";
        }
        if (!ConvertFromJsValue(env, argv[0], token)) {
            return "Parameter error. The type of \"token\" must be number";
        }
        return std::string();
    } ();
    if (!errInfo.empty()) {
        HILOGE("%{public}s", errInfo.c_str());
        napi_throw(env, GenerateBusinessError(env, PARAMETER_CHECK_FAILED, errInfo));
        return CreateJsUndefined(env);
    }
    NapiAsyncTask::CompleteCallback complete =
        [this, token](napi_env env, NapiAsyncTask &task, int32_t status) {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return;
        }
        int32_t errCode = DistributedAbilityManagerClient::GetInstance().Unregister(token);
        if (errCode == ERR_OK) {
            task.Resolve(env, CreateJsNull(env));
        } else {
            errCode = ErrorCodeReturn(errCode);
            task.Reject(env, CreateJsError(env, errCode, ErrorMessageReturn(errCode)));
        }

        napi_close_handle_scope(env, scope);
    };

    napi_value lastParam = (argc == ARG_COUNT_ONE) ? nullptr : argv[ARG_COUNT_ONE];
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("JsContinuationManager::OnUnregisterContinuation",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

std::string JsContinuationManager::OnRegisterDeviceSelectionCallbackParameterCheck(napi_env env,
    napi_callback_info info, std::string &cbType, int32_t &token, napi_value *jsListenerObj)
{
    size_t argc = ARG_COUNT_THREE;
    napi_value argv[ARG_COUNT_THREE] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc != ARG_COUNT_THREE) {
        return "Parameter error. The type of \"number of parameters\" must be 3";
    }
    if (!ConvertFromJsValue(env, argv[0], cbType)) {
        return "Parameter error. The type of \"type\" must be string";
    }
    if (cbType != EVENT_CONNECT && cbType != EVENT_DISCONNECT) {
        return "Parameter error. The type of \"type\" must be " +
            std::string(EVENT_CONNECT) + " or " + std::string(EVENT_DISCONNECT);
    }
    if (!ConvertFromJsValue(env, argv[ARG_COUNT_ONE], token)) {
        return "Parameter error. The type of \"token\" must be number";
    }
    *jsListenerObj = argv[ARG_COUNT_TWO];
    if (!IsCallbackValid(env, *jsListenerObj)) {
        return "Parameter error. The type of \"callback\" must be Callback<Array<ContinuationResult>>";
    }
    return std::string();
}

napi_value JsContinuationManager::OnRegisterDeviceSelectionCallback(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    std::string cbType;
    int32_t token = -1;
    int32_t errCode = PARAMETER_CHECK_FAILED;
    napi_value jsListenerObj = nullptr;
    std::string errInfo = OnRegisterDeviceSelectionCallbackParameterCheck(env, info, cbType, token, &jsListenerObj);
    if (errInfo.empty()) {
        errInfo = [this, &env, &info, &cbType, &token, &jsListenerObj, &errCode]() -> std::string {
            std::lock_guard<std::mutex> jsCbMapLock(jsCbMapMutex_);
            if (IsCallbackRegistered(token, cbType)) {
                errCode = REPEATED_REGISTRATION;
                return ErrorMessageReturn(errCode);
            }
            napi_ref tempRef = nullptr;
            napi_create_reference(env, jsListenerObj, 1, &tempRef);
            std::unique_ptr<NativeReference> callbackRef;
            callbackRef.reset(reinterpret_cast<NativeReference*>(tempRef));
            sptr<JsDeviceSelectionListener> deviceSelectionListener(new JsDeviceSelectionListener(env));
            if (deviceSelectionListener == nullptr) {
                HILOGE("deviceSelectionListener is nullptr!");
                errCode = SYSTEM_WORK_ABNORMALLY;
                return ErrorMessageReturn(errCode);
            }
            errCode = DistributedAbilityManagerClient::GetInstance().RegisterDeviceSelectionCallback(
                token, cbType, deviceSelectionListener);
            if (errCode == ERR_OK) {
                deviceSelectionListener->AddCallback(cbType, jsListenerObj);
                CallbackPair callbackPair = std::make_pair(std::move(callbackRef), deviceSelectionListener);
                jsCbMap_[token][cbType] = std::move(callbackPair); // move assignment
                HILOGI("RegisterDeviceSelectionListener success");
            } else {
                deviceSelectionListener = nullptr;
                errCode = ErrorCodeReturn(errCode);
                return ErrorMessageReturn(errCode);
            }
            return std::string();
        }();
    }
    if (!errInfo.empty()) {
        HILOGE("%{public}s", errInfo.c_str());
        napi_throw(env,
            GenerateBusinessError(env, errCode, errInfo));
    }
    return CreateJsUndefined(env);
}

napi_value JsContinuationManager::OnUnregisterDeviceSelectionCallback(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    std::string cbType;
    int32_t token = -1;
    int32_t errCode = PARAMETER_CHECK_FAILED;
    std::string errInfo = [this, &env, &info, &cbType, &token, &errCode]() -> std::string {
        size_t argc = ARG_COUNT_TWO;
        napi_value argv[ARG_COUNT_TWO] = { 0 };
        NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
        if (argc != ARG_COUNT_TWO) {
            return "Parameter error. The type of \"number of parameters\" must be 2";
        }
        if (!ConvertFromJsValue(env, argv[0], cbType)) {
            return "Parameter error. The type of \"type\" must be string";
        }
        if (cbType != EVENT_CONNECT && cbType != EVENT_DISCONNECT) {
            return "Parameter error. The type of \"type\" must be " +
                std::string(EVENT_CONNECT) + " or " + std::string(EVENT_DISCONNECT);
        }
        if (!ConvertFromJsValue(env, argv[ARG_COUNT_ONE], token)) {
            return "Parameter error. The type of \"token\" must be number";
        }
        {
            std::lock_guard<std::mutex> jsCbMapLock(jsCbMapMutex_);
            if (!IsCallbackRegistered(token, cbType)) {
                errCode = CALLBACK_TOKEN_UNREGISTERED;
                return ErrorMessageReturn(errCode);
            }
            errCode = DistributedAbilityManagerClient::GetInstance().UnregisterDeviceSelectionCallback(token, cbType);
            if (errCode == ERR_OK) {
                CallbackPair& callbackPair = jsCbMap_[token][cbType];
                callbackPair.second->RemoveCallback(cbType);
                jsCbMap_[token].erase(cbType);
                if (jsCbMap_[token].empty()) {
                    jsCbMap_.erase(token);
                }
                HILOGI("UnregisterDeviceSelectionCallback success");
            } else {
                errCode = ErrorCodeReturn(errCode);
                return ErrorMessageReturn(errCode);
            }
        }
        return std::string();
    } ();
    if (!errInfo.empty()) {
        HILOGE("%{public}s", errInfo.c_str());
        napi_throw(env, GenerateBusinessError(env, errCode, errInfo));
    }
    return CreateJsUndefined(env);
}

int32_t JsContinuationManager::GetInfoForUpdateConnectStatus(napi_env env,
    napi_value *argv, int32_t &token, std::string &deviceId, DeviceConnectStatus &deviceConnectStatus)
{
    int32_t errCode = 0;
    if (!errCode && !ConvertFromJsValue(env, argv[0], token)) {
        HILOGE("Parse token failed");
        errCode = ERR_NOT_OK;
    }
    if (!errCode && !ConvertFromJsValue(env, argv[ARG_COUNT_ONE], deviceId)) {
        HILOGE("Parse deviceId failed");
        errCode = ERR_NOT_OK;
    }
    if (!errCode && !ConvertFromJsValue(env, argv[ARG_COUNT_TWO], deviceConnectStatus)) {
        HILOGE("Parse device connect status failed");
        errCode = ERR_NOT_OK;
    }
    return errCode;
}

napi_value JsContinuationManager::OnUpdateConnectStatus(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    int32_t errCode = 0;
    size_t argc = ARG_COUNT_FOUR;
    napi_value argv[ARG_COUNT_FOUR] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < ARG_COUNT_THREE) {
        HILOGE("Params not match");
        errCode = ERR_NOT_OK;
    }
    int32_t token = -1;
    std::string deviceId;
    DeviceConnectStatus deviceConnectStatus = DeviceConnectStatus::IDLE;
    errCode = GetInfoForUpdateConnectStatus(env, argv, token, deviceId, deviceConnectStatus);
    NapiAsyncTask::CompleteCallback complete =
        [token, deviceId, deviceConnectStatus, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return;
        }

        if (errCode != 0) {
            task.Reject(env, CreateJsError(env, errCode, "Invalidate params."));
            napi_close_handle_scope(env, scope);
            return;
        }
        int32_t ret = DistributedAbilityManagerClient::GetInstance().UpdateConnectStatus(
            token, deviceId, deviceConnectStatus);
        if (ret == ERR_OK) {
            task.Resolve(env, CreateJsUndefined(env));
        } else {
            task.Reject(env, CreateJsError(env, ret, "UpdateConnectStatus failed."));
        }
        napi_close_handle_scope(env, scope);
    };

    napi_value lastParam = (argc <= ARG_COUNT_THREE) ? nullptr : argv[ARG_COUNT_THREE];
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("JsContinuationManager::OnUpdateConnectStatus",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

std::string JsContinuationManager::GetErrorInfo(napi_env env, napi_callback_info info, int32_t &token,
                                                std::string &deviceId, DeviceConnectStatus &deviceConnectStatus)
{
    size_t argc = ARG_COUNT_FOUR;
    napi_value argv[ARG_COUNT_FOUR] = { nullptr };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr));
    if (argc != ARG_COUNT_THREE && argc != ARG_COUNT_FOUR) {
        return "Parameter error. The type of \"number of parameters\" must be 3 or 4";
    }
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (!ConvertFromJsValue(env, argv[0], token)) {
        return "Parameter error. The type of \"token\" must be number";
    }
    if (!ConvertFromJsValue(env, argv[ARG_COUNT_ONE], deviceId) || deviceId.empty()) {
        return "Parameter error. The type of \"deviceId\" must be string and not empty";
    }
    deviceConnectStatus = DeviceConnectStatus::IDLE;
    if (!ConvertFromJsValue(env, argv[ARG_COUNT_TWO], deviceConnectStatus)) {
        return "Parameter error. The type of \"status\" must be DeviceConnectState";
    }
    if (static_cast<int32_t>(deviceConnectStatus) < static_cast<int32_t>(DeviceConnectStatus::IDLE) ||
        static_cast<int32_t>(deviceConnectStatus) > static_cast<int32_t>(DeviceConnectStatus::DISCONNECTING)) {
        HILOGE("deviceConnectStatus is invalid");
        return "Parameter error. The type of \"status\" must be DeviceConnectState";
    }
    return std::string();
}

napi_value JsContinuationManager::OnUpdateContinuationState(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    int32_t token = -1;
    std::string deviceId;
    DeviceConnectStatus deviceConnectStatus;
    std::string errInfo = GetErrorInfo(env, info, token, deviceId, deviceConnectStatus);
    if (!errInfo.empty()) {
        HILOGE("%{public}s", errInfo.c_str());
        napi_throw(env,
            GenerateBusinessError(env, PARAMETER_CHECK_FAILED, errInfo));
        return CreateJsUndefined(env);
    }
    NapiAsyncTask::CompleteCallback complete =
        [this, token, deviceId, deviceConnectStatus](napi_env env, NapiAsyncTask &task, int32_t status) {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return;
        }

        int32_t errCode = DistributedAbilityManagerClient::GetInstance().UpdateConnectStatus(
            token, deviceId, deviceConnectStatus);
        if (errCode == ERR_OK) {
            task.Resolve(env, CreateJsNull(env));
        } else {
            errCode = ErrorCodeReturn(errCode);
            task.Reject(env, CreateJsError(env, errCode, ErrorMessageReturn(errCode)));
        }

        napi_close_handle_scope(env, scope);
    };

    size_t argc = ARG_COUNT_FOUR;
    napi_value argv[ARG_COUNT_FOUR] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    napi_value lastParam = (argc == ARG_COUNT_THREE) ? nullptr : argv[ARG_COUNT_THREE];
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("JsContinuationManager::OnUpdateContinuationState",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

int32_t JsContinuationManager::CheckParamAndGetToken(napi_env env, size_t argc, napi_value *argv, int32_t &token)
{
    int32_t errCode = 0;
    if (argc < ARG_COUNT_ONE) {
        HILOGE("Params not match");
        errCode = ERR_NOT_OK;
    }
    if (!errCode && !ConvertFromJsValue(env, argv[0], token)) {
        HILOGE("Parse token failed");
        errCode = ERR_NOT_OK;
    }
    return errCode;
}

napi_value JsContinuationManager::OnStartDeviceManager(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    int32_t token = -1;
    size_t argc = ARG_COUNT_THREE;
    napi_value argv[ARG_COUNT_THREE] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    int32_t errCode = CheckParamAndGetToken(env, argc, argv, token);
    size_t unwrapArgc = ARG_COUNT_ONE;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    napi_valuetype valuetype = napi_valuetype::napi_undefined;
    if (argc > ARG_COUNT_ONE) {
        NAPI_CALL(env, napi_typeof(env, argv[ARG_COUNT_ONE], &valuetype));
    }
    if (valuetype == napi_valuetype::napi_object) {
        HILOGI("startDeviceManager options is used.");
        if (!UnWrapContinuationExtraParams(env, argv[ARG_COUNT_ONE], continuationExtraParams)) {
            HILOGE("Parse continuationExtraParams failed");
            errCode = ERR_NOT_OK;
        }
        unwrapArgc++;
    }
    NapiAsyncTask::CompleteCallback complete =
        [token, continuationExtraParams, unwrapArgc, errCode](napi_env env, NapiAsyncTask &task, int32_t status) {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return;
        }

        if (errCode != 0) {
            task.Reject(env, CreateJsError(env, errCode, "Invalidate params."));
            napi_close_handle_scope(env, scope);
            return;
        }
        int32_t ret = (unwrapArgc == ARG_COUNT_ONE) ?
            DistributedAbilityManagerClient::GetInstance().StartDeviceManager(token) :
            DistributedAbilityManagerClient::GetInstance().StartDeviceManager(token, continuationExtraParams);
        if (ret == ERR_OK) {
            task.Resolve(env, CreateJsUndefined(env));
        } else {
            task.Reject(env, CreateJsError(env, ret, "StartDeviceManager failed."));
        }

        napi_close_handle_scope(env, scope);
    };

    napi_value lastParam = (argc <= unwrapArgc) ? nullptr : argv[unwrapArgc];
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("JsContinuationManager::OnStartDeviceManager",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

std::string JsContinuationManager::GetErrorForStartContinuation(napi_env env, napi_callback_info info,
    int32_t &token, int32_t &unwrapArgc, std::shared_ptr<ContinuationExtraParams> &continuationExtraParams)
{
    size_t argc = ARG_COUNT_THREE;
    napi_value argv[ARG_COUNT_THREE] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr));
    if (argc < ARG_COUNT_ONE || argc > ARG_COUNT_THREE) {
        return "Parameter error. The type of \"number of parameters\" must be greater than 1 and less than 3";
    }
    if (!ConvertFromJsValue(env, argv[0], token)) {
        return "Parameter error. The type of \"token\" must be number";
    }
    continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    napi_valuetype valuetype = napi_valuetype::napi_undefined;
    if (argc > ARG_COUNT_ONE) {
        NAPI_CALL(env, napi_typeof(env, argv[ARG_COUNT_ONE], &valuetype));
    }
    if (valuetype == napi_valuetype::napi_object) {
        HILOGI("StartContinuationDeviceManager options is used.");
        if (!UnWrapContinuationExtraParams(env, argv[ARG_COUNT_ONE], continuationExtraParams)) {
            return "Parameter error. The type of \"options\" must be ContinuationExtraParams";
        }
        unwrapArgc++;
    }
    return std::string();
}

napi_value JsContinuationManager::OnStartContinuationDeviceManager(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    int32_t token = -1;
    int32_t argc = ARG_COUNT_ONE;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams;
    std::string errInfo = GetErrorForStartContinuation(env, info, token, argc, continuationExtraParams);
    if (!errInfo.empty()) {
        HILOGE("%{public}s", errInfo.c_str());
        napi_throw(env,
            GenerateBusinessError(env, PARAMETER_CHECK_FAILED, errInfo));
        return CreateJsUndefined(env);
    }
    size_t unwrapArgc = argc;
    NapiAsyncTask::CompleteCallback complete =
        [this, token, continuationExtraParams, unwrapArgc](napi_env env, NapiAsyncTask &task, int32_t status) {
        napi_handle_scope scope = nullptr;
        napi_open_handle_scope(env, &scope);
        if (scope == nullptr) {
            return;
        }
        int32_t errCode = (unwrapArgc == ARG_COUNT_ONE) ?
            DistributedAbilityManagerClient::GetInstance().StartDeviceManager(token) :
            DistributedAbilityManagerClient::GetInstance().StartDeviceManager(token, continuationExtraParams);
        if (errCode == ERR_OK) {
            task.Resolve(env, CreateJsNull(env));
        } else {
            errCode = ErrorCodeReturn(errCode);
            task.Reject(env, CreateJsError(env, errCode, ErrorMessageReturn(errCode)));
        }
        napi_close_handle_scope(env, scope);
    };
    size_t napiArgc = ARG_COUNT_THREE;
    napi_value argv[ARG_COUNT_THREE] = { 0 };
    NAPI_CALL(env, napi_get_cb_info(env, info, &napiArgc, argv, nullptr, nullptr));
    napi_value lastParam = (napiArgc <= unwrapArgc) ? nullptr : argv[unwrapArgc];
    napi_value result = nullptr;
    NapiAsyncTask::Schedule("JsContinuationManager::OnStartContinuationDeviceManager",
        env, CreateAsyncTaskWithLastParam(env, lastParam, nullptr, std::move(complete), &result));
    return result;
}

napi_value JsContinuationManager::OnInitDeviceConnectStateObject(napi_env env, napi_callback_info info)
{
    napi_value object;
    NAPI_CALL(env, napi_create_object(env, &object));

    NAPI_CALL(env, SetEnumItem(env, object, "IDLE",
        static_cast<int32_t>(DeviceConnectStatus::IDLE)));
    NAPI_CALL(env, SetEnumItem(env, object, "CONNECTING",
        static_cast<int32_t>(DeviceConnectStatus::CONNECTING)));
    NAPI_CALL(env, SetEnumItem(env, object, "CONNECTED",
        static_cast<int32_t>(DeviceConnectStatus::CONNECTED)));
    NAPI_CALL(env, SetEnumItem(env, object, "DISCONNECTING",
        static_cast<int32_t>(DeviceConnectStatus::DISCONNECTING)));

    return object;
}

napi_value JsContinuationManager::OnInitContinuationModeObject(napi_env env, napi_callback_info info)
{
    napi_value object;
    NAPI_CALL(env, napi_create_object(env, &object));

    NAPI_CALL(env, SetEnumItem(env, object, "COLLABORATION_SINGLE",
        static_cast<int32_t>(ContinuationMode::COLLABORATION_SINGLE)));
    NAPI_CALL(env, SetEnumItem(env, object, "COLLABORATION_MULTIPLE",
        static_cast<int32_t>(ContinuationMode::COLLABORATION_MUTIPLE)));

    return object;
}

napi_status JsContinuationManager::SetEnumItem(const napi_env &env, napi_value object, const char* name, int32_t value)
{
    napi_status status;
    napi_value itemName;
    napi_value itemValue;

    NAPI_CALL_BASE(env, status = napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &itemName), status);
    NAPI_CALL_BASE(env, status = napi_create_int32(env, value, &itemValue), status);
    NAPI_CALL_BASE(env, status = napi_set_property(env, object, itemName, itemValue), status);
    NAPI_CALL_BASE(env, status = napi_set_property(env, object, itemValue, itemName), status);

    return napi_ok;
}

bool JsContinuationManager::IsCallbackValid(napi_env env, napi_value listenerObj)
{
    if (listenerObj == nullptr) {
        HILOGE("listenerObj is nullptr");
        return false;
    }
    bool isCallable = false;
    napi_is_callable(env, listenerObj, &isCallable);
    return isCallable;
}

bool JsContinuationManager::IsCallbackRegistered(int32_t token, const std::string& cbType)
{
    if (jsCbMap_.empty() || jsCbMap_.find(token) == jsCbMap_.end()) {
        HILOGE("token %{public}s not registered callback!", GetAnonymStr(std::to_string(token)).c_str());
        return false;
    }
    if (jsCbMap_[token].empty() || jsCbMap_[token].find(cbType) == jsCbMap_[token].end()) {
        HILOGE("cbType %{public}s not registered callback!", cbType.c_str());
        return false;
    }
    HILOGI("callback already registered, token: %{public}s, cbType %{public}s",
        GetAnonymStr(std::to_string(token)).c_str(), cbType.c_str());
    return true;
}

bool JsContinuationManager::UnWrapContinuationExtraParams(const napi_env &env, const napi_value& options,
    std::shared_ptr<ContinuationExtraParams>& continuationExtraParams)
{
    HILOGD("called.");
    if (!IsTypeForNapiValue(env, options, napi_object)) {
        HILOGE("options is invalid.");
        return false;
    }
    if (!continuationExtraParams) {
        HILOGE("continuationExtraParams is nullptr.");
        return false;
    }
    std::vector<std::string> deviceTypes;
    if (UnwrapStringArrayByPropertyName(env, options, "deviceType", deviceTypes)) {
        continuationExtraParams->SetDeviceType(deviceTypes);
    }
    std::string targetBundle("");
    if (UnwrapStringByPropertyName(env, options, "targetBundle", targetBundle)) {
        continuationExtraParams->SetTargetBundle(targetBundle);
    }
    std::string description("");
    if (UnwrapStringByPropertyName(env, options, "description", description)) {
        continuationExtraParams->SetDescription(description);
    }
    nlohmann::json filter;
    if (!UnwrapJsonByPropertyName(env, options, "filter", filter)) {
        return false;
    }
    continuationExtraParams->SetFilter(filter.dump());
    int32_t continuationMode = 0;
    if (UnwrapInt32ByPropertyName(env, options, "continuationMode", continuationMode)) {
        continuationExtraParams->SetContinuationMode(static_cast<ContinuationMode>(continuationMode));
    }
    nlohmann::json authInfo;
    if (UnwrapJsonByPropertyName(env, options, "authInfo", authInfo)) {
        continuationExtraParams->SetAuthInfo(authInfo.dump());
    }
    return true;
}

bool JsContinuationManager::UnwrapJsonByPropertyName(const napi_env &env, const napi_value& param,
    const std::string& field, nlohmann::json& jsonObj)
{
    HILOGD("called.");
    if (!IsTypeForNapiValue(env, param, napi_object)) {
        HILOGE("param is invalid.");
        return false;
    }
    napi_value jsonField = nullptr;
    napi_get_named_property(env, param, field.c_str(), &jsonField);
    napi_valuetype jsonFieldType = napi_undefined;
    napi_typeof(env, jsonField, &jsonFieldType);
    if (jsonFieldType != napi_object && jsonFieldType != napi_undefined) {
        HILOGE("field: %{public}s is invalid json.", field.c_str());
        return false;
    }
    napi_value jsProNameList = nullptr;
    uint32_t jsProCount = 0;
    napi_get_property_names(env, jsonField, &jsProNameList);
    napi_get_array_length(env, jsProNameList, &jsProCount);
    if (!PraseJson(env, jsonField, jsProNameList, jsProCount, jsonObj)) {
        HILOGE("PraseJson failed.");
        return false;
    }
    return true;
}

bool JsContinuationManager::PraseJson(const napi_env &env, const napi_value& jsonField,
    const napi_value& jsProNameList, uint32_t jsProCount, nlohmann::json& jsonObj)
{
    napi_value jsProName = nullptr;
    napi_value jsProValue = nullptr;
    napi_valuetype jsValueType = napi_undefined;
    if (jsProCount > MAX_JSPROCOUNT) {
        HILOGE("value of jsProCount is larger than MAX_JSPROCOUNT");
        return false;
    }
    for (uint32_t index = 0; index < jsProCount; index++) {
        napi_get_element(env, jsProNameList, index, &jsProName);
        std::string strProName = UnwrapStringFromJS(env, jsProName);
        napi_get_named_property(env, jsonField, strProName.c_str(), &jsProValue);
        napi_typeof(env, jsProValue, &jsValueType);
        switch (jsValueType) {
            case napi_string: {
                std::string elementValue = UnwrapStringFromJS(env, jsProValue);
                HILOGI("Property name=%{public}s, string, value=%{public}s", strProName.c_str(), elementValue.c_str());
                jsonObj[strProName] = elementValue;
                break;
            }
            case napi_boolean: {
                bool elementValue = false;
                napi_get_value_bool(env, jsProValue, &elementValue);
                HILOGI("Property name=%{public}s, boolean, value=%{public}d.", strProName.c_str(), elementValue);
                jsonObj[strProName] = elementValue;
                break;
            }
            case napi_number: {
                int32_t elementValue = 0;
                if (napi_get_value_int32(env, jsProValue, &elementValue) != napi_ok) {
                    HILOGE("Property name=%{public}s, Property int32_t parse error", strProName.c_str());
                } else {
                    HILOGI("Property name=%{public}s, number, value=%{public}d.", strProName.c_str(), elementValue);
                    jsonObj[strProName] = elementValue;
                }
                break;
            }
            default: {
                HILOGE("Property name=%{public}s, value type not support.", strProName.c_str());
                break;
            }
        }
    }
    return true;
}

int32_t JsContinuationManager::ErrorCodeReturn(int32_t code)
{
    switch (code) {
        case DMS_PERMISSION_DENIED:
            return PERMISSION_DENIED;
        case ERR_NULL_OBJECT:
            return SYSTEM_WORK_ABNORMALLY;
        case ERR_FLATTEN_OBJECT:
            return SYSTEM_WORK_ABNORMALLY;
        case CONNECT_ABILITY_FAILED:
            return SYSTEM_WORK_ABNORMALLY;
        case INVALID_CONTINUATION_MODE:
            return PARAMETER_CHECK_FAILED;
        case UNKNOWN_CALLBACK_TYPE:
            return PARAMETER_CHECK_FAILED;
        case INVALID_CONNECT_STATUS:
            return PARAMETER_CHECK_FAILED;
        case CALLBACK_HAS_NOT_REGISTERED:
            return CALLBACK_TOKEN_UNREGISTERED;
        case TOKEN_HAS_NOT_REGISTERED:
            return CALLBACK_TOKEN_UNREGISTERED;
        case REGISTER_EXCEED_MAX_TIMES:
            return OVER_MAX_REGISTERED_TIMES;
        case CALLBACK_HAS_REGISTERED:
            return REPEATED_REGISTRATION;
        default:
            return SYSTEM_WORK_ABNORMALLY;
    };
}

std::string JsContinuationManager::ErrorMessageReturn(int32_t code)
{
    switch (code) {
        case PARAMETER_CHECK_FAILED:
            return "The parameter check failed.";
        case SYSTEM_WORK_ABNORMALLY:
            return "The system ability works abnormally.";
        case CALLBACK_TOKEN_UNREGISTERED:
            return "The specified token or callback is not registered.";
        case OVER_MAX_REGISTERED_TIMES:
            return "The number of token registration times has reached the upper limit.";
        case REPEATED_REGISTRATION:
            return "The specified callback has been registered.";
        default:
            return "The system ability works abnormally.";
    };
}

napi_value JsContinuationManager::GenerateBusinessError(const napi_env &env, int32_t errCode, const std::string &errMsg)
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

napi_value JsContinuationManagerInit(napi_env env, napi_value exportObj)
{
    HILOGD("called.");
    if (env == nullptr || exportObj == nullptr) {
        HILOGE("Invalid input parameters");
        return nullptr;
    }

    JsContinuationManager* jsContinuationManager = new JsContinuationManager();
    napi_wrap(env, exportObj, jsContinuationManager, JsContinuationManager::Finalizer, nullptr, nullptr);
    const char *moduleName = "JsContinuationManager";
    BindNativeFunction(env, exportObj, "register", moduleName, JsContinuationManager::Register);
    BindNativeFunction(env, exportObj, "unregister", moduleName, JsContinuationManager::Unregister);
    BindNativeFunction(env, exportObj, "on", moduleName, JsContinuationManager::RegisterDeviceSelectionCallback);
    BindNativeFunction(env, exportObj, "off", moduleName, JsContinuationManager::UnregisterDeviceSelectionCallback);
    BindNativeFunction(env, exportObj, "updateConnectStatus", moduleName, JsContinuationManager::UpdateConnectStatus);
    BindNativeFunction(env, exportObj, "startDeviceManager", moduleName, JsContinuationManager::StartDeviceManager);
    BindNativeProperty(env, exportObj, "DeviceConnectState", JsContinuationManager::InitDeviceConnectStateObject);
    BindNativeProperty(env, exportObj, "ContinuationMode", JsContinuationManager::InitContinuationModeObject);
    BindNativeFunction(env, exportObj, "registerContinuation", moduleName,
        JsContinuationManager::RegisterContinuation);
    BindNativeFunction(env, exportObj, "unregisterContinuation", moduleName,
        JsContinuationManager::UnregisterContinuation);
    BindNativeFunction(env, exportObj, "updateContinuationState", moduleName,
        JsContinuationManager::UpdateContinuationState);
    BindNativeFunction(env, exportObj, "startContinuationDeviceManager", moduleName,
        JsContinuationManager::StartContinuationDeviceManager);

    return CreateJsUndefined(env);
}
}  // namespace DistributedSchedule
}  // namespace OHOS