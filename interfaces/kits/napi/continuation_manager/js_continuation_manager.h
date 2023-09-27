/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_ABILITY_MANAGER_JS_CONTINUATION_MANAGER_H
#define OHOS_DISTRIBUTED_ABILITY_MANAGER_JS_CONTINUATION_MANAGER_H

#include <utility>

#include "continuation_extra_params.h"
#include "device_connect_status.h"
#include "js_device_selection_listener.h"
#include "native_engine/native_engine.h"
#include "nlohmann/json.hpp"

namespace OHOS {
namespace DistributedSchedule {
using JsDeviceSelectionListenerPtr = std::shared_ptr<JsDeviceSelectionListener>;

class JsContinuationManager final {
public:
    JsContinuationManager() = default;
    ~JsContinuationManager() = default;

    static void Finalizer(napi_env env, void* data, void* hint);
    static napi_value Register(napi_env env, napi_callback_info info);
    static napi_value Unregister(napi_env env, napi_callback_info info);
    static napi_value RegisterDeviceSelectionCallback(napi_env env, napi_callback_info info);
    static napi_value UnregisterDeviceSelectionCallback(napi_env env, napi_callback_info info);
    static napi_value UpdateConnectStatus(napi_env env, napi_callback_info info);
    static napi_value StartDeviceManager(napi_env env, napi_callback_info info);
    static napi_value InitDeviceConnectStateObject(napi_env env, napi_callback_info info);
    static napi_value InitContinuationModeObject(napi_env env, napi_callback_info info);
    static napi_value RegisterContinuation(napi_env env, napi_callback_info info);
    static napi_value UnregisterContinuation(napi_env env, napi_callback_info info);
    static napi_value UpdateContinuationState(napi_env env, napi_callback_info info);
    static napi_value StartContinuationDeviceManager(napi_env env, napi_callback_info info);

private:
    using CallbackPair = std::pair<std::unique_ptr<NativeReference>, sptr<JsDeviceSelectionListener>>;
    napi_value OnRegister(napi_env env, napi_callback_info info);
    napi_value OnUnregister(napi_env env, napi_callback_info info);
    napi_value OnRegisterDeviceSelectionCallback(napi_env env, napi_callback_info info);
    napi_value OnUnregisterDeviceSelectionCallback(napi_env env, napi_callback_info info);
    napi_value OnUpdateConnectStatus(napi_env env, napi_callback_info info);
    int32_t GetInfoForUpdateConnectStatus(napi_env env,
        napi_value *argv,int32_t &token, std::string &deviceId, DeviceConnectStatus &deviceConnectStatus);
    napi_value OnStartDeviceManager(napi_env env, napi_callback_info info);
    int32_t CheckParamAndGetToken(napi_env env, size_t argc, napi_value *argv, int32_t &token);
    napi_value OnInitDeviceConnectStateObject(napi_env env, napi_callback_info info);
    napi_value OnInitContinuationModeObject(napi_env env, napi_callback_info info);
    static napi_status SetEnumItem(const napi_env &env, napi_value object, const char* name, int32_t value);
    napi_value OnRegisterContinuation(napi_env env, napi_callback_info info);
    napi_value OnUnregisterContinuation(napi_env env, napi_callback_info info);
    napi_value OnUpdateContinuationState(napi_env env, napi_callback_info info);
    std::string GetErrorInfo(napi_env env, napi_callback_info info, int32_t &token,
        std::string &deviceId, DeviceConnectStatus &deviceConnectStatus);
    std::string GetErrorForStartContinuation(napi_env env, napi_callback_info info,
        int32_t &token, int32_t &unwrapArgc, std::shared_ptr<ContinuationExtraParams> &continuationExtraParams);
    std::string GetErrorInforForRegisterContination(napi_env env, napi_callback_info info,
        size_t &unwrapArgc, std::shared_ptr<ContinuationExtraParams> &continuationExtraParams);
    napi_value OnStartContinuationDeviceManager(napi_env env, napi_callback_info info);

    static bool IsCallbackValid(napi_env env, napi_value listenerObj);
    bool IsCallbackRegistered(int32_t token, const std::string& cbType);
    bool UnWrapContinuationExtraParams(const napi_env &env, const napi_value& options,
        std::shared_ptr<ContinuationExtraParams>& continuationExtraParams);
    bool UnwrapJsonByPropertyName(const napi_env &env, const napi_value& param,
        const std::string& field, nlohmann::json& jsonObj);
    static bool PraseJson(const napi_env &env, const napi_value& jsonField, const napi_value& jsProNameList,
        uint32_t jsProCount, nlohmann::json& jsonObj);
    static int32_t ErrorCodeReturn(int32_t code);
    static std::string ErrorMessageReturn(int32_t code);
    static std::string OnRegisterDeviceSelectionCallbackParameterCheck(napi_env env,
        napi_callback_info info, std::string &cbType, int32_t &token, napi_value *jsListenerObj);
    napi_value GenerateBusinessError(const napi_env &env, int32_t errCode, const std::string &errMsg);
    std::mutex jsCbMapMutex_;
    std::map<int32_t, std::map<std::string, CallbackPair>> jsCbMap_;
};

napi_value JsContinuationManagerInit(napi_env env, napi_value exportObj);
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_ABILITY_MANAGER_JS_CONTINUATION_MANAGER_H