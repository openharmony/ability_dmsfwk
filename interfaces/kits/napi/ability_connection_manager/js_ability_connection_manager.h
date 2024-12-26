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

#ifndef OHOS_DISTRIBUTED_COLLAB_SESSION_MANAGER_JS_ABILITY_CONNECTION_MANAGER_H
#define OHOS_DISTRIBUTED_COLLAB_SESSION_MANAGER_JS_ABILITY_CONNECTION_MANAGER_H

#include <utility>

#include "ability_connection_info.h"
#include "ability_info.h"
#include "js_ability_connection_session_listener.h"
#include "native_engine/native_engine.h"
#include "pixel_map_napi.h"

namespace OHOS {
namespace DistributedCollab {
using JsAbilityConnectionSessionListenerPtr = std::shared_ptr<JsAbilityConnectionSessionListener>;
struct AsyncCallbackInfo {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_threadsafe_function tsfn = nullptr;
    int32_t sessionId;
    ConnectResult result;
};

struct AsyncCallbackInfo {
    napi_async_work asyncWork = nullptr;
    napi_deferred deferred = nullptr;
    napi_threadsafe_function tsfn;
    bool result = false;
    int32_t sessionId;
    std::string token;
    std::string msg;
    std::shared_ptr<AVTransDataBuffer> buffer = nullptr;
    std::shared_ptr<Media::PixelMap> image = nullptr;
    int32_t streamId;
    StreamParams streamParam;
};

enum BussinessErrorCode {
    // The caller is not a system application.
    ERR_NOT_SYSTEM_APP = 202,
    // Input parameter error.
    ERR_INVALID_PARAMS = 401,
    // Multiple streams can not be created.
    ERR_ONLY_SUPPORT_ONE_STREAM = 29425664,
    // The stream at the receive end is not started.
    ERR_RECEIVE_STREAM_NOT_START = 29425665,
};

class JsAbilityConnectionManager final {
public:
    JsAbilityConnectionManager() = default;
    ~JsAbilityConnectionManager() = default;

    static napi_value CreateAbilityConnectionSession(napi_env env, napi_callback_info info);
    static napi_value DestroyAbilityConnectionSession(napi_env env, napi_callback_info info);
    static napi_value GetPeerInfoById(napi_env env, napi_callback_info info);
    static napi_value RegisterAbilityConnectionSessionCallback(napi_env env, napi_callback_info info);
    static napi_value UnregisterAbilityConnectionSessionCallback(napi_env env, napi_callback_info info);
    static napi_value Connect(napi_env env, napi_callback_info info);
    static napi_value DisConnect(napi_env env, napi_callback_info info);
    static napi_value AcceptConnect(napi_env env, napi_callback_info info);
    static napi_value Reject(napi_env env, napi_callback_info info);
    static napi_value SendMessage(napi_env env, napi_callback_info info);
    static napi_value SendData(napi_env env, napi_callback_info info);
    static napi_value SendImage(napi_env env, napi_callback_info info);
    static napi_value CreateStream(napi_env env, napi_callback_info info);
    static napi_value SetSurfaceId(napi_env env, napi_callback_info info);
    static napi_value GetSurfaceId(napi_env env, napi_callback_info info);
    static napi_value UpdateSurfaceParam(napi_env env, napi_callback_info info);
    static napi_value DestroyStream(napi_env env, napi_callback_info info);
    static napi_value StartStream(napi_env env, napi_callback_info info);
    static napi_value StopStream(napi_env env, napi_callback_info info);

    static napi_value OnCreateAbilityConnectionSession(napi_env env, napi_callback_info info);

private:
    void GetParams(const napi_env &env, const napi_callback_info &info, int32_t num);
    static bool JsToAbilityInfo(const napi_env &env, const napi_value &jsValue,
        std::shared_ptr<OHOS::AppExecFwk::AbilityInfo>& abilityInfo);
    static bool JsToPeerInfo(const napi_env &env, const napi_value &jsValue, PeerInfo &peerInfo);
    static bool JSToConnectOption(const napi_env &env, const napi_value &jsValue, ConnectOption &option);
    static bool JsToStreamParam(const napi_env &env, const napi_value &jsValue, StreamParams &streamParam);
    static bool JsToSurfaceParam(const napi_env &env, const napi_value &jsValue, SurfaceParams &surfaceParam);

    static void ConnectThreadsafeFunctionCallback(napi_env env, napi_value js_callback, void* context, void* data);
    static napi_status CreateConnectThreadsafeFunction(napi_env env, napi_value js_func,
        napi_threadsafe_function* tsfn);
    static void ExecuteConnect(napi_env env, void *data);
    static void CompleteAsyncConnectWork(napi_env env, napi_status status, void* data);
    static void ExecuteAcceptConnect(napi_env env, void *data);
    static void ExecuteSendMessage(napi_env env, void *data);
    static void ExecuteSendData(napi_env env, void *data);
    static void ExecuteSendImage(napi_env env, void *data);
    static void CompleteAsyncWork(napi_env env, napi_status status, void* data);
    static void ExecuteCreateStream(napi_env env, void *data);
    static void CompleteAsyncCreateStreamWork(napi_env env, napi_status status, void* data);

    static napi_value WrapPeerInfo(napi_env& env, const PeerInfo& peerInfo);

    static void CreateErrorForCall(const napi_env &env, int32_t code, const std::string &errMsg);
    static void CreateBusinessError(const napi_env &env, int32_t errCode, const std::string &errMsg);
    static bool CheckArgsCount(const napi_env &env, bool assertion, const std::string &message);
    static bool CheckArgsType(const napi_env &env, bool assertion,
        const std::string &paramName, const std::string &type);
    static bool JsToInt32(const napi_env &env, const napi_value &value,
        const std::string &valueName, int32_t &strValue);
    static bool JsToString(const napi_env &env, const napi_value &value, const std::string &valueName,
        std::string &strValue);
    static bool JsObjectToString(const napi_env &env, const napi_value &object, const std::string &fieldStr,
        std::string& fieldRef);
    static bool JsObjectToBool(const napi_env &env, const napi_value &object, const std::string &fieldStr,
        bool &fieldRef);
    static bool JsObjectToInt(const napi_env &env, const napi_value &object, const std::string &fieldStr,
        int32_t &fieldRef);
    static bool CheckEventType(const std::string& eventType);
    static void UnwrapOptions(napi_env env, napi_value options, ConnectOption &option);
    static void UnwrapParameters(napi_env env, napi_value parameters, ConnectOption &option);
    static bool IsTypeForNapiValue(napi_env env, napi_value param, napi_valuetype expectType);
};

napi_value JsAbilityConnectionManagerInit(napi_env env, napi_value exportObj);
} // namespace DistributedCollab
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_COLLAB_SESSION_MANAGER_JS_ABILITY_CONNECTION_MANAGER_H