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

#include "js_ability_connection_manager.h"

#include <memory>

#include "ability_connection_manager.h"
#include "dtbcollabmgr_log.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"
#include "napi_base_context.h"
#include "string_wrapper.h"

namespace OHOS {
namespace DistributedCollab {
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;
namespace {
#define GET_PARAMS(env, info, num)    \
    size_t argc = num;                \
    napi_value argv[num] = {nullptr}; \
    napi_value thisVar = nullptr;     \
    NAPI_CALL(env, napi_get_cb_info(env, info, &argc, argv, &thisVar, nullptr))

const std::string TAG = "JsAbilityConnectionManager";
constexpr int32_t ARG_INDEX_ZERO = 0;
constexpr int32_t ARG_INDEX_ONE = 1;
constexpr int32_t ARG_INDEX_TWO = 2;
constexpr int32_t ARG_INDEX_THREE = 3;
constexpr int32_t ARG_COUNT_ONE = 1;
constexpr int32_t ARG_COUNT_TWO = 2;
constexpr int32_t ARG_COUNT_THREE = 3;
constexpr int32_t ARG_COUNT_FOUR = 4;
constexpr int32_t NAPI_BUF_LENGTH = 256;

constexpr const char* EVENT_CONNECT = "connect";
constexpr const char* EVENT_DISCONNECT = "disconnect";
constexpr const char* EVENT_RECEIVE_MESSAGE = "receiveMessage";
constexpr const char* EVENT_RECEIVE_DATA = "receiveData";
constexpr const char* EVENT_RECEIVE_IMAGE = "receiveImage";

const std::string ERR_MESSAGE_NO_PERMISSION =
    "Permission verification failed. The application does not have the permission required to call the API.";
const std::string ERR_MESSAGE_INVALID_PARAMS = "Parameter error.";
const std::string ERR_MESSAGE_FAILED = "Failed to execute the function.";
}

bool JsAbilityConnectionManager::CheckArgsCount(const napi_env &env, bool assertion, const std::string &message)
{
    if (!(assertion)) {
        std::string errMsg = ERR_MESSAGE_INVALID_PARAMS + message;
        napi_throw_error(env, std::to_string(ERR_INVALID_PARAMS).c_str(), errMsg.c_str());
        return false;
    }
    return true;
}

bool JsAbilityConnectionManager::CheckArgsType(const napi_env &env, bool assertion,
    const std::string &paramName, const std::string &type)
{
    if (!(assertion)) {
        std::string errMsg = ERR_MESSAGE_INVALID_PARAMS + "The type of " + paramName +
                " must be " + type;
        napi_throw_error(env, std::to_string(
            static_cast<int32_t>(BussinessErrorCode::ERR_INVALID_PARAMS)).c_str(), errMsg.c_str());
        return false;
    }
    return true;
}

bool JsAbilityConnectionManager::JsToInt32(const napi_env &env, const napi_value &value,
    const std::string &valueName, int32_t &strValue)
{
    HILOGD("called.");
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, value, &valueType) != napi_ok) {
        HILOGE("Failed to get argument type");
        return false;
    }

    if (!CheckArgsType(env, valueType == napi_number, valueName, "number")) {
        HILOGE("Argument must be a number");
        return false;
    }

    if (napi_get_value_int32(env, value, &strValue) != napi_ok) {
        HILOGE("Failed to get number value");
        return false;
    }
    return true;
}

bool JsAbilityConnectionManager::JsToString(const napi_env &env, const napi_value &value, const std::string &valueName,
    std::string &strValue)
{
    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, value, &valueType) != napi_ok) {
        HILOGE("Failed to get argument type");
        return false;
    }
    
    if (!CheckArgsType(env, valueType == napi_string, valueName, "string")) {
        HILOGE("Argument must be a string");
        return false;
    }

    size_t valueLen = 0;
    if (napi_get_value_string_utf8(env, value, nullptr, 0, &valueLen) != napi_ok) {
        HILOGE("Failed to get string length");
        return false;
    }

    if (valueLen == 0 && valueLen < NAPI_BUF_LENGTH) {
        HILOGE("string length mast > 0, < %{public}d", NAPI_BUF_LENGTH);
        return false;
    }

    std::vector<char> buf(NAPI_BUF_LENGTH, 0);
    if (napi_get_value_string_utf8(env, value, buf.data(), valueLen + 1, &valueLen) != napi_ok) {
        HILOGE("Failed to read string value");
        return false;
    }
    strValue.assign(buf.begin(), buf.begin() + valueLen);
    return true;
}

bool JsAbilityConnectionManager::JsObjectToString(const napi_env &env, const napi_value &object,
    const std::string &fieldStr, std::string& fieldRef)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, fieldStr.c_str(), &hasProperty) != napi_ok) {
        HILOGE("check object has named property failed.");
        return false;
    }

    if (!hasProperty) {
        HILOGE("napi js to str no property: %{public}s", fieldStr.c_str());
        return false;
    }

    napi_value field = nullptr;
    if (napi_get_named_property(env, object, fieldStr.c_str(), &field) != napi_ok) {
        HILOGE("get property failed, property is %{public}s.", fieldStr.c_str());
        return false;
    }
    return JsToString(env, field, fieldStr, fieldRef);
}

bool JsAbilityConnectionManager::JsObjectToBool(const napi_env &env, const napi_value &object,
    const std::string &fieldStr, bool &fieldRef)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, fieldStr.c_str(), &hasProperty) != napi_ok) {
        HILOGE("check object has named property failed.");
        return false;
    }

    if (!hasProperty) {
        HILOGE("napi js to str no property: %{public}s", fieldStr.c_str());
        return false;
    }

    napi_value field = nullptr;
    if (napi_get_named_property(env, object, fieldStr.c_str(), &field) != napi_ok) {
        HILOGE("get property failed, property is %{public}s.", fieldStr.c_str());
        return false;
    }

    napi_valuetype valueType = napi_undefined;
    if (napi_typeof(env, field, &valueType) != napi_ok) {
        HILOGE("Failed to get argument type");
        return false;
    }

    if (!CheckArgsType(env, valueType == napi_boolean, fieldStr.c_str(), "bool")) {
        return false;
    }

    if (napi_get_value_bool(env, field, &fieldRef) != napi_ok) {
        HILOGE("Failed to read bool value");
        return false;
    }
    return true;
}

bool JsAbilityConnectionManager::JsObjectToInt(const napi_env &env, const napi_value &object,
    const std::string &fieldStr, int32_t &fieldRef)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, object, fieldStr.c_str(), &hasProperty) != napi_ok) {
        HILOGE("check object has named property failed.");
        return false;
    }

    if (!hasProperty) {
        HILOGE("napi js to str no property: %{public}s", fieldStr.c_str());
        return false;
    }

    napi_value field = nullptr;
    if (napi_get_named_property(env, object, fieldStr.c_str(), &field) != napi_ok) {
        HILOGE("get property failed, property is %{public}s.", fieldStr.c_str());
        return false;
    }
    return JsToInt32(env, field, fieldStr, fieldRef);
}

void JsAbilityConnectionManager::CreateBusinessError(const napi_env &env, int32_t errCode, const std::string &errMsg)
{
    switch (errCode) {
        case INVALID_PARAMETERS_ERR:
            napi_throw_error(env, std::to_string(
                static_cast<int32_t>(BussinessErrorCode::ERR_INVALID_PARAMS)).c_str(), errMsg.c_str());
            break;
        default:
            napi_throw_error(env, std::to_string(
                static_cast<int32_t>(BussinessErrorCode::ERR_INVALID_PARAMS)).c_str(), errMsg.c_str());
            break;
    }
}

napi_value JsAbilityConnectionManager::CreateAbilityConnectionSession(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_FOUR);
    napi_value result = nullptr;
    if (!CheckArgsCount(env, argc == ARG_COUNT_FOUR, "Wrong number of arguments, required 4")) {
        HILOGE("CheckArgsCount failed.");
        return result;
    }

    std::string serverId;
    if (!JsToString(env, argv[ARG_INDEX_ZERO], "serverId", serverId)) {
        HILOGE("Failed to unwrap serverId.");
        CreateBusinessError(env, INVALID_PARAMETERS_ERR, "serverId parameter check error.");
        return result;
    }
    std::shared_ptr<AbilityInfo> abilityInfo = nullptr;
    if (!JsToAbilityInfo(env, argv[ARG_INDEX_ONE], abilityInfo)) {
        HILOGE("Failed to unwrap abilityInfo.");
        CreateBusinessError(env, INVALID_PARAMETERS_ERR, "Context parameter check error.");
        return result;
    }

    PeerInfo peerInfo;
    if (!JsToPeerInfo(env, argv[ARG_INDEX_TWO], peerInfo)) {
        HILOGE("Failed to unwrap PeerInfo.");
        CreateBusinessError(env, INVALID_PARAMETERS_ERR, "PeerInfo parameter check error.");
        return result;
    }

    ConnectOption connectOption;
    if (!JSToConnectOption(env, argv[ARG_INDEX_THREE], connectOption)) {
        HILOGE("Failed to unwrap ConnectOption.");
        CreateBusinessError(env, INVALID_PARAMETERS_ERR, "ConnectOption parameter check error.");
        return result;
    }

    int32_t sessionId = -1;
    int32_t ret = AbilityConnectionManager::GetInstance().CreateSession(
        abilityInfo, peerInfo, connectOption, sessionId);
    if (ret != ERR_OK) {
        HILOGE("create session failed!");
        CreateBusinessError(env, ret, "create session failed!");
        return result;
    }
    NAPI_CALL(env, napi_create_int32(env, sessionId, &result));
    return result;
}

bool JsAbilityConnectionManager::JsToAbilityInfo(const napi_env &env, const napi_value &jsValue,
    std::shared_ptr<AbilityInfo>& abilityInfo)
{
    bool stageMode = false;
    napi_status status = OHOS::AbilityRuntime::IsStageContext(env, jsValue, stageMode);
    if (status != napi_ok || !stageMode) {
        auto ability = OHOS::AbilityRuntime::GetCurrentAbility(env);
        if (!ability) {
            HILOGE("get current ability failed!");
            return false;
        }
        auto abilityContext = ability->GetAbilityContext();
        if (!abilityContext) {
            HILOGE("get ability context failed!");
            return false;
        }
        abilityInfo = abilityContext->GetAbilityInfo();
    } else {
        auto context = AbilityRuntime::GetStageModeContext(env, jsValue);
        if (!context) {
            HILOGE("get stage mode context failed!");
            return false;
        }
        auto abilityContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::AbilityContext>(context);
        if (!abilityContext) {
            HILOGE("convertTo AbilityContext failed!");
            return false;
        }
        abilityInfo = abilityContext->GetAbilityInfo();
    }
    return true;
}

bool JsAbilityConnectionManager::JsToPeerInfo(const napi_env &env, const napi_value &jsValue, PeerInfo &peerInfo)
{
    napi_valuetype argvType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, jsValue, &argvType), false);
    if (!CheckArgsType(env, argvType == napi_object, "PeerInfo", "object")) {
        HILOGE("Parameter verification failed.");
        return false;
    }
    
    if (!JsObjectToString(env, jsValue, "deviceId", peerInfo.deviceId)) {
        HILOGE("Failed to unwrap deviceId.");
        return false;
    }

    if (!JsObjectToString(env, jsValue, "bundleName", peerInfo.bundleName)) {
        HILOGE("Failed to unwrap bundleName.");
        return false;
    }

    if (!JsObjectToString(env, jsValue, "moduleName", peerInfo.moduleName)) {
        HILOGE("Failed to unwrap moduleName.");
        return false;
    }

    if (!JsObjectToString(env, jsValue, "abilityName", peerInfo.abilityName)) {
        HILOGE("Failed to unwrap abilityName.");
        return false;
    }

    if (!JsObjectToString(env, jsValue, "serverId", peerInfo.serverId)) {
        HILOGE("Failed to unwrap serverId.");
        return false;
    }
    return true;
}

bool JsAbilityConnectionManager::JSToConnectOption(const napi_env &env, const napi_value &jsValue,
    ConnectOption &option)
{
    napi_valuetype argvType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, jsValue, &argvType), false);
    if (!CheckArgsType(env, argvType == napi_object, "ConnectOption", "object")) {
        HILOGE("Parameter verification failed.");
        return false;
    }

    if (!JsObjectToBool(env, jsValue, "needSendBigData", option.needSendBigData)) {
        HILOGE("Failed to unwrap needSendBigData.");
        return false;
    }

    if (!JsObjectToBool(env, jsValue, "needSendStream", option.needSendStream)) {
        HILOGE("Failed to unwrap needSendStream.");
        return false;
    }

    if (!JsObjectToBool(env, jsValue, "needReceiveStream", option.needReceiveStream)) {
        HILOGE("Failed to unwrap needSendStream.");
        return false;
    }

    napi_value optionsVal;
    if (napi_get_named_property(env, jsValue, "options", &optionsVal) == napi_ok) {
        UnwrapOptions(env, optionsVal, option);
    }

    napi_value parametersVal;
    if (napi_get_named_property(env, jsValue, "parameters", &parametersVal) == napi_ok) {
        UnwrapParameters(env, parametersVal, option);
    }

    return true;
}

bool JsAbilityConnectionManager::UnwrapOptions(napi_env env, napi_value options, ConnectOption &connectOption)
{
    if (options == nullptr) {
        HILOGI("options is nullptr");
        return false;
    }

    napi_valuetype argvType = napi_undefined;
    if (napi_typeof(env, options, &argvType) != napi_ok) {
        return false;
    }

    if (argvType != napi_object) {
        HILOGE("options verification failed.");
        return false;
    }

    napi_value jsProNameList = nullptr;
    NAPI_CALL_BASE(env, napi_get_property_names(env, options, &jsProNameList), false);

    uint32_t jsProCount = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, jsProNameList, &jsProCount), false);

    napi_value jsProName = nullptr;
    napi_value jsProValue = nullptr;
    for (uint32_t index = 0; index < jsProCount; index++) {
        NAPI_CALL_BASE(env, napi_get_element(env, jsProNameList, index, &jsProName), false);

        std::string strProName;
        if (!JsToString(env, jsProName, "options key", strProName)) {
            HILOGE("options get key failed");
            return false;
        }

        NAPI_CALL_BASE(env, napi_get_named_property(env, options, strProName.c_str(), &jsProValue), false);
        std::string natValue;
        if (!JsToString(env, jsProValue, "options value", natValue)) {
            HILOGE("options get value failed");
            return false;
        }
        connectOption.options.SetParam(strProName, AAFwk::String::Box(natValue));
    }
    return true;
}

bool JsAbilityConnectionManager::UnwrapParameters(napi_env env, napi_value parameters, ConnectOption &option)
{
    if (parameters == nullptr) {
        HILOGI("parameters is nullptr");
        return false;
    }

    napi_valuetype argvType = napi_undefined;
    if (napi_typeof(env, parameters, &argvType) != napi_ok) {
        return false;
    }

    if (argvType != napi_object) {
        HILOGE("parameters verification failed.");
        return false;
    }

    napi_value jsProNameList = nullptr;
    NAPI_CALL_BASE(env, napi_get_property_names(env, parameters, &jsProNameList), false);

    uint32_t jsProCount = 0;
    NAPI_CALL_BASE(env, napi_get_array_length(env, jsProNameList, &jsProCount), false);

    napi_value jsProName = nullptr;
    napi_value jsProValue = nullptr;
    for (uint32_t index = 0; index < jsProCount; index++) {
        NAPI_CALL_BASE(env, napi_get_element(env, jsProNameList, index, &jsProName), false);

        std::string strProName;
        if (!JsToString(env, jsProName, "parameters key", strProName)) {
            HILOGE("parameters get key failed");
            return false;
        }

        NAPI_CALL_BASE(env, napi_get_named_property(env, parameters, strProName.c_str(), &jsProValue), false);
        std::string natValue;
        if (!JsToString(env, jsProValue, "parameters value", natValue)) {
            HILOGE("parameters get value failed");
            return false;
        }
        option.parameters.SetParam(strProName, AAFwk::String::Box(natValue));
    }
    return true;
}

napi_value JsAbilityConnectionManager::DestroyAbilityConnectionSession(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_ONE);
    napi_value result = nullptr;
    if (!CheckArgsCount(env, argc == ARG_COUNT_ONE, "Wrong number of arguments, required 1")) {
        HILOGE("Params not match");
        return result;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        return result;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().DestroySession(sessionId);
    if (ret != ERR_OK) {
        HILOGE("destroy session failed!");
        CreateBusinessError(env, ret, "destroy session failed.");
        return result;
    }
    return result;
}

napi_value JsAbilityConnectionManager::GetPeerInfoById(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_ONE);
    napi_value result = nullptr;
    if (!CheckArgsCount(env, argc == ARG_COUNT_ONE, "Wrong number of arguments, required 1")) {
        HILOGE("Params not match");
        return result;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        return result;
    }

    PeerInfo peerInfo;
    int32_t ret = AbilityConnectionManager::GetInstance().getPeerInfoBySessionId(sessionId, peerInfo);
    if (ret != ERR_OK) {
        HILOGE("get peerInfo failed!");
        CreateBusinessError(env, ret, "get peerInfo failed.");
        return result;
    }

    return WrapPeerInfo(env, peerInfo);
}

napi_value JsAbilityConnectionManager::WrapPeerInfo(napi_env& env,
    const PeerInfo& peerInfo)
{
    napi_value peerInfoObj;
    napi_create_object(env, &peerInfoObj);

    napi_value deviceId;
    napi_create_string_utf8(env, peerInfo.deviceId.c_str(), NAPI_AUTO_LENGTH, &deviceId);
    napi_set_named_property(env, peerInfoObj, "deviceId", deviceId);

    napi_value bundleName;
    napi_create_string_utf8(env, peerInfo.bundleName.c_str(), NAPI_AUTO_LENGTH, &bundleName);
    napi_set_named_property(env, peerInfoObj, "bundleName", bundleName);

    napi_value moduleName;
    napi_create_string_utf8(env, peerInfo.moduleName.c_str(), NAPI_AUTO_LENGTH, &moduleName);
    napi_set_named_property(env, peerInfoObj, "moduleName", moduleName);

    napi_value abilityName;
    napi_create_string_utf8(env, peerInfo.abilityName.c_str(), NAPI_AUTO_LENGTH, &abilityName);
    napi_set_named_property(env, peerInfoObj, "abilityName", abilityName);

    napi_value serverId;
    napi_create_string_utf8(env, peerInfo.serverId.c_str(), NAPI_AUTO_LENGTH, &serverId);
    napi_set_named_property(env, peerInfoObj, "serverId", serverId);

    return peerInfoObj;
}

bool JsAbilityConnectionManager::CheckEventType(const std::string& eventType)
{
    return strcmp(eventType.c_str(), EVENT_CONNECT) == 0 ||
        strcmp(eventType.c_str(), EVENT_DISCONNECT) == 0 ||
        strcmp(eventType.c_str(), EVENT_RECEIVE_MESSAGE) == 0 ||
        strcmp(eventType.c_str(), EVENT_RECEIVE_DATA) == 0 ||
        strcmp(eventType.c_str(), EVENT_RECEIVE_IMAGE) == 0;
}

napi_value JsAbilityConnectionManager::RegisterAbilityConnectionSessionCallback(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_THREE);
    napi_value result = nullptr;
    if (!CheckArgsCount(env, argc == ARG_COUNT_THREE, "Wrong number of arguments, required 3")) {
        HILOGE("Params not match");
        return result;
    }

    std::string eventType;
    if (!JsToString(env, argv[ARG_INDEX_ZERO], "eventType", eventType)) {
        HILOGE("Failed to unwrap type.");
        return result;
    }

    if (!CheckEventType(eventType)) {
        HILOGE("The type error. eventType is %{public}s", eventType.c_str());
        return result;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ONE], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        return result;
    }

    napi_value listenerObj = argv[ARG_INDEX_TWO];
    if (listenerObj == nullptr) {
        HILOGE("listenerObj is nullptr");
        return result;
    }

    bool isCallable = false;
    NAPI_CALL(env, napi_is_callable(env, listenerObj, &isCallable));

    if (!isCallable) {
        HILOGE("Failed to check listenerObj is callable");
        return result;
    }

    std::shared_ptr<JsAbilityConnectionSessionListener> listener =
        std::make_shared<JsAbilityConnectionSessionListener>(env);

    listener->SetCallback(listenerObj);
    int32_t ret = AbilityConnectionManager::GetInstance().RegisterEventCallback(
        sessionId, eventType, listener);
    if (ret != ERR_OK) {
        HILOGE("Register event callback failed!");
        CreateBusinessError(env, ret, "Register event callback failed.");
        return result;
    }

    return result;
}

napi_value JsAbilityConnectionManager::UnregisterAbilityConnectionSessionCallback(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_THREE);
    napi_value result = nullptr;
    if (!CheckArgsCount(env, argc >= ARG_COUNT_TWO, "Wrong number of arguments, at least 2 parameters")) {
        HILOGE("Params not match");
        return result;
    }

    std::string eventType;
    if (!JsToString(env, argv[ARG_INDEX_ZERO], "eventType", eventType)) {
        HILOGE("Failed to unwrap type.");
        return result;
    }

    if (!CheckEventType(eventType)) {
        HILOGE("The type error. eventType is %{public}s", eventType.c_str());
        return result;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ONE], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        return result;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().UnregisterEventCallback(sessionId, eventType);
    if (ret != ERR_OK) {
        HILOGE("Unregister event callback failed!");
        CreateBusinessError(env, ret, "Unregister event callback failed.");
        return result;
    }

    return result;
}

napi_value JsAbilityConnectionManager::Connect(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_ONE);
    if (!CheckArgsCount(env, argc == ARG_COUNT_ONE, "Wrong number of arguments, required 1")) {
        HILOGE("Params not match");
        return nullptr;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        return nullptr;
    }

    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    AsyncConnectCallbackInfo* asyncCallbackInfo = new AsyncConnectCallbackInfo();
    asyncCallbackInfo->deferred = deferred;
    asyncCallbackInfo->sessionId = sessionId;

    napi_value asyncResourceName;
    NAPI_CALL(env, napi_create_string_utf8(env, "connectAsync", NAPI_AUTO_LENGTH, &asyncResourceName));

    napi_status status = napi_create_async_work(
        env, nullptr, asyncResourceName, ExecuteConnect, CompleteAsyncConnectWork,
        static_cast<void *>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    napi_threadsafe_function tsfn;
    if (CreateConnectThreadsafeFunction(env, nullptr, &tsfn) != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    asyncCallbackInfo->tsfn = tsfn;
    return promise;
}

napi_status JsAbilityConnectionManager::CreateConnectThreadsafeFunction(napi_env env,
    napi_value js_func, napi_threadsafe_function* tsfn)
{
    napi_value async_resource = nullptr;
    napi_value async_resource_name = nullptr;
    napi_create_string_utf8(env, "connectAsync", NAPI_AUTO_LENGTH, &async_resource_name);

    return napi_create_threadsafe_function(
        env, js_func, async_resource, async_resource_name,
        0, 1, nullptr, nullptr, nullptr,
        ConnectThreadsafeFunctionCallback, tsfn);
}

void JsAbilityConnectionManager::ConnectThreadsafeFunctionCallback(napi_env env, napi_value js_callback,
    void* context, void* data)
{
    HILOGD("called.");
    AsyncConnectCallbackInfo* asyncData = static_cast<AsyncConnectCallbackInfo*>(data);
    napi_value connectResultObj;
    napi_create_object(env, &connectResultObj);

    napi_value isConnected;
    napi_get_boolean(env, asyncData->result.isConnected, &isConnected);
    napi_set_named_property(env, connectResultObj, "isConnected", isConnected);

    if (asyncData->result.isConnected && !asyncData->result.reason.empty()) {
        napi_value reason;
        napi_create_string_utf8(env, asyncData->result.reason.c_str(), NAPI_AUTO_LENGTH, &reason);
        napi_set_named_property(env, connectResultObj, "reason", reason);
    }
    napi_resolve_deferred(env, asyncData->deferred, connectResultObj);

    napi_async_work asyncWork = asyncData->asyncWork;
    napi_release_threadsafe_function(asyncData->tsfn, napi_tsfn_release);
    napi_delete_async_work(env, asyncWork);
    delete asyncData;
}

void JsAbilityConnectionManager::ExecuteConnect(napi_env env, void *data)
{
    AsyncConnectCallbackInfo* asyncData = static_cast<AsyncConnectCallbackInfo*>(data);
    napi_threadsafe_function tsfn = asyncData->tsfn;

    AbilityConnectionManager::ConnectCallback connectCallback = [tsfn, asyncData](ConnectResult result) {
        asyncData->result = result;
        napi_call_threadsafe_function(tsfn, asyncData, napi_tsfn_nonblocking);
    };
    AbilityConnectionManager::GetInstance().ConnectSession(asyncData->sessionId, connectCallback);
}

void JsAbilityConnectionManager::CompleteAsyncConnectWork(napi_env env, napi_status status, void* data)
{
    HILOGD("called.");
}

napi_value JsAbilityConnectionManager::DisConnect(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    napi_value result = nullptr;
    GET_PARAMS(env, info, ARG_COUNT_ONE);
    if (!CheckArgsCount(env, argc == ARG_COUNT_ONE, "Wrong number of arguments, required 1")) {
        HILOGE("Params not match");
        return result;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        return result;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().DisconnectSession(sessionId);
    if (ret != ERR_OK) {
        HILOGE("disconnect session failed!");
        CreateBusinessError(env, ret, "disconnect session failed.");
        return result;
    }
    return CreateJsUndefined(env);
}

void JsAbilityConnectionManager::CompleteAsyncWork(napi_env env, napi_status status, void* data)
{
    HILOGD("called.");
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    if (asyncData->result) {
        napi_value result;
        napi_get_undefined(env, &result);
        napi_resolve_deferred(env, asyncData->deferred, result);
    } else {
        napi_value error;
        napi_create_string_utf8(env, ERR_MESSAGE_FAILED.c_str(), NAPI_AUTO_LENGTH, &error);
        napi_reject_deferred(env, asyncData->deferred, error);
    }
    napi_delete_async_work(env, asyncData->asyncWork);
    delete asyncData;
}

napi_value JsAbilityConnectionManager::AcceptConnect(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (!CheckArgsCount(env, argc == ARG_COUNT_TWO, "Wrong number of arguments, required 2")) {
        HILOGE("parameters not match");
        return nullptr;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        return nullptr;
    }

    std::string token;
    if (!JsToString(env, argv[ARG_INDEX_ONE], "token", token)) {
        HILOGE("Failed to unwrap token.");
        return nullptr;
    }

    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    AsyncCallbackInfo* asyncCallbackInfo = new AsyncCallbackInfo();
    asyncCallbackInfo->deferred = deferred;
    asyncCallbackInfo->sessionId = sessionId;
    asyncCallbackInfo->token = token;

    napi_value asyncResourceName;
    NAPI_CALL(env, napi_create_string_utf8(env, "acceptConnectAsync", NAPI_AUTO_LENGTH, &asyncResourceName));

    napi_status status = napi_create_async_work(
        env, nullptr, asyncResourceName, ExecuteAcceptConnect, CompleteAsyncWork,
        static_cast<void *>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }
    return promise;
}

void JsAbilityConnectionManager::ExecuteAcceptConnect(napi_env env, void *data)
{
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    int32_t ret = AbilityConnectionManager::GetInstance().AcceptConnect(asyncData->sessionId, asyncData->token);
    if (ret != ERR_OK) {
        HILOGE("accept connect failed.");
        asyncData->result = false;
    }
    asyncData->result = true;
}

napi_value JsAbilityConnectionManager::Reject(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (!CheckArgsCount(env, argc == ARG_COUNT_TWO, "Wrong number of arguments, required 2")) {
        HILOGE("Params not match");
        return nullptr;
    }

    std::string token;
    if (!JsToString(env, argv[ARG_INDEX_ZERO], "token", token)) {
        HILOGE("Failed to unwrap token.");
        return nullptr;
    }

    std::string reason;
    if (!JsToString(env, argv[ARG_INDEX_ONE], "reason", reason)) {
        HILOGE("Failed to unwrap reason.");
        return nullptr;
    }

    napi_value result = nullptr;
    int32_t ret = AbilityConnectionManager::GetInstance().Reject(token, reason);
    if (ret != ERR_OK) {
        HILOGE("Reject session failed!");
        CreateBusinessError(env, ret, "Reject session failed.");
        return result;
    }
    return result;
}

napi_value JsAbilityConnectionManager::SendMessage(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (!CheckArgsCount(env, argc == ARG_COUNT_TWO, "Wrong number of arguments, required 2")) {
        HILOGE("Params not match");
        return nullptr;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        
        return nullptr;
    }

    std::string msg;
    if (!JsToString(env, argv[ARG_INDEX_ONE], "msg", msg)) {
        HILOGE("Failed to unwrap msg.");
        return nullptr;
    }

    // 创建 Promise 和 deferred 对象
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    AsyncCallbackInfo* asyncCallbackInfo = new AsyncCallbackInfo();
    asyncCallbackInfo->deferred = deferred;
    asyncCallbackInfo->sessionId = sessionId;
    asyncCallbackInfo->msg = msg;

    napi_value asyncResourceName;
    NAPI_CALL(env, napi_create_string_utf8(env, "sendMessageAsync", NAPI_AUTO_LENGTH, &asyncResourceName));

    napi_status status = napi_create_async_work(
        env, nullptr, asyncResourceName, ExecuteSendMessage, CompleteAsyncWork,
        static_cast<void *>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    return promise;
}

void JsAbilityConnectionManager::ExecuteSendMessage(napi_env env, void *data)
{
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    int32_t ret = AbilityConnectionManager::GetInstance().SendMessage(asyncData->sessionId, asyncData->msg);
    if (ret != ERR_OK) {
        asyncData->result = false;
    }
    asyncData->result = true;
}

napi_value JsAbilityConnectionManager::SendData(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (!CheckArgsCount(env, argc == ARG_COUNT_TWO, "Wrong number of arguments, required 2")) {
        HILOGE("Params not match");
        return nullptr;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        return nullptr;
    }

    void *data;
    size_t length;
    if (napi_get_arraybuffer_info(env, argv[ARG_INDEX_ONE], &data, &length) != napi_ok) {
        HILOGE("get arraybuffer info failed.");
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(length);
    if (memcpy_s(buffer->Data(), buffer->Size(), data, length) != ERR_OK) {
        HILOGE("pack recv data failed");
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    AsyncCallbackInfo* asyncCallbackInfo = new AsyncCallbackInfo();
    asyncCallbackInfo->deferred = deferred;
    asyncCallbackInfo->sessionId = sessionId;
    asyncCallbackInfo->buffer = buffer;

    napi_value asyncResourceName;
    NAPI_CALL(env, napi_create_string_utf8(env, "sendDataAsync", NAPI_AUTO_LENGTH, &asyncResourceName));

    napi_status status = napi_create_async_work(
        env, nullptr, asyncResourceName, ExecuteSendData, CompleteAsyncWork,
        static_cast<void *>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    return promise;
}

void JsAbilityConnectionManager::ExecuteSendData(napi_env env, void *data)
{
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    int32_t ret = AbilityConnectionManager::GetInstance().SendData(asyncData->sessionId, asyncData->buffer);
    if (ret != ERR_OK) {
        asyncData->result = false;
    }
    asyncData->result = true;
}

napi_value JsAbilityConnectionManager::SendImage(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (!CheckArgsCount(env, argc == ARG_COUNT_TWO, "Wrong number of arguments, required 2")) {
        HILOGE("Params not match");
        return nullptr;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        return nullptr;
    }

    std::shared_ptr<Media::PixelMap> pixelMapPtr = Media::PixelMapNapi::GetPixelMap(env, argv[ARG_INDEX_ONE]);
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    AsyncCallbackInfo* asyncCallbackInfo = new AsyncCallbackInfo();
    asyncCallbackInfo->deferred = deferred;
    asyncCallbackInfo->sessionId = sessionId;
    asyncCallbackInfo->image = pixelMapPtr;

    napi_value asyncResourceName;
    NAPI_CALL(env, napi_create_string_utf8(env, "sendImageAsync", NAPI_AUTO_LENGTH, &asyncResourceName));

    napi_status status = napi_create_async_work(
        env, nullptr, asyncResourceName, ExecuteSendImage, CompleteAsyncWork,
        static_cast<void *>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    return promise;
}

void JsAbilityConnectionManager::ExecuteSendImage(napi_env env, void *data)
{
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    int32_t ret = AbilityConnectionManager::GetInstance().SendImage(asyncData->sessionId, asyncData->image);
    if (ret != ERR_OK) {
        asyncData->result = false;
    }
    asyncData->result = true;
}

napi_value JsAbilityConnectionManager::CreateStream(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (!CheckArgsCount(env, argc == ARG_COUNT_TWO, "Wrong number of arguments, required 2")) {
        HILOGE("Params not match");
        return nullptr;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        return nullptr;
    }

    HILOGI("StreamParam.");
    StreamParams streamParam;
    if (!JsToStreamParam(env, argv[ARG_INDEX_ONE], streamParam)) {
        HILOGE("Failed to unwrap streamParam.");
        CreateBusinessError(env, INVALID_PARAMETERS_ERR, "ConnectOption parameter check error.");
        return nullptr;
    }

    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    AsyncCallbackInfo* asyncCallbackInfo = new AsyncCallbackInfo();
    asyncCallbackInfo->deferred = deferred;
    asyncCallbackInfo->sessionId = sessionId;
    asyncCallbackInfo->streamParam = streamParam;

    napi_value asyncResourceName;
    NAPI_CALL(env, napi_create_string_utf8(env, "createStreamAsync", NAPI_AUTO_LENGTH, &asyncResourceName));

    napi_status status = napi_create_async_work(
        env, nullptr, asyncResourceName, ExecuteCreateStream, CompleteAsyncCreateStreamWork,
        static_cast<void *>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_throw_error(env, nullptr, ERR_MESSAGE_FAILED.c_str());
        return nullptr;
    }

    return promise;
}

bool JsAbilityConnectionManager::JsToStreamParam(const napi_env &env, const napi_value &jsValue,
    StreamParams &streamParam)
{
    napi_valuetype argvType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, jsValue, &argvType), false);
    if (!CheckArgsType(env, argvType == napi_object, "StreamParam", "object")) {
        HILOGE("Parameter verification failed.");
        return false;
    }

    if (!JsObjectToString(env, jsValue, "name", streamParam.name)) {
        HILOGE("name parameter parsing failed.");
        return false;
    }

    int32_t role = -1;
    if (!JsObjectToInt(env, jsValue, "role", role)) {
        HILOGE("role verification failed.");
        return false;
    }

    if (role < static_cast<int32_t>(StreamRole::SOURCE) ||
        role > static_cast<int32_t>(StreamRole::SINK)) {
        HILOGE("Invalid role value: %{public}d", role);
        return false;
    }
    streamParam.role = static_cast<StreamRole>(role);
    
    return true;
}

void JsAbilityConnectionManager::ExecuteCreateStream(napi_env env, void *data)
{
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);

    int32_t ret = AbilityConnectionManager::GetInstance().CreateStream(asyncData->sessionId,
        asyncData->streamParam, asyncData->streamId);
    if (ret != ERR_OK) {
        asyncData->result = false;
    }
    asyncData->result = true;
}

void JsAbilityConnectionManager::CompleteAsyncCreateStreamWork(napi_env env, napi_status status, void* data)
{
    HILOGD("called.");
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    if (asyncData->result) {
        napi_value result;
        napi_create_int32(env, asyncData->streamId, &result);
        napi_resolve_deferred(env, asyncData->deferred, result);
    } else {
        napi_value error;
        napi_create_string_utf8(env, ERR_MESSAGE_FAILED.c_str(), NAPI_AUTO_LENGTH, &error);
        napi_reject_deferred(env, asyncData->deferred, error);
    }
    napi_delete_async_work(env, asyncData->asyncWork);
    delete asyncData;
}

napi_value JsAbilityConnectionManager::SetSurfaceId(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_THREE);
    if (!CheckArgsCount(env, argc == ARG_COUNT_THREE, "Wrong number of arguments, required 3")) {
        HILOGE("Params not match");
        return nullptr;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("Parameter parsing failed.");
        return nullptr;
    }

    std::string surfaceId;
    if (!JsToString(env, argv[ARG_INDEX_ONE], "surfaceId", surfaceId)) {
        HILOGE("surfaceId parsing failed.");
        return nullptr;
    }

    SurfaceParams surfaceParam;
    if (!JsToSurfaceParam(env, argv[ARG_INDEX_TWO], surfaceParam)) {
        HILOGE("Failed to unwrap surfaceParam.");
        CreateBusinessError(env, INVALID_PARAMETERS_ERR, "ConnectOption parameter check error.");
        return nullptr;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().SetSurfaceId(streamId,
        surfaceId, surfaceParam);
    if (ret != ERR_OK) {
        HILOGE("SetSurfaceId failed.");
        return nullptr;
    }
    return nullptr;
}

bool JsAbilityConnectionManager::JsToSurfaceParam(const napi_env &env, const napi_value &jsValue,
    SurfaceParams &surfaceParam)
{
    napi_valuetype argvType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, jsValue, &argvType), false);
    if (!CheckArgsType(env, argvType == napi_object, "SurfaceParams", "object")) {
        HILOGE("Parameter verification failed.");
        return false;
    }

    if (!JsObjectToInt(env, jsValue, "width", surfaceParam.width)) {
        HILOGE("Unable to get width parameter.");
        return false;
    }

    if (!JsObjectToInt(env, jsValue, "height", surfaceParam.height)) {
        HILOGE("Unable to get height parameter.");
        return false;
    }

    int32_t format = -1;
    if (JsObjectToInt(env, jsValue, "format", format)) {
        if (format < static_cast<int32_t>(VideoPixelFormat::UNKNOWN) ||
            format > static_cast<int32_t>(VideoPixelFormat::NV21)) {
            HILOGE("Invalid format value: %{public}d", format);
            return false;
        }
        surfaceParam.format = static_cast<VideoPixelFormat>(format);
    }

    int32_t flip = -1;
    if (JsObjectToInt(env, jsValue, "flip", flip)) {
        if (flip < static_cast<int32_t>(FlipOption::HORIZONTAL) ||
            flip > static_cast<int32_t>(FlipOption::VERTICAL)) {
            HILOGE("Invalid flip value: %{public}d", flip);
            return false;
        }
        surfaceParam.flip = static_cast<FlipOption>(flip);
    }

    if (!JsObjectToInt(env, jsValue, "rotation", surfaceParam.rotation)) {
        HILOGW("Unable to get rotation parameter.");
    }
    
    return true;
}

napi_value JsAbilityConnectionManager::GetSurfaceId(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (!CheckArgsCount(env, argc == ARG_COUNT_TWO, "Wrong number of arguments, required 2")) {
        HILOGE("Params not match");
        return nullptr;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("Parameter parsing failed.");
        return nullptr;
    }

    SurfaceParams surfaceParam;
    if (!JsToSurfaceParam(env, argv[ARG_INDEX_ONE], surfaceParam)) {
        HILOGE("Failed to unwrap surfaceParam.");
        CreateBusinessError(env, INVALID_PARAMETERS_ERR, "ConnectOption parameter check error.");
        return nullptr;
    }

    std::string surfaceId;
    int32_t ret = AbilityConnectionManager::GetInstance().GetSurfaceId(streamId, surfaceParam, surfaceId);
    if (ret != ERR_OK) {
        HILOGE("SetSurfaceId failed.");
        return nullptr;
    }

    napi_value result;
    napi_create_string_utf8(env, surfaceId.c_str(), surfaceId.size(), &result);
    return result;
}

napi_value JsAbilityConnectionManager::UpdateSurfaceParam(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_THREE);
    napi_value result = nullptr;
    if (!CheckArgsCount(env, argc == ARG_COUNT_TWO, "Wrong number of arguments, required 2")) {
        HILOGE("Params not match");
        return result;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("streamId parsing failed.");
        return result;
    }

    SurfaceParams surfaceParam;
    if (!JsToSurfaceParam(env, argv[ARG_INDEX_ONE], surfaceParam)) {
        HILOGE("Failed to unwrap surfaceParam.");
        CreateBusinessError(env, INVALID_PARAMETERS_ERR, "ConnectOption parameter check error.");
        return result;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().UpdateSurfaceParam(streamId, surfaceParam);
    if (ret != ERR_OK) {
        HILOGE("SetSurfaceId failed.");
        return result;
    }
    return result;
}

napi_value JsAbilityConnectionManager::DestroyStream(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_ONE);
    if (!CheckArgsCount(env, argc == ARG_COUNT_ONE, "Wrong number of arguments, required 1")) {
        HILOGE("Params not match");
        return nullptr;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("Parameter parsing failed.");
        return nullptr;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().DestroyStream(streamId);
    if (ret != ERR_OK) {
        HILOGE("DestroyStream failed.");
        return nullptr;
    }
    return nullptr;
}

napi_value JsAbilityConnectionManager::StartStream(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_ONE);
    if (!CheckArgsCount(env, argc == ARG_COUNT_ONE, "Wrong number of arguments, required 1")) {
        HILOGE("Params not match");
        return nullptr;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("Parameter parsing failed.");
        return nullptr;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().StartStream(streamId);
    if (ret != ERR_OK) {
        HILOGE("StartStream failed.");
        return nullptr;
    }
    return nullptr;
}

napi_value JsAbilityConnectionManager::StopStream(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_ONE);
    if (!CheckArgsCount(env, argc == ARG_COUNT_ONE, "Wrong number of arguments, required 1")) {
        HILOGE("Params not match");
        return nullptr;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("Parameter parsing failed.");
        return nullptr;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().StopStream(streamId);
    if (ret != ERR_OK) {
        HILOGE("StopStream failed.");
        return nullptr;
    }
    return nullptr;
}

napi_value JsAbilityConnectionManagerInit(napi_env env, napi_value exports)
{
    HILOGD("called.");
    if (env == nullptr || exports == nullptr) {
        HILOGE("Invalid input parameters");
        return nullptr;
    }
    static napi_property_descriptor desc[] = {
        DECLARE_NAPI_FUNCTION("createAbilityConnectionSession",
            JsAbilityConnectionManager::CreateAbilityConnectionSession),
        DECLARE_NAPI_FUNCTION("destroyAbilityConnectionSession",
            JsAbilityConnectionManager::DestroyAbilityConnectionSession),
        DECLARE_NAPI_FUNCTION("getPeerInfoById", JsAbilityConnectionManager::GetPeerInfoById),
        DECLARE_NAPI_FUNCTION("on", JsAbilityConnectionManager::RegisterAbilityConnectionSessionCallback),
        DECLARE_NAPI_FUNCTION("off", JsAbilityConnectionManager::UnregisterAbilityConnectionSessionCallback),
        DECLARE_NAPI_FUNCTION("connect", JsAbilityConnectionManager::Connect),
        DECLARE_NAPI_FUNCTION("disconnect", JsAbilityConnectionManager::DisConnect),
        DECLARE_NAPI_FUNCTION("acceptConnect", JsAbilityConnectionManager::AcceptConnect),
        DECLARE_NAPI_FUNCTION("reject", JsAbilityConnectionManager::Reject),
        DECLARE_NAPI_FUNCTION("sendMessage", JsAbilityConnectionManager::SendMessage),
        DECLARE_NAPI_FUNCTION("sendData", JsAbilityConnectionManager::SendData),
        DECLARE_NAPI_FUNCTION("sendImage", JsAbilityConnectionManager::SendImage),
        DECLARE_NAPI_FUNCTION("createStream", JsAbilityConnectionManager::CreateStream),
        DECLARE_NAPI_FUNCTION("setSurfaceId", JsAbilityConnectionManager::SetSurfaceId),
        DECLARE_NAPI_FUNCTION("getSurfaceId", JsAbilityConnectionManager::GetSurfaceId),
        DECLARE_NAPI_FUNCTION("updateSurfaceParam", JsAbilityConnectionManager::UpdateSurfaceParam),
        DECLARE_NAPI_FUNCTION("destroyStream", JsAbilityConnectionManager::DestroyStream),
        DECLARE_NAPI_FUNCTION("startStream", JsAbilityConnectionManager::StartStream),
        DECLARE_NAPI_FUNCTION("stopStream", JsAbilityConnectionManager::StopStream),
    };
    NAPI_CALL(env, napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc));
    AbilityConnectionManager::GetInstance().Init();
    HILOGI("napi_define_properties end");
    return exports;
}
}  // namespace DistributedSchedule
}  // namespace OHOS