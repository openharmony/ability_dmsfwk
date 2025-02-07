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
#include "ipc_skeleton.h"
#include "js_runtime_utils.h"
#include "napi_common_util.h"
#include "napi_base_context.h"
#include "string_wrapper.h"
#include "tokenid_kit.h"

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
constexpr int32_t PEER_APP_EXIT = 0;
constexpr int32_t NETWORK_DISCONNECTED = 1;
constexpr int32_t HORIZONTAL = 0;
constexpr int32_t VERTICAL = 1;
constexpr int32_t SOURCE = 0;
constexpr int32_t SINK = 1;
constexpr int32_t UNKNOWN = -1;
constexpr int32_t NV12 = 0;
constexpr int32_t NV21 = 1;

const std::string EVENT_CONNECT = "connect";
const std::string EVENT_DISCONNECT = "disconnect";
const std::string EVENT_RECEIVE_MESSAGE = "receiveMessage";
const std::string EVENT_RECEIVE_DATA = "receiveData";
const std::string EVENT_RECEIVE_IMAGE = "receiveImage";

const std::string ERR_MESSAGE_NO_PERMISSION =
    "Permission verification failed. The application does not have the permission required to call the API.";
const std::string ERR_MESSAGE_INVALID_PARAMS = "Parameter error.";
const std::string ERR_MESSAGE_FAILED = "Failed to execute the function.";
const std::string ERR_MESSAGE_ONE_STREAM = "Only one stream can be created for the current session.";
const std::string ERR_MESSAGE_RECEIVE_NOT_START = "The stream at the receive end is not started.";
const std::string KEY_START_OPTION = "ohos.collabrate.key.start.option";
const std::string VALUE_START_OPTION_FOREGROUND = "ohos.collabrate.value.forefround";
const std::string VALUE_START_OPTION_BACKGROUND = "ohos.collabrate.value.background";
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

    if (valueType != napi_number) {
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
    
    if (valueType != napi_string) {
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

    if (valueType != napi_boolean) {
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

bool JsAbilityConnectionManager::IsSystemApp()
{
    uint64_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
    return OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
}

napi_value GenerateBusinessError(napi_env env,
    int32_t err, const std::string &msg)
{
    napi_value businessError = nullptr;
    NAPI_CALL(env, napi_create_object(env, &businessError));
    napi_value errorCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, err, &errorCode));
    napi_value errorMessage = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errorMessage));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "code", errorCode));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "message", errorMessage));

    return businessError;
}

napi_value CreateErrorForCall(napi_env env, int32_t code, const std::string &errMsg, bool isAsync = true)
{
    HILOGI("CreateErrorForCall code:%{public}d, message:%{public}s", code, errMsg.c_str());
    napi_value error = nullptr;
    if (isAsync) {
        napi_throw_error(env, std::to_string(code).c_str(), errMsg.c_str());
    } else {
        error = GenerateBusinessError(env, code, errMsg);
    }
    return error;
}

napi_value CreateBusinessError(napi_env env, int32_t errCode, bool isAsync = true)
{
    napi_value error = nullptr;
    switch (errCode) {
        case ERR_IS_NOT_SYSTEM_APP:
            error = CreateErrorForCall(env, static_cast<int32_t>(BussinessErrorCode::ERR_NOT_SYSTEM_APP),
                ERR_MESSAGE_NO_PERMISSION, isAsync);
            break;
        case ERR_INVALID_PARAMETERS:
            error = CreateErrorForCall(env, static_cast<int32_t>(BussinessErrorCode::ERR_INVALID_PARAMS),
                ERR_MESSAGE_INVALID_PARAMS, isAsync);
            break;
        case ONLY_SUPPORT_ONE_STREAM:
            error = CreateErrorForCall(env, static_cast<int32_t>(BussinessErrorCode::ERR_ONLY_SUPPORT_ONE_STREAM),
                ERR_MESSAGE_ONE_STREAM, isAsync);
            break;
        case RECEIVE_STREAM_NOT_START:
            error = CreateErrorForCall(env, static_cast<int32_t>(BussinessErrorCode::ERR_RECEIVE_STREAM_NOT_START),
                ERR_MESSAGE_RECEIVE_NOT_START, isAsync);
            break;
        case ERR_EXECUTE_FUNCTION:
            error = CreateErrorForCall(env, static_cast<int32_t>(BussinessErrorCode::ERR_INVALID_PARAMS),
                ERR_MESSAGE_FAILED, isAsync);
            break;
        default:
            error = CreateErrorForCall(env, static_cast<int32_t>(BussinessErrorCode::ERR_INVALID_PARAMS),
                ERR_MESSAGE_FAILED, isAsync);
            break;
    }
    return error;
}

napi_value JsAbilityConnectionManager::CreateAbilityConnectionSession(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_FOUR);
    napi_value result = nullptr;
    if (argc != ARG_COUNT_FOUR) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return result;
    }

    std::string serverId;
    if (!JsToString(env, argv[ARG_INDEX_ZERO], "serverId", serverId)) {
        HILOGE("Failed to unwrap serverId.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return result;
    }
    std::shared_ptr<AbilityInfo> abilityInfo = nullptr;
    if (!JsToAbilityInfo(env, argv[ARG_INDEX_ONE], abilityInfo)) {
        HILOGE("Failed to unwrap abilityInfo.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return result;
    }

    PeerInfo peerInfo;
    if (!JsToPeerInfo(env, argv[ARG_INDEX_TWO], peerInfo)) {
        HILOGE("Failed to unwrap PeerInfo.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return result;
    }

    ConnectOption connectOption;
    int32_t ret = JSToConnectOption(env, argv[ARG_INDEX_THREE], connectOption);
    if (ret != ERR_OK) {
        HILOGE("Failed to unwrap ConnectOption.");
        CreateBusinessError(env, ret);
        return result;
    }

    int32_t sessionId = -1;
    ret = AbilityConnectionManager::GetInstance().CreateSession(
        abilityInfo, peerInfo, connectOption, sessionId);
    if (ret != ERR_OK) {
        HILOGE("create session failed!");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
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
    if (argvType != napi_object) {
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

int32_t JsAbilityConnectionManager::JSToConnectOption(const napi_env &env, const napi_value &jsValue,
    ConnectOption &option)
{
    napi_valuetype argvType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, jsValue, &argvType), false);
    if (argvType != napi_object) {
        HILOGE("Parameter verification failed.");
        return ERR_INVALID_PARAMETERS;
    }

    if (!JsObjectToBool(env, jsValue, "needSendData", option.needSendData)) {
        HILOGE("Failed to unwrap needSendData.");
        return ERR_INVALID_PARAMETERS;
    }

    if (!JsObjectToBool(env, jsValue, "needSendStream", option.needSendStream)) {
        HILOGE("Failed to unwrap needSendStream.");
        return ERR_INVALID_PARAMETERS;
    }

    if (!JsObjectToBool(env, jsValue, "needReceiveStream", option.needReceiveStream)) {
        HILOGE("Failed to unwrap needSendStream.");
        return ERR_INVALID_PARAMETERS;
    }

    napi_value optionsVal;
    if (napi_get_named_property(env, jsValue, "options", &optionsVal) == napi_ok) {
        UnwrapOptions(env, optionsVal, option);
        if (option.options.GetStringParam(KEY_START_OPTION) == VALUE_START_OPTION_BACKGROUND &&
            !IsSystemApp()) {
            return ERR_IS_NOT_SYSTEM_APP;
        }
    }

    napi_value parametersVal;
    if (napi_get_named_property(env, jsValue, "parameters", &parametersVal) == napi_ok) {
        UnwrapParameters(env, parametersVal, option);
    }

    return ERR_OK;
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
        HILOGW("options verification failed.");
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
    if (argc != ARG_COUNT_ONE) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        return nullptr;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().DestroySession(sessionId);
    if (ret != ERR_OK) {
        HILOGE("destroy session failed!");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
    }
    return nullptr;
}

napi_value JsAbilityConnectionManager::GetPeerInfoById(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_ONE);
    napi_value result = nullptr;
    if (argc != ARG_COUNT_ONE) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
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
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
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

int32_t JsAbilityConnectionManager::CheckEventType(const std::string& eventType)
{
    if (eventType != EVENT_CONNECT && eventType != EVENT_DISCONNECT &&
        eventType != EVENT_RECEIVE_MESSAGE && eventType != EVENT_RECEIVE_DATA &&
        eventType != EVENT_RECEIVE_IMAGE) {
        return ERR_INVALID_PARAMETERS;
    }

    if ((eventType == EVENT_RECEIVE_DATA || eventType == EVENT_RECEIVE_IMAGE) &&
        !IsSystemApp()) {
        return ERR_IS_NOT_SYSTEM_APP;
    }
    return ERR_OK;
}

napi_value JsAbilityConnectionManager::RegisterAbilityConnectionSessionCallback(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_THREE);
    if (argc != ARG_COUNT_THREE) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    std::string eventType;
    if (!JsToString(env, argv[ARG_INDEX_ZERO], "eventType", eventType)) {
        HILOGE("Failed to unwrap type.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t ret = CheckEventType(eventType);
    if (ret != ERR_OK) {
        HILOGE("The type error. eventType is %{public}s", eventType.c_str());
        CreateBusinessError(env, ret);
        return nullptr;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ONE], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    napi_value listenerObj = argv[ARG_INDEX_TWO];
    if (listenerObj == nullptr) {
        HILOGE("listenerObj is nullptr");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    bool isCallable = false;
    napi_status status = napi_is_callable(env, listenerObj, &isCallable);
    if (status != napi_ok || !isCallable) {
        HILOGE("Failed to check listenerObj is callable");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    std::shared_ptr<JsAbilityConnectionSessionListener> listener =
        std::make_shared<JsAbilityConnectionSessionListener>(env);

    listener->SetCallback(listenerObj);
    ret = AbilityConnectionManager::GetInstance().RegisterEventCallback(
        sessionId, eventType, listener);
    if (ret != ERR_OK) {
        HILOGE("Register event callback failed!");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
    }
    return nullptr;
}

napi_value JsAbilityConnectionManager::UnregisterAbilityConnectionSessionCallback(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (argc != ARG_COUNT_TWO) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    std::string eventType;
    if (!JsToString(env, argv[ARG_INDEX_ZERO], "eventType", eventType)) {
        HILOGE("Failed to unwrap type.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t ret = CheckEventType(eventType);
    if (ret != ERR_OK) {
        HILOGE("The type error. eventType is %{public}s", eventType.c_str());
        CreateBusinessError(env, ret);
        return nullptr;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ONE], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    ret = AbilityConnectionManager::GetInstance().UnregisterEventCallback(sessionId, eventType);
    if (ret != ERR_OK) {
        HILOGE("Unregister event callback failed!");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
    }
    return nullptr;
}

napi_value JsAbilityConnectionManager::Connect(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_ONE);
    if (argc != ARG_COUNT_ONE) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
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
        HILOGE("Failed to create async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        return promise;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        HILOGE("Failed to queue async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        return promise;
    }

    napi_threadsafe_function tsfn;
    if (CreateConnectThreadsafeFunction(env, nullptr, &tsfn) != napi_ok) {
        HILOGE("Failed to create connect function.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        return promise;
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
    HILOGI("called.");
    AsyncConnectCallbackInfo* asyncData = static_cast<AsyncConnectCallbackInfo*>(data);
    napi_value connectResultObj;
    napi_create_object(env, &connectResultObj);

    napi_value isConnected;
    napi_get_boolean(env, asyncData->result.isConnected, &isConnected);
    napi_set_named_property(env, connectResultObj, "isConnected", isConnected);

    if (!asyncData->result.isConnected && !asyncData->result.reason.empty()) {
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
    AbilityConnectionManager::ConnectCallback connectCallback = [asyncData](ConnectResult result) {
        asyncData->result = result;
        napi_threadsafe_function tsfn = asyncData->tsfn;
        if (tsfn == nullptr) {
            HILOGE("tsfn is nullptr");
        }
        napi_status status = napi_call_threadsafe_function(tsfn, asyncData, napi_tsfn_nonblocking);
        if (status != napi_ok) {
            HILOGE("Failed to create async work. status is %{public}d", static_cast<int32_t>(status));
        }
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
    GET_PARAMS(env, info, ARG_COUNT_ONE);
    if (argc != ARG_COUNT_ONE) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        return nullptr;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().DisconnectSession(sessionId);
    if (ret != ERR_OK) {
        HILOGE("disconnect session failed!");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
    }
    return nullptr;
}

void JsAbilityConnectionManager::CompleteAsyncWork(napi_env env, napi_status status, void* data)
{
    HILOGD("called.");
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    if (asyncData->result == ERR_OK) {
        napi_value result;
        napi_get_undefined(env, &result);
        napi_resolve_deferred(env, asyncData->deferred, result);
    } else {
        napi_reject_deferred(env, asyncData->deferred,
            CreateBusinessError(env, asyncData->result, false));
    }
    napi_delete_async_work(env, asyncData->asyncWork);
    delete asyncData;
}

napi_value JsAbilityConnectionManager::AcceptConnect(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (argc != ARG_COUNT_TWO) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
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
        HILOGE("Failed to create async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        return promise;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        HILOGE("Failed to queue async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        return promise;
    }
    return promise;
}

void JsAbilityConnectionManager::ExecuteAcceptConnect(napi_env env, void *data)
{
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    asyncData->result = AbilityConnectionManager::GetInstance().AcceptConnect(asyncData->sessionId, asyncData->token);
}

napi_value JsAbilityConnectionManager::Reject(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (argc != ARG_COUNT_TWO) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
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

    int32_t ret = AbilityConnectionManager::GetInstance().Reject(token, reason);
    if (ret != ERR_OK) {
        HILOGE("Reject session failed!");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
    }
    return nullptr;
}

napi_value JsAbilityConnectionManager::SendMessage(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (argc != ARG_COUNT_TWO) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return promise;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return promise;
    }

    std::string msg;
    if (!JsToString(env, argv[ARG_INDEX_ONE], "msg", msg)) {
        HILOGE("Failed to unwrap msg.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return promise;
    }

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
        HILOGE("Failed to create async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        return promise;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        HILOGE("Failed to queue async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        return promise;
    }

    return promise;
}

void JsAbilityConnectionManager::ExecuteSendMessage(napi_env env, void *data)
{
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    asyncData->result = AbilityConnectionManager::GetInstance().SendMessage(asyncData->sessionId, asyncData->msg);
}

napi_value JsAbilityConnectionManager::SendData(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        CreateBusinessError(env, ERR_IS_NOT_SYSTEM_APP);
    }

    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (argc != ARG_COUNT_TWO) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return promise;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return promise;
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

    AsyncCallbackInfo* asyncCallbackInfo = new AsyncCallbackInfo();
    asyncCallbackInfo->deferred = deferred;
    asyncCallbackInfo->sessionId = sessionId;
    asyncCallbackInfo->buffer = buffer;
    CreateSendDataAsyncWork(env, asyncCallbackInfo);
    return promise;
}

void JsAbilityConnectionManager::CreateSendDataAsyncWork(napi_env env, AsyncCallbackInfo* asyncCallbackInfo)
{
    napi_value asyncResourceName;
    napi_create_string_utf8(env, "sendDataAsync", NAPI_AUTO_LENGTH, &asyncResourceName);

    napi_status status = napi_create_async_work(
        env, nullptr, asyncResourceName, ExecuteSendData, CompleteAsyncWork,
        static_cast<void *>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        HILOGE("Failed to create async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        delete asyncCallbackInfo;
        return;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        HILOGE("Failed to queue async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        delete asyncCallbackInfo;
        return;
    }
}

void JsAbilityConnectionManager::ExecuteSendData(napi_env env, void *data)
{
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    asyncData->result = AbilityConnectionManager::GetInstance().SendData(asyncData->sessionId, asyncData->buffer);
}

napi_value JsAbilityConnectionManager::SendImage(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        CreateBusinessError(env, ERR_IS_NOT_SYSTEM_APP);
    }

    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (argc != ARG_COUNT_TWO) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return promise;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("Failed to unwrap sessionId.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return promise;
    }

    AsyncCallbackInfo* asyncCallbackInfo = new AsyncCallbackInfo();
    asyncCallbackInfo->deferred = deferred;
    asyncCallbackInfo->sessionId = sessionId;
    asyncCallbackInfo->image = Media::PixelMapNapi::GetPixelMap(env, argv[ARG_INDEX_ONE]);

    napi_value asyncResourceName;
    NAPI_CALL(env, napi_create_string_utf8(env, "sendImageAsync", NAPI_AUTO_LENGTH, &asyncResourceName));

    napi_status status = napi_create_async_work(
        env, nullptr, asyncResourceName, ExecuteSendImage, CompleteAsyncWork,
        static_cast<void *>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        HILOGE("Failed to create async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        return promise;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        HILOGE("Failed to queue async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        return promise;
    }

    return promise;
}

void JsAbilityConnectionManager::ExecuteSendImage(napi_env env, void *data)
{
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    asyncData->result = AbilityConnectionManager::GetInstance().SendImage(asyncData->sessionId, asyncData->image);
}

napi_value JsAbilityConnectionManager::CreateStream(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        CreateBusinessError(env, ERR_IS_NOT_SYSTEM_APP);
    }

    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (argc != ARG_COUNT_TWO) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return promise;
    }

    int32_t sessionId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return promise;
    }

    HILOGI("StreamParam.");
    StreamParams streamParam;
    if (!JsToStreamParam(env, argv[ARG_INDEX_ONE], streamParam)) {
        HILOGE("Failed to unwrap streamParam.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return promise;
    }

    AsyncCallbackInfo* asyncCallbackInfo = new AsyncCallbackInfo();
    asyncCallbackInfo->deferred = deferred;
    asyncCallbackInfo->sessionId = sessionId;
    asyncCallbackInfo->streamParam = streamParam;
    CreateStreamAsyncWork(env, asyncCallbackInfo);

    return promise;
}

void JsAbilityConnectionManager::CreateStreamAsyncWork(napi_env env, AsyncCallbackInfo* asyncCallbackInfo)
{
    napi_value asyncResourceName;
    napi_create_string_utf8(env, "createStreamAsync", NAPI_AUTO_LENGTH, &asyncResourceName);

    napi_status status = napi_create_async_work(
        env, nullptr, asyncResourceName, ExecuteCreateStream, CompleteAsyncCreateStreamWork,
        static_cast<void *>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        HILOGE("Failed to create async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        delete asyncCallbackInfo;
        return;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        HILOGE("Failed to queue async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        delete asyncCallbackInfo;
        return;
    }
}

bool JsAbilityConnectionManager::JsToStreamParam(const napi_env &env, const napi_value &jsValue,
    StreamParams &streamParam)
{
    napi_valuetype argvType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, jsValue, &argvType), false);
    if (argvType != napi_object) {
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

    asyncData->result = AbilityConnectionManager::GetInstance().CreateStream(asyncData->sessionId,
        asyncData->streamParam, asyncData->streamId);
}

void JsAbilityConnectionManager::CompleteAsyncCreateStreamWork(napi_env env, napi_status status, void* data)
{
    HILOGD("called.");
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    if (asyncData->result == ERR_OK) {
        napi_value result;
        napi_create_int32(env, asyncData->streamId, &result);
        napi_resolve_deferred(env, asyncData->deferred, result);
    } else {
        napi_reject_deferred(env, asyncData->deferred,
            CreateBusinessError(env, asyncData->result, false));
    }
    napi_delete_async_work(env, asyncData->asyncWork);
    delete asyncData;
}

napi_value JsAbilityConnectionManager::SetSurfaceId(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        CreateBusinessError(env, ERR_IS_NOT_SYSTEM_APP);
    }

    GET_PARAMS(env, info, ARG_COUNT_THREE);
    if (argc != ARG_COUNT_THREE) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("Parameter parsing failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    std::string surfaceId;
    if (!JsToString(env, argv[ARG_INDEX_ONE], "surfaceId", surfaceId)) {
        HILOGE("surfaceId parsing failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    SurfaceParams surfaceParam;
    if (!JsToSurfaceParam(env, argv[ARG_INDEX_TWO], surfaceParam)) {
        HILOGE("Failed to unwrap surfaceParam.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().SetSurfaceId(streamId,
        surfaceId, surfaceParam);
    if (ret != ERR_OK) {
        HILOGE("SetSurfaceId failed.");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
    }
    return nullptr;
}

bool JsAbilityConnectionManager::JsToSurfaceParam(const napi_env &env, const napi_value &jsValue,
    SurfaceParams &surfaceParam)
{
    napi_valuetype argvType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, jsValue, &argvType), false);
    if (argvType != napi_object) {
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
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        CreateBusinessError(env, ERR_IS_NOT_SYSTEM_APP);
    }

    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (argc != ARG_COUNT_TWO) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("Parameter parsing failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    SurfaceParams surfaceParam;
    if (!JsToSurfaceParam(env, argv[ARG_INDEX_ONE], surfaceParam)) {
        HILOGE("Failed to unwrap surfaceParam.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    std::string surfaceId;
    int32_t ret = AbilityConnectionManager::GetInstance().GetSurfaceId(streamId, surfaceParam, surfaceId);
    if (ret != ERR_OK) {
        HILOGE("SetSurfaceId failed.");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
        return nullptr;
    }

    napi_value result;
    napi_create_string_utf8(env, surfaceId.c_str(), surfaceId.size(), &result);
    return result;
}

napi_value JsAbilityConnectionManager::UpdateSurfaceParam(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        CreateBusinessError(env, ERR_IS_NOT_SYSTEM_APP);
    }

    GET_PARAMS(env, info, ARG_COUNT_THREE);
    if (argc != ARG_COUNT_THREE) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("streamId parsing failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    SurfaceParams surfaceParam;
    if (!JsToSurfaceParam(env, argv[ARG_INDEX_ONE], surfaceParam)) {
        HILOGE("Failed to unwrap surfaceParam.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().UpdateSurfaceParam(streamId, surfaceParam);
    if (ret != ERR_OK) {
        HILOGE("SetSurfaceId failed.");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
    }
    return nullptr;
}

napi_value JsAbilityConnectionManager::DestroyStream(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        CreateBusinessError(env, ERR_IS_NOT_SYSTEM_APP);
    }

    GET_PARAMS(env, info, ARG_COUNT_ONE);
    if (argc != ARG_COUNT_ONE) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("Parameter parsing failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().DestroyStream(streamId);
    if (ret != ERR_OK) {
        HILOGE("DestroyStream failed.");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
    }
    return nullptr;
}

napi_value JsAbilityConnectionManager::StartStream(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        CreateBusinessError(env, ERR_IS_NOT_SYSTEM_APP);
    }

    GET_PARAMS(env, info, ARG_COUNT_ONE);
    if (argc != ARG_COUNT_ONE) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("Parameter parsing failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().StartStream(streamId);
    if (ret != ERR_OK) {
        HILOGE("StartStream failed.");
        CreateBusinessError(env, ret);
    }
    return nullptr;
}

napi_value JsAbilityConnectionManager::StopStream(napi_env env, napi_callback_info info)
{
    HILOGD("called.");
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        CreateBusinessError(env, ERR_IS_NOT_SYSTEM_APP);
    }

    GET_PARAMS(env, info, ARG_COUNT_ONE);
    if (argc != ARG_COUNT_ONE) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t streamId = -1;
    if (!JsToInt32(env, argv[ARG_INDEX_ZERO], "streamId", streamId)) {
        HILOGE("Parameter parsing failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return nullptr;
    }

    int32_t ret = AbilityConnectionManager::GetInstance().StopStream(streamId);
    if (ret != ERR_OK) {
        HILOGE("StopStream failed.");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
    }
    return nullptr;
}

void InitConnectOptionParams(napi_env& env, napi_value& exports)
{
    char propertyName[] = "ConnectOptionParams";
    napi_value startOptionKey = nullptr;
    napi_value startToForeground = nullptr;
    napi_value startTobackground = nullptr;
    napi_create_string_utf8(env, KEY_START_OPTION.c_str(), KEY_START_OPTION.size(), &startOptionKey);
    napi_create_string_utf8(env, VALUE_START_OPTION_FOREGROUND.c_str(),
        VALUE_START_OPTION_FOREGROUND.size(), &startToForeground);
    napi_create_string_utf8(env, VALUE_START_OPTION_BACKGROUND.c_str(),
        VALUE_START_OPTION_BACKGROUND.size(), &startTobackground);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("KEY_START_OPTION", startOptionKey),
        DECLARE_NAPI_STATIC_PROPERTY("VALUE_START_OPTION_FOREGROUND", startToForeground),
        DECLARE_NAPI_STATIC_PROPERTY("VALUE_START_OPTION_BACKGROUND", startTobackground),
    };
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_define_properties(env, obj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_set_named_property(env, exports, propertyName, obj);
}

void InitDisconnectReason(napi_env& env, napi_value& exports)
{
    char propertyName[] = "DisconnectReason";
    napi_value peerAppExit = nullptr;
    napi_value networkDisconnected = nullptr;
    napi_create_int32(env, PEER_APP_EXIT, &peerAppExit);
    napi_create_int32(env, NETWORK_DISCONNECTED, &networkDisconnected);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("PEER_APP_EXIT", peerAppExit),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_DISCONNECTED", networkDisconnected),
    };
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_define_properties(env, obj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_set_named_property(env, exports, propertyName, obj);
}

void InitFlipOption(napi_env& env, napi_value& exports)
{
    char propertyName[] = "FlipOption";
    napi_value horizontal = nullptr;
    napi_value vertical = nullptr;
    napi_create_int32(env, HORIZONTAL, &horizontal);
    napi_create_int32(env, VERTICAL, &vertical);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("HORIZONTAL", horizontal),
        DECLARE_NAPI_STATIC_PROPERTY("VERTICAL", vertical),
    };
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_define_properties(env, obj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_set_named_property(env, exports, propertyName, obj);
}

void InitStreamRole(napi_env& env, napi_value& exports)
{
    char propertyName[] = "StreamRole";
    napi_value source = nullptr;
    napi_value sink = nullptr;
    napi_create_int32(env, SOURCE, &source);
    napi_create_int32(env, SINK, &sink);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("SOURCE", source),
        DECLARE_NAPI_STATIC_PROPERTY("SINK", sink),
    };
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_define_properties(env, obj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_set_named_property(env, exports, propertyName, obj);
}

void InitVideoPixelFormat(napi_env& env, napi_value& exports)
{
    char propertyName[] = "VideoPixelFormat";
    napi_value unknown = nullptr;
    napi_value nv12 = nullptr;
    napi_value nv21 = nullptr;
    napi_create_int32(env, UNKNOWN, &unknown);
    napi_create_int32(env, NV12, &nv12);
    napi_create_int32(env, NV21, &nv21);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("UNKNOWN", unknown),
        DECLARE_NAPI_STATIC_PROPERTY("NV12", nv12),
        DECLARE_NAPI_STATIC_PROPERTY("NV21", nv21),
    };
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_define_properties(env, obj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_set_named_property(env, exports, propertyName, obj);
}

void InitFunction(napi_env env, napi_value exports)
{
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
    napi_define_properties(env, exports, sizeof(desc) / sizeof(desc[0]), desc);
}

napi_value JsAbilityConnectionManagerInit(napi_env env, napi_value exports)
{
    HILOGD("called.");
    if (env == nullptr || exports == nullptr) {
        HILOGE("Invalid input parameters");
        return nullptr;
    }
    InitConnectOptionParams(env, exports);
    InitDisconnectReason(env, exports);
    InitFlipOption(env, exports);
    InitStreamRole(env, exports);
    InitVideoPixelFormat(env, exports);
    InitFunction(env, exports);

    HILOGI("napi_define_properties end");
    return exports;
}
}  // namespace DistributedSchedule
}  // namespace OHOS