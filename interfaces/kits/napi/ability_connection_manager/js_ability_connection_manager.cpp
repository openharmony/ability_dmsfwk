/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

#include "ability_connection_manager.h"
#include "app_event.h"
#include "app_event_processor_mgr.h"
#include "dtbcollabmgr_log.h"
#include "ipc_skeleton.h"
#include "js_runtime_utils.h"
#include "napi_ability_connection_session_listener.h"
#include "napi_common_util.h"
#include "napi_base_context.h"
#include "native_avcapability.h"
#include "native_avcodec_base.h"
#include "native_avformat.h"
#include "native_avcodec_videoencoder.h"
#include "native_avcodec_videodecoder.h"
#include "string_wrapper.h"
#include "tokenid_kit.h"
#include "ui_extension_context.h"

namespace OHOS {
namespace DistributedCollab {
using namespace OHOS::AbilityRuntime;
using namespace OHOS::AppExecFwk;
using namespace OHOS::MediaAVCodec;
using namespace OHOS::HiviewDFX;
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
constexpr int32_t NAPI_BUF_LENGTH = 1024;
constexpr int32_t SOURCE = 0;
constexpr int32_t SINK = 1;
constexpr int32_t UNKNOWN = -1;
constexpr int32_t NV12 = 0;
constexpr int32_t NV21 = 1;
constexpr int32_t IMAGE_COMPRESSION_QUALITY = 30;
constexpr int32_t TRIGGER_COND_TIMEOUT = 90;
constexpr int32_t TRIGGER_COND_ROW = 30;
constexpr int32_t EVENT_RESULT_SUCCESS = 0;
constexpr int32_t EVENT_RESULT_FAIL = 1;

const std::string EVENT_CONNECT = "connect";
const std::string EVENT_DISCONNECT = "disconnect";
const std::string EVENT_RECEIVE_MESSAGE = "receiveMessage";
const std::string EVENT_RECEIVE_DATA = "receiveData";
const std::string EVENT_RECEIVE_IMAGE = "receiveImage";
const std::string EVENT_COLLABORATE = "collaborateEvent";
const std::vector<std::string> REGISTER_EVENT_TYPES = {
    EVENT_CONNECT, EVENT_DISCONNECT, EVENT_RECEIVE_MESSAGE, EVENT_RECEIVE_DATA,
    EVENT_RECEIVE_IMAGE, EVENT_COLLABORATE
};
const std::vector<std::string> SYSTEM_APP_EVENT_TYPES = {
    EVENT_RECEIVE_IMAGE, EVENT_COLLABORATE
};

const std::string ERR_MESSAGE_NO_PERMISSION =
    "Permission verification failed. The application does not have the permission required to call the API.";
const std::string ERR_MESSAGE_INVALID_PARAMS = "Parameter error.";
const std::string ERR_MESSAGE_FAILED = "Failed to execute the function.";
const std::string ERR_MESSAGE_ONE_STREAM = "Only one stream can be created for the current session.";
const std::string ERR_MESSAGE_RECEIVE_NOT_START = "The stream at the receive end is not started.";
const std::string ERR_MESSAGE_NOT_SUPPORTED_BITATE = "Bitrate not supported.";
const std::string ERR_MESSAGE_NOT_SUPPORTED_COLOR_SPACE = "Color space not supported.";
const std::string KEY_START_OPTION = "ohos.collabrate.key.start.option";
const std::string VALUE_START_OPTION_FOREGROUND = "ohos.collabrate.value.forefround";
const std::string VALUE_START_OPTION_BACKGROUND = "ohos.collabrate.value.background";
const std::string COLLABORATE_KEYS_PEER_INFO  = "ohos.collaboration.key.peerInfo";
const std::string COLLABORATE_KEYS_CONNECT_OPTIONS = "ohos.collaboration.key.connectOptions";
const std::string COLLABORATE_KEYS_COLLABORATE_TYPE = "ohos.collaboration.key.abilityCollaborateType";
const std::string ABILITY_COLLABORATION_TYPE_DEFAULT  = "ohos.collaboration.value.abilityCollab";
const std::string ABILITY_COLLABORATION_TYPE_CONNECT_PROXY = "ohos.collaboration.value.connectProxy";
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

    if (valueLen >= NAPI_BUF_LENGTH) {
        HILOGE("string length mast < %{public}d", NAPI_BUF_LENGTH);
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
    static bool isSystemApp = []() {
        uint64_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
        return OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    }();
    return isSystemApp;
}

napi_value GenerateBusinessError(napi_env env,
    int32_t err, const std::string &msg)
{
    napi_value businessError = nullptr;
    NAPI_CALL(env, napi_create_object(env, &businessError));
    napi_value errorCode = nullptr;
    NAPI_CALL(env, napi_create_int32(env, err, &errorCode));
    napi_value errorMsg = nullptr;
    NAPI_CALL(env, napi_create_string_utf8(env, msg.c_str(), NAPI_AUTO_LENGTH, &errorMsg));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "code", errorCode));
    NAPI_CALL(env, napi_set_named_property(env, businessError, "message", errorMsg));

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
        case NOT_SUPPORTED_BITATE:
            error = CreateErrorForCall(env, static_cast<int32_t>(BussinessErrorCode::ERR_BITATE_NOT_SUPPORTED),
                ERR_MESSAGE_NOT_SUPPORTED_BITATE, isAsync);
            break;
        case NOT_SUPPORTED_COLOR_SPACE:
            error = CreateErrorForCall(env, static_cast<int32_t>(BussinessErrorCode::ERR_COLOR_SPACE_NOT_SUPPORTED),
                ERR_MESSAGE_NOT_SUPPORTED_COLOR_SPACE, isAsync);
            break;
        case ERR_EXECUTE_FUNCTION:
            error = CreateErrorForCall(env, static_cast<int32_t>(BussinessErrorCode::ERR_INVALID_PARAMS),
                ERR_MESSAGE_FAILED, isAsync);
            break;
        case COLLAB_PERMISSION_DENIED:
            error = CreateErrorForCall(env, static_cast<int32_t>(BussinessErrorCode::ERR_INVALID_PERMISSION),
                ERR_MESSAGE_NO_PERMISSION, isAsync);
            break;
        case INVALID_PARAMETERS_ERR:
            error = CreateErrorForCall(env, static_cast<int32_t>(BussinessErrorCode::ERR_INVALID_PARAMS),
                ERR_MESSAGE_INVALID_PARAMS, isAsync);
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
    HILOGI("called.");
    GET_PARAMS(env, info, ARG_COUNT_FOUR);
    napi_value result = nullptr;
    if (argc != ARG_COUNT_FOUR) {
        HILOGE("CheckArgsCount failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return result;
    }

    std::string serviceName = "";
    if (!JsToServiceName(env, argv[ARG_INDEX_ZERO], serviceName)) {
        HILOGE("Failed to unwrap service name/id");
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
    if (peerInfo.serverId.empty()) {
        peerInfo.serverId = serviceName;
        peerInfo.serviceName = serviceName;
    }

    ConnectOption connectOption;
    int32_t ret = JSToConnectOption(env, argv[ARG_INDEX_THREE], connectOption);
    if (ret != ERR_OK) {
        HILOGE("Failed to unwrap ConnectOption.");
        CreateBusinessError(env, ret);
        return result;
    }

    return ExecuteCreateSession(serviceName, abilityInfo, peerInfo, connectOption, env);
}

napi_value JsAbilityConnectionManager::ExecuteCreateSession(
    const std::string& serviceName, std::shared_ptr<AbilityInfo>& abilityInfo,
    PeerInfo& peerInfo, ConnectOption& connectOption, const napi_env& env)
{
    napi_value result = nullptr;
    int32_t sessionId = -1;
    int32_t ret = AbilityConnectionManager::GetInstance().CreateSession(
        serviceName, abilityInfo, peerInfo, connectOption, sessionId);
    if (ret == COLLAB_PERMISSION_DENIED || ret == INVALID_PARAMETERS_ERR) {
        HILOGE("create session failed due to param or permission valid");
        CreateBusinessError(env, ret);
        return result;
    } else if (ret != ERR_OK) {
        HILOGE("create session failed due to function err");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
        return result;
    }
    NAPI_CALL(env, napi_create_int32(env, sessionId, &result));
    return result;
}

bool JsAbilityConnectionManager::JsToServiceName(const napi_env &env, const napi_value &jsValue,
    std::string& serviceName)
{
    HILOGI("parse serviceName");
    // no serviceName
    if (!JsToString(env, jsValue, "serviceName", serviceName)) {
        HILOGW("Failed to unwrap serviceName.");
    } else {
        return true;
    }
    // neither exist
    if (!JsToString(env, jsValue, "serverId", serviceName)) {
        HILOGE("Failed to unwrap serverId and serviceName.");
        return false;
    }
    return true;
}

bool JsAbilityConnectionManager::JsToAbilityInfo(const napi_env &env, const napi_value &jsValue,
    std::shared_ptr<AbilityInfo>& abilityInfo)
{
    HILOGI("parse abilityInfo");
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
        if (abilityContext == nullptr) {
            HILOGW("convertTo AbilityContext failed! try convertTo UIExtensionContext");
            auto extensionContext = AbilityRuntime::Context::ConvertTo<AbilityRuntime::UIExtensionContext>(context);
            if (extensionContext == nullptr) {
                HILOGE("convertTo UIExtensionContext failed!");
                return false;
            }
            abilityInfo = extensionContext->GetAbilityInfo();
        } else {
            abilityInfo = abilityContext->GetAbilityInfo();
        }
    }
    return true;
}

bool JsAbilityConnectionManager::JsToPeerInfo(const napi_env &env, const napi_value &jsValue, PeerInfo &peerInfo)
{
    HILOGI("parse PeerInfo");
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

    if (!JsObjectToString(env, jsValue, "serviceName", peerInfo.serverId)) {
        HILOGW("Failed to unwrap serviceName.");
    }
    if (!JsObjectToString(env, jsValue, "serverId", peerInfo.serverId)) {
        HILOGW("Failed to unwrap serverId.");
    }
    peerInfo.serviceName = peerInfo.serverId;
    return true;
}

int32_t JsAbilityConnectionManager::JSToConnectOption(const napi_env &env, const napi_value &jsValue,
    ConnectOption &option)
{
    HILOGI("parse ConnectOption");
    napi_valuetype argvType = napi_undefined;
    NAPI_CALL_BASE(env, napi_typeof(env, jsValue, &argvType), false);
    if (argvType != napi_object) {
        HILOGE("Parameter verification failed.");
        return ERR_INVALID_PARAMETERS;
    }
    if (!JsObjectToBool(env, jsValue, "needSendData", option.needSendData)) {
        HILOGW("Failed to unwrap needSendData.");
    }
    if (!JsObjectToBool(env, jsValue, "needSendStream", option.needSendStream)) {
        HILOGW("Failed to unwrap needSendStream.");
    }

    if (!JsObjectToBool(env, jsValue, "needReceiveStream", option.needReceiveStream)) {
        HILOGW("Failed to unwrap needSendStream.");
    }
    // check start option/options
    napi_value startOptionsVal;
    if (napi_get_named_property(env, jsValue, "startOptions", &startOptionsVal) == napi_ok) {
        UnwrapStartOptions(env, startOptionsVal, option);
    }
    napi_value optionsVal;
    if (napi_get_named_property(env, jsValue, "options", &optionsVal) == napi_ok) {
        UnwrapOptions(env, optionsVal, option);
    }
    // set default
    if (option.options.IsEmpty()) {
        option.options.SetParam(KEY_START_OPTION, AAFwk::String::Box(VALUE_START_OPTION_FOREGROUND));
    }

    napi_value parametersVal;
    if (napi_get_named_property(env, jsValue, "parameters", &parametersVal) == napi_ok) {
        UnwrapParameters(env, parametersVal, option);
    }
    
    return CheckConnectOption(option);
}

bool JsAbilityConnectionManager::UnwrapStartOptions(napi_env env, napi_value startOptionsVal,
    ConnectOption &connectOption)
{
    HILOGI("unwrap StartOptions");
    if (startOptionsVal == nullptr) {
        HILOGE("start options is nullptr");
        return false;
    }
    napi_valuetype argvType = napi_undefined;
    if (napi_typeof(env, startOptionsVal, &argvType) != napi_ok) {
        return false;
    }
    if (argvType != napi_number) {
        HILOGW("start options verification failed.");
        return false;
    }
    int32_t startOption = 0;
    napi_get_value_int32(env, startOptionsVal, &startOption);
    if (startOption < static_cast<int32_t>(StartOptionParams::START_IN_FOREGROUND) ||
            startOption > static_cast<int32_t>(StartOptionParams::START_IN_BACKGROUND)) {
            HILOGE("invalid start option");
            return false;
    }
    if (startOption == static_cast<int32_t>(StartOptionParams::START_IN_FOREGROUND)) {
        connectOption.options.SetParam(KEY_START_OPTION, AAFwk::String::Box(VALUE_START_OPTION_FOREGROUND));
    } else if (startOption == static_cast<int32_t>(StartOptionParams::START_IN_BACKGROUND)) {
        connectOption.options.SetParam(KEY_START_OPTION, AAFwk::String::Box(VALUE_START_OPTION_BACKGROUND));
    } else {
        HILOGE("Invalid startOptions value.");
        return false;
    }
    return true;
}

bool JsAbilityConnectionManager::UnwrapOptions(napi_env env, napi_value options, ConnectOption &connectOption)
{
    HILOGI("unwrap Options");
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

int32_t JsAbilityConnectionManager::CheckConnectOption(const ConnectOption &connectOption)
{
    // check background
    if (connectOption.options.GetStringParam(KEY_START_OPTION) == VALUE_START_OPTION_BACKGROUND &&
            !IsSystemApp()) {
            HILOGE("normal app background denied");
            return ERR_IS_NOT_SYSTEM_APP;
    }
    if (connectOption.needSendStream && !IsSystemApp()) {
        HILOGE("normal app stream denied");
        return ERR_IS_NOT_SYSTEM_APP;
    }
    if (connectOption.needReceiveStream && !IsSystemApp()) {
        HILOGE("normal app stream denied");
        return ERR_IS_NOT_SYSTEM_APP;
    }
    return ERR_OK;
}

bool JsAbilityConnectionManager::UnwrapParameters(napi_env env, napi_value parameters, ConnectOption &option)
{
    HILOGI("Unwrap Parameters");
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
    HILOGI("called.");
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
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return result;
    }

    PeerInfo peerInfo;
    int32_t ret = AbilityConnectionManager::GetInstance().getPeerInfoBySessionId(sessionId, peerInfo);
    if (ret != ERR_OK) {
        HILOGE("get peerInfo failed!");
        napi_value undefinedValue;
        napi_get_undefined(env, &undefinedValue);
        return undefinedValue;
    }

    return WrapPeerInfo(env, peerInfo);
}

napi_value JsAbilityConnectionManager::WrapPeerInfo(napi_env& env,
    const PeerInfo& peerInfo)
{
    napi_value peerInfoObj;
    napi_create_object(env, &peerInfoObj);

    // empty peerInfo return undefined
    if (peerInfo.deviceId.empty()) {
        napi_value undefinedValue;
        napi_get_undefined(env, &undefinedValue);
        return undefinedValue;
    }

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

    napi_value serviceName;
    napi_create_string_utf8(env, peerInfo.serverId.c_str(), NAPI_AUTO_LENGTH, &serviceName);
    napi_set_named_property(env, peerInfoObj, "serviceName", serviceName);

    return peerInfoObj;
}

int32_t JsAbilityConnectionManager::CheckEventType(const std::string& eventType)
{
    bool isExist = (std::find(REGISTER_EVENT_TYPES.begin(),
        REGISTER_EVENT_TYPES.end(), eventType) != REGISTER_EVENT_TYPES.end());
    if (!isExist) {
        HILOGE("invalid event type not exist: %{public}s", eventType.c_str());
        return ERR_INVALID_PARAMETERS;
    }

    bool isCallSystemApi = (std::find(SYSTEM_APP_EVENT_TYPES.begin(),
        SYSTEM_APP_EVENT_TYPES.end(), eventType) != SYSTEM_APP_EVENT_TYPES.end());
    if (isCallSystemApi && !IsSystemApp()) {
        HILOGE("event type %{public}s only allow system app", eventType.c_str());
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

    std::shared_ptr<NapiAbilityConnectionSessionListener> listener =
        std::make_shared<NapiAbilityConnectionSessionListener>(env);

    listener->SetCallback(listenerObj);
    ret = AbilityConnectionManager::GetInstance().RegisterEventCallback(
        sessionId, eventType, listener);
    if (ret != ERR_OK) {
        HILOGE("Register event callback failed!");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
    }
    return nullptr;
}

napi_value JsAbilityConnectionManager::UnregisterAbilityConnectionSessionCallback(napi_env env,
    napi_callback_info info)
{
    HILOGD("called.");
    GET_PARAMS(env, info, ARG_COUNT_THREE);
    if (argc < ARG_COUNT_TWO || argc > ARG_COUNT_THREE) {
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

static int64_t AddProcessor()
{
    HiAppEvent::ReportConfig config;
    config.name = "ha_app_event";
    config.appId = "com_hmos_sdk_ocg";
    config.routeInfo = "AUTO";
    config.triggerCond.timeout = TRIGGER_COND_TIMEOUT;
    config.triggerCond.row = TRIGGER_COND_ROW;
    config.eventConfigs.clear();
    {
        HiAppEvent::EventConfig event1;
        event1.domain = "api_diagnostic";
        event1.name = "api_exec_end";
        event1.isRealTime = false;
        config.eventConfigs.push_back(event1);
    }
    {
        HiAppEvent::EventConfig event2;
        event2.domain = "api_diagnostic";
        event2.name = "api_called_stat";
        event2.isRealTime = true;
        config.eventConfigs.push_back(event2);
    }
    {
        HiAppEvent::EventConfig event3;
        event3.domain = "api_diagnostic";
        event3.name = "api_called_stat_cnt";
        event3.isRealTime = true;
        config.eventConfigs.push_back(event3);
    }
    return HiAppEvent::AppEventProcessorMgr::AddProcessor(config);
}

static void WriteEndEvent(const std::string& transId, const int result, const int errCode, const time_t beginTime,
    int64_t processorId)
{
    HiAppEvent::Event event("api_diagnostic", "api_exec_end", HiAppEvent::BEHAVIOR);
    event.AddParam("transId", transId);
    event.AddParam("result", result);
    event.AddParam("error_code", errCode);
    event.AddParam("api_name", std::string("connect"));
    event.AddParam("sdk_name", std::string("DistributedServiceKit"));
    event.AddParam("begin_time", beginTime);
    event.AddParam("end_time", time(nullptr));
    if (processorId > 0) {
        Write(event);
    }
}

napi_value JsAbilityConnectionManager::Connect(napi_env env, napi_callback_info info)
{
    HILOGI("called.");
    int64_t processorId = -1;
    processorId = AddProcessor();
    if (processorId <= 0) {
        HILOGE("Add processor fail.Error code is %{public}lld", processorId);
    }
    time_t beginTime = time(nullptr);
    std::string transId = std::string("transId_") + std::to_string(std::rand());
    int32_t sessionId = -1;
    GET_PARAMS(env, info, ARG_COUNT_ONE);
    if (argc != ARG_COUNT_ONE || !JsToInt32(env, argv[ARG_INDEX_ZERO], "sessionId", sessionId)) {
        HILOGE("CheckArgsCount failed or Failed to unwrap sessionId.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        WriteEndEvent(transId, EVENT_RESULT_FAIL, ERR_INVALID_PARAMETERS, beginTime, processorId);
        return nullptr;
    }
    return ConnectInner(env, sessionId, transId, beginTime, processorId);
}

napi_value JsAbilityConnectionManager::ConnectInner(
    napi_env env, int32_t sessionId, const std::string &transId, time_t beginTime, int64_t processorId)
{
    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    AsyncConnectCallbackInfo* asyncCallbackInfo = new AsyncConnectCallbackInfo();
    asyncCallbackInfo->deferred = deferred;
    asyncCallbackInfo->sessionId = sessionId;

    napi_threadsafe_function tsfn;
    if (CreateConnectThreadsafeFunction(env, nullptr, &tsfn) != napi_ok || tsfn == nullptr) {
        HILOGE("Failed to create connect function.");
        delete asyncCallbackInfo;
        napi_release_threadsafe_function(tsfn, napi_tsfn_release);
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        WriteEndEvent(transId, EVENT_RESULT_FAIL, ERR_EXECUTE_FUNCTION, beginTime, processorId);
        return promise;
    }
    asyncCallbackInfo->tsfn = tsfn;

    napi_value asyncResourceName;
    NAPI_CALL(env, napi_create_string_utf8(env, "connectAsync", NAPI_AUTO_LENGTH, &asyncResourceName));

    napi_status status = napi_create_async_work(
        env, nullptr, asyncResourceName, ExecuteConnect, CompleteAsyncConnectWork,
        static_cast<void *>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        HILOGE("Failed to create async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_release_threadsafe_function(tsfn, napi_tsfn_release);
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        WriteEndEvent(transId, EVENT_RESULT_FAIL, ERR_EXECUTE_FUNCTION, beginTime, processorId);
        return promise;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        HILOGE("Failed to queue async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        delete asyncCallbackInfo;
        napi_release_threadsafe_function(tsfn, napi_tsfn_release);
        napi_reject_deferred(env, deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        WriteEndEvent(transId, EVENT_RESULT_FAIL, ERR_EXECUTE_FUNCTION, beginTime, processorId);
        return promise;
    }

    WriteEndEvent(transId, EVENT_RESULT_SUCCESS, EVENT_RESULT_SUCCESS, beginTime, processorId);
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
    HILOGI("called real connect callback.");
    if (data == nullptr) {
        HILOGE("Async data is null");
        return;
    }

    AsyncConnectCallbackInfo* asyncData = static_cast<AsyncConnectCallbackInfo*>(data);
    napi_deferred deferred = asyncData->deferred;
    napi_threadsafe_function tsfn = asyncData->tsfn;
    ConnectResult result = asyncData->result;
    // reset
    asyncData->deferred = nullptr;
    asyncData->tsfn = nullptr;

    if (!result.isConnected && result.errorCode == ConnectErrorCode::INVALID_SESSION_ID) {
        napi_status ret = napi_reject_deferred(env, deferred,
            CreateBusinessError(env, ERR_INVALID_PARAMETERS, false));
        if (ret != napi_ok) {
            HILOGE("Failed to throw error. status is %{public}d", static_cast<int32_t>(ret));
        }
        CleanupConnectionResources(env, asyncData, tsfn);
        return;
    }

    napi_value connectResultObj;
    napi_create_object(env, &connectResultObj);

    napi_value isConnected;
    napi_get_boolean(env, result.isConnected, &isConnected);
    napi_set_named_property(env, connectResultObj, "isConnected", isConnected);

    napi_value reason;
    napi_create_string_utf8(env, result.reason.c_str(), NAPI_AUTO_LENGTH, &reason);
    napi_set_named_property(env, connectResultObj, "reason", reason);

    if (!result.isConnected) {
        napi_value errorCode;
        napi_create_int32(env, static_cast<int32_t>(result.errorCode), &errorCode);
        napi_set_named_property(env, connectResultObj, "errorCode", errorCode);
    }
    napi_resolve_deferred(env, deferred, connectResultObj);
    HILOGI("resolve defer");
    AbilityConnectionManager::GetInstance().FinishSessionConnect(result.sessionId);
    CleanupConnectionResources(env, asyncData, tsfn);
}

void JsAbilityConnectionManager::CleanupConnectionResources(napi_env env, AsyncConnectCallbackInfo* asyncData,
    napi_threadsafe_function tsfn)
{
    HILOGI("called.");
    if (env == nullptr) {
        HILOGE("env is nullptr");
        return;
    }
    if (tsfn != nullptr) {
        napi_release_threadsafe_function(tsfn, napi_tsfn_release);
        HILOGI("release tsfn");
    }
    asyncData->connectCallbackExecuted = true;
    // The later of ConnectThreadsafeFunctionCallback/CompleteAsyncConnectWork frees asyncData
    if (asyncData->completeAsyncworkExecuted) {
        delete asyncData;
        HILOGI("release async data");
    }
}

void JsAbilityConnectionManager::ExecuteConnect(napi_env env, void *data)
{
    HILOGI("called.");
    AsyncConnectCallbackInfo* asyncData = static_cast<AsyncConnectCallbackInfo*>(data);
    if (asyncData == nullptr) {
        HILOGE("asyncData is nullptr");
        return;
    }
    AbilityConnectionManager::ConnectCallback connectCallback = [env, asyncData](ConnectResult result) mutable {
        HILOGI("called.");
        if (asyncData == nullptr || env == nullptr) {
            HILOGE("asyncData or env is nullptr");
            return;
        }
        asyncData->result = result;
        napi_threadsafe_function tsfn = asyncData->tsfn;
        if (tsfn == nullptr) {
            HILOGE("tsfn is nullptr");
            return;
        }
        napi_status status = napi_call_threadsafe_function(tsfn, asyncData, napi_tsfn_nonblocking);
        if (status != napi_ok) {
            HILOGE("Failed to create async work. status is %{public}d", static_cast<int32_t>(status));
        }
        HILOGI("clear asyncData to prevent secondary calls.");
        asyncData = nullptr;
    };
    AbilityConnectionManager::GetInstance().ConnectSession(asyncData->sessionId, connectCallback);
}

void JsAbilityConnectionManager::CompleteAsyncConnectWork(napi_env env, napi_status status, void* data)
{
    HILOGI("called.");
    if (data == nullptr) {
        HILOGE("Async data is null");
        return;
    }

    AsyncConnectCallbackInfo* asyncData = static_cast<AsyncConnectCallbackInfo*>(data);
    napi_async_work asyncWork = asyncData->asyncWork;
    // reset
    asyncData->asyncWork = nullptr;
    if (asyncWork != nullptr) {
        napi_delete_async_work(env, asyncWork);
        HILOGI("release asyncWork");
    }
    asyncData->completeAsyncworkExecuted = true;
    // The later of ConnectThreadsafeFunctionCallback/CompleteAsyncConnectWork frees asyncData
    if (asyncData->connectCallbackExecuted) {
        delete asyncData;
        HILOGI("release async data");
    }
}

napi_value JsAbilityConnectionManager::DisConnect(napi_env env, napi_callback_info info)
{
    HILOGI("called.");
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

    int32_t ret = AbilityConnectionManager::GetInstance().DisconnectSession(sessionId);
    if (ret != ERR_OK) {
        HILOGE("disconnect session failed!");
        CreateBusinessError(env, ERR_EXECUTE_FUNCTION);
    }
    return nullptr;
}

void JsAbilityConnectionManager::CompleteAsyncWork(napi_env env, napi_status status, void* data)
{
    HILOGI("called.");
    if (data == nullptr) {
        HILOGE("Async data is null");
        return;
    }

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
    HILOGI("called.");
    GET_PARAMS(env, info, ARG_COUNT_TWO);
    if (argc != ARG_COUNT_TWO) {
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
    HILOGI("called.");
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    asyncData->result = AbilityConnectionManager::GetInstance().AcceptConnect(asyncData->sessionId, asyncData->token);
}

napi_value JsAbilityConnectionManager::Reject(napi_env env, napi_callback_info info)
{
    HILOGI("called.");
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
    HILOGI("called.");
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

    HILOGI("start send message.");
    int32_t ret = AbilityConnectionManager::GetInstance().SendMessage(sessionId, msg);
    HILOGI("notify sendMessage event.");
    if (ret == ERR_OK) {
        napi_value result;
        napi_get_undefined(env, &result);
        napi_resolve_deferred(env, deferred, result);
    } else {
        napi_reject_deferred(env, deferred,
            CreateBusinessError(env, ret, false));
    }

    HILOGI("end.");
    return promise;
}

void JsAbilityConnectionManager::ExecuteSendMessage(napi_env env, void *data)
{
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    asyncData->result = AbilityConnectionManager::GetInstance().SendMessage(asyncData->sessionId, asyncData->msg);
}

napi_value JsAbilityConnectionManager::SendData(napi_env env, napi_callback_info info)
{
    HILOGI("called.");
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
    if (asyncCallbackInfo == nullptr) {
        return;
    }
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
    HILOGI("called.");
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        CreateBusinessError(env, ERR_IS_NOT_SYSTEM_APP);
    }

    napi_deferred deferred;
    napi_value promise = nullptr;
    NAPI_CALL(env, napi_create_promise(env, &deferred, &promise));

    GET_PARAMS(env, info, ARG_COUNT_THREE);
    if (argc < ARG_COUNT_TWO || argc > ARG_COUNT_THREE) {
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

    int32_t quality = IMAGE_COMPRESSION_QUALITY;
    if (argc == ARG_COUNT_THREE) {
        if (!JsToInt32(env, argv[ARG_INDEX_TWO], "quality", quality)) {
            HILOGE("Failed to unwrap quality.");
            CreateBusinessError(env, ERR_INVALID_PARAMETERS);
            return promise;
        }
    }

    AsyncCallbackInfo* asyncCallbackInfo = new AsyncCallbackInfo();
    asyncCallbackInfo->deferred = deferred;
    asyncCallbackInfo->sessionId = sessionId;
    asyncCallbackInfo->image = Media::PixelMapNapi::GetPixelMap(env, argv[ARG_INDEX_ONE]);
    if (!asyncCallbackInfo->image) {
        HILOGE("Failed to unwrap image.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        delete asyncCallbackInfo;
        return promise;
    }
    asyncCallbackInfo->imageQuality = quality;
    return CreateSendImageAsyncWork(env, asyncCallbackInfo);
}

napi_value JsAbilityConnectionManager::CreateSendImageAsyncWork(napi_env env, AsyncCallbackInfo* asyncCallbackInfo)
{
    napi_value promise = nullptr;
    if (asyncCallbackInfo == nullptr) {
        return promise;
    }
    napi_value asyncResourceName;
    NAPI_CALL(env, napi_create_string_utf8(env, "sendImageAsync", NAPI_AUTO_LENGTH, &asyncResourceName));

    napi_status status = napi_create_async_work(
        env, nullptr, asyncResourceName, ExecuteSendImage, CompleteAsyncWork,
        static_cast<void *>(asyncCallbackInfo), &asyncCallbackInfo->asyncWork);
    if (status != napi_ok) {
        HILOGE("Failed to create async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        delete asyncCallbackInfo;
        return promise;
    }

    if (napi_queue_async_work(env, asyncCallbackInfo->asyncWork) != napi_ok) {
        HILOGE("Failed to queue async work.");
        napi_delete_async_work(env, asyncCallbackInfo->asyncWork);
        napi_reject_deferred(env, asyncCallbackInfo->deferred, CreateBusinessError(env, ERR_EXECUTE_FUNCTION, false));
        delete asyncCallbackInfo;
        return promise;
    }

    return promise;
}

void JsAbilityConnectionManager::ExecuteSendImage(napi_env env, void *data)
{
    AsyncCallbackInfo* asyncData = static_cast<AsyncCallbackInfo*>(data);
    asyncData->result = AbilityConnectionManager::GetInstance().SendImage(asyncData->sessionId,
        asyncData->image, asyncData->imageQuality);
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
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return false;
    }

    if (!JsObjectToString(env, jsValue, "name", streamParam.name)) {
        HILOGE("name parameter parsing failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return false;
    }

    int32_t role = -1;
    if (!JsObjectToInt(env, jsValue, "role", role)) {
        HILOGE("role verification failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return false;
    }

    if (role < static_cast<int32_t>(StreamRole::SOURCE) ||
        role > static_cast<int32_t>(StreamRole::SINK)) {
        HILOGE("Invalid role value: %{public}d", role);
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return false;
    }
    streamParam.role = static_cast<StreamRole>(role);
    if (!GetStreamParamBitrate(env, jsValue, streamParam)) {
        return false;
    }
    if (!UnwrapColorSpace(env, jsValue, streamParam)) {
        return false;
    }
    return true;
}

bool JsAbilityConnectionManager::GetStreamParamBitrate(const napi_env &env, const napi_value &jsValue,
    StreamParams &streamParam)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, jsValue, "bitrate", &hasProperty) != napi_ok || !hasProperty) {
        HILOGW("no bitrate propertys");
        return true;
    }

    int32_t bitrate = -1;
    if (!JsObjectToInt(env, jsValue, "bitrate", bitrate)) {
        HILOGE("bitrate verification failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return false;
    }

    if (!IsVaildBitrate(bitrate)) {
        HILOGE("not support bitrate: %{public}d.", bitrate);
        CreateBusinessError(env, NOT_SUPPORTED_BITATE);
        return false;
    }
    HILOGI("bitrate is %{public}d.", bitrate);
    streamParam.bitrate = bitrate;
    return true;
}

bool JsAbilityConnectionManager::IsVaildBitrate(int32_t bitrate)
{
    OH_BitrateMode bitrateMode = BITRATE_MODE_CBR;
    OH_AVCapability *capability = OH_AVCodec_GetCapability(OH_AVCODEC_MIMETYPE_VIDEO_AVC, true);
    if (capability == nullptr) {
        HILOGE("GetCapability failed, it's nullptr");
        return false;
    }
    bool isSupported = OH_AVCapability_IsEncoderBitrateModeSupported(capability, bitrateMode);
    if (!isSupported) {
        HILOGE("BITRATE_MODE_CBR is not support.");
        return false;
    }
    OH_AVRange bitrateRange = {-1, -1};
    int32_t ret = OH_AVCapability_GetEncoderBitrateRange(capability, &bitrateRange);
    if (ret != AV_ERR_OK || bitrateRange.maxVal <= 0) {
        HILOGE("bitrate range query failed. ret: %{public}d; maxVal: %{public}d;", ret, bitrateRange.maxVal);
        return false;
    }
    if (bitrate < bitrateRange.minVal || bitrate > bitrateRange.maxVal) {
        HILOGE("Bitrate is not supported, it should be between %{public}d and %{public}d", bitrateRange.minVal,
            bitrateRange.maxVal);
        return false;
    }
    return true;
}

bool JsAbilityConnectionManager::UnwrapColorSpace(const napi_env &env, const napi_value &jsValue,
    StreamParams &streamParam)
{
    bool hasProperty = false;
    if (napi_has_named_property(env, jsValue, "colorSpaceConversionTarget", &hasProperty) != napi_ok || !hasProperty) {
        HILOGW("no colorSpaceConversionTarget propertys");
        return true;
    }

    int32_t colorSpace = -1;
    if (!JsObjectToInt(env, jsValue, "colorSpaceConversionTarget", colorSpace)) {
        HILOGE("colorSpace verification failed.");
        CreateBusinessError(env, ERR_INVALID_PARAMETERS);
        return false;
    }

    // only BT709_LIMIT is supported
    if (colorSpace != static_cast<int32_t>(ColorSpace::BT709_LIMIT)) {
        HILOGE("colorSpace not BT709_LIMIT.");
        CreateBusinessError(env, NOT_SUPPORTED_COLOR_SPACE);
        return false;
    }
    streamParam.colorSpace = static_cast<ColorSpace>(colorSpace);
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
    HILOGI("called.");
    if (data == nullptr) {
        HILOGE("Async data is null");
        return;
    }

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
    HILOGI("called.");
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
        if (flip < static_cast<int32_t>(FlipOptions::HORIZONTAL) ||
            flip > static_cast<int32_t>(FlipOptions::VERTICAL)) {
            HILOGE("Invalid flip value: %{public}d", flip);
            return false;
        }
        surfaceParam.flip = static_cast<FlipOptions>(flip);
    }

    if (!JsObjectToInt(env, jsValue, "rotation", surfaceParam.rotation)) {
        HILOGW("Unable to get rotation parameter.");
    }
    
    return true;
}

napi_value JsAbilityConnectionManager::GetSurfaceId(napi_env env, napi_callback_info info)
{
    HILOGI("called.");
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
    HILOGI("called.");
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
    HILOGI("called.");
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
    HILOGI("called.");
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
    HILOGI("called.");
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
    napi_value peerAppCloseCollab = nullptr;
    napi_value networkDisconnected = nullptr;
    napi_create_int32(env,
        static_cast<int32_t>(DisconnectReason::PEER_APP_CLOSE_COLLABORATION), &peerAppCloseCollab);
    napi_create_int32(env,
        static_cast<int32_t>(DisconnectReason::PEER_APP_EXIT), &peerAppExit);
    napi_create_int32(env,
        static_cast<int32_t>(DisconnectReason::NETWORK_DISCONNECTED), &networkDisconnected);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("PEER_APP_CLOSE_COLLABORATION", peerAppCloseCollab),
        DECLARE_NAPI_STATIC_PROPERTY("PEER_APP_EXIT", peerAppExit),
        DECLARE_NAPI_STATIC_PROPERTY("NETWORK_DISCONNECTED", networkDisconnected),
    };
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_define_properties(env, obj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_set_named_property(env, exports, propertyName, obj);
}

void InitFlipOptions(napi_env& env, napi_value& exports)
{
    char propertyName[] = "FlipOptions";
    char propertyNameOld[] = "FlipOption";
    napi_value horizontal = nullptr;
    napi_value vertical = nullptr;
    napi_create_int32(env, static_cast<int32_t>(FlipOptions::HORIZONTAL), &horizontal);
    napi_create_int32(env, static_cast<int32_t>(FlipOptions::VERTICAL), &vertical);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("HORIZONTAL", horizontal),
        DECLARE_NAPI_STATIC_PROPERTY("VERTICAL", vertical),
    };
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_define_properties(env, obj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_set_named_property(env, exports, propertyName, obj);
    napi_set_named_property(env, exports, propertyNameOld, obj);
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

void InitStartOptionParams(napi_env& env, napi_value& exports)
{
    char propertyName[] = "StartOptionParams";
    napi_value startInForeground = nullptr;
    napi_value startInBackground = nullptr;
    napi_create_int32(env, static_cast<int32_t>(StartOptionParams::START_IN_FOREGROUND),
        &startInForeground);
    napi_create_int32(env, static_cast<int32_t>(StartOptionParams::START_IN_BACKGROUND),
        &startInBackground);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("START_IN_FOREGROUND", startInForeground),
        DECLARE_NAPI_STATIC_PROPERTY("START_IN_BACKGROUND", startInBackground),
    };
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_define_properties(env, obj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_set_named_property(env, exports, propertyName, obj);
}

void InitCollaborateEventType(napi_env& env, napi_value& exports)
{
    char propertyName[] = "CollaborateEventType";
    napi_value sendFailure = nullptr;
    napi_value colorSpaceConversionFailure = nullptr;
    napi_create_int32(env, static_cast<int32_t>(CollaborateEventType::SEND_FAILURE),
        &sendFailure);
    napi_create_int32(env, static_cast<int32_t>(CollaborateEventType::COLOR_SPACE_CONVERSION_FAILURE),
        &colorSpaceConversionFailure);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("SEND_FAILURE", sendFailure),
        DECLARE_NAPI_STATIC_PROPERTY("COLOR_SPACE_CONVERSION_FAILURE", colorSpaceConversionFailure),
    };
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_define_properties(env, obj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_set_named_property(env, exports, propertyName, obj);
}

void InitConnectErrorCode(napi_env env, napi_value exports)
{
    char propertyName[] = "ConnectErrorCode";
    napi_value connectedSessionExists = nullptr;
    napi_value peerAppRejected = nullptr;
    napi_value localWifiNotOpen = nullptr;
    napi_value peerWifiNotOpen = nullptr;
    napi_value peerAbilityNoOncollaborate = nullptr;
    napi_value systemInternalError = nullptr;

    napi_create_int32(env,
        static_cast<int32_t>(ConnectErrorCode::CONNECTED_SESSION_EXISTS), &connectedSessionExists);
    napi_create_int32(env,
        static_cast<int32_t>(ConnectErrorCode::PEER_APP_REJECTED), &peerAppRejected);
    napi_create_int32(env,
        static_cast<int32_t>(ConnectErrorCode::LOCAL_WIFI_NOT_OPEN), &localWifiNotOpen);
    napi_create_int32(env,
        static_cast<int32_t>(ConnectErrorCode::PEER_WIFI_NOT_OPEN), &peerWifiNotOpen);
    napi_create_int32(env,
        static_cast<int32_t>(ConnectErrorCode::PEER_ABILITY_NO_ONCOLLABORATE), &peerAbilityNoOncollaborate);
    napi_create_int32(env,
        static_cast<int32_t>(ConnectErrorCode::SYSTEM_INTERNAL_ERROR), &systemInternalError);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("CONNECTED_SESSION_EXISTS", connectedSessionExists),
        DECLARE_NAPI_STATIC_PROPERTY("PEER_APP_REJECTED", peerAppRejected),
        DECLARE_NAPI_STATIC_PROPERTY("LOCAL_WIFI_NOT_OPEN", localWifiNotOpen),
        DECLARE_NAPI_STATIC_PROPERTY("PEER_WIFI_NOT_OPEN", peerWifiNotOpen),
        DECLARE_NAPI_STATIC_PROPERTY("PEER_ABILITY_NO_ONCOLLABORATE", peerAbilityNoOncollaborate),
        DECLARE_NAPI_STATIC_PROPERTY("SYSTEM_INTERNAL_ERROR", systemInternalError),
    };

    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_define_properties(env, obj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_set_named_property(env, exports, propertyName, obj);
}

void InitCollaborationKeys(napi_env& env, napi_value& exports)
{
    char propertyName[] = "CollaborationKeys";
    napi_value peerInfo = nullptr;
    napi_value connectOptions = nullptr;
    napi_value collaborateType = nullptr;

    napi_create_string_utf8(env, COLLABORATE_KEYS_PEER_INFO.c_str(),
        COLLABORATE_KEYS_PEER_INFO.size(), &peerInfo);
    napi_create_string_utf8(env, COLLABORATE_KEYS_CONNECT_OPTIONS.c_str(),
        COLLABORATE_KEYS_CONNECT_OPTIONS.size(), &connectOptions);
    napi_create_string_utf8(env, COLLABORATE_KEYS_COLLABORATE_TYPE.c_str(),
        COLLABORATE_KEYS_COLLABORATE_TYPE.size(), &collaborateType);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("PEER_INFO", peerInfo),
        DECLARE_NAPI_STATIC_PROPERTY("CONNECT_OPTIONS", connectOptions),
        DECLARE_NAPI_STATIC_PROPERTY("COLLABORATE_TYPE", collaborateType),
    };
    napi_value obj = nullptr;
    napi_create_object(env, &obj);
    napi_define_properties(env, obj, sizeof(desc) / sizeof(desc[0]), desc);
    napi_set_named_property(env, exports, propertyName, obj);
}

void InitCollaborationValues(napi_env& env, napi_value& exports)
{
    char propertyName[] = "CollaborationValues";
    napi_value abilityCollab = nullptr;
    napi_value connectProxy = nullptr;

    napi_create_string_utf8(env, ABILITY_COLLABORATION_TYPE_DEFAULT.c_str(),
        ABILITY_COLLABORATION_TYPE_DEFAULT.size(), &abilityCollab);
    napi_create_string_utf8(env, ABILITY_COLLABORATION_TYPE_CONNECT_PROXY.c_str(),
        ABILITY_COLLABORATION_TYPE_CONNECT_PROXY.size(), &connectProxy);

    napi_property_descriptor desc[] = {
        DECLARE_NAPI_STATIC_PROPERTY("ABILITY_COLLABORATION_TYPE_DEFAULT", abilityCollab),
        DECLARE_NAPI_STATIC_PROPERTY("ABILITY_COLLABORATION_TYPE_CONNECT_PROXY", connectProxy),
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
    InitFlipOptions(env, exports);
    InitStreamRole(env, exports);
    InitVideoPixelFormat(env, exports);
    InitStartOptionParams(env, exports);
    InitCollaborateEventType(env, exports);
    InitConnectErrorCode(env, exports);
    InitCollaborationKeys(env, exports);
    InitCollaborationValues(env, exports);
    InitFunction(env, exports);

    HILOGI("napi_define_properties end");
    return exports;
}
}  // namespace DistributedCollab
}  // namespace OHOS