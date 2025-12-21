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

#include "dmsfwk_taihe_utils.h"

#include "ani_common_want.h"
#include "distributed_ability_manager_client.h"
#include "dtbcollabmgr_log.h"
#include "ipc_skeleton.h"
#include "pixel_map_taihe_ani.h"
#include "string_wrapper.h"
#include "taihe/runtime.hpp"
#include "tokenid_kit.h"
#include "want_params_wrapper.h"

namespace OHOS {
namespace DistributedCollab {
const std::string TAG = "DmsfwkTaiheUtils";
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

bool IsSystemApp()
{
    static bool isSystemApp = []() {
        uint64_t tokenId = OHOS::IPCSkeleton::GetSelfTokenID();
        return OHOS::Security::AccessToken::TokenIdKit::IsSystemAppByFullTokenID(tokenId);
    }();
    return isSystemApp;
}

std::string GetBusinessErrorInfo(int32_t errCode)
{
    std::string errorInfo = "";
    switch (errCode) {
        case ERR_IS_NOT_SYSTEM_APP:
            errorInfo = ERR_MESSAGE_NO_PERMISSION;
            break;
        case ERR_INVALID_PARAMETERS:
            errorInfo = ERR_MESSAGE_INVALID_PARAMS;
            break;
        case ONLY_SUPPORT_ONE_STREAM:
            errorInfo = ERR_MESSAGE_ONE_STREAM;
            break;
        case RECEIVE_STREAM_NOT_START:
            errorInfo = ERR_MESSAGE_RECEIVE_NOT_START;
            break;
        case NOT_SUPPORTED_BITATE:
            errorInfo = ERR_MESSAGE_NOT_SUPPORTED_BITATE;
            break;
        case NOT_SUPPORTED_COLOR_SPACE:
            errorInfo = ERR_MESSAGE_NOT_SUPPORTED_COLOR_SPACE;
            break;
        case ERR_EXECUTE_FUNCTION:
            errorInfo = ERR_MESSAGE_FAILED;
            break;
        case COLLAB_PERMISSION_DENIED:
            errorInfo = ERR_MESSAGE_NO_PERMISSION;
            break;
        case INVALID_PARAMETERS_ERR:
            errorInfo = ERR_MESSAGE_INVALID_PARAMS;
            break;
        default:
            errorInfo = ERR_MESSAGE_FAILED;
            break;
    }
    return errorInfo;
}

abilityConnectionManagerTaihe::PeerInfo PeerInfoAdapter::ConvertToTaihe(const PeerInfo &peerInfo)
{
    abilityConnectionManagerTaihe::PeerInfo result = {
        .deviceId = taihe::string(peerInfo.deviceId),
        .bundleName = taihe::string(peerInfo.bundleName),
        .moduleName = taihe::string(peerInfo.moduleName),
        .abilityName = taihe::string(peerInfo.abilityName),
        .serviceName = taihe::optional<taihe::string>(std::in_place_t{}, peerInfo.serviceName)
    };
    return result;
}

PeerInfo PeerInfoAdapter::ConvertFromTaihe(const abilityConnectionManagerTaihe::PeerInfo &peerInfo)
{
    PeerInfo result(
        std::string(peerInfo.deviceId),
        std::string(peerInfo.bundleName),
        std::string(peerInfo.moduleName),
        std::string(peerInfo.abilityName),
        std::string(peerInfo.serviceName.has_value() ? peerInfo.serviceName.value() : "")
    );
    return result;
}

abilityConnectionManagerTaihe::ConnectOptions ConnectOptionsAdapter::ConvertToTaihe(
    const ConnectOption &connectOptions)
{
    abilityConnectionManagerTaihe::ConnectOptions result = {
        .needSendData = taihe::optional<bool>(std::in_place_t{}, connectOptions.needSendData),
        .needSendStream = taihe::optional<bool>(std::in_place_t{}, connectOptions.needSendStream),
        .needReceiveStream = taihe::optional<bool>(std::in_place_t{}, connectOptions.needReceiveStream),
    };

    auto startOptionsStr = QueryStartOptions(connectOptions);
    if (!startOptionsStr.empty()) {
        if (startOptionsStr == VALUE_START_OPTION_FOREGROUND) {
            result.startOptions = taihe::optional<abilityConnectionManagerTaihe::StartOptionParams>(
                std::in_place_t{}, abilityConnectionManagerTaihe::StartOptionParams::key_t::START_IN_FOREGROUND);
        } else {
            result.startOptions = taihe::optional<abilityConnectionManagerTaihe::StartOptionParams>(
                std::in_place_t{}, abilityConnectionManagerTaihe::StartOptionParams::key_t::START_IN_BACKGROUND);
        }
    }

    taihe::map<taihe::string, taihe::string> taiheparametersMap;
    const std::map<std::string, OHOS::sptr<OHOS::AAFwk::IInterface>> &parametersMap
        = connectOptions.parameters.GetParams();
    for (const auto &itParametersMap : parametersMap) {
        OHOS::AAFwk::IString *parameter = OHOS::AAFwk::IString::Query(itParametersMap.second);
        if (parameter != nullptr) {
            taiheparametersMap.emplace(
                taihe::string(itParametersMap.first), taihe::string(OHOS::AAFwk::String::Unbox(parameter)));
        }
    }
    result.parameters = taihe::optional<::taihe::map<::taihe::string, ::taihe::string>>(std::in_place_t{},
        taiheparametersMap);
    return result;
}

ConnectOption ConnectOptionsAdapter::ConvertFromTaihe(
    const abilityConnectionManagerTaihe::ConnectOptions &connectOptions)
{
    ConnectOption result;
    if (connectOptions.needSendData.has_value()) {
        result.needSendData = connectOptions.needSendData.value();
    }
    if (connectOptions.needSendStream.has_value()) {
        result.needSendStream = connectOptions.needSendStream.value();
    }
    if (connectOptions.needReceiveStream.has_value()) {
        result.needReceiveStream = connectOptions.needReceiveStream.value();
    }
    if (connectOptions.startOptions.has_value()) {
        if (connectOptions.startOptions.value() ==
            abilityConnectionManagerTaihe::StartOptionParams::key_t::START_IN_FOREGROUND) {
            result.options.SetParam(KEY_START_OPTION, AAFwk::String::Box(VALUE_START_OPTION_FOREGROUND));
        } else if (connectOptions.startOptions.value() ==
            abilityConnectionManagerTaihe::StartOptionParams::key_t::START_IN_BACKGROUND) {
            result.options.SetParam(KEY_START_OPTION, AAFwk::String::Box(VALUE_START_OPTION_BACKGROUND));
        } else {
            HILOGE("Invalid startOptions value.");
            return result;
        }
    }
    if (connectOptions.parameters.has_value()) {
        for (const auto &it : connectOptions.parameters.value()) {
            result.parameters.SetParam(std::string(it.first), AAFwk::String::Box(std::string(it.second)));
        }
    }
    return result;
}

std::string ConnectOptionsAdapter::QueryStartOptions(const ConnectOption &connectOptions)
{
    std::string result = "";
    const std::map<std::string, OHOS::sptr<OHOS::AAFwk::IInterface>> &optionsMap = connectOptions.options.GetParams();
    const auto &itOptionsMap = optionsMap.find(KEY_START_OPTION);
    if (itOptionsMap != optionsMap.end()) {
        OHOS::AAFwk::IString *option = OHOS::AAFwk::IString::Query(itOptionsMap->second);
        if (option == nullptr) {
            return result;
        }
        std::string optionStr = OHOS::AAFwk::String::Unbox(option);
        if (optionStr != VALUE_START_OPTION_FOREGROUND && optionStr != VALUE_START_OPTION_BACKGROUND) {
            return result;
        }
        result = optionStr;
    }
    return result;
}

abilityConnectionManagerTaihe::StartOptionParams StartOptionParamsAdapter::ConvertToTaihe(
    StartOptionParams startOptionParams)
{
    switch (startOptionParams) {
        case StartOptionParams::START_IN_FOREGROUND:
            return abilityConnectionManagerTaihe::StartOptionParams::key_t::START_IN_FOREGROUND;
        default:
            return abilityConnectionManagerTaihe::StartOptionParams::key_t::START_IN_BACKGROUND;
    }
}

StartOptionParams StartOptionParamsAdapter::ConvertFromTaihe(
    abilityConnectionManagerTaihe::StartOptionParams startOptionParams)
{
    switch (startOptionParams.get_key()) {
        case abilityConnectionManagerTaihe::StartOptionParams::key_t::START_IN_FOREGROUND:
            return StartOptionParams::START_IN_FOREGROUND;
        default:
            return StartOptionParams::START_IN_BACKGROUND;
    }
}

abilityConnectionManagerTaihe::ConnectErrorCode ConnectErrorCodeAdapter::ConvertToTaihe(
    ConnectErrorCode connectErrorCode)
{
    switch (connectErrorCode) {
        case ConnectErrorCode::CONNECTED_SESSION_EXISTS:
            return abilityConnectionManagerTaihe::ConnectErrorCode::key_t::CONNECTED_SESSION_EXISTS;
        case ConnectErrorCode::LOCAL_WIFI_NOT_OPEN:
            return abilityConnectionManagerTaihe::ConnectErrorCode::key_t::LOCAL_WIFI_NOT_OPEN;
        case ConnectErrorCode::PEER_WIFI_NOT_OPEN:
            return abilityConnectionManagerTaihe::ConnectErrorCode::key_t::PEER_WIFI_NOT_OPEN;
        case ConnectErrorCode::PEER_ABILITY_NO_ONCOLLABORATE:
            return abilityConnectionManagerTaihe::ConnectErrorCode::key_t::PEER_ABILITY_NO_ONCOLLABORATE;
        default:
            return abilityConnectionManagerTaihe::ConnectErrorCode::key_t::SYSTEM_INTERNAL_ERROR;
    }
}

abilityConnectionManagerTaihe::ConnectResult ConnectResultAdapter::ConvertToTaihe(const ConnectResult &connectResult)
{
    auto errorCode = ConnectErrorCodeAdapter::ConvertToTaihe(connectResult.errorCode);
    abilityConnectionManagerTaihe::ConnectResult result = {
        .isConnected = connectResult.isConnected,
        .errorCode = taihe::optional<abilityConnectionManagerTaihe::ConnectErrorCode>(std::in_place_t{}, errorCode),
        .reason = taihe::optional<taihe::string>(std::in_place_t{}, connectResult.reason)
    };
    return result;
}

StreamRole StreamRoleAdapter::ConvertFromTaihe(abilityConnectionManagerTaihe::StreamRole streamRole)
{
    switch (streamRole.get_key()) {
        case abilityConnectionManagerTaihe::StreamRole::key_t::SOURCE:
            return StreamRole::SOURCE;
        default:
            return StreamRole::SINK;
    }
}

StreamParams StreamParamAdapter::ConvertFromTaihe(const abilityConnectionManagerTaihe::StreamParam &streamParam)
{
    StreamParams result;
    result.name = std::string(streamParam.name);
    result.role = StreamRoleAdapter::ConvertFromTaihe(streamParam.role);
    if (streamParam.bitrate.has_value()) {
        result.bitrate = streamParam.bitrate.value();
    }
    if (streamParam.colorSpaceConversionTarget.has_value()) {
        auto colorSpace = streamParam.colorSpaceConversionTarget.value();
        auto env = taihe::get_env();
        if (env == nullptr) {
            HILOGE("get env failed!");
            return result;
        }
        ani_int aniInt {};
        if (env->EnumItem_GetValue_Int(reinterpret_cast<ani_enum_item>(colorSpace), &aniInt) != ANI_OK) {
            HILOGE("EnumItem_GetValue_Int failed!");
            return result;
        }
        auto realColorSpace = static_cast<int32_t>(aniInt);
        // only BT709_LIMIT is supported
        if (realColorSpace != static_cast<int32_t>(ColorSpace::BT709_LIMIT)) {
            HILOGE("colorSpace not BT709_LIMIT.");
            taihe::set_business_error(NOT_SUPPORTED_COLOR_SPACE, GetBusinessErrorInfo(NOT_SUPPORTED_COLOR_SPACE));
            return result;
        }
        result.colorSpace = static_cast<ColorSpace>(realColorSpace);
    }
    return result;
}

VideoPixelFormat VideoPixelFormatAdapter::ConvertFromTaihe(
    abilityConnectionManagerTaihe::VideoPixelFormat videoPixelFormat)
{
    switch (videoPixelFormat.get_key()) {
        case abilityConnectionManagerTaihe::VideoPixelFormat::key_t::NV12:
            return VideoPixelFormat::NV12;
        case abilityConnectionManagerTaihe::VideoPixelFormat::key_t::NV21:
            return VideoPixelFormat::NV21;
        default:
            return VideoPixelFormat::UNKNOWN;
    }
}

FlipOptions FlipOptionsAdapter::ConvertFromTaihe(abilityConnectionManagerTaihe::FlipOptions flipOptions)
{
    switch (flipOptions.get_key()) {
        case abilityConnectionManagerTaihe::FlipOptions::key_t::HORIZONTAL:
            return FlipOptions::HORIZONTAL;
        case abilityConnectionManagerTaihe::FlipOptions::key_t::VERTICAL:
            return FlipOptions::VERTICAL;
        default:
            return FlipOptions::UNKNOWN;
    }
}

SurfaceParams SurfaceParamAdapter::ConvertFromTaihe(const abilityConnectionManagerTaihe::SurfaceParam &surfaceParam)
{
    SurfaceParams result;
    result.width = surfaceParam.width;
    result.height = surfaceParam.height;
    if (surfaceParam.format.has_value()) {
        result.format = VideoPixelFormatAdapter::ConvertFromTaihe(surfaceParam.format.value());
    }
    if (surfaceParam.rotation.has_value()) {
        result.rotation = surfaceParam.rotation.value();
    }
    if (surfaceParam.flip.has_value()) {
        result.flip = FlipOptionsAdapter::ConvertFromTaihe(surfaceParam.flip.value());
    }
    return result;
}

abilityConnectionManagerTaihe::DisconnectReason DisconnectReasonAdapter::ConvertToTaihe(
    DisconnectReason disconnectReason)
{
    switch (disconnectReason) {
        case DisconnectReason::PEER_APP_CLOSE_COLLABORATION:
            return abilityConnectionManagerTaihe::DisconnectReason::key_t::PEER_APP_CLOSE_COLLABORATION;
        case DisconnectReason::PEER_APP_EXIT:
            return abilityConnectionManagerTaihe::DisconnectReason::key_t::PEER_APP_EXIT;
        default:
            return abilityConnectionManagerTaihe::DisconnectReason::key_t::NETWORK_DISCONNECTED;
    }
}

abilityConnectionManagerTaihe::EventCallbackInfo EventCallbackInfoAdapter::ConvertToTaihe(
    const EventCallbackInfo &eventCallbackInfo)
{
    auto disconnectReason = DisconnectReasonAdapter::ConvertToTaihe(eventCallbackInfo.reason);
    std::vector<uint8_t> data;
    if (eventCallbackInfo.data != nullptr) {
        data.resize(eventCallbackInfo.data->Size());
        auto ret = memcpy_s(data.data(), eventCallbackInfo.data->Size(),
            eventCallbackInfo.data->Data(), eventCallbackInfo.data->Size());
        if (ret != OHOS::ERR_OK) {
            HILOGE("memcpy_s failed.");
            return abilityConnectionManagerTaihe::EventCallbackInfo{};
        }
    }
    auto pixelMapObj = OHOS::Media::PixelMapTaiheAni::CreateEtsPixelMap(taihe::get_env(), eventCallbackInfo.image);
    auto pixelMapPtr = reinterpret_cast<uintptr_t>(pixelMapObj);
    abilityConnectionManagerTaihe::EventCallbackInfo result = {
        .sessionId = eventCallbackInfo.sessionId,
        .reason = taihe::optional<abilityConnectionManagerTaihe::DisconnectReason>(
            std::in_place_t{}, disconnectReason),
        .msg = taihe::optional<taihe::string>(std::in_place_t{}, eventCallbackInfo.msg),
        .data = taihe::optional<taihe::array<uint8_t>>(std::in_place_t{}, data),
        .image = taihe::optional<uintptr_t>(std::in_place_t{}, pixelMapPtr)
    };
    return result;
}

abilityConnectionManagerTaihe::CollaborateEventType CollaborateEventTypeAdapter::ConvertToTaihe(
    CollaborateEventType collaborateEventType)
{
    switch (collaborateEventType) {
        case CollaborateEventType::SEND_FAILURE:
            return abilityConnectionManagerTaihe::CollaborateEventType::key_t::SEND_FAILURE;
        default:
            return abilityConnectionManagerTaihe::CollaborateEventType::key_t::COLOR_SPACE_CONVERSION_FAILURE;
    }
}

abilityConnectionManagerTaihe::CollaborateEventInfo CollaborateEventInfoAdapter::ConvertToTaihe(
    const CollaborateEventInfo &collaborateEventInfo)
{
    abilityConnectionManagerTaihe::CollaborateEventInfo result = {
        .eventType = CollaborateEventTypeAdapter::ConvertToTaihe(collaborateEventInfo.eventType),
        .eventMsg = taihe::optional<taihe::string>(std::in_place_t{}, collaborateEventInfo.eventMsg)
    };
    return result;
}

TaiheAbilityConnectionSessionListener::TaiheAbilityConnectionSessionListener(ani_env *env)
{
    env_ = env;
    callbackRef_ = nullptr;
}

TaiheAbilityConnectionSessionListener::~TaiheAbilityConnectionSessionListener()
{
    if (env_ == nullptr) {
        HILOGE("Failed to register, env is nullptr");
        return;
    }
    if (env_->GlobalReference_Delete(callbackRef_) != ANI_OK) {
        HILOGE("GlobalReference_Delete failed!");
    }
}

void TaiheAbilityConnectionSessionListener::CallJsMethod(const EventCallbackInfo& eventCallbackInfo)
{
    if (callbackPtr_) {
        (*callbackPtr_)(EventCallbackInfoAdapter::ConvertToTaihe(eventCallbackInfo));
    }
}

void TaiheAbilityConnectionSessionListener::CallJsMethod(const CollaborateEventInfo& collaborateEventInfo)
{
    if (collaborateCallbackPtr_) {
        (*collaborateCallbackPtr_)(CollaborateEventInfoAdapter::ConvertToTaihe(collaborateEventInfo));
    }
}

void TaiheAbilityConnectionSessionListener::SetCallback(
    taihe::callback_view<void(abilityConnectionManagerTaihe::EventCallbackInfo const& info)> f, uintptr_t opq)
{
    if (!SetCallbackCommon(opq)) {
        HILOGE("Set callback common failed!");
        return;
    }
    callbackPtr_ =
        std::make_shared<taihe::callback<void(abilityConnectionManagerTaihe::EventCallbackInfo const& info)>>(f);
}

void TaiheAbilityConnectionSessionListener::SetCallback(
    taihe::callback_view<void(abilityConnectionManagerTaihe::CollaborateEventInfo const& info)> f, uintptr_t opq)
{
    if (!SetCallbackCommon(opq)) {
        HILOGE("Set callback common failed!");
        return;
    }
    collaborateCallbackPtr_ =
        std::make_shared<taihe::callback<void(abilityConnectionManagerTaihe::CollaborateEventInfo const& info)>>(f);
}

bool TaiheAbilityConnectionSessionListener::SetCallbackCommon(uintptr_t opq)
{
    ani_object callbackObj = reinterpret_cast<ani_object>(opq);
    if (env_ == nullptr) {
        HILOGE("Failed to register, env is nullptr");
        return false;
    }
    if (callbackRef_ != nullptr) {
        if (env_->GlobalReference_Delete(callbackRef_) != ANI_OK) {
            HILOGE("GlobalReference_Delete failed!");
        }
        callbackRef_ = nullptr;
    }
    if (ANI_OK != env_->GlobalReference_Create(callbackObj, &callbackRef_)) {
        HILOGE("Create reference failed");
        return false;
    }
    return true;
}
} // namespace DistributedCollab
} // namespace OHOS