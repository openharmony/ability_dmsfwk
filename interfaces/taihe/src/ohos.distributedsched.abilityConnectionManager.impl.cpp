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

#include "ohos.distributedsched.abilityConnectionManager.proj.hpp"
#include "ohos.distributedsched.abilityConnectionManager.impl.hpp"
#include "taihe/runtime.hpp"
#include "stdexcept"

#include "ability.h"
#include "ability_connection_manager.h"
#include "ability_info.h"
#include "ani_base_context.h"
#include "dmsfwk_taihe_utils.h"
#include "dtbcollabmgr_log.h"
#include "pixel_map_taihe_ani.h"
#include "ui_extension_context.h"

using namespace OHOS::DistributedCollab;
using namespace ohos::distributedsched;

namespace {
constexpr int32_t IMAGE_COMPRESSION_QUALITY = 30;
const std::string TAG = "AbilityConnectionManagerImpl";

// To be implemented.
template<class T>
void OnCommon(T f, uintptr_t opq, int32_t sessionId, std::string type)
{
    auto listener = std::make_shared<TaiheAbilityConnectionSessionListener>(taihe::get_env());
    listener->SetCallback(f, opq);
    auto result = AbilityConnectionManager::GetInstance().RegisterEventCallback(sessionId, type, listener);
    if (result != OHOS::ERR_OK) {
        HILOGE("Register event callback failed!");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
    }
}

void OffCommon(int32_t sessionId, std::string type)
{
    auto result = AbilityConnectionManager::GetInstance().UnregisterEventCallback(sessionId, type);
    if (result != OHOS::ERR_OK) {
        HILOGE("Unregister event callback failed!");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
    }
}

void OnConnect(int32_t sessionId,
    taihe::callback_view<void(ohos::distributedsched::abilityConnectionManager::EventCallbackInfo const& info)> f,
    uintptr_t opq)
{
    OnCommon(f, opq, sessionId, "connect");
}

void OffConnect(int32_t sessionId, taihe::optional_view<uintptr_t> opq)
{
    OffCommon(sessionId, "connect");
}

void OnDisconnect(int32_t sessionId,
    taihe::callback_view<void(ohos::distributedsched::abilityConnectionManager::EventCallbackInfo const& info)> f,
    uintptr_t opq)
{
    OnCommon(f, opq, sessionId, "disconnect");
}

void OffDisconnect(int32_t sessionId, taihe::optional_view<uintptr_t> opq)
{
    OffCommon(sessionId, "disconnect");
}

void OnReceiveMessage(int32_t sessionId,
    taihe::callback_view<void(ohos::distributedsched::abilityConnectionManager::EventCallbackInfo const& info)> f,
    uintptr_t opq)
{
    OnCommon(f, opq, sessionId, "receiveMessage");
}

void OffReceiveMessage(int32_t sessionId, taihe::optional_view<uintptr_t> opq)
{
    OffCommon(sessionId, "receiveMessage");
}

void OnReceiveData(int32_t sessionId,
    taihe::callback_view<void(ohos::distributedsched::abilityConnectionManager::EventCallbackInfo const& info)> f,
    uintptr_t opq)
{
    OnCommon(f, opq, sessionId, "receiveData");
}

void OffReceiveData(int32_t sessionId, taihe::optional_view<uintptr_t> opq)
{
    OffCommon(sessionId, "receiveData");
}

void OnReceiveImage(int32_t sessionId,
    taihe::callback_view<void(ohos::distributedsched::abilityConnectionManager::EventCallbackInfo const& info)> f,
    uintptr_t opq)
{
    OnCommon(f, opq, sessionId, "receiveImage");
}

void OffReceiveImage(int32_t sessionId, taihe::optional_view<uintptr_t> opq)
{
    OffCommon(sessionId, "receiveImage");
}

void OnCollaborateEvent(int32_t sessionId,
    taihe::callback_view<void(ohos::distributedsched::abilityConnectionManager::CollaborateEventInfo const& info)> f,
    uintptr_t opq)
{
    OnCommon(f, opq, sessionId, "collaborateEvent");
}

void OffCollaborateEvent(int32_t sessionId, taihe::optional_view<uintptr_t> opq)
{
    OffCommon(sessionId, "collaborateEvent");
}

std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> GetAbilityInfoByContext(uintptr_t context)
{
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo = nullptr;
    auto contextObj = reinterpret_cast<ani_object>(context);
    if (contextObj == nullptr) {
        HILOGE("Parameter context is nullptr.");
        ThrowBusinessError(ERR_INVALID_PARAMETERS);
        return abilityInfo;
    }
    auto contextPtr = OHOS::AbilityRuntime::GetStageModeContext(taihe::get_env(), contextObj);
    if (contextPtr == nullptr) {
        HILOGE("get stage mode context failed!");
        ThrowBusinessError(ERR_INVALID_PARAMETERS);
        return abilityInfo;
    }
    auto abilityContext = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::AbilityContext>(contextPtr);
    if (abilityContext == nullptr) {
        HILOGW("convertTo AbilityContext failed! try convertTo UIExtensionContext");
        auto extensionContext
            = OHOS::AbilityRuntime::Context::ConvertTo<OHOS::AbilityRuntime::UIExtensionContext>(contextPtr);
        if (extensionContext == nullptr) {
            HILOGE("convertTo UIExtensionContext failed!");
            ThrowBusinessError(ERR_INVALID_PARAMETERS);
            return abilityInfo;
        }
        abilityInfo = extensionContext->GetAbilityInfo();
    } else {
        abilityInfo = abilityContext->GetAbilityInfo();
    }
    return abilityInfo;
}

int32_t CreateAbilityConnectionSession(taihe::string_view serviceName, uintptr_t context,
    ohos::distributedsched::abilityConnectionManager::PeerInfo const& peerInfo,
    ohos::distributedsched::abilityConnectionManager::ConnectOptions const& connectOptions)
{
    int32_t sessionId = -1;
    std::string realServiceName(serviceName);
    PeerInfo realPeerInfo = PeerInfoAdapter::ConvertFromTaihe(peerInfo);
    ConnectOption realconnectOptions = ConnectOptionsAdapter::ConvertFromTaihe(connectOptions);
    if (realPeerInfo.serverId.empty()) {
        realPeerInfo.serverId = realServiceName;
        realPeerInfo.serviceName = realServiceName;
    }
    auto abilityInfo = GetAbilityInfoByContext(context);
    if (abilityInfo == nullptr) {
        HILOGE("get ability info failed!");
        ThrowBusinessError(ERR_INVALID_PARAMETERS);
        return ERR_INVALID_PARAMETERS;
    }
    auto ret = AbilityConnectionManager::GetInstance().CreateSession(
        realServiceName, abilityInfo, realPeerInfo, realconnectOptions, sessionId);
    if (ret == COLLAB_PERMISSION_DENIED || ret == INVALID_PARAMETERS_ERR) {
        HILOGE("create session failed due to param or permission valid");
        ThrowBusinessError(ret);
        return ret;
    } else if (ret != OHOS::ERR_OK) {
        HILOGE("create session failed due to function err");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
        return ret;
    }
    return sessionId;
}

void DestroyAbilityConnectionSession(int32_t sessionId)
{
    if (AbilityConnectionManager::GetInstance().DestroySession(sessionId) != OHOS::ERR_OK) {
        HILOGE("destroy session failed!");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
    }
}

abilityConnectionManager::PeerInfoOrNull GetPeerInfoById(int32_t sessionId)
{
    PeerInfo peerInfo;
    auto ret = AbilityConnectionManager::GetInstance().getPeerInfoBySessionId(sessionId, peerInfo);
    if (ret != OHOS::ERR_OK) {
        HILOGE("get peerInfo failed!");
        return abilityConnectionManager::PeerInfoOrNull::make_nullData();
    }
    abilityConnectionManagerTaihe::PeerInfo taihePeerInfo = PeerInfoAdapter::ConvertToTaihe(peerInfo);
    return abilityConnectionManager::PeerInfoOrNull::make_peerInfo(
        taihe::optional<abilityConnectionManagerTaihe::PeerInfo>(std::in_place_t{}, taihePeerInfo));
}

ohos::distributedsched::abilityConnectionManager::ConnectResult ConnectSync(int32_t sessionId)
{
    std::mutex lock;
    std::condition_variable condition;
    bool callbackExecuted = false;
    abilityConnectionManagerTaihe::ConnectResult taiheResult;
    AbilityConnectionManager::ConnectCallback connectCallback
        = [&taiheResult, &lock, &condition, &callbackExecuted](ConnectResult result) mutable {
        HILOGI("called.");
        taiheResult = ConnectResultAdapter::ConvertToTaihe(result);
        std::unique_lock<std::mutex> locker(lock);
        callbackExecuted = true;
        condition.notify_one();
    };
    AbilityConnectionManager::GetInstance().ConnectSession(sessionId, connectCallback);
    std::unique_lock<std::mutex> locker(lock);
    condition.wait(locker, [&callbackExecuted] {
        return callbackExecuted;
    });
    return taiheResult;
}

void Disconnect(int32_t sessionId)
{
    if (AbilityConnectionManager::GetInstance().DisconnectSession(sessionId) != OHOS::ERR_OK) {
        HILOGE("disconnect session failed!");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
    }
}

void AcceptConnectSync(int32_t sessionId, taihe::string_view token)
{
    std::string tokenStr(token);
    auto result = AbilityConnectionManager::GetInstance().AcceptConnect(sessionId, tokenStr);
    if (result != OHOS::ERR_OK) {
        HILOGE("AcceptConnect failed.");
        ThrowBusinessError(result);
    }
}

void Reject(taihe::string_view token, taihe::string_view reason)
{
    std::string tokenStr(token);
    std::string reasonStr(reason);
    if (AbilityConnectionManager::GetInstance().Reject(tokenStr, reasonStr) != OHOS::ERR_OK) {
        HILOGE("Reject session failed!");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
    }
}

void SendMessageSync(int32_t sessionId, taihe::string_view msg)
{
    std::string msgStr(msg);
    HILOGI("start send message.");
    auto result = AbilityConnectionManager::GetInstance().SendMessage(sessionId, msgStr);
    HILOGI("notify sendMessage event.");
    if (result != OHOS::ERR_OK) {
        HILOGE("SendMessage failed.");
        ThrowBusinessError(result);
    }
}

void SendDataSync(int32_t sessionId, taihe::array_view<uint8_t> data)
{
    auto length = data.size();
    auto buffer = std::make_shared<AVTransDataBuffer>(length);
    if (memcpy_s(buffer->Data(), length, static_cast<const void*>(data.data()), length) != OHOS::ERR_OK) {
        HILOGE("pack recv data failed");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
        return;
    }
    auto result = AbilityConnectionManager::GetInstance().SendData(sessionId, buffer);
    if (result != OHOS::ERR_OK) {
        HILOGE("SendData failed.");
        ThrowBusinessError(result);
    }
}

void SendImageSync(int32_t sessionId, uintptr_t image, taihe::optional_view<int32_t> quality)
{
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        ThrowBusinessError(ERR_IS_NOT_SYSTEM_APP);
        return;
    }
    auto pixelMapObj = reinterpret_cast<ani_object>(image);
    if (pixelMapObj == nullptr) {
        HILOGE("Parameter image is nullptr.");
        ThrowBusinessError(ERR_INVALID_PARAMETERS);
        return;
    }
    auto pixelMap = OHOS::Media::PixelMapTaiheAni::GetNativePixelMap(taihe::get_env(), pixelMapObj);
    if (pixelMap == nullptr) {
        HILOGE("Failed to unwrap image.");
        ThrowBusinessError(ERR_INVALID_PARAMETERS);
        return;
    }
    int32_t realQuality = IMAGE_COMPRESSION_QUALITY;
    if (quality.has_value()) {
        realQuality = quality.value();
    }
    auto result = AbilityConnectionManager::GetInstance().SendImage(sessionId, pixelMap, realQuality);
    if (result != OHOS::ERR_OK) {
        HILOGE("send image failed!");
        ThrowBusinessError(result);
        return;
    }
}

int32_t CreateStreamSync(int32_t sessionId, ohos::distributedsched::abilityConnectionManager::StreamParam const& param)
{
    int32_t streamId = -1;
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        ThrowBusinessError(ERR_IS_NOT_SYSTEM_APP);
        return streamId;
    }
    StreamParams streamParams = StreamParamAdapter::ConvertFromTaihe(param);
    auto result = AbilityConnectionManager::GetInstance().CreateStream(sessionId, streamParams, streamId);
    if (result != OHOS::ERR_OK) {
        HILOGE("CreateStream failed.");
        ThrowBusinessError(result);
    }
    return streamId;
}

void SetSurfaceId(int32_t streamId, taihe::string_view surfaceId,
    ohos::distributedsched::abilityConnectionManager::SurfaceParam const& param)
{
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        ThrowBusinessError(ERR_IS_NOT_SYSTEM_APP);
        return;
    }
    std::string surfaceIdStr(surfaceId);
    SurfaceParams surfaceParams = SurfaceParamAdapter::ConvertFromTaihe(param);
    auto result = AbilityConnectionManager::GetInstance().SetSurfaceId(streamId, surfaceIdStr, surfaceParams);
    if (result != OHOS::ERR_OK) {
        HILOGE("SetSurfaceId failed.");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
    }
}

taihe::string GetSurfaceId(int32_t streamId,
    ohos::distributedsched::abilityConnectionManager::SurfaceParam const& param)
{
    std::string surfaceId;
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        ThrowBusinessError(ERR_IS_NOT_SYSTEM_APP);
        return taihe::string(surfaceId);
    }
    SurfaceParams surfaceParams = SurfaceParamAdapter::ConvertFromTaihe(param);
    auto result = AbilityConnectionManager::GetInstance().GetSurfaceId(streamId, surfaceParams, surfaceId);
    if (result != OHOS::ERR_OK) {
        HILOGE("GetSurfaceId failed.");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
    }
    return taihe::string(surfaceId);
}

void UpdateSurfaceParam(int32_t streamId, ohos::distributedsched::abilityConnectionManager::SurfaceParam const& param)
{
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        ThrowBusinessError(ERR_IS_NOT_SYSTEM_APP);
        return;
    }
    SurfaceParams surfaceParams = SurfaceParamAdapter::ConvertFromTaihe(param);
    auto result = AbilityConnectionManager::GetInstance().UpdateSurfaceParam(streamId, surfaceParams);
    if (result != OHOS::ERR_OK) {
        HILOGE("UpdateSurfaceParam failed.");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
    }
}

void DestroyStream(int32_t streamId)
{
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        ThrowBusinessError(ERR_IS_NOT_SYSTEM_APP);
        return;
    }
    auto result = AbilityConnectionManager::GetInstance().DestroyStream(streamId);
    if (result != OHOS::ERR_OK) {
        HILOGE("DestroyStream failed.");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
    }
}

void StartStream(int32_t streamId)
{
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        ThrowBusinessError(ERR_IS_NOT_SYSTEM_APP);
        return;
    }
    auto result = AbilityConnectionManager::GetInstance().StartStream(streamId);
    if (result != OHOS::ERR_OK) {
        HILOGE("StartStream failed.");
        ThrowBusinessError(result);
    }
}

void StopStream(int32_t streamId)
{
    if (!IsSystemApp()) {
        HILOGE("Permission verification failed.");
        ThrowBusinessError(ERR_IS_NOT_SYSTEM_APP);
        return;
    }
    auto result = AbilityConnectionManager::GetInstance().StopStream(streamId);
    if (result != OHOS::ERR_OK) {
        HILOGE("StopStream failed.");
        ThrowBusinessError(ERR_EXECUTE_FUNCTION);
    }
}
}  // namespace

// Since these macros are auto-generate, lint will cause false positive.
// NOLINTBEGIN
TH_EXPORT_CPP_API_OnConnect(OnConnect);
TH_EXPORT_CPP_API_OffConnect(OffConnect);
TH_EXPORT_CPP_API_OnDisconnect(OnDisconnect);
TH_EXPORT_CPP_API_OffDisconnect(OffDisconnect);
TH_EXPORT_CPP_API_OnReceiveMessage(OnReceiveMessage);
TH_EXPORT_CPP_API_OffReceiveMessage(OffReceiveMessage);
TH_EXPORT_CPP_API_OnReceiveData(OnReceiveData);
TH_EXPORT_CPP_API_OffReceiveData(OffReceiveData);
TH_EXPORT_CPP_API_OnReceiveImage(OnReceiveImage);
TH_EXPORT_CPP_API_OffReceiveImage(OffReceiveImage);
TH_EXPORT_CPP_API_OnCollaborateEvent(OnCollaborateEvent);
TH_EXPORT_CPP_API_OffCollaborateEvent(OffCollaborateEvent);
TH_EXPORT_CPP_API_CreateAbilityConnectionSession(CreateAbilityConnectionSession);
TH_EXPORT_CPP_API_DestroyAbilityConnectionSession(DestroyAbilityConnectionSession);
TH_EXPORT_CPP_API_GetPeerInfoById(GetPeerInfoById);
TH_EXPORT_CPP_API_ConnectSync(ConnectSync);
TH_EXPORT_CPP_API_Disconnect(Disconnect);
TH_EXPORT_CPP_API_AcceptConnectSync(AcceptConnectSync);
TH_EXPORT_CPP_API_Reject(Reject);
TH_EXPORT_CPP_API_SendMessageSync(SendMessageSync);
TH_EXPORT_CPP_API_SendDataSync(SendDataSync);
TH_EXPORT_CPP_API_SendImageSync(SendImageSync);
TH_EXPORT_CPP_API_CreateStreamSync(CreateStreamSync);
TH_EXPORT_CPP_API_SetSurfaceId(SetSurfaceId);
TH_EXPORT_CPP_API_GetSurfaceId(GetSurfaceId);
TH_EXPORT_CPP_API_UpdateSurfaceParam(UpdateSurfaceParam);
TH_EXPORT_CPP_API_DestroyStream(DestroyStream);
TH_EXPORT_CPP_API_StartStream(StartStream);
TH_EXPORT_CPP_API_StopStream(StopStream);
// NOLINTEND
