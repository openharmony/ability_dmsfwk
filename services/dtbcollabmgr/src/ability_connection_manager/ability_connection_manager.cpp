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

#include "ability_connection_manager.h"

#include <map>
#include <memory>
#include <unistd.h>
#include <sstream>
#include <iomanip>

#include "ability_info.h"
#include "ability_connection_session.h"
#include "distributed_client.h"
#include "dtbcollabmgr_log.h"
#include "openssl/sha.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
const std::string TAG = "AbilityConnectionManager";
constexpr int32_t SERVER_SOCKET_NAME_LENGTH = 64;
constexpr int32_t HEX_WIDTH = 2;
constexpr char FILL_CHAR = '0';
}

IMPLEMENT_SINGLE_INSTANCE(AbilityConnectionManager);

AbilityConnectionManager::AbilityConnectionManager()
{
}

AbilityConnectionManager::~AbilityConnectionManager()
{
}

int32_t AbilityConnectionManager::CreateSession(const std::string& serverId,
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo, PeerInfo& peerInfo,
    ConnectOption& options, int32_t& sessionId)
{
    HILOGI("called.");
    if (!IsVaildPeerInfo(peerInfo)) {
        HILOGE("peerInfo is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    if (!IsVaildConnectOption(options)) {
        HILOGE("ConnectOption is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    PeerInfo localInfo = {"", abilityInfo->bundleName, abilityInfo->moduleName,
        abilityInfo->name, peerInfo.serverId};
    
    std::string serverSocketName = GetServerSocketName(getprocpid(), abilityInfo->uid, abilityInfo->bundleName);
    if (ChannelManager::GetInstance().Init(serverSocketName) != ERR_OK) {
        HILOGE("ChannelManager init failed.");
        return INVALID_PARAMETERS_ERR;
    }
    AbilityConnectionSessionInfo sessionInfo = { serverId, localInfo, peerInfo };
    sessionId = sessionId_++;
    auto connectionSesion = std::make_shared<AbilityConnectionSession>(sessionId, serverSocketName,
        sessionInfo, options);
    connectionSesion->Init();

    std::unique_lock<std::shared_mutex> writeLock(sessionMutex_);
    sessionMap_.emplace(sessionId, connectionSesion);
    return ERR_OK;
}

bool AbilityConnectionManager::FindExistingSession(const PeerInfo& peerInfo, const PeerInfo& localInfo,
    int32_t& sessionId)
{
    std::shared_lock<std::shared_mutex> readLock(sessionMutex_);
    for (auto iterItem = sessionMap_.begin(); iterItem != sessionMap_.end(); ++iterItem) {
        if (iterItem->second != nullptr) {
            auto connectionSession = iterItem->second;
            if (connectionSession->GetPeerInfo() == peerInfo &&
                connectionSession->GetLocalInfo() == localInfo) {
                sessionId = iterItem->first;
                return true;
            }
        }
    }
    return false;
}

int32_t AbilityConnectionManager::DestroySession(int32_t sessionId)
{
    HILOGI("called.");
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    connectionSesion->Disconnect();
    connectionSesion->UnInit();

    std::unique_lock<std::shared_mutex> writeLock(sessionMutex_);
    sessionMap_.erase(sessionId);
    return ERR_OK;
}

int32_t AbilityConnectionManager::getPeerInfoBySessionId(int32_t sessionId, PeerInfo& peerInfo)
{
    HILOGI("called.");
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    peerInfo = connectionSesion->GetPeerInfo();
    return ERR_OK;
}

int32_t AbilityConnectionManager::ConnectSession(int32_t sessionId, ConnectCallback& callback)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_SESSION_ID;
    }

    return connectionSesion->Connect(callback);
}

int32_t AbilityConnectionManager::DisconnectSession(int32_t sessionId)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    return connectionSesion->Disconnect();
}

int32_t AbilityConnectionManager::AcceptConnect(int32_t sessionId, const std::string& token)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    
    return connectionSesion->AcceptConnect(token);
}

int32_t AbilityConnectionManager::Reject(const std::string& token, const std::string& reason)
{
    HILOGD("called, token is %{public}s", token.c_str());
    DistributedClient dmsClient;
    return dmsClient.NotifyRejectReason(token, reason);
}

int32_t AbilityConnectionManager::NotifyCollabResult(int32_t sessionId, int32_t result,
    const std::string& peerServerName, const std::string& dmsServerToken, const std::string& reason)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    return connectionSesion->HandleCollabResult(result, peerServerName, dmsServerToken, reason);
}

int32_t AbilityConnectionManager::NotifyDisconnect(int32_t sessionId)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    connectionSesion->HandleDisconnect();
    return ERR_OK;
}

int32_t AbilityConnectionManager::SendMessage(int32_t sessionId, const std::string& msg)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    return connectionSesion->SendMessage(msg);
}

int32_t AbilityConnectionManager::SendData(int32_t sessionId, const std::shared_ptr<AVTransDataBuffer>& buffer)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    return connectionSesion->SendData(buffer);
}

int32_t AbilityConnectionManager::SendImage(int32_t sessionId, const std::shared_ptr<Media::PixelMap>& image)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    return connectionSesion->SendImage(image);
}

int32_t AbilityConnectionManager::SendFile(int32_t sessionId, const std::vector<std::string>& sFiles,
    const std::vector<std::string>& dFiles)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    return connectionSesion->SendFile(sFiles, dFiles);
}

int32_t AbilityConnectionManager::CreateStream(int32_t sessionId, const StreamParams& param, int32_t& streamId)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    int32_t ret = connectionSesion->CreateStream(streamId_, param);
    if (ret != ERR_OK) {
        return ret;
    }
    streamId = streamId_++;
    std::unique_lock<std::shared_mutex> writeLock(streamMutex_);
    streamMap_[streamId] = sessionId;
    return ERR_OK;
}

int32_t AbilityConnectionManager::SetSurfaceId(int32_t streamId, const std::string& surfaceId,
    const SurfaceParams& param)
{
    HILOGD("called, streamId is %{public}d, surfaceId is %{public}s", streamId, surfaceId.c_str());
    auto connectionSesion = GetAbilityConnectionSessionByStreamId(streamId);
    if (connectionSesion == nullptr) {
        HILOGE("streamId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    return connectionSesion->SetSurfaceId(surfaceId, param);
}

bool AbilityConnectionManager::CheckStreamIsRegistered(int32_t sessionId)
{
    std::shared_lock<std::shared_mutex> readLock(streamMutex_);
    for (auto iter = streamMap_.begin(); iter != streamMap_.end(); iter++) {
        if (iter->second == sessionId) {
            return true;
        }
    }
    return false;
}

int32_t AbilityConnectionManager::GetSurfaceId(int32_t streamId, const SurfaceParams& param, std::string& surfaceId)
{
    HILOGD("called, streamId is %{public}d", streamId);
    auto connectionSesion = GetAbilityConnectionSessionByStreamId(streamId);
    if (connectionSesion == nullptr) {
        HILOGE("streamId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    return connectionSesion->GetSurfaceId(param, surfaceId);
}

int32_t AbilityConnectionManager::UpdateSurfaceParam(int32_t streamId, const SurfaceParams& param)
{
    HILOGD("called, streamId is %{public}d", streamId);
    auto connectionSesion = GetAbilityConnectionSessionByStreamId(streamId);
    if (connectionSesion == nullptr) {
        HILOGE("streamId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    return connectionSesion->UpdateSurfaceParam(param);
}

int32_t AbilityConnectionManager::DestroyStream(int32_t streamId)
{
    HILOGD("called, streamId is %{public}d", streamId);
    auto connectionSesion = GetAbilityConnectionSessionByStreamId(streamId);
    if (connectionSesion == nullptr) {
        HILOGE("streamId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }

    if (connectionSesion->DestroyStream() != ERR_OK) {
        HILOGE("destroy stream failed.");
        return INVALID_PARAMETERS_ERR;
    }
    std::unique_lock<std::shared_mutex> writeLock(streamMutex_);
    streamMap_.erase(streamId);
    return ERR_OK;
}

int32_t AbilityConnectionManager::StartStream(int32_t streamId)
{
    HILOGD("called, streamId is %{public}d", streamId);
    auto connectionSesion = GetAbilityConnectionSessionByStreamId(streamId);
    if (connectionSesion == nullptr) {
        HILOGE("streamId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    
    return connectionSesion->StartStream(streamId);
}

int32_t AbilityConnectionManager::StopStream(int32_t streamId)
{
    HILOGD("called, streamId is %{public}d", streamId);
    auto connectionSesion = GetAbilityConnectionSessionByStreamId(streamId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    
    return connectionSesion->StopStream(streamId);
}

int32_t AbilityConnectionManager::RegisterEventCallback(int32_t sessionId, const std::string& eventType,
    const std::shared_ptr<JsAbilityConnectionSessionListener>& listener)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    
    return connectionSesion->RegisterEventCallback(eventType, listener);
}

int32_t AbilityConnectionManager::UnregisterEventCallback(int32_t sessionId, const std::string& eventType)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    
    return connectionSesion->UnregisterEventCallback(eventType);
}

int32_t AbilityConnectionManager::RegisterEventCallback(int32_t sessionId,
    const std::shared_ptr<IAbilityConnectionSessionListener>& listener)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    
    return connectionSesion->RegisterEventCallback(listener);
}

int32_t AbilityConnectionManager::UnregisterEventCallback(int32_t sessionId)
{
    HILOGD("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    
    return connectionSesion->UnregisterEventCallback();
}

int32_t AbilityConnectionManager::NotifyWifiOpen(int32_t sessionId)
{
    HILOGI("called, sessionId is %{public}d", sessionId);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    return connectionSesion->ConnectStreamChannel();
}

bool AbilityConnectionManager::IsVaildPeerInfo(const PeerInfo& peerInfo)
{
    if (peerInfo.deviceId.empty() || peerInfo.bundleName.empty() || peerInfo.moduleName.empty() ||
        peerInfo.abilityName.empty() || peerInfo.serverId.empty()) {
        HILOGE("peerInfo is %{public}s", peerInfo.toString().c_str());
        return false;
    }

    return true;
}

bool AbilityConnectionManager::IsVaildConnectOption(const ConnectOption& opt)
{
    if (opt.needSendStream && opt.needReceiveStream) {
        HILOGE("Streams cannot be sent and received at the same end.");
        return false;
    }
    return true;
}

std::string AbilityConnectionManager::GetServerSocketName(int32_t userId,
    int32_t pid, const std::string& bundle)
{
    std::string input = std::to_string(userId) + std::to_string(pid) + bundle;

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((const unsigned char*)input.c_str(), input.length(), hash);

    std::stringstream hashStr;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
        hashStr << std::hex << std::setw(HEX_WIDTH) << std::setfill(FILL_CHAR) << (int)hash[i];
    }

    std::string serverSocketName = hashStr.str().substr(0, SERVER_SOCKET_NAME_LENGTH);

    return serverSocketName;
}

std::shared_ptr<AbilityConnectionSession> AbilityConnectionManager::GetAbilityConnectionSession(const int32_t sessionId)
{
    if (sessionId <= 0) {
        HILOGE("invaild session id");
        return nullptr;
    }

    std::shared_lock<std::shared_mutex> readLock(sessionMutex_);
    auto iter = sessionMap_.find(sessionId);
    if (iter == sessionMap_.end()) {
        HILOGE("no match session, sessionId is %{public}d", sessionId);
        return nullptr;
    }
    return iter->second;
}

std::shared_ptr<AbilityConnectionSession> AbilityConnectionManager::GetAbilityConnectionSessionByStreamId(
    const int32_t streamId)
{
    HILOGI("called. streamId is %{public}d", streamId);
    int32_t sessionId = -1;
    {
        std::shared_lock<std::shared_mutex> readLock(streamMutex_);
        sessionId = streamMap_[streamId];
    }
    return GetAbilityConnectionSession(sessionId);
}

int32_t AbilityConnectionManager::UpdateClientSession(const AbilityConnectionSessionInfo& sessionInfo,
    const int32_t sessionId)
{
    std::lock_guard<std::mutex> lock(connectSessionMutex_);
    if (clientSessionMap_.count(sessionInfo) > 0 || serverSessionMap_.count(sessionInfo) > 0) {
        HILOGE("The same session is being connected. sessionId is %{public}d", sessionId);
        return SAME_SESSION_IS_CONNECTING;
    }
    HILOGI("The current client session has not initiated a connection. sessionId is %{public}d", sessionId);
    clientSessionMap_[sessionInfo] = sessionId;
    return ERR_OK;
}
 
int32_t AbilityConnectionManager::UpdateServerSession(const AbilityConnectionSessionInfo& sessionInfo,
    const int32_t sessionId)
{
    HILOGI("called. sessionId is %{public}d", sessionId);
    std::lock_guard<std::mutex> lock(connectSessionMutex_);
    if (serverSessionMap_.count(sessionInfo) > 0) {
        HILOGE("The same server session is being connected.");
        return SAME_SESSION_IS_CONNECTING;
    }
    auto iter = clientSessionMap_.find(sessionInfo);
    if (iter == clientSessionMap_.end()) {
        HILOGI("no same session is connecting.");
        serverSessionMap_[sessionInfo] = sessionId;
        return ERR_OK;
    }
 
    if (GetSessionToken(sessionId) > GetSessionToken(iter->second)) {
        HILOGI("select client session continue to connect.");
        return SAME_SESSION_IS_CONNECTING;
    }
    HILOGI("select server session continue to connect.");
    serverSessionMap_[sessionInfo] = sessionId;
    return ERR_OK;
}
 
int32_t AbilityConnectionManager::DeleteConnectSession(const AbilityConnectionSessionInfo& sessionInfo,
    int32_t sessionId)
{
    HILOGI("called. sessionId is %{public}d", sessionId);
    std::lock_guard<std::mutex> lock(connectSessionMutex_);
    auto clientIt = clientSessionMap_.find(sessionInfo);
    if (clientIt != clientSessionMap_.end() && clientIt->second == sessionId) {
        HILOGI("session removed from clientSessionMap_");
        clientSessionMap_.erase(clientIt);
        return ERR_OK;
    }
    auto serverIt = serverSessionMap_.find(sessionInfo);
    if (serverIt != serverSessionMap_.end() && serverIt->second == sessionId) {
        HILOGI("session removed from serverSessionMap_");
        serverSessionMap_.erase(serverIt);
        return ERR_OK;
    }
    HILOGI("The current session has not initiated a connection.");
    return ERR_OK;
}
 
std::string AbilityConnectionManager::GetSessionToken(int32_t sessionId)
{
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return "";
    }
    std::string dmsServertoken = connectionSesion->GetServerToken();
    HILOGI("sessionId is %{public}d, token is %{public}s", sessionId, dmsServertoken.c_str());
    return dmsServertoken;
}

int32_t AbilityConnectionManager::NotifyPeerVersion(int32_t sessionId, int32_t version)
{
    HILOGI("called, sessionId is %{public}d, peer version is %{public}d", sessionId, version);
    auto connectionSesion = GetAbilityConnectionSession(sessionId);
    if (connectionSesion == nullptr) {
        HILOGE("sessionId is invalid parameter");
        return INVALID_PARAMETERS_ERR;
    }
    
    return connectionSesion->HandlePeerVersion(version);
}
}  // namespace DistributedCollab
}  // namespace OHOS