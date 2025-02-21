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

#ifndef OHOS_DISTRIBUTED_ABILITY_CONNECTION_MANAGER_H
#define OHOS_DISTRIBUTED_ABILITY_CONNECTION_MANAGER_H

#include <atomic>
#include <map>
#include <memory>

#include "ability_connection_info.h"
#include "ability_connection_session.h"
#include "ability_connection_session_listener.h"
#include "single_instance.h"
#include "ability_info.h"
#include "js_ability_connection_session_listener.h"

namespace OHOS {
namespace DistributedCollab {
class AbilityConnectionManager {
    DECLARE_SINGLE_INSTANCE_BASE(AbilityConnectionManager);
public:
    AbilityConnectionManager();
    ~AbilityConnectionManager();
    
    int32_t CreateSession(const std::string& serverId, std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo,
        PeerInfo& peerInfo, ConnectOption& opt, int32_t& sessionId);
    int32_t DestroySession(int32_t sessionId);

    int32_t getPeerInfoBySessionId(int32_t sessionId, PeerInfo& peerInfo);

    using ConnectCallback = std::function<void(const ConnectResult& result)>;
    int32_t ConnectSession(int32_t sessionId, ConnectCallback& callback);
    int32_t DisconnectSession(int32_t sessionId);

    int32_t AcceptConnect(int32_t sessionId, const std::string& token);
    int32_t Reject(const std::string& token, const std::string& reason);

    int32_t NotifyCollabResult(int32_t sessionId, int32_t result, const std::string& peerServerName,
        const std::string& dmsServerToken, const std::string& reason);
    int32_t NotifyDisconnect(int32_t sessionId);

    int32_t SendMessage(int32_t sessionId, const std::string& msg);
    int32_t SendData(int32_t sessionId, const std::shared_ptr<AVTransDataBuffer>& buffer);
    int32_t SendImage(int32_t sessionId, const std::shared_ptr<Media::PixelMap> &pixelMapPtr);
    int32_t SendFile(int32_t sessionId, const std::vector<std::string>& sFiles,
        const std::vector<std::string>& dFiles);

    int32_t CreateStream(int32_t sessionId, const StreamParams& param, int32_t& streamId);
    int32_t SetSurfaceId(int32_t streamId, const std::string& surfaceId, const SurfaceParams& param);
    int32_t GetSurfaceId(int32_t streamId, const SurfaceParams& param, std::string& surfaceId);
    int32_t UpdateSurfaceParam(int32_t streamId, const SurfaceParams& param);
    int32_t DestroyStream(int32_t streamId);
    int32_t StartStream(int32_t streamId);
    int32_t StopStream(int32_t streamId);
    int32_t RegisterEventCallback(int32_t sessionId, const std::string& eventType,
        const std::shared_ptr<JsAbilityConnectionSessionListener>& listener);
    int32_t UnregisterEventCallback(int32_t sessionId, const std::string& eventType);
    int32_t NotifyWifiOpen(int32_t sessionId);
    int32_t RegisterEventCallback(int32_t sessionId,
        const std::shared_ptr<IAbilityConnectionSessionListener>& listener);
    int32_t UpdateClientSession(const AbilityConnectionSessionInfo& sessionInfo,
        const int32_t sessionId);
    int32_t DeleteClientSession(const AbilityConnectionSessionInfo& sessionInfo);
    int32_t UpdateServerSession(const AbilityConnectionSessionInfo& sessionInfo,
        const int32_t sessionId);
    int32_t DeleteConnectSession(const AbilityConnectionSessionInfo& sessionInfo, int32_t sessionId);
    std::string GetSessionToken(int32_t sessionId);

private:
    std::shared_mutex sessionMutex_;
    std::map <int32_t, std::shared_ptr<AbilityConnectionSession>> sessionMap_;
    std::atomic<int32_t> sessionId_ = 100;
    std::atomic<int32_t> streamId_ = 1000;

    std::shared_mutex streamMutex_;
    std::map<int32_t, int32_t> streamMap_;

    std::mutex connectSessionMutex_;
    //Record the client session that invokes connect.
    std::map<AbilityConnectionSessionInfo, int32_t> clientSessionMap_;
    //Record the server session that invokes acceptConnect.
    std::map<AbilityConnectionSessionInfo, int32_t> serverSessionMap_;

private:
    bool IsVaildPeerInfo(const PeerInfo& peerInfo);
    bool IsVaildConnectOption(const ConnectOption& opt);
    std::string GetServerSocketName(int32_t userId, int32_t pid, const std::string& bundle);
    std::shared_ptr<AbilityConnectionSession> GetAbilityConnectionSession(const int32_t sessionId);
    std::shared_ptr<AbilityConnectionSession> GetAbilityConnectionSessionByStreamId(const int32_t streamId);
    bool FindExistingSession(const PeerInfo& peerInfo, const PeerInfo& localInfo, int32_t& sessionId);
    bool CheckStreamIsRegistered(int32_t sessionId);
};
} // namespace DistributedCollab
} // namespace OHOS
#endif //OHOS_DISTRIBUTED_ABILITY_CONNECTION_MANAGER_H