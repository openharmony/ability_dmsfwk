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
#include "dtbcollabmgr_log.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
const std::string TAG = "AbilityConnectionManagerDisabled";
constexpr int32_t SERVICE_DISABLED_ERR = 401;
}

IMPLEMENT_SINGLE_INSTANCE(AbilityConnectionManager);

AbilityConnectionManager::AbilityConnectionManager()
{
    HILOGI("Distributed sched service disabled, AbilityConnectionManager stub created.");
}

AbilityConnectionManager::~AbilityConnectionManager()
{
    HILOGI("AbilityConnectionManager stub destroyed.");
}

int32_t AbilityConnectionManager::CreateSession(const std::string& serverId,
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo, PeerInfo& peerInfo,
    ConnectOption& opt, int32_t& sessionId)
{
    HILOGI("Distributed sched service disabled, CreateSession returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::DestroySession(int32_t sessionId)
{
    HILOGI("Distributed sched service disabled, DestroySession returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::getPeerInfoBySessionId(int32_t sessionId, PeerInfo& peerInfo)
{
    HILOGI("Distributed sched service disabled, getPeerInfoBySessionId returning SERVICE_DISABLED_ERR.");
    peerInfo = PeerInfo();
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::ConnectSession(int32_t sessionId, ConnectCallback& callback)
{
    HILOGI("Distributed sched service disabled, ConnectSession returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::DisconnectSession(int32_t sessionId)
{
    HILOGI("Distributed sched service disabled, DisconnectSession returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::AcceptConnect(int32_t sessionId, const std::string& token)
{
    HILOGI("Distributed sched service disabled, AcceptConnect returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::Reject(const std::string& token, const std::string& reason)
{
    HILOGI("Distributed sched service disabled, Reject returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::NotifyCollabResult(int32_t sessionId, int32_t result,
    const std::string& peerServerName, const std::string& dmsServerToken, const std::string& reason)
{
    HILOGI("Distributed sched service disabled, NotifyCollabResult returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::NotifyDisconnect(int32_t sessionId)
{
    HILOGI("Distributed sched service disabled, NotifyDisconnect returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::SendMessage(int32_t sessionId, const std::string& msg)
{
    HILOGI("Distributed sched service disabled, SendMessage returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::SendData(int32_t sessionId, const std::shared_ptr<AVTransDataBuffer>& buffer)
{
    HILOGI("Distributed sched service disabled, SendData returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::SendImage(int32_t sessionId, const std::shared_ptr<Media::PixelMap>& pixelMapPtr,
    int32_t imageQuality)
{
    HILOGI("Distributed sched service disabled, SendImage returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::SendFile(int32_t sessionId, const std::vector<std::string>& sFiles,
    const std::vector<std::string>& dFiles)
{
    HILOGI("Distributed sched service disabled, SendFile returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::CreateStream(int32_t sessionId, const StreamParams& param, int32_t& streamId)
{
    HILOGI("Distributed sched service disabled, CreateStream returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::SetSurfaceId(int32_t streamId, const std::string& surfaceId,
    const SurfaceParams& param)
{
    HILOGI("Distributed sched service disabled, SetSurfaceId returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::GetSurfaceId(int32_t streamId, const SurfaceParams& param, std::string& surfaceId)
{
    HILOGI("Distributed sched service disabled, GetSurfaceId returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::UpdateSurfaceParam(int32_t streamId, const SurfaceParams& param)
{
    HILOGI("Distributed sched service disabled, UpdateSurfaceParam returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::DestroyStream(int32_t streamId)
{
    HILOGI("Distributed sched service disabled, DestroyStream returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::StartStream(int32_t streamId)
{
    HILOGI("Distributed sched service disabled, StartStream returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::StopStream(int32_t streamId)
{
    HILOGI("Distributed sched service disabled, StopStream returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::RegisterEventCallback(int32_t sessionId, const std::string& eventType,
    const std::shared_ptr<JsAbilityConnectionSessionListener>& listener)
{
    HILOGI("Distributed sched service disabled, RegisterEventCallback returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::UnregisterEventCallback(int32_t sessionId, const std::string& eventType)
{
    HILOGI("Distributed sched service disabled, UnregisterEventCallback returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::NotifyWifiOpen(int32_t sessionId)
{
    HILOGI("Distributed sched service disabled, NotifyWifiOpen returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::RegisterEventCallback(int32_t sessionId,
    const std::shared_ptr<IAbilityConnectionSessionListener>& listener)
{
    HILOGI("Distributed sched service disabled, RegisterEventCallback returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::UnregisterEventCallback(int32_t sessionId)
{
    HILOGI("Distributed sched service disabled, UnregisterEventCallback returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::UpdateClientSession(const AbilityConnectionSessionInfo& sessionInfo,
    const int32_t sessionId)
{
    HILOGI("Distributed sched service disabled, UpdateClientSession returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::DeleteClientSession(const AbilityConnectionSessionInfo& sessionInfo)
{
    HILOGI("Distributed sched service disabled, DeleteClientSession returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::UpdateServerSession(const AbilityConnectionSessionInfo& sessionInfo,
    const int32_t sessionId)
{
    HILOGI("Distributed sched service disabled, UpdateServerSession returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t AbilityConnectionManager::DeleteConnectSession(const AbilityConnectionSessionInfo& sessionInfo,
    int32_t sessionId)
{
    HILOGI("Distributed sched service disabled, DeleteConnectSession returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

std::string AbilityConnectionManager::GetSessionToken(int32_t sessionId)
{
    HILOGI("Distributed sched service disabled, GetSessionToken returning empty string.");
    return "";
}

int32_t AbilityConnectionManager::NotifyPeerVersion(int32_t sessionId, int32_t version)
{
    HILOGI("Distributed sched service disabled, NotifyPeerVersion returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

void AbilityConnectionManager::FinishSessionConnect(int32_t sessionId)
{
    HILOGI("Distributed sched service disabled, FinishSessionConnect doing nothing.");
}

bool AbilityConnectionManager::IsMDMControl()
{
    HILOGI("Distributed sched service disabled, IsMDMControl returning false.");
    return false;
}

} // namespace DistributedCollab
} // namespace OHOS
