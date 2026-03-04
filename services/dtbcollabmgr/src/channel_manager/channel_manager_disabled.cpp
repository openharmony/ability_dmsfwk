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

#include "channel_manager.h"
#include "dtbcollabmgr_log.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
const std::string TAG = "ChannelManagerDisabled";
constexpr int32_t SERVICE_DISABLED_ERR = 401;
}

IMPLEMENT_SINGLE_INSTANCE(ChannelManager);

int32_t ChannelManager::Init(const std::string& ownerName)
{
    HILOGI("Distributed sched service disabled, Init returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

void ChannelManager::DeInit()
{
    HILOGI("Distributed sched service disabled, DeInit doing nothing.");
}

int32_t ChannelManager::GetVersion()
{
    HILOGI("Distributed sched service disabled, GetVersion returning 0.");
    return 0;
}

int32_t ChannelManager::CreateServerChannel(const std::string& channelName,
    const ChannelDataType dataType, const ChannelPeerInfo& peerInfo)
{
    HILOGI("Distributed sched service disabled, CreateServerChannel returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t ChannelManager::CreateClientChannel(const std::string& channelName,
    const ChannelDataType dataType, const ChannelPeerInfo& peerInfo)
{
    HILOGI("Distributed sched service disabled, CreateClientChannel returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

bool ChannelManager::isValidChannelId(const int32_t channelId)
{
    HILOGI("Distributed sched service disabled, isValidChannelId returning false.");
    return false;
}

int32_t ChannelManager::DeleteChannel(const int32_t channelId)
{
    HILOGI("Distributed sched service disabled, DeleteChannel returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

void ChannelManager::ClearSendTask(int32_t channelId)
{
    HILOGI("Distributed sched service disabled, ClearSendTask doing nothing.");
}

int32_t ChannelManager::RegisterChannelListener(const int32_t channelId,
    const std::shared_ptr<IChannelListener> listener)
{
    HILOGI("Distributed sched service disabled, RegisterChannelListener returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t ChannelManager::ConnectChannel(const int32_t channelId)
{
    HILOGI("Distributed sched service disabled, ConnectChannel returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t ChannelManager::SendBytes(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& data)
{
    HILOGI("Distributed sched service disabled, SendBytes returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t ChannelManager::SendStream(const int32_t channelId, const std::shared_ptr<AVTransStreamData>& data)
{
    HILOGI("Distributed sched service disabled, SendStream returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t ChannelManager::SendMessage(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& data)
{
    HILOGI("Distributed sched service disabled, SendMessage returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t ChannelManager::SendMessageSync(const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& data)
{
    HILOGI("Distributed sched service disabled, SendMessageSync returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

int32_t ChannelManager::SendFile(const int32_t channelId, const std::vector<std::string>& sFiles,
    const std::vector<std::string>& dFiles)
{
    HILOGI("Distributed sched service disabled, SendFile returning SERVICE_DISABLED_ERR.");
    return SERVICE_DISABLED_ERR;
}

void ChannelManager::OnSocketError(int32_t socketId, const int32_t errorCode)
{
    HILOGI("Distributed sched service disabled, OnSocketError doing nothing.");
}

void ChannelManager::OnSocketConnected(int32_t socketId, const PeerSocketInfo& info)
{
    HILOGI("Distributed sched service disabled, OnSocketConnected doing nothing.");
}

void ChannelManager::OnSocketClosed(int32_t socketId, const ShutdownReason& reason)
{
    HILOGI("Distributed sched service disabled, OnSocketClosed doing nothing.");
}

void ChannelManager::OnBytesReceived(int32_t socketId, const void* data, const uint32_t dataLen)
{
    HILOGI("Distributed sched service disabled, OnBytesReceived doing nothing.");
}

void ChannelManager::OnMessageReceived(int32_t socketId, const void* data, const uint32_t dataLen)
{
    HILOGI("Distributed sched service disabled, OnMessageReceived doing nothing.");
}

void ChannelManager::OnStreamReceived(int32_t socketId, const StreamData* data,
    const StreamData* ext, const StreamFrameInfo* param)
{
    HILOGI("Distributed sched service disabled, OnStreamReceived doing nothing.");
}

void ChannelManager::OnFileEventReceived(int32_t socketId, FileEvent* event)
{
    HILOGI("Distributed sched service disabled, OnFileEventReceived doing nothing.");
}

const char* ChannelManager::GetRecvPathFromUser()
{
    HILOGI("Distributed sched service disabled, GetRecvPathFromUser returning empty string.");
    return "";
}

} // namespace DistributedCollab
} // namespace OHOS
