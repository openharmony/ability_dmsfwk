/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#include "distributed_client.h"

#include "ability_connection_manager_listener.h"
#include "parcel_helper.h"
#include "ipc_skeleton.h"
#include "dtbcollabmgr_log.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "system_ability.h"
#include <chrono>

namespace OHOS {
namespace DistributedCollab {
namespace {
const std::string TAG = "DistributedClient";
const std::u16string DMS_PROXY_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
static constexpr int32_t SA_TIMEOUT = 4;
}

DistributedClient::~DistributedClient()
{
    HILOGI("destroy DistributedClient");
    std::lock_guard<std::mutex> lock(mtx_);
    if (listener_) {
        auto samgrProxy =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
        if (samgrProxy != nullptr) {
            HILOGI("unregister listener");
            samgrProxy->UnSubscribeSystemAbility(DISTRIBUTED_SCHED_SA_ID, listener_);
        }
    }
    listener_ = nullptr;
}

sptr<IRemoteObject> DistributedClient::GetDmsProxy()
{
    auto samgrProxy =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("fail to get samgr");
        return nullptr;
    }
    sptr<IRemoteObject> dmsProxy = samgrProxy->CheckSystemAbility(DISTRIBUTED_SCHED_SA_ID);
    if (dmsProxy != nullptr) {
        return dmsProxy;
    }
    // not online, register listener and wait
    if (listener_ == nullptr) {
        listener_ = sptr<SystemAbilityStatusChangeListener>::MakeSptr(this);
    }
    int32_t ret = samgrProxy->SubscribeSystemAbility(DISTRIBUTED_SCHED_SA_ID, listener_);
    if (ret != 0) {
        HILOGE("fail to subscribe system ability");
        return nullptr;
    }
    // waiting for service online
    std::unique_lock<std::mutex> lock(mtx_);
    if (!cv_.wait_for(lock, std::chrono::seconds(SA_TIMEOUT),
    [this]() { return callbackReceived_; })) {
        HILOGE("wait for system ability timeout");
        return nullptr;
    }
    dmsProxy = samgrProxy->CheckSystemAbility(DISTRIBUTED_SCHED_SA_ID);
    if (dmsProxy == nullptr) {
        HILOGE("fail to get system ability after callback");
        return nullptr;
    }
    return dmsProxy;
}

void DistributedClient::SystemAbilityStatusChangeListener::OnAddSystemAbility(
    int32_t systemAbilityId, const std::string& deviceId)
{
    HILOGI("OnAddSystemAbility, %{public}d", systemAbilityId);
    if (systemAbilityId == DISTRIBUTED_SCHED_SA_ID && client_ != nullptr) {
        std::unique_lock<std::mutex> lock(client_->mtx_);
        client_->callbackReceived_ = true;
        client_->cv_.notify_all();
    }
}

void DistributedClient::SystemAbilityStatusChangeListener::OnRemoveSystemAbility(int32_t systemAbilityId,
    const std::string& deviceId)
{
    HILOGI("SystemAbility removed: %{public}d", systemAbilityId);
}

sptr<IRemoteObject> DistributedClient::SystemAbilityStatusChangeListener::AsObject()
{
    return nullptr;
}

int32_t DistributedClient::CollabMission(int32_t sessionId, const std::string& serverSocketName,
    const AbilityConnectionSessionInfo& sessionInfo, const ConnectOption& options, const std::string& token)
{
    sptr<IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOGW("remote is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGW("write token failed");
        return ERR_FLATTEN_OBJECT;
    }

    sptr<IAbilityConnectionManager> listener(new AbilityConnectionManagerListener);
    
    PARCEL_WRITE_HELPER(data, Int32, sessionId);
    PARCEL_WRITE_HELPER(data, String, serverSocketName);
    PARCEL_WRITE_HELPER(data, Parcelable, &sessionInfo.localInfo_);
    PARCEL_WRITE_HELPER(data, Parcelable, &sessionInfo.peerInfo_);
    PARCEL_WRITE_HELPER(data, Parcelable, &options);
    PARCEL_WRITE_HELPER(data, String, token);
    PARCEL_WRITE_HELPER(data, RemoteObject, listener->AsObject());
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, COLLAB_MESSION, data, reply);
}

int32_t DistributedClient::NotifyPrepareResult(const std::string& token, int32_t result,
    int32_t sessionId, const std::string& serverSocketName)
{
    HILOGD("called");
    sptr<IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOGW("remote is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGW("write token failed");
        return ERR_FLATTEN_OBJECT;
    }

    PARCEL_WRITE_HELPER(data, String, token);
    PARCEL_WRITE_HELPER(data, Int32, result);
    PARCEL_WRITE_HELPER(data, Int32, sessionId);
    PARCEL_WRITE_HELPER(data, String, serverSocketName);
    sptr<IAbilityConnectionManager> listener(new AbilityConnectionManagerListener);
    PARCEL_WRITE_HELPER(data, RemoteObject, listener->AsObject());
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, NOTIFY_PREPARE_RESULT, data, reply);
}

int32_t DistributedClient::NotifyCloseCollabSession(const std::string& token)
{
    HILOGD("called.");
    sptr<IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOGW("remote is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGW("write token failed");
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, token);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, BNOTIFY_CLOSE_COLLAB_SESSION, data, reply);
}

int32_t DistributedClient::NotifyRejectReason(const std::string& token, const std::string& reason)
{
    HILOGD("called.");
    sptr<IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOGW("remote is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGW("write token failed");
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, token);
    PARCEL_WRITE_HELPER(data, String, reason);
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, NOTIFY_REJECT_REASON, data, reply);
}

int32_t DistributedClient::GetPeerVersion(int32_t sessionId, const std::string& peerDeviceId,
    const std::string dmsServerToken)
{
    HILOGD("called.");
    sptr<IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOGW("remote is nullptr");
        return INVALID_PARAMETERS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGW("write token failed");
        return ERR_FLATTEN_OBJECT;
    }
    
    sptr<IAbilityConnectionManager> listener(new AbilityConnectionManagerListener);
    PARCEL_WRITE_HELPER(data, Int32, sessionId);
    PARCEL_WRITE_HELPER(data, String, peerDeviceId);
    PARCEL_WRITE_HELPER(data, String, dmsServerToken);
    PARCEL_WRITE_HELPER(data, RemoteObject, listener->AsObject());
    MessageParcel reply;
    PARCEL_TRANSACT_SYNC_RET_INT(remote, GET_SINK_COLLAB_VERSION, data, reply);
}
}  // namespace AAFwk
}  // namespace OHOS