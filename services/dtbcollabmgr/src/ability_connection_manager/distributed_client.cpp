/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "if_system_ability_manager.h"
#include "system_ability.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
const std::string TAG = "DistributedClient";
const std::u16string DMS_PROXY_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
}
sptr<IRemoteObject> DistributedClient::GetDmsProxy()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("fail to get samgr");
        return nullptr;
    }
    return samgrProxy->CheckSystemAbility(DISTRIBUTED_SCHED_SA_ID);
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
}  // namespace AAFwk
}  // namespace OHOS