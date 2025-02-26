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

#include "dms_client.h"

#include "ability_manager_errors.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

#include "distributed_parcel_helper.h"
#include "distributedsched_ipc_interface_code.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::u16string DMS_PROXY_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
constexpr uint32_t DSCHED_EVENT_MAX_NUM = 10000;
}

sptr<IRemoteObject> DistributedClient::GetDmsProxy()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOG_ERROR("fail to get samgr.");
        return nullptr;
    }
    return samgrProxy->CheckSystemAbility(DISTRIBUTED_SCHED_SA_ID);
}

int32_t DistributedClient::RegisterDSchedEventListener(const DSchedEventType& type,
    const sptr<IDSchedEventListener>& obj)
{
    HILOG_INFO("RegisterDSchedEventListener called");
    sptr<IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOG_ERROR("remote system ablity is nullptr");
        return AAFwk::INVALID_PARAMETERS_ERR;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Uint8, type);
    if (obj == nullptr) {
        HILOG_ERROR("Received null IDSchedEventListener object");
        return AAFwk::INVALID_PARAMETERS_ERR;
    }
    PARCEL_WRITE_HELPER(data, RemoteObject, obj->AsObject());
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_DSCHED_EVENT_LISTENER),
        data, reply);
}

int32_t DistributedClient::UnRegisterDSchedEventListener(const DSchedEventType& type,
    const sptr<IDSchedEventListener>& obj)
{
    HILOG_INFO("UnRegisterDSchedEventListener called");
    sptr<IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOG_ERROR("remote system ablity is null");
        return AAFwk::INVALID_PARAMETERS_ERR;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOG_DEBUG("write interface token failed.");
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Uint8, type);
    if (obj == nullptr) {
        HILOG_ERROR("Received null IDSchedEventListener object");
        return AAFwk::INVALID_PARAMETERS_ERR;
    }
    PARCEL_WRITE_HELPER(data, RemoteObject, obj->AsObject());
    PARCEL_TRANSACT_SYNC_RET_INT(remote, static_cast<uint32_t>(IDSchedInterfaceCode::UNREGISTER_DSCHED_EVENT_LISTENER),
        data, reply);
}

int32_t DistributedClient::ConnectDExtAbility(std::string& bundleName, std::string& abilityName, int32_t userId)
{
    HILOG_INFO("call begin.");
    sptr<IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOG_ERROR("remote system ablity is null");
        return AAFwk::INVALID_PARAMETERS_ERR;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOG_DEBUG("write interface token failed.");
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, String, bundleName);
    PARCEL_WRITE_HELPER(data, String, abilityName);
    PARCEL_WRITE_HELPER(data, Int32, userId);
 
    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(IDSchedInterfaceCode::DSCHED_START_DEXTENSION),
        data, reply, option);
    HILOG_INFO("call end.");
    return ret;
}

int32_t DistributedClient::GetContinueInfo(ContinueInfo &continueInfo)
{
    HILOG_INFO("%{public}s called", __func__);
    sptr<IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOG_ERROR("remote system ablity is null");
        return AAFwk::INVALID_PARAMETERS_ERR;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOG_DEBUG("write interface token failed.");
        return ERR_FLATTEN_OBJECT;
    }

    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(IDSchedInterfaceCode::GET_CONTINUE_INFO),
        data, reply, option);
    if (ret != ERR_NONE) {
        HILOG_ERROR("sendRequest fail, error: %{public}d", ret);
        return ret;
    }
    continueInfo.dstNetworkId_ = reply.ReadString();
    continueInfo.srcNetworkId_ = reply.ReadString();
    if (continueInfo.dstNetworkId_ == "") {
        HILOG_ERROR("read type failed!");
        return ERR_FLATTEN_OBJECT;
    }
    return ret;
}

int32_t DistributedClient::GetDecodeDSchedEventNotify(MessageParcel &reply, EventNotify &event)
{
    event.eventResult_ = reply.ReadInt32();
    event.srcNetworkId_ = reply.ReadString();
    event.dstNetworkId_ = reply.ReadString();
    event.srcBundleName_ = reply.ReadString();
    event.srcModuleName_ = reply.ReadString();
    event.srcAbilityName_ = reply.ReadString();
    event.destBundleName_ = reply.ReadString();
    event.destModuleName_ = reply.ReadString();
    event.destAbilityName_ = reply.ReadString();
    event.dSchedEventType_ = static_cast<DSchedEventType>(reply.ReadInt32());
    event.state_ = static_cast<DSchedEventState>(reply.ReadInt32());
    return ERR_OK;
}

int32_t DistributedClient::GetDSchedEventInfo(const DSchedEventType &type, std::vector<EventNotify> &events)
{
    HILOG_INFO("%{public}s called", __func__);
    sptr<IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOG_ERROR("remote system ablity is null");
        return ERR_FLATTEN_OBJECT;
    }
    MessageParcel data;
    MessageParcel reply;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOG_DEBUG("write interface token failed.");
        return ERR_FLATTEN_OBJECT;
    }
    PARCEL_WRITE_HELPER(data, Uint32, type);

    MessageOption option;
    int32_t ret = remote->SendRequest(static_cast<uint32_t>(IDSchedInterfaceCode::GET_DSCHED_EVENT_INFO),
        data, reply, option);
    if (ret != ERR_OK) {
        HILOG_ERROR("sendRequest fail, ret: %{public}d", ret);
        return ret;
    }

    ret = reply.ReadInt32();
    if (ret != ERR_OK) {
        HILOG_ERROR("Proxy get dms eventInfos from dms service fail, ret: %{public}d", ret);
        return ret;
    }

    uint32_t eventNum = reply.ReadUint32();
    if (eventNum > DSCHED_EVENT_MAX_NUM) {
        HILOG_ERROR("Proxy get dms eventInfos num %{public}u is invalid.", eventNum);
        return AAFwk::INVALID_PARAMETERS_ERR;
    }
    for (uint32_t i = 0; i < eventNum; i++) {
        EventNotify event;
        GetDecodeDSchedEventNotify(reply, event);
        events.emplace_back(event);
    }
    return ret;
}
}  // namespace DistributedSchedule
}  // namespace OHOS