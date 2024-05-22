/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#include "distributed_parcel_helper.h"
#include "if_system_ability_manager.h"
#include "ipc_skeleton.h"
#include "iservice_registry.h"
#include "string_ex.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::u16string DMS_PROXY_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
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

int32_t DistributedClient::RegisterDSchedEventListener(const uint8_t& type,
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
    PARCEL_WRITE_HELPER(data, RemoteObject, obj->AsObject());
    PARCEL_TRANSACT_SYNC_RET_INT(remote, REGISTER_DSCHED_EVENT_LISTENER, data, reply);
}

int32_t DistributedClient::UnRegisterDSchedEventListener(const uint8_t& type,
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
    PARCEL_WRITE_HELPER(data, RemoteObject, obj->AsObject());
    PARCEL_TRANSACT_SYNC_RET_INT(remote, UNREGISTER_DSCHED_EVENT_LISTENER, data, reply);
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
    int32_t ret = remote->SendRequest(GET_CONTINUE_INFO, data, reply, option);
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
}  // namespace DistributedSchedule
}  // namespace OHOS