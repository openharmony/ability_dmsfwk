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

#include "js_continuation_state_client.h"
#include "if_system_ability_manager.h"
#include "system_ability_definition.h"
#include "iservice_registry.h"
#include "ipc_skeleton.h"
#include "distributedsched_ipc_interface_code.h"
#include "napi_error_code.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string TAG = "ContinuationStateClient";
    const std::u16string DMS_PROXY_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
}

sptr<IRemoteObject> ContinuationStateClient::GetDmsProxy()
{
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("fail to get samgr.");
        return nullptr;
    }
    return samgrProxy->CheckSystemAbility(DISTRIBUTED_SCHED_SA_ID);
}

int32_t ContinuationStateClient::RegisterContinueStateCallback(const sptr<JsContinuationStateManagerStub> stub)
{
    HILOGI("call");
    JsContinuationStateManagerStub::StateCallbackData callbackData = stub->callbackData_;
    sptr <IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOGE("get dms proxy failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGE("write token failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    if (!data.WriteString(callbackData.bundleName)) {
        HILOGE("write bundleName failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    if (!data.WriteInt32(callbackData.missionId)) {
        HILOGE("write missionId failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    if (!data.WriteString(callbackData.moduleName)) {
        HILOGE("write moduleName failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    if (!data.WriteString(callbackData.abilityName)) {
        HILOGE("write abilityName failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    if (!data.WriteRemoteObject(stub)) {
        HILOGE("write stub failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    MessageParcel reply;
    MessageOption option;
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::CONTINUE_STATE_CALLBACK_REGISTER),
        data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("send register request failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    int32_t result = reply.ReadInt32();
    HILOGI("end, register result is: %{public}d", result);
    return result;
}


int32_t ContinuationStateClient::UnRegisterContinueStateCallback(const sptr<JsContinuationStateManagerStub> stub)
{
    HILOGI("call");
    JsContinuationStateManagerStub::StateCallbackData callbackData = stub->callbackData_;
    sptr <IRemoteObject> remote = GetDmsProxy();
    if (remote == nullptr) {
        HILOGE("get dms proxy failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN)) {
        HILOGE("write token failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }

    if (!data.WriteString(callbackData.bundleName)) {
        HILOGE("write bundleName failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    if (!data.WriteInt32(callbackData.missionId)) {
        HILOGE("write missionId failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    if (!data.WriteString(callbackData.moduleName)) {
        HILOGE("write moduleName failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    if (!data.WriteString(callbackData.abilityName)) {
        HILOGE("write abilityName failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t error = remote->SendRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::CONTINUE_STATE_CALLBACK_UNREGISTER),
            data, reply, option);
    if (error != ERR_NONE) {
        HILOGE("send unregister request failed.");
        return SYSTEM_WORK_ABNORMALLY;
    }
    int32_t result = reply.ReadInt32();
    HILOGI("end, register result is: %{public}d", result);
    return result;
}
} // namespace DistributedSchedule
} // namespace OHOS