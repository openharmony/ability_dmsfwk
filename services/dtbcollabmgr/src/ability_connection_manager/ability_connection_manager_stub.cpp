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

#include "ability_connection_manager_stub.h"

#include <iosfwd>
#include <memory>
#include <string>
#include <utility>

#include "dtbcollabmgr_log.h"
#include "ipc_skeleton.h"
#include "iremote_object.h"
#include "parcel_helper.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
const std::string TAG = "AbilityConnectionManagerStub";
}

AbilityConnectionManagerStub::AbilityConnectionManagerStub()
{
    funcsMap_[static_cast<uint32_t>(IAbilityConnectionManager::Message::NOTIFY_COLLAB_RESULT)] =
        &AbilityConnectionManagerStub::NotifyCollabResultInner;
    funcsMap_[static_cast<uint32_t>(IAbilityConnectionManager::Message::NOTIFY_DIS_CONNECT)] =
        &AbilityConnectionManagerStub::NotifyDisconnectInner;
    funcsMap_[static_cast<uint32_t>(IAbilityConnectionManager::Message::NOTIFY_WIFI_OPEN)] =
        &AbilityConnectionManagerStub::NotifyWifiOpenInner;
}

AbilityConnectionManagerStub::~AbilityConnectionManagerStub()
{
    funcsMap_.clear();
}

int32_t AbilityConnectionManagerStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGI("code = %{public}u", code);
    std::u16string desc = AbilityConnectionManagerStub::GetDescriptor();
    std::u16string remoteDesc = data.ReadInterfaceToken();
    if (desc != remoteDesc) {
        std::wstring_convert<std::codecvt_utf8<char16_t>, char16_t> converter;
        std::string utf8strdesc = converter.to_bytes(desc);
        std::string utf8strremoteDesc = converter.to_bytes(remoteDesc);
        HILOGE("remoteDesc is invalid!, desc is %{public}s, remoteDesc is %{public}s",
            utf8strdesc.c_str(), utf8strremoteDesc.c_str());
        return DMS_PERMISSION_DENIED;
    }

    auto iter = funcsMap_.find(code);
    if (iter != funcsMap_.end()) {
        auto func = iter->second;
        if (func != nullptr) {
            return (this->*func)(data, reply);
        }
    }

    HILOGW("OnRemoteRequest default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t AbilityConnectionManagerStub::NotifyCollabResultInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t sessionId = -1;
    PARCEL_READ_HELPER(data, Int32, sessionId);
    bool startResult = false;
    PARCEL_READ_HELPER(data, Bool, startResult);
    std::string peerSocketName = "";
    PARCEL_READ_HELPER(data, String, peerSocketName);
    std::string dmsServerToken = "";
    PARCEL_READ_HELPER(data, String, dmsServerToken);
    std::string reason = "";
    PARCEL_READ_HELPER(data, String, reason);
    int32_t result = NotifyCollabResult(sessionId, startResult, peerSocketName, dmsServerToken, reason);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    return ERR_NONE;
}

int32_t AbilityConnectionManagerStub::NotifyDisconnectInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t sessionId = -1;
    PARCEL_READ_HELPER(data, Int32, sessionId);
    
    int32_t result = NotifyDisconnect(sessionId);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    return ERR_NONE;
}

int32_t AbilityConnectionManagerStub::NotifyWifiOpenInner(MessageParcel& data, MessageParcel& reply)
{
    HILOGI("called.");
    int32_t sessionId = -1;
    PARCEL_READ_HELPER(data, Int32, sessionId);
    
    int32_t result = NotifyWifiOpen(sessionId);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    return ERR_NONE;
}
} // namespace DistributedCollab
} // namespace OHOS