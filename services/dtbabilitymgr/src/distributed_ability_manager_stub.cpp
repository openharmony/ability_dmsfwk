/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "distributed_ability_manager_stub.h"

#include <iosfwd>
#include <memory>
#include <string>
#include <utility>

#include "accesstoken_kit.h"
#include "base/continuationmgr_log.h"
#include "base/parcel_helper.h"
#include "continuation_extra_params.h"
#include "device_connect_status.h"
#include "iremote_object.h"
#include "ipc_skeleton.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace OHOS::Security;
namespace {
const std::string TAG = "ContinuationManagerStub";
const std::string PERMISSION_DISTRIBUTED_DATASYNC = "ohos.permission.DISTRIBUTED_DATASYNC";
}

DistributedAbilityManagerStub::DistributedAbilityManagerStub()
{
    funcsMap_[static_cast<uint32_t>(IDAbilityManagerInterfaceCode::REGISTER)] =
        &DistributedAbilityManagerStub::RegisterInner;
    funcsMap_[static_cast<uint32_t>(IDAbilityManagerInterfaceCode::UNREGISTER)] =
        &DistributedAbilityManagerStub::UnregisterInner;
    funcsMap_[static_cast<uint32_t>(IDAbilityManagerInterfaceCode::REGISTER_DEVICE_SELECTION_CALLBACK)] =
        &DistributedAbilityManagerStub::RegisterDeviceSelectionCallbackInner;
    funcsMap_[static_cast<uint32_t>(IDAbilityManagerInterfaceCode::UNREGISTER_DEVICE_SELECTION_CALLBACK)] =
        &DistributedAbilityManagerStub::UnregisterDeviceSelectionCallbackInner;
    funcsMap_[static_cast<uint32_t>(IDAbilityManagerInterfaceCode::UPDATE_CONNECT_STATUS)] =
        &DistributedAbilityManagerStub::UpdateConnectStatusInner;
    funcsMap_[static_cast<uint32_t>(IDAbilityManagerInterfaceCode::START_DEVICE_MANAGER)] =
        &DistributedAbilityManagerStub::StartDeviceManagerInner;
}

DistributedAbilityManagerStub::~DistributedAbilityManagerStub()
{
    funcsMap_.clear();
}

int32_t DistributedAbilityManagerStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGI("code = %{public}u", code);
    auto iter = funcsMap_.find(code);
    if (iter != funcsMap_.end()) {
        auto func = iter->second;
        if (!EnforceInterfaceToken(data)) {
            HILOGE("interface token check failed!");
            return DMS_PERMISSION_DENIED;
        }
        uint32_t accessToken = IPCSkeleton::GetCallingTokenID();
        if (!VerifyPermission(accessToken, PERMISSION_DISTRIBUTED_DATASYNC)) {
            HILOGE("DISTRIBUTED_DATASYNC permission check failed!");
            return DMS_PERMISSION_DENIED;
        }
        if (func != nullptr) {
            return (this->*func)(data, reply);
        } else {
            HILOGE("func is nullptr");
            return ERR_NULL_OBJECT;
        }
    }
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

bool DistributedAbilityManagerStub::EnforceInterfaceToken(MessageParcel& data)
{
    std::u16string interfaceToken = data.ReadInterfaceToken();
    return interfaceToken == IDistributedAbilityManager::GetDescriptor();
}

int32_t DistributedAbilityManagerStub::RegisterInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t flag = VALUE_NULL;
    PARCEL_READ_HELPER(data, Int32, flag);
    int32_t token = -1;
    ContinuationExtraParams* continuationExtraParams = nullptr;
    if (flag == VALUE_OBJECT) {
        continuationExtraParams = data.ReadParcelable<ContinuationExtraParams>();
        if (continuationExtraParams == nullptr) {
            HILOGE("ContinuationExtraParams readParcelable failed!");
            return ERR_NULL_OBJECT;
        }
    }
    std::shared_ptr<ContinuationExtraParams> continuationExtraParamsPtr(continuationExtraParams);
    int32_t result = Register(continuationExtraParamsPtr, token);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    PARCEL_WRITE_HELPER(reply, Int32, token);
    return ERR_NONE;
}

int32_t DistributedAbilityManagerStub::UnregisterInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t token = -1;
    PARCEL_READ_HELPER(data, Int32, token);
    int32_t result = Unregister(token);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    return ERR_NONE;
}

int32_t DistributedAbilityManagerStub::RegisterDeviceSelectionCallbackInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t token = -1;
    PARCEL_READ_HELPER(data, Int32, token);
    std::string cbType;
    PARCEL_READ_HELPER(data, String, cbType);
    if (cbType.empty()) {
        HILOGE("cbType unmarshalling failed!");
        return ERR_NULL_OBJECT;
    }
    sptr<IRemoteObject> notifier = data.ReadRemoteObject();
    if (notifier == nullptr) {
        HILOGE("notifier unmarshalling failed!");
        return ERR_NULL_OBJECT;
    }
    int32_t result = RegisterDeviceSelectionCallback(token, cbType, notifier);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    return ERR_NONE;
}

int32_t DistributedAbilityManagerStub::UnregisterDeviceSelectionCallbackInner(MessageParcel& data,
    MessageParcel& reply)
{
    int32_t token = -1;
    PARCEL_READ_HELPER(data, Int32, token);
    std::string cbType;
    PARCEL_READ_HELPER(data, String, cbType);
    if (cbType.empty()) {
        HILOGE("cbType unmarshalling failed!");
        return ERR_NULL_OBJECT;
    }
    int32_t result = UnregisterDeviceSelectionCallback(token, cbType);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    return ERR_NONE;
}

int32_t DistributedAbilityManagerStub::UpdateConnectStatusInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t token = -1;
    PARCEL_READ_HELPER(data, Int32, token);
    std::string deviceId;
    PARCEL_READ_HELPER(data, String, deviceId);
    DeviceConnectStatus deviceConnectStatus = static_cast<DeviceConnectStatus>(data.ReadInt32());
    int32_t result = UpdateConnectStatus(token, deviceId, deviceConnectStatus);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    return ERR_NONE;
}

int32_t DistributedAbilityManagerStub::StartDeviceManagerInner(MessageParcel& data, MessageParcel& reply)
{
    int32_t token = -1;
    PARCEL_READ_HELPER(data, Int32, token);
    int32_t flag = VALUE_NULL;
    PARCEL_READ_HELPER(data, Int32, flag);
    ContinuationExtraParams* continuationExtraParams = nullptr;
    if (flag == VALUE_OBJECT) {
        continuationExtraParams = data.ReadParcelable<ContinuationExtraParams>();
        if (continuationExtraParams == nullptr) {
            HILOGE("ContinuationExtraParams readParcelable failed!");
            return ERR_NULL_OBJECT;
        }
    }
    std::shared_ptr<ContinuationExtraParams> continuationExtraParamsPtr(continuationExtraParams);
    int32_t result = StartDeviceManager(token, continuationExtraParamsPtr);
    HILOGI("result = %{public}d", result);
    PARCEL_WRITE_HELPER(reply, Int32, result);
    return ERR_NONE;
}

bool DistributedAbilityManagerStub::VerifyPermission(uint32_t accessToken, const std::string& permissionName) const
{
    int32_t result = AccessToken::AccessTokenKit::VerifyAccessToken(accessToken, permissionName);
    if (result == AccessToken::PermissionState::PERMISSION_DENIED) {
        HILOGE("permission denied, permissionName:%{public}s", permissionName.c_str());
        return false;
    }
    HILOGD("permission matched.");
    return true;
}

} // namespace DistributedSchedule
} // namespace OHOS