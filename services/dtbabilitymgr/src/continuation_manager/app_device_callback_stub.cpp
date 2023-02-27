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

#include "continuation_manager/app_device_callback_stub.h"

#include <string>

#include "base/continuationmgr_log.h"
#include "base/parcel_helper.h"
#include "distributed_ability_manager_service.h"
#include "ipc_object_stub.h"
#include "ipc_types.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "AppDeviceCallbackStub";
}

int32_t AppDeviceCallbackStub::OnRemoteRequest(uint32_t code, MessageParcel& data,
    MessageParcel& reply, MessageOption& option)
{
    HILOGD("code = %{public}u", code);
    std::u16string descriptor = AppDeviceCallbackInterface::GetDescriptor();
    std::u16string remoteDescriptor = data.ReadInterfaceToken();
    if (descriptor != remoteDescriptor) {
        HILOGE("descriptor check failed");
        return ERR_INVALID_STATE;
    }
    int32_t token = -1;
    switch (code) {
        case AppDeviceCallbackInterface::EVENT_DEVICE_CONNECT: {
            PARCEL_READ_HELPER(data, Int32, token);
            std::vector<ContinuationResult> continuationResults;
            if (!ContinuationResult::ReadContinuationResultsFromParcel(data, continuationResults)) {
                return ERR_FLATTEN_OBJECT;
            }
            int32_t result = OnDeviceConnect(token, continuationResults);
            return result;
        }
        case AppDeviceCallbackInterface::EVENT_DEVICE_DISCONNECT: {
            PARCEL_READ_HELPER(data, Int32, token);
            std::vector<ContinuationResult> continuationResults;
            if (!ContinuationResult::ReadContinuationResultsFromParcel(data, continuationResults)) {
                return ERR_FLATTEN_OBJECT;
            }
            int32_t result = OnDeviceDisconnect(token, continuationResults);
            return result;
        }
        case AppDeviceCallbackInterface::EVENT_DEVICE_CANCEL: {
            int32_t result = OnDeviceCancel();
            return result;
        }
        default: {
            HILOGE("unknown request code, please check");
            return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
        }
    }
}

int32_t AppDeviceCallbackStub::OnDeviceConnect(int32_t token,
    const std::vector<ContinuationResult>& continuationResults)
{
    HILOGD("called.");
    return DistributedAbilityManagerService::GetInstance().OnDeviceConnect(token, continuationResults);
}

int32_t AppDeviceCallbackStub::OnDeviceDisconnect(int32_t token,
    const std::vector<ContinuationResult>& continuationResults)
{
    HILOGD("called.");
    return DistributedAbilityManagerService::GetInstance().OnDeviceDisconnect(token, continuationResults);
}

int32_t AppDeviceCallbackStub::OnDeviceCancel()
{
    HILOGD("called.");
    return DistributedAbilityManagerService::GetInstance().OnDeviceCancel();
}
} // namespace DistributedSchedule
} // namespace OHOS