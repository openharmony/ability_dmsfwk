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

#include "dschedallconnectmanager_fuzzer.h"

#include "dsched_all_connect_manager.h"
#include "service_collaboration_manager_capi.h"

namespace OHOS {
namespace DistributedSchedule {
void FuzzApplyAdvanceResource(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }
    const std::string peerNetworkId(reinterpret_cast<const char*>(data), size);
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    reqInfoSets.remoteHardwareListSize = *(reinterpret_cast<const uint32_t*>(data));
    reqInfoSets.localHardwareListSize = *(reinterpret_cast<const uint32_t*>(data));
    DSchedAllConnectManager::GetInstance().ApplyAdvanceResource(peerNetworkId, reqInfoSets);
}

void FuzzGetResourceRequest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;
    reqInfoSets.remoteHardwareListSize = *(reinterpret_cast<const uint32_t*>(data));
    reqInfoSets.localHardwareListSize = *(reinterpret_cast<const uint32_t*>(data));
    DSchedAllConnectManager::GetInstance().GetResourceRequest(reqInfoSets);
}

void FuzzPublishServiceState(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }
    const std::string peerNetworkId(reinterpret_cast<const char*>(data), size);
    const std::string extraInfo(reinterpret_cast<const char*>(data), size);
    ServiceCollaborationManagerBussinessStatus state =
        *(reinterpret_cast<const ServiceCollaborationManagerBussinessStatus*>(data));
    DSchedAllConnectManager::GetInstance().PublishServiceState(peerNetworkId, extraInfo, state);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzApplyAdvanceResource(data, size);
    OHOS::DistributedSchedule::FuzzGetResourceRequest(data, size);
    OHOS::DistributedSchedule::FuzzPublishServiceState(data, size);
    return 0;
}