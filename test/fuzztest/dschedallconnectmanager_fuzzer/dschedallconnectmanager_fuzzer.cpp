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
namespace {
constexpr uint32_t MIN_SIZE = 38;
constexpr uint32_t UINT32_T_OFFSET = 4;
constexpr uint32_t ENUM_OFFSET = 4;
constexpr uint32_t BOOL_OFFSET = 1;
constexpr uint32_t INT32_T_OFFSET = 4;
constexpr uint32_t CHAR_PONTER_OFFSET = 4;
}

void FuzzApplyAdvanceResource(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < MIN_SIZE)) {
        return;
    }
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;

    reqInfoSets.remoteHardwareListSize = *(reinterpret_cast<const uint32_t*>(data));

    ServiceCollaborationManager_HardwareRequestInfo remoteHardwareListTemp;
    uint32_t offset = UINT32_T_OFFSET;
    remoteHardwareListTemp.hardWareType =
        *(reinterpret_cast<const ServiceCollaborationManagerHardwareType*>(data + offset));
    offset += ENUM_OFFSET;
    remoteHardwareListTemp.canShare = *(reinterpret_cast<const bool*>(data + offset));
    offset += BOOL_OFFSET;
    reqInfoSets.remoteHardwareList = &remoteHardwareListTemp;

    reqInfoSets.localHardwareListSize = *(reinterpret_cast<const uint32_t*>(data + offset));
    offset += UINT32_T_OFFSET;

    ServiceCollaborationManager_HardwareRequestInfo localHardwareListTemp;
    localHardwareListTemp.hardWareType =
        *(reinterpret_cast<const ServiceCollaborationManagerHardwareType*>(data + offset));
    offset += ENUM_OFFSET;
    localHardwareListTemp.canShare = *(reinterpret_cast<const bool*>(data + offset));
    offset += BOOL_OFFSET;
    reqInfoSets.localHardwareList = &localHardwareListTemp;

    ServiceCollaborationManager_CommunicationRequestInfo communicationRequestTemp;
    communicationRequestTemp.minBandwidth = *(reinterpret_cast<const int32_t*>(data + offset));
    offset += INT32_T_OFFSET;
    communicationRequestTemp.maxLatency = *(reinterpret_cast<const int32_t*>(data + offset));
    offset += INT32_T_OFFSET;
    communicationRequestTemp.minLatency = *(reinterpret_cast<const int32_t*>(data + offset));
    offset += INT32_T_OFFSET;
    communicationRequestTemp.maxWaitTime = *(reinterpret_cast<const int32_t*>(data + offset));
    offset += INT32_T_OFFSET;
    communicationRequestTemp.dataType = reinterpret_cast<const char*>(data + offset);
    offset += CHAR_PONTER_OFFSET;
    reqInfoSets.communicationRequest = &communicationRequestTemp;

    const std::string peerNetworkId(reinterpret_cast<const char*>(data + offset), size - MIN_SIZE);
    DSchedAllConnectManager::GetInstance().ApplyAdvanceResource(peerNetworkId, reqInfoSets);
}

void FuzzGetResourceRequest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < MIN_SIZE)) {
        return;
    }
    ServiceCollaborationManager_ResourceRequestInfoSets reqInfoSets;

    reqInfoSets.remoteHardwareListSize = *(reinterpret_cast<const uint32_t*>(data));

    ServiceCollaborationManager_HardwareRequestInfo remoteHardwareListTemp;
    uint32_t offset = UINT32_T_OFFSET;
    remoteHardwareListTemp.hardWareType =
        *(reinterpret_cast<const ServiceCollaborationManagerHardwareType*>(data + offset));
    offset += ENUM_OFFSET;
    remoteHardwareListTemp.canShare = *(reinterpret_cast<const bool*>(data + offset));
    offset += BOOL_OFFSET;
    reqInfoSets.remoteHardwareList = &remoteHardwareListTemp;

    reqInfoSets.localHardwareListSize = *(reinterpret_cast<const uint32_t*>(data + offset));
    offset += UINT32_T_OFFSET;

    ServiceCollaborationManager_HardwareRequestInfo localHardwareListTemp;
    localHardwareListTemp.hardWareType =
        *(reinterpret_cast<const ServiceCollaborationManagerHardwareType*>(data + offset));
    offset += ENUM_OFFSET;
    localHardwareListTemp.canShare = *(reinterpret_cast<const bool*>(data + offset));
    offset += BOOL_OFFSET;
    reqInfoSets.localHardwareList = &localHardwareListTemp;

    ServiceCollaborationManager_CommunicationRequestInfo communicationRequestTemp;
    communicationRequestTemp.minBandwidth = *(reinterpret_cast<const int32_t*>(data + offset));
    offset += INT32_T_OFFSET;
    communicationRequestTemp.maxLatency = *(reinterpret_cast<const int32_t*>(data + offset));
    offset += INT32_T_OFFSET;
    communicationRequestTemp.minLatency = *(reinterpret_cast<const int32_t*>(data + offset));
    offset += INT32_T_OFFSET;
    communicationRequestTemp.maxWaitTime = *(reinterpret_cast<const int32_t*>(data + offset));
    offset += INT32_T_OFFSET;
    communicationRequestTemp.dataType = reinterpret_cast<const char*>(data + offset);
    reqInfoSets.communicationRequest = &communicationRequestTemp;
    DSchedAllConnectManager::GetInstance().GetResourceRequest(reqInfoSets);
}

void FuzzPublishServiceState(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(size_t))) {
        return;
    }
    const std::string peerNetworkId(reinterpret_cast<const char*>(data), size);
    const std::string extraInfo(reinterpret_cast<const char*>(data), size);
    uint8_t* temp = const_cast<uint8_t*>(data);
    ServiceCollaborationManagerBussinessStatus state =
        *(reinterpret_cast<ServiceCollaborationManagerBussinessStatus*>(temp));
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
