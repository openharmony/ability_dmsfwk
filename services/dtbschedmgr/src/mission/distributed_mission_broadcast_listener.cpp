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

#include "mission/distributed_mission_broadcast_listener.h"

#include <string>
#include "dtbschedmgr_log.h"
#include "mission/notification/dms_continue_recv_manager.h"
#include "multi_user_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedMissionBroadcastListener";
}
void DistributedMissionBroadcastListener::OnDataRecv(std::string& senderNetworkId, uint8_t* payload, uint32_t dataLen)
{
    HILOGI("OnDataRecv, dataLen = %{public}u", dataLen);
    auto recvMgr = MultiUserManager::GetInstance().GetCurrentRecvMgr();
    if (recvMgr == nullptr) {
        HILOGI("GetRecvMgr failed.");
        return;
    }
    recvMgr->NotifyDataRecv(senderNetworkId, payload, dataLen);
}
} // namespace DistributedSchedule
} // namespace OHOS
