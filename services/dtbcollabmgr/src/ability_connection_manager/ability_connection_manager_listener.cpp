/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "ability_connection_manager_listener.h"

#include "ability_connection_manager.h"
#include "dtbcollabmgr_log.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
const std::string TAG = "AbilityConnectionManagerListener";
}

int32_t AbilityConnectionManagerListener::NotifyCollabResult(int32_t sessionId, int32_t result,
    const std::string& peerServerName, const std::string& dmsServerToken, const std::string& reason)
{
    return AbilityConnectionManager::GetInstance().NotifyCollabResult(sessionId,
        result, peerServerName, dmsServerToken, reason);
}

int32_t AbilityConnectionManagerListener::NotifyDisconnect(int32_t sessionId)
{
    return AbilityConnectionManager::GetInstance().NotifyDisconnect(sessionId);
}

int32_t AbilityConnectionManagerListener::NotifyWifiOpen(int32_t sessionId)
{
    HILOGI("called.");
    return AbilityConnectionManager::GetInstance().NotifyWifiOpen(sessionId);
}

int32_t AbilityConnectionManagerListener::NotifyPeerVersion(int32_t sessionId, int32_t version)
{
    HILOGI("called.");
    return AbilityConnectionManager::GetInstance().NotifyPeerVersion(sessionId, version);
}
}  // namespace DistributedCollab
}  // namespace OHOS