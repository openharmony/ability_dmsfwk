/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "intent_all_connect_manager_mock.h"
#include "intent_all_connect_manager.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

IMPLEMENT_SINGLE_INSTANCE(IntentAllConnectManager);

bool IntentAllConnectManager::IsAllConnectAvailable()
{
    if (IIntentAllConnectManager::allConnectMock == nullptr) {
        return false;
    }
    return IIntentAllConnectManager::allConnectMock->IsAllConnectAvailable();
}

int32_t IntentAllConnectManager::ApplyResource(const std::string &peerNetworkId)
{
    if (IIntentAllConnectManager::allConnectMock == nullptr) {
        return -1;
    }
    return IIntentAllConnectManager::allConnectMock->ApplyResource(peerNetworkId);
}

int32_t IntentAllConnectManager::PublishServiceState(const std::string &peerNetworkId,
    ServiceCollaborationManagerBussinessStatus state)
{
    if (IIntentAllConnectManager::allConnectMock == nullptr) {
        return -1;
    }
    return IIntentAllConnectManager::allConnectMock->PublishServiceState(peerNetworkId, state);
}

} // namespace DistributedSchedule
} // namespace OHOS
