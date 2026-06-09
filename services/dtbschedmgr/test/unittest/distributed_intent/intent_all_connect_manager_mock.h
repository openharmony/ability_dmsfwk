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

#ifndef OHOS_INTENT_ALL_CONNECT_MANAGER_MOCK_H
#define OHOS_INTENT_ALL_CONNECT_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include <string>
#include "service_collaboration_manager_capi.h"

namespace OHOS {
namespace DistributedSchedule {

class IIntentAllConnectManager {
public:
    virtual ~IIntentAllConnectManager() = default;
    virtual bool IsAllConnectAvailable() = 0;
    virtual int32_t ApplyResource(const std::string &peerNetworkId) = 0;
    virtual int32_t PublishServiceState(const std::string &peerNetworkId,
        ServiceCollaborationManagerBussinessStatus state) = 0;
    static inline std::shared_ptr<IIntentAllConnectManager> allConnectMock = nullptr;
};

class IntentAllConnectManagerMock : public IIntentAllConnectManager {
public:
    MOCK_METHOD0(IsAllConnectAvailable, bool());
    MOCK_METHOD1(ApplyResource, int32_t(const std::string &peerNetworkId));
    MOCK_METHOD2(PublishServiceState, int32_t(const std::string &peerNetworkId,
        ServiceCollaborationManagerBussinessStatus state));
};

} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_INTENT_ALL_CONNECT_MANAGER_MOCK_H
