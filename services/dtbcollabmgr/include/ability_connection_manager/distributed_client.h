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

#ifndef OHOS_ABILITY_CONNECTION_MANAGER_DISTRIBUTED_CLIENT_H
#define OHOS_ABILITY_CONNECTION_MANAGER_DISTRIBUTED_CLIENT_H


#include <string>

#include "ability_connection_info.h"
#include "iremote_broker.h"

namespace OHOS {
namespace DistributedCollab {
class DistributedClient {
public:
    DistributedClient() = default;
    virtual ~DistributedClient() = default;
    
    int32_t CollabMission(int32_t sessionId, const std::string& serverSocketName, const PeerInfo& localInfo,
        const PeerInfo& peerInfo, const ConnectOption& options);
    int32_t NotifyPrepareResult(const std::string& token, int32_t result, int32_t sessionId,
        const std::string& serverSocketName);
    int32_t NotifyCloseCollabSession(const std::string& token);
    int32_t NotifyRejectReason(const std::string& token, const std::string& reason);
    
    enum {
        COLLAB_MESSION = 330,
        NOTIFY_PREPARE_RESULT = 331,
        NOTIFY_REJECT_REASON = 332,
        BNOTIFY_CLOSE_COLLAB_SESSION = 333,
    };
private:
    sptr<IRemoteObject> GetDmsProxy();
};
}  // namespace AAFwk
}  // namespace OHOS
#endif