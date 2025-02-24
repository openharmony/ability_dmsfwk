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

#ifndef OHOS_DSCHED_COLLAB_MANAGER_H
#define OHOS_DSCHED_COLLAB_MANAGER_H

#include <atomic>
#include <map>
#include <string>

#include "dsched_collab.h"
#include "dsched_data_buffer.h"
#include "idata_listener.h"
#include "inner_socket.h"
#include "iremote_object.h"
#include "single_instance.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t COLLAB_TIMEOUT = 20000;
constexpr int32_t BACKGROUND_TIMEOUT = 5000;
}
class DSchedCollabManager {
DECLARE_SINGLE_INSTANCE_BASE(DSchedCollabManager);
public:
    explicit DSchedCollabManager();
    ~DSchedCollabManager();

    int32_t GetSinkCollabVersion(DSchedCollabInfo &info);
    int32_t CollabMission(DSchedCollabInfo &info);
    int32_t NotifyStartAbilityResult(const std::string& collabToken, const int32_t &result,
        const int32_t &sinkPid, const int32_t &sinkUid, const int32_t &sinkAccessTokenId);
    int32_t NotifySinkPrepareResult(const std::string &collabToken, const int32_t &result,
        const int32_t &collabSessionId, const std::string &socketName, const sptr<IRemoteObject> &clientCB);
    int32_t NotifySinkRejectReason(const std::string& collabToken, const std::string& reason);
    int32_t NotifyAbilityDied(const std::string &bundleName, const int32_t &pid);
    int32_t NotifySessionClose(const std::string &collabToken);
    int32_t CleanUpSession(const std::string &collabToken);
    int32_t CheckCollabRelation(const CollabInfo *sourceInfo, const CollabInfo *sinkInfo);
    int32_t ReleaseAbilityLink(const std::string &bundleName, const int32_t &pid);
    int32_t CancleReleaseAbilityLink(const std::string &bundleName, const int32_t &pid);
    void NotifyWifiOpen();

    void Init();
    void UnInit();
    void NotifyAllConnectDecision(std::string peerDeviceId, bool isSupport);
    void OnDataRecv(int32_t softbusSessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer);
    void OnShutdown(int32_t socket, bool isSelfCalled);

    std::shared_ptr<DSchedCollab> GetDSchedCollabByTokenId(const std::string &tokenId);

private:
    void StartEvent();
    void HandleGetSinkCollabVersion(const DSchedCollabInfo &info);
    void HandleCollabMission(const DSchedCollabInfo &info);
    void HandleCollabPrepareResult(const std::string &collabToken, const int32_t &result,
        const int32_t &collabSessionId, const std::string &socketName, const sptr<IRemoteObject> &clientCB);
    int32_t HandleCloseSessions(const std::string &bundleName, const int32_t &pid);
    void HandleReleaseAbilityLink(const std::string &bundleName, const int32_t &pid);
    void HandleDataRecv(const int32_t &softbusSessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer);
    void NotifyDataRecv(const int32_t &softbusSessionId, int32_t command, const std::string& jsonStr,
        std::shared_ptr<DSchedDataBuffer> dataBuffer, const std::string& collabToken);
    void WaitAllConnectDecision(const std::string &peerDeviceId, const std::shared_ptr<DSchedCollab> &dCollab);
    void SetTimeOut(const std::string &collabToken, int32_t timeout);
    void RemoveTimeout(const std::string &collabToken);
    bool  IsSessionExists(const DSchedCollabInfo &info);
    std::string GenerateCollabToken(const std::string &sourceDeviceId);
    int32_t CheckSrcCollabRelation(const CollabInfo *sourceInfo, const DSchedCollabInfo *collabInfo);
    int32_t CheckSinkCollabRelation(const CollabInfo *sinkInfo, const DSchedCollabInfo *collabInfo);

    class SoftbusListener : public IDataListener {
        void OnBind(int32_t socket, PeerSocketInfo info);
        void OnShutdown(int32_t socket, bool isSelfCalled);
        void OnDataRecv(int32_t socket, std::shared_ptr<DSchedDataBuffer> dataBuffer);
    };

private:
    std::thread eventThread_;
    std::condition_variable eventCon_;
    std::mutex eventMutex_;
    std::shared_ptr<OHOS::AppExecFwk::EventHandler> eventHandler_;
    std::shared_ptr<DSchedCollabManager::SoftbusListener> softbusListener_;
    std::map<std::string, std::shared_ptr<DSchedCollab>> collabs_;
    std::mutex collabMutex_;

#ifdef DMSFWK_ALL_CONNECT_MGR
    std::mutex connectDecisionMutex_;
    std::condition_variable connectDecisionCond_;
    std::map<std::string, std::atomic<bool>> peerConnectDecision_;
    static constexpr int32_t CONNECT_DECISION_TIME_OUT = 10;
#endif
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_COLLAB_MANAGER_H