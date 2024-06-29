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

#ifndef OHOS_DSCHED_CONTINUE_MANAGER_H
#define OHOS_DSCHED_CONTINUE_MANAGER_H

#include <map>
#include <string>
#include <atomic>

#include "dsched_data_buffer.h"
#include "dsched_continue.h"
#include "idata_listener.h"
#include "iremote_object.h"
#include "single_instance.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t MAX_CONCURRENT_SINK = 1;
constexpr int32_t MAX_CONCURRENT_SOURCE = 1;
constexpr int32_t CONTINUE_TIMEOUT = 7000;
}
class DSchedContinueManager {
DECLARE_SINGLE_INSTANCE_BASE(DSchedContinueManager);
public:
    explicit DSchedContinueManager();
    ~DSchedContinueManager();
    int32_t ContinueMission(const std::string &srcDeviceId, const std::string &dstDeviceId,
        int32_t missionId, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams &wantParams);
    int32_t ContinueMission(const std::string &srcDeviceId, const std::string &dstDeviceId,
        std::string bundleName, const std::string& continueType,
        const sptr<IRemoteObject> &callback, const OHOS::AAFwk::WantParams &wantParams);
    int32_t StartContinuation(const OHOS::AAFwk::Want& want, int32_t missionId, int32_t callerUid, int32_t status,
        uint32_t accessToken);
    int32_t NotifyCompleteContinuation(const std::u16string& devId, int32_t sessionId, bool isSuccess);
    int32_t OnContinueEnd(const DSchedContinueInfo& info);

    void Init();
    void UnInit();
    void OnDataRecv(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer);
    void OnShutdown(int32_t socket, bool isSelfCalled);
    void OnBind();

    int32_t GetContinueInfo(std::string &srcDeviceId, std::string &dstDeviceId);
    std::shared_ptr<DSchedContinue> GetDSchedContinueByWant(const OHOS::AAFwk::Want& want, int32_t missionId);
    std::shared_ptr<DSchedContinue> GetDSchedContinueByDevId(const std::u16string& devId, int32_t missionId);
    void NotifyTerminateContinuation(const int32_t missionId);
    
private:
    void StartEvent();
    void HandleContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId, int32_t missionId,
        const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams);
    void HandleContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
        std::string bundleName, const std::string& continueType,
        const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams);
    void HandleContinueMissionWithBundleName(const DSchedContinueInfo &info, const sptr<IRemoteObject>& callback,
        const OHOS::AAFwk::WantParams& wantParams);
    void HandleStartContinuation(const OHOS::AAFwk::Want& want, int32_t missionId, int32_t callerUid,
        int32_t status, uint32_t accessToken);
    void HandleNotifyCompleteContinuation(const std::u16string& devId, int32_t missionId, bool isSuccess);
    void HandleContinueEnd(const DSchedContinueInfo& info);
    void HandleDataRecv(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer);
    void NotifyContinueDataRecv(int32_t sessionId, int32_t command, const std::string& jsonStr,
        std::shared_ptr<DSchedDataBuffer> dataBuffer);
    int32_t CheckContinuationLimit(const std::string& srcDeviceId, const std::string& dstDeviceId);
    void SetTimeOut(const DSchedContinueInfo& info, int32_t timeout);
    void RemoveTimeout(const DSchedContinueInfo& info);
    bool GetLocalDeviceId(std::string& localDeviceId);

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
    std::shared_ptr<DSchedContinueManager::SoftbusListener> softbusListener_;

    std::map<DSchedContinueInfo, std::shared_ptr<DSchedContinue>> continues_;
    std::mutex continueMutex_;

    std::atomic<int32_t> cntSink_ {0};
    std::atomic<int32_t> cntSource_ {0};
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_CONTINUE_MANAGER_H
