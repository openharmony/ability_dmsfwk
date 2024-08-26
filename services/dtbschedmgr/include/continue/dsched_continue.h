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

#ifndef OHOS_DSCHED_CONTINUE_H
#define OHOS_DSCHED_CONTINUE_H

#include <condition_variable>
#include <mutex>
#include <thread>
#include <string>

#include "ability_manager_client.h"
#include "distributedWant/distributed_want.h"
#include "distributedWant/distributed_want_params.h"
#include "distributed_sched_interface.h"
#include "distributed_sched_utils.h"
#include "dsched_data_buffer.h"
#include "dsched_continue_event.h"
#include "dsched_continue_event_handler.h"
#include "dsched_continue_state_machine.h"
#include "mission/distributed_bm_storage.h"
#include "event_handler.h"

namespace OHOS {
namespace DistributedSchedule {

using AccountInfo = IDistributedSched::AccountInfo;

class DSchedContinueInfo {
public:
    DSchedContinueInfo() = default;
    DSchedContinueInfo(const std::string& sourceDeviceId, const std::string& sourceBundleName,
        const std::string& sinkDeviceId, const std::string& sinkBundleName, const std::string& continueType)
        : sourceDeviceId_(sourceDeviceId), sourceBundleName_(sourceBundleName), sinkDeviceId_(sinkDeviceId),
        sinkBundleName_(sinkBundleName), continueType_(continueType) {}

    DSchedContinueInfo(const std::string& sourceDeviceId, const std::string& sinkDeviceId, int32_t missionId)
        : sourceDeviceId_(sourceDeviceId), sinkDeviceId_(sinkDeviceId), missionId_(missionId) {}
    ~DSchedContinueInfo() = default;

    bool operator == (const DSchedContinueInfo &index) const
    {
        std::string compareInfo = this->sourceDeviceId_ + this->sourceBundleName_ + this->sinkDeviceId_ +
            this->sinkBundleName_;
        std::string otherCompareInfo = index.sourceDeviceId_ + index.sourceBundleName_ + index.sinkDeviceId_ +
            index.sinkBundleName_;
        return compareInfo.compare(otherCompareInfo) == 0;
    }

    bool operator < (const DSchedContinueInfo &index) const
    {
        std::string compareInfo = this->sourceDeviceId_ + this->sourceBundleName_ + this->sinkDeviceId_ +
            this->sinkBundleName_;
        std::string otherCompareInfo = index.sourceDeviceId_ + index.sourceBundleName_ + index.sinkDeviceId_ +
            index.sinkBundleName_;
        return compareInfo < otherCompareInfo;
    }

    std::string ToStringIgnoreMissionId() const
    {
        return "SrcDevId: " + GetAnonymStr(this->sourceDeviceId_) + " " +
            "SrcBundle: " + this->sourceBundleName_ + " " +
            "DstDevId: "+ GetAnonymStr(this->sinkDeviceId_) + " " +
            "DstBundle: " + this->sinkBundleName_ + " " +
            "ContiType: " + this->continueType_;
    }

    std::string toString() const
    {
        return "SrcDevId: " + GetAnonymStr(this->sourceDeviceId_) + " " +
            "SrcBundle: " + this->sourceBundleName_ + " " +
            "DstDevId: "+ GetAnonymStr(this->sinkDeviceId_) + " " +
            "DstBundle: " + this->sinkBundleName_ + " " +
            "ContiType: " + this->continueType_ + " " +
            "MissionId: " + std::to_string(this->missionId_);
    }

    std::string sourceDeviceId_;
    std::string sourceBundleName_;
    std::string sinkDeviceId_;
    std::string sinkBundleName_;
    std::string continueType_;
    std::string sinkAbilityName_;
    int32_t missionId_ = 0;
};

typedef enum {
    CONTINUE_SOURCE = 0,
    CONTINUE_SINK = 1
} DSchedContinueDirection;

typedef enum {
    CONTINUE_PULL = 0,
    CONTINUE_PUSH = 1
} DSchedContinueSubType;

struct ContinueAbilityData {
    OHOS::AAFwk::Want want;
    int32_t callerUid;
    uint32_t accessToken;
};

struct ContinueEventData {
    std::string moduleName;
    std::string abilityName;
};

class DSchedContinue : public std::enable_shared_from_this<DSchedContinue> {
    friend class DSchedContinueManager;
    friend class DSchedContinueEventHandler;
    friend class DSchedContinueSourceStartState;
    friend class DSchedContinueAbilityState;
    friend class DSchedContinueWaitEndState;
    friend class DSchedContinueEndState;
    friend class DSchedContinueSinkStartState;
    friend class DSchedContinueDataState;
    friend class DSchedContinueSinkWaitEndState;
    friend class DSchedContinueSinkEndState;

public:
    DSchedContinue(int32_t subServiceType, int32_t direction,  const sptr<IRemoteObject>& callback,
        const DSchedContinueInfo& continueInfo);
    DSchedContinue(std::shared_ptr<DSchedContinueStartCmd> startCmd, int32_t sessionId);
    ~DSchedContinue();

private:
    int32_t Init();
    void StartEventHandler();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer& event);

    int32_t PostStartTask(const OHOS::AAFwk::WantParams& wantParams);
    int32_t PostReplyTask(std::shared_ptr<DSchedContinueReplyCmd> cmd);
    int32_t PostCotinueAbilityTask(int32_t appVersion);
    int32_t PostContinueSendTask(const OHOS::AAFwk::Want& want, int32_t callerUid, int32_t status,
        uint32_t accessToken);
    int32_t PostContinueDataTask(std::shared_ptr<DSchedContinueDataCmd> cmd);
    int32_t PostNotifyCompleteTask(int32_t result);
    int32_t PostContinueEndTask(int32_t result);

    int32_t ExecuteContinueReq(std::shared_ptr<DistributedWantParams> wantParams);
    int32_t ExecuteContinueAbility(int32_t appVersion);
    int32_t ExecuteContinueReply();
    int32_t ExecuteContinueSend(std::shared_ptr<ContinueAbilityData> data);
    int32_t ExecuteContinueData(std::shared_ptr<DSchedContinueDataCmd> cmd);
    int32_t ExecuteNotifyComplete(int32_t result);
    int32_t ExecuteContinueEnd(int32_t result);
    int32_t ExecuteContinueError(int32_t result);

    int32_t OnContinueMission(const OHOS::AAFwk::WantParams& wantParams);
    int32_t OnStartCmd(int32_t appVersion);
    int32_t OnReplyCmd(std::shared_ptr<DSchedContinueReplyCmd> cmd);
    int32_t OnStartContinuation(const OHOS::AAFwk::Want& want, int32_t callerUid, int32_t status,
        uint32_t accessToken);
    int32_t OnContinueDataCmd(std::shared_ptr<DSchedContinueDataCmd> cmd);
    int32_t OnNotifyComplete(int32_t missionId, bool isSuccess);
    int32_t OnContinueEndCmd(std::shared_ptr<DSchedContinueEndCmd> cmd);
    int32_t OnContinueEnd(int32_t result);

    void OnDataRecv(int32_t command, std::shared_ptr<DSchedDataBuffer> dataBuffer);
    void OnShutDown();
    void OnBind();

    int32_t GetSessionId();
    DSchedContinueInfo GetContinueInfo();

    int32_t PackStartCmd(std::shared_ptr<DSchedContinueStartCmd>& cmd,
        std::shared_ptr<DistributedWantParams> wantParams);
    int32_t PackDataCmd(std::shared_ptr<DSchedContinueDataCmd>& cmd, const OHOS::AAFwk::Want& want,
        const AppExecFwk::AbilityInfo& abilityInfo, const CallerInfo& callerInfo,
        const AccountInfo& accountInfo);
    int32_t PackEndCmd(std::shared_ptr<DSchedContinueEndCmd> cmd, int32_t result);
    int32_t PackReplyCmd(std::shared_ptr<DSchedContinueReplyCmd> cmd, int32_t replyCmd, int32_t appVersion,
        int32_t result, const std::string reason);
    int32_t SendCommand(std::shared_ptr<DSchedContinueCmdBase> cmd);

    int32_t SetWantForContinuation(AAFwk::Want& newWant);
    void SetCleanMissionFlag(const OHOS::AAFwk::Want& want);
    int32_t ConvertToDmsSdkErr(int32_t result);
    void NotifyContinuationCallbackResult(int32_t result);
    bool GetLocalDeviceId(std::string& localDeviceId);
    bool CheckDeviceIdFromRemote(const std::string& localDevId, const std::string& destDevId,
        const std::string& srcDevId);
    int32_t GetMissionIdByBundleName();
    int32_t CheckContinueAbilityPermission();
    void DurationDumperStart();
    void DurationDumperBeforeStartRemoteAbility();
    void DurationDumperBeforeStartAbility(std::shared_ptr<DSchedContinueDataCmd> cmd);
    void DurationDumperComplete(int32_t result);
    void NotifyDSchedEventResult(int32_t result);
    bool WaitAbilityStateInitial(int32_t persistentId);
    int32_t StartAbility(const OHOS::AAFwk::Want& want, int32_t requestCode);
    std::string QuerySinkAbilityName();
    int32_t QuickStartAbility();
    int32_t UpdateWantForContinueType(OHOS::AAFwk::Want& want);
    bool CheckQuickStartConfiguration();
    std::string GetAbilityNameByContinueType();
    void SetEventData();
    void UpdateState(DSchedContinueStateType stateType);

private:
    static constexpr int32_t INVALID_SESSION_ID = -1;
    static constexpr int32_t ERROR_BASE_DSOFTBUS_WIFI = -200000;
    static constexpr int32_t ERROR_PEER_THREE_VAP_CONFLICT = ERROR_BASE_DSOFTBUS_WIFI - 6604;
    static const std::map<int32_t, int32_t> DMS_CONVERT_TO_SDK_ERR_MAP;

    std::shared_ptr<DSchedContinueStateMachine> stateMachine_;
    std::shared_ptr<DSchedContinueEventHandler> eventHandler_;
    std::condition_variable eventCon_;
    std::thread eventThread_;
    std::mutex eventMutex_;

    int32_t version_ = 0;
    int32_t subServiceType_ = 0;
    int32_t continueByType_ = 0;
    int32_t direction_ = 0;
    DSchedContinueInfo continueInfo_;
    bool isSourceExit_ = true;
    int32_t softbusSessionId_ = INVALID_SESSION_ID;
    sptr<IRemoteObject> callback_ = nullptr;
    EventNotify eventData_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_CONTINUE_H