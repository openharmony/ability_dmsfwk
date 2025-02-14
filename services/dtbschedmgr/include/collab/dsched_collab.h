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

#ifndef OHOS_DSCHED_COLLAB_H
#define OHOS_DSCHED_COLLAB_H

#include <condition_variable>
#include <mutex>
#include <thread>
#include <string>

#include "ability_manager_client.h"
#include "ability_state_observer.h"
#include "distributed_sched_service.h"
#include "dsched_collab_event.h"
#include "dsched_collab_event_handler.h"
#include "dsched_collab_state_machine.h"
#include "dsched_data_buffer.h"
#include "distributed_sched_utils.h"
#include "event_handler.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {

using AccountInfo = IDistributedSched::AccountInfo;

struct CollabMessage : public Parcelable {
    int32_t pid_ = -1;
    int32_t uid_ = -1;
    int32_t accessToken_ = -1;
    std::string deviceId_;
    std::string bundleName_;
    std::string abilityName_;
    std::string moduleName_;
    std::string serverId_;
    std::string socketName_;

    bool ReadFromParcel(Parcel &parcel)
    {
        deviceId_ = Str16ToStr8(parcel.ReadString16());
        bundleName_ = Str16ToStr8(parcel.ReadString16());
        moduleName_ = Str16ToStr8(parcel.ReadString16());
        abilityName_ = Str16ToStr8(parcel.ReadString16());
        serverId_ = Str16ToStr8(parcel.ReadString16());
        return true;
    }

    virtual bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    static CollabMessage *Unmarshalling(Parcel &parcel)
    {
        CollabMessage *collabInfo = new (std::nothrow) CollabMessage();
        if (collabInfo && !collabInfo->ReadFromParcel(parcel)) {
            delete collabInfo;
            collabInfo = nullptr;
        }
        return collabInfo;
    }
};

struct ConnectOpt : public Parcelable {
    bool needSendBigData_ = false;
    bool needSendStream_ = false;
    bool needRecvStream_ = false;
    AAFwk::WantParams startParams_;
    AAFwk::WantParams messageParams_;

    bool ReadFromParcel(Parcel &parcel)
    {
        needSendBigData_ = parcel.ReadBool();
        needSendStream_ = parcel.ReadBool();
        needRecvStream_ = parcel.ReadBool();
        std::shared_ptr<AAFwk::WantParams> startParamsPtr(parcel.ReadParcelable<AAFwk::WantParams>());
        if (startParamsPtr == nullptr) {
            return false;
        }
        startParams_ = *startParamsPtr;

        std::shared_ptr<AAFwk::WantParams> wantParamsPtr(parcel.ReadParcelable<AAFwk::WantParams>());
        if (wantParamsPtr == nullptr) {
            return false;
        }
        messageParams_ = *wantParamsPtr;
        return true;
    }

    virtual bool Marshalling(Parcel &parcel) const override
    {
        return true;
    }

    static ConnectOpt *Unmarshalling(Parcel &parcel)
    {
        ConnectOpt *connectOpt = new (std::nothrow) ConnectOpt();
        if (connectOpt && !connectOpt->ReadFromParcel(parcel)) {
            delete connectOpt;
            connectOpt = nullptr;
        }
        return connectOpt;
    }
};

typedef enum {
    COLLAB_SOURCE = 0,
    COLLAB_SINK = 1
} DSchedCollabDirection;

class DSchedCollabInfo {
public:
    DSchedCollabInfo() = default;
    DSchedCollabInfo(const int32_t &collabSessionId, const CollabMessage &localInfo, const CollabMessage &peerInfo,
        const ConnectOpt &opt, const sptr<IRemoteObject> &clientCB)
        : srcCollabSessionId_(collabSessionId), srcInfo_(localInfo), sinkInfo_(peerInfo),
        srcOpt_(opt), srcClientCB_(clientCB) {}
    ~DSchedCollabInfo() = default;

    std::string ToString() const
    {
        return "srcCollabVersion: " + std::to_string(this->srcCollabVersion_) + " " +
            "srcAppVersion: " + std::to_string(this->srcAppVersion_) + " " +
            "srcCollabSessionId: " + std::to_string(this->srcCollabSessionId_) + " " +
            "collabToken: " + GetAnonymStr(this->collabToken_) + " " +
            "needSendBigData: " + std::to_string(this->srcOpt_.needSendBigData_) + " " +
            "needSendStream: " + std::to_string(this->srcOpt_.needSendStream_) + " " +
            "needRecvStream: " + std::to_string(this->srcOpt_.needRecvStream_) + " " +
            "srcDevId: " + GetAnonymStr(this->srcInfo_.deviceId_) + " " +
            "srcBundle: " + this->srcInfo_.bundleName_ + " " +
            "srcAbility: " + this->srcInfo_.abilityName_ + " " +
            "srcModuleName: "+ this->srcInfo_.moduleName_ + " " +
            "srcServerId: "+ this->srcInfo_.serverId_ + " " +
            "srcPid: "+ std::to_string(this->srcInfo_.pid_) + " " +
            "srcUid: "+ std::to_string(this->srcInfo_.uid_) + " " +
            "srcAccessToken: "+ GetAnonymStr(std::to_string(this->srcInfo_.accessToken_)) + " " +
            "srcUserId: " + std::to_string(this->srcAccountInfo_.userId) + " " +
            "srcActiveAccountId: " + GetAnonymStr(this->srcAccountInfo_.activeAccountId) + " " +
            "srcSocketName: "+ this->srcInfo_.socketName_ + " " +
            "sinkCollabSessionId: " + std::to_string(this->sinkCollabSessionId_) + " " +
            "sinkDevId: "+ GetAnonymStr(this->sinkInfo_.deviceId_) + " " +
            "sinkBundle: " + this->sinkInfo_.bundleName_ + " " +
            "sinkAbility: " + this->sinkInfo_.abilityName_ + " " +
            "sinkModuleName: " + this->sinkInfo_.moduleName_ + " " +
            "sinkServerId: " + this->sinkInfo_.serverId_ + " " +
            "sinkPid: " + std::to_string(this->sinkInfo_.pid_) + " " +
            "sinkUid: " + std::to_string(this->sinkInfo_.uid_) + " " +
            "sinkAccessToken: " + GetAnonymStr(std::to_string(this->sinkInfo_.accessToken_)) + " " +
            "sinkUserId: " + std::to_string(this->sinkUserId_) + " " +
            "sinkSocketName: " + this->sinkInfo_.socketName_ + " ";
    }

    int32_t srcCollabSessionId_ = -1;
    int32_t sinkCollabSessionId_ = -1;
    int32_t sinkUserId_ = -1;
    int32_t srcCollabVersion_ = 0;
    int32_t srcAppVersion_ = 0;
    int32_t direction_ = COLLAB_SOURCE;
    std::string collabToken_;
    std::string srcUdid_;
    std::string sinkUdid_;
    int32_t sinkAccountId_;
    CallerInfo callerInfo_;
    AccountInfo srcAccountInfo_;
    CollabMessage srcInfo_;
    CollabMessage sinkInfo_;
    ConnectOpt srcOpt_;
    sptr<IRemoteObject> srcClientCB_ = nullptr;
    sptr<IRemoteObject> sinkClientCB_ = nullptr;
};

class DSchedCollab : public std::enable_shared_from_this<DSchedCollab> {
    friend class DSchedCollabManager;
    friend class DSchedCollabEventHandler;
    friend class CollabSrcStartState;
    friend class CollabSrcWaitResultState;
    friend class CollabSrcWaitEndState;
    friend class CollabSinkStartState;
    friend class CollabSinkConnectState;
    friend class CollabSinkWaitEndState;
    friend class CollabSinkEndState;

public:
    DSchedCollab(const std::string &collabToken, const DSchedCollabInfo &info);
    DSchedCollab(std::shared_ptr<SinkStartCmd> startCmd, const int32_t &softbusSessionId);
    ~DSchedCollab();

private:
    int32_t Init();
    void StartEventHandler();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer& event);

    int32_t PostSrcStartTask();
    int32_t PostSinkStartTask();
    int32_t PostSinkPrepareResultTask(const int32_t &result, const int32_t &collabSessionId,
        const std::string &socketName, const sptr<IRemoteObject> &clientCB);
    int32_t PostSrcResultTask(std::shared_ptr<NotifyResultCmd> replyCmd);
    int32_t PostErrEndTask(const int32_t &result);
    int32_t PostAbilityRejectTask(const std::string &reason);
    int32_t PostEndTask();

    int32_t ExeSrcStart();
    int32_t ExeStartAbility();
    int32_t ExeAbilityRejectError(const std::string &reason);
    int32_t ExeSinkPrepareResult(const int32_t &result);
    int32_t ExeSrcCollabResult(const int32_t &result, const std::string reason = "");
    int32_t NotifyWifiOpen();
    int32_t ExeSrcStartError(const int32_t &result);
    int32_t ExeSrcWaitResultError(const int32_t &result);
    int32_t ExeSinkStartError(const int32_t &result);
    int32_t ExeSinkConnectError(const int32_t &result);
    int32_t ExeSinkError(const int32_t &result);
    int32_t ExeDisconnect();
    int32_t ExeSrcClientNotify(const int32_t &result, const std::string reason = "");
    int32_t ExeClientDisconnectNotify();

    int32_t PackStartCmd(std::shared_ptr<SinkStartCmd>& cmd);
    int32_t PackPartCmd(std::shared_ptr<SinkStartCmd>& cmd);
    int32_t PackNotifyResultCmd(std::shared_ptr<NotifyResultCmd> cmd, const int32_t &result,
        const std::string &abilityRejectReason = "");
    int32_t PackDisconnectCmd(std::shared_ptr<DisconnectCmd> cmd);
    int32_t SendCommand(std::shared_ptr<BaseCmd> cmd);

    int32_t GetSoftbusSessionId();
    DSchedCollabInfo GetCollabInfo();
    AAFwk::Want GenerateCollabWant();
    bool IsStartForeground();
    int32_t SaveSinkAbilityData(const std::string& collabToken, const int32_t &result,
        const int32_t &sinkPid, const int32_t &sinkUid, const int32_t &sinkAccessTokenId);
    int32_t CleanUpSession();
    void UpdateState(CollabStateType stateType);

    sptr<AppExecFwk::IAppMgr> GetAppManager();
    bool RegisterAbilityLifecycleObserver(const std::string &bundleName);
    void UnregisterAbilityLifecycleObserver();

    void OnDataRecv(int32_t command, std::shared_ptr<DSchedDataBuffer> dataBuffer);
    void OnShutDown();
    void OnBind();
    void SetScreenLockParameters(AAFwk::WantParams& wantParams);

private:
    static constexpr int32_t INVALID_SESSION_ID = -1;
    static constexpr int32_t ERROR_BASE_DSOFTBUS_WIFI = -200000;
    static constexpr int32_t ERROR_PEER_THREE_VAP_CONFLICT = ERROR_BASE_DSOFTBUS_WIFI - 6604;
    static const std::map<int32_t, int32_t> DMS_CONVERT_TO_SDK_ERR_MAP;

    std::shared_ptr<DSchedCollabStateMachine> stateMachine_;
    std::shared_ptr<DSchedCollabEventHandler> eventHandler_;
    std::condition_variable eventCon_;
    std::thread eventThread_;
    std::mutex eventMutex_;

    DSchedCollabInfo collabInfo_;
    int32_t softbusSessionId_ = INVALID_SESSION_ID;
    sptr<AbilityLifecycleObserver> appStateObserver_ = nullptr;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_COLLAB_H
