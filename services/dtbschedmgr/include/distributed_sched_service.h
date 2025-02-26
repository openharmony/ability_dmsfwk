/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_SCHED_SERVICE_H
#define OHOS_DISTRIBUTED_SCHED_SERVICE_H

#include <memory>
#include <mutex>
#include <set>
#include <unordered_map>

#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
#include "form_mgr_interface.h"
#endif
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "system_ability.h"

#include "app_mgr_interface.h"
#include "app_state_observer.h"
#include "datashare_manager.h"
#include "distributed_sched_stub.h"
#include "distributed_sched_continuation.h"
#include "dms_callback_task.h"
#include "dsched_collaborate_callback_mgr.h"
#include "idms_interactive_adapter.h"
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
#include "mission/distributed_mission_focused_listener.h"
#include "mission/distributed_mission_info.h"
#include "nocopyable.h"
#endif
#include "dsched_collab.h"
#include "dsched_continue.h"
#include "dsched_continue_event.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
class ConnectAbilitySession;

enum class ServiceRunningState {
    STATE_NO_START,
    STATE_RUNNING
};

enum class TargetComponent {
    HARMONY_COMPONENT,
};

struct ConnectInfo {
    CallerInfo callerInfo;
    sptr<IRemoteObject> callbackWrapper;
    AppExecFwk::ElementName element;
};

struct ProcessDiedNotifyInfo {
    std::string remoteDeviceId;
    CallerInfo callerInfo;
    TargetComponent targetComponent;
};

struct CallInfo {
    int32_t connectToken;
    std::string remoteDeviceId;
};

struct ObserverInfo {
    sptr<AppStateObserver> appStateObserver;
    std::string srcDeviceId;
    int32_t connectToken;
    std::string dstBundleName;
    std::string dstAbilityName;
    sptr<IRemoteObject> srcConnect;
    sptr<IRemoteObject> token;
};

class DistributedSchedService : public SystemAbility, public DistributedSchedStub {
    DECLARE_SYSTEM_ABILITY(DistributedSchedService);
    DECLARE_SINGLE_INSTANCE_BASE(DistributedSchedService);

public:
    ~DistributedSchedService() = default;
    void OnStart(const SystemAbilityOnDemandReason &startReason) override;
    void OnStop(const SystemAbilityOnDemandReason &stopReason) override;
    void OnActive(const SystemAbilityOnDemandReason &activeReason) override;

    /**
     * @brief If SA is pulled by root and not networked with other devices, uninstall SA after creating the database
     *
     * @param startReason, The reason why SA was pulled up.
     */
    void HandleBootStart(const SystemAbilityOnDemandReason &startReason);
    bool DoStart();
    int32_t Dump(int32_t fd, const std::vector<std::u16string>& args) override;
    void DeviceOnlineNotify(const std::string& deviceId);
    void DeviceOfflineNotify(const std::string& deviceId);
    void DurationStart(const std::string srcDeviceId, const std::string dstDeviceId);

    int32_t StartRemoteAbility(const OHOS::AAFwk::Want& want, int32_t callerUid, int32_t requestCode,
        uint32_t accessToken) override;
    int32_t StartAbilityFromRemote(const OHOS::AAFwk::Want& want,
        const OHOS::AppExecFwk::AbilityInfo& abilityInfo, int32_t requestCode, const CallerInfo& callerInfo,
        const AccountInfo& accountInfo) override;
    int32_t SendResultFromRemote(OHOS::AAFwk::Want& want, int32_t requestCode,
        const CallerInfo& callerInfo, const AccountInfo& accountInfo, int32_t resultCode) override;
    int32_t ContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId, int32_t missionId,
        const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams) override;
    int32_t ProcessContinueLocalMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
        const std::string& bundleName, const sptr<IRemoteObject>& callback,
        const OHOS::AAFwk::WantParams& wantParams);
    int32_t ProcessContinueRemoteMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
        const std::string& bundleName, const sptr<IRemoteObject>& callback,
        const OHOS::AAFwk::WantParams& wantParams);
    int32_t ContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
        const std::string& bundleName, const sptr<IRemoteObject>& callback,
        const OHOS::AAFwk::WantParams& wantParams) override;
    int32_t DealDSchedEventResult(const OHOS::AAFwk::Want& want, int32_t status);
    bool GetIsFreeInstall(int32_t missionId);
    int32_t StartContinuation(const OHOS::AAFwk::Want& want, int32_t missionId, int32_t callerUid,
        int32_t status, uint32_t accessToken) override;
    void NotifyCompleteContinuation(const std::u16string& devId, int32_t sessionId, bool isSuccess) override;
    int32_t NotifyContinuationResultFromRemote(int32_t sessionId, bool isSuccess, const std::string dstInfo) override;
    int32_t NotifyDSchedEventResultFromRemote(const std::string type, int32_t dSchedEventResult) override;
    void NotifyContinuationCallbackResult(int32_t missionId, int32_t resultCode);
    void NotifyDSchedEventCallbackResult(int32_t resultCode);
    void NotifyDSchedEventCallbackResult(int32_t resultCode, const EventNotify& event);
    int32_t NotifyFreeInstallResult(const CallbackTaskItem item, int32_t resultCode);
    int32_t ConnectRemoteAbility(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect,
        int32_t callerUid, int32_t callerPid, uint32_t accessToken) override;
    int32_t DisconnectRemoteAbility(const sptr<IRemoteObject>& connect, int32_t callerUid,
        uint32_t accessToken) override;
    int32_t ConnectAbilityFromRemote(const OHOS::AAFwk::Want& want, const AppExecFwk::AbilityInfo& abilityInfo,
        const sptr<IRemoteObject>& connect, const CallerInfo& callerInfo, const AccountInfo& accountInfo) override;
    int32_t DisconnectAbilityFromRemote(const sptr<IRemoteObject>& connect,
        int32_t uid, const std::string& sourceDeviceId) override;
    int32_t NotifyProcessDiedFromRemote(const CallerInfo& callerInfo) override;
#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
    int32_t GetMissionInfos(const std::string& deviceId, int32_t numMissions,
        std::vector<AAFwk::MissionInfo>& missionInfos) override;
    int32_t NotifyMissionsChangedFromRemote(const std::vector<DstbMissionInfo>& missionInfos,
        const CallerInfo& callerInfo) override;
    int32_t GetRemoteMissionSnapshotInfo(const std::string& networkId, int32_t missionId,
        std::unique_ptr<AAFwk::MissionSnapshot>& missionSnapshot) override;
    int32_t StartSyncRemoteMissions(const std::string& devId, bool fixConflict, int64_t tag,
        int32_t callingUid) override;
    int32_t StartSyncMissionsFromRemote(const CallerInfo& callerInfo,
        std::vector<DstbMissionInfo>& missionInfos) override;
    int32_t StopSyncRemoteMissions(const std::string& devId, int32_t callingUid) override;
    int32_t StopSyncMissionsFromRemote(const CallerInfo& callerInfo) override;
    int32_t RegisterMissionListener(const std::u16string& devId, const sptr<IRemoteObject>& obj,
        int32_t callingUid) override;
    int32_t RegisterOnListener(const std::string& type, const sptr<IRemoteObject>& obj, int32_t callingUid) override;
    int32_t RegisterOffListener(const std::string& type, const sptr<IRemoteObject>& obj, int32_t callingUid) override;
    int32_t UnRegisterMissionListener(const std::u16string& devId, const sptr<IRemoteObject>& obj) override;
    int32_t SetMissionContinueState(int32_t missionId, const AAFwk::ContinueState &state, int32_t callingUid) override;
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
#endif
    int32_t RegisterDSchedEventListener(const DSchedEventType& type, const sptr<IRemoteObject>& obj) override;
    int32_t UnRegisterDSchedEventListener(const DSchedEventType& type, const sptr<IRemoteObject>& obj) override;
    int32_t GetContinueInfo(std::string& dstNetworkId, std::string& srcNetworkId) override;
    int32_t GetDSchedEventInfo(const DSchedEventType &type, std::vector<EventNotify> &events) override;
    void ProcessConnectDied(const sptr<IRemoteObject>& connect);
    void ProcessDeviceOffline(const std::string& deviceId);
    void DumpConnectInfo(std::string& info);
    void DumpSessionsLocked(const std::list<ConnectAbilitySession>& sessionsList, std::string& info);
    void DumpElementLocked(const std::list<AppExecFwk::ElementName>& elementsList, std::string& info);
    int32_t StartRemoteAbilityByCall(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect,
        int32_t callerUid, int32_t callerPid, uint32_t accessToken) override;
    int32_t ReleaseRemoteAbility(const sptr<IRemoteObject>& connect,
        const AppExecFwk::ElementName &element) override;
    int32_t StartAbilityByCallFromRemote(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect,
        const CallerInfo& callerInfo, const AccountInfo& accountInfo) override;
    int32_t ReleaseAbilityFromRemote(const sptr<IRemoteObject>& connect, const AppExecFwk::ElementName &element,
        const CallerInfo& callerInfo) override;
#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
    int32_t StartRemoteShareForm(const std::string& remoteDeviceId,
        const AppExecFwk::FormShareInfo& formShareInfo) override;
    int32_t StartShareFormFromRemote(
        const std::string& remoteDeviceId, const AppExecFwk::FormShareInfo& formShareInfo) override;
    void ProcessFormMgrDied(const wptr<IRemoteObject>& remote);
#endif
    void ProcessCallerDied(const sptr<IRemoteObject>& connect, int32_t deviceType);
    void ProcessCalleeDied(const sptr<IRemoteObject>& connect);
    void ProcessCallResult(const sptr<IRemoteObject>& calleeConnect, const sptr<IRemoteObject>& callerConnect);
    int32_t StartRemoteFreeInstall(const OHOS::AAFwk::Want& want, int32_t callerUid, int32_t requestCode,
        uint32_t accessToken, const sptr<IRemoteObject>& callback) override;
    int32_t StartFreeInstallFromRemote(const FreeInstallInfo& info, int64_t taskId) override;
    int32_t NotifyCompleteFreeInstallFromRemote(int64_t taskId, int32_t resultCode) override;
    int32_t NotifyCompleteFreeInstall(const FreeInstallInfo& info, int64_t taskId, int32_t resultCode);
    int32_t GetDistributedComponentList(std::vector<std::string>& distributedComponents) override;
    void SetContinuationTimeout(int32_t missionId, int32_t timeout);
    void RemoveContinuationTimeout(int32_t missionId);
    std::string GetContinuaitonDevice(int32_t missionId);
    int32_t NotifyStateChangedFromRemote(int32_t abilityState, int32_t connectToken,
        const AppExecFwk::ElementName& element) override;
    int32_t NotifyStateChanged(int32_t abilityState, AppExecFwk::ElementName& element,
        const sptr<IRemoteObject>& token);
    int32_t StopRemoteExtensionAbility(const OHOS::AAFwk::Want& want, int32_t callerUid,
        uint32_t accessToken, int32_t extensionType) override;
    int32_t StopExtensionAbilityFromRemote(const OHOS::AAFwk::Want& remoteWant, const CallerInfo& callerInfo,
        const AccountInfo& accountInfo, int32_t extensionType) override;
    int32_t CheckTargetPermission(const OHOS::AAFwk::Want& want, const CallerInfo& callerInfo,
        const AccountInfo& accountInfo, int32_t flag, bool needQueryExtension);
    int32_t CheckTargetPermission4DiffBundle(const OHOS::AAFwk::Want& want, const CallerInfo& callerInfo,
        const AccountInfo& accountInfo, int32_t flag, bool needQueryExtension);
    int32_t CheckCollabStartPermission(const OHOS::AAFwk::Want& want, const CallerInfo& callerInfo,
        const AccountInfo& accountInfo, bool needQueryExtension);
    ErrCode QueryOsAccount(int32_t& activeAccountId);
    void RegisterDataShareObserver(const std::string& key);
    int32_t ContinueStateCallbackRegister(int32_t missionId, std::string bundleName, std::string moduleName,
        std::string abilityName, sptr<IRemoteObject> callback);
    int32_t ContinueStateCallbackUnRegister(int32_t missionId, std::string bundleName, std::string moduleName,
        std::string abilityName);

#ifdef DMSFWK_INTERACTIVE_ADAPTER
    bool CheckRemoteOsType(const std::string& netwokId) override;
    int32_t StartAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply) override;
    int32_t StopAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply) override;
    int32_t ConnectAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply) override;
    int32_t DisconnectAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply) override;
    int32_t NotifyAbilityLifecycleChangedFromRemoteAdapter(MessageParcel& data, MessageParcel& reply) override;

    void OnDeviceOnlineEx(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);
    void OnDeviceOfflineEx(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);
    void OnDeviceInfoChangedEx(const OHOS::DistributedHardware::DmDeviceInfo& deviceInfo);
#endif

private:
    DistributedSchedService();
    bool Init();
    void InitDataShareManager();
    void InitMissionManager();
    void InitCommonEventListener();
    int32_t GetCallerInfo(const std::string &localDeviceId, int32_t callerUid, uint32_t accessToken,
        CallerInfo &callerInfo);
    void RemoteConnectAbilityMappingLocked(const sptr<IRemoteObject>& connect, const std::string& localDeviceId,
        const std::string& remoteDeviceId, const AppExecFwk::ElementName& element, const CallerInfo& callerInfo,
        TargetComponent targetComponent);
    int32_t DisconnectEachRemoteAbilityLocked(const std::string& localDeviceId,
        const std::string& remoteDeviceId, const sptr<IRemoteObject>& connect);
    sptr<IDistributedSched> GetRemoteDms(const std::string& remoteDeviceId);
    static bool GetLocalDeviceId(std::string& localDeviceId);
    bool CheckDeviceId(const std::string& localDeviceId, const std::string& remoteDeviceId);
    bool CheckDeviceIdFromRemote(const std::string& localDeviceId,
        const std::string& destinationDeviceId, const std::string& sourceDeviceId);
    void NotifyDeviceOfflineToAppLocked(const sptr<IRemoteObject>& connect, const ConnectAbilitySession& session);
    int32_t NotifyApp(const sptr<IRemoteObject>& connect, const AppExecFwk::ElementName& element, int32_t errCode);
    void NotifyProcessDiedAll(const std::list<ProcessDiedNotifyInfo>& notifyList);
    void NotifyProcessDied(const std::string& remoteDeviceId, const CallerInfo& callerInfo,
        TargetComponent targetComponent);
    int32_t CheckDistributedConnectLocked(const CallerInfo& callerInfo) const;
    void DecreaseConnectLocked(int32_t uid);
    static int32_t GetUidLocked(const std::list<ConnectAbilitySession>& sessionList);
    int32_t TryConnectRemoteAbility(const OHOS::AAFwk::Want& want,
        const sptr<IRemoteObject>& connect, const CallerInfo& callerInfo);
    int32_t ContinueLocalMissionDealFreeInstall(OHOS::AAFwk::Want& want, int32_t missionId,
        const std::string& dstDeviceId, const sptr<IRemoteObject>& callback);
#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
    sptr<AppExecFwk::IFormMgr> GetFormMgrProxy();
#endif
    int32_t SetCallerInfo(int32_t callerUid, std::string localDeviceId, uint32_t accessToken, CallerInfo& callerInfo);
    int32_t SetWantForContinuation(AAFwk::Want& newWant, int32_t missionId);
    int32_t ContinueLocalMission(const std::string& dstDeviceId, int32_t missionId,
        const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams);
    int32_t ContinueAbilityWithTimeout(const std::string& dstDeviceId, int32_t missionId,
        const sptr<IRemoteObject>& callback, uint32_t remoteBundleVersion = 0);
    int32_t ContinueRemoteMission(const std::string& srcDeviceId, const std::string& dstDeviceId, int32_t missionId,
        const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams);
    int32_t ContinueRemoteMission(const std::string& srcDeviceId, const std::string& dstDeviceId,
        const std::string& bundleName, const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams);
    int32_t TryStartRemoteAbilityByCall(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect,
        const CallerInfo& callerInfo);
    int32_t StartLocalAbility(const FreeInstallInfo& info, int64_t taskId, int32_t resultCode);
    int32_t StartAbility(const OHOS::AAFwk::Want& want, int32_t requestCode);
    int32_t HandleRemoteNotify(const FreeInstallInfo& info, int64_t taskId, int32_t resultCode);
    void ReportDistributedComponentChange(const CallerInfo& callerInfo, int32_t changeType,
        int32_t componentType, int32_t deviceType);
    void ReportDistributedComponentChange(const ConnectInfo& connectInfo, int32_t changeType,
        int32_t componentType, int32_t deviceType);
    void HandleLocalCallerDied(const sptr<IRemoteObject>& connect);
    void SaveCallerComponent(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect,
        const CallerInfo& callerInfo);
    void RemoveCallerComponent(const sptr<IRemoteObject>& connect);
    void ProcessCalleeOffline(const std::string& deviceId);
    void GetConnectComponentList(std::vector<std::string>& distributedComponents);
    void GetCallComponentList(std::vector<std::string>& distributedComponents);
    void ProcessFreeInstallOffline(const std::string& deviceId);
    bool RegisterAppStateObserver(const OHOS::AAFwk::Want& want, const CallerInfo& callerInfo,
        const sptr<IRemoteObject>& srcConnect, const sptr<IRemoteObject>& callbackWrapper);
    void UnregisterAppStateObserver(const sptr<IRemoteObject>& callbackWrapper);
    sptr<AppExecFwk::IAppMgr> GetAppManager();
    int32_t SaveConnectToken(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect);
    void SetCleanMissionFlag(const OHOS::AAFwk::Want& want, int32_t missionId);
    void RemoveConnectAbilityInfo(const std::string& deviceId);
    void InitWifiStateListener();
    void InitWifiSemiStateListener();
    void InitBluetoothStateListener();
    void NotifyContinuateEventResult(int32_t resultCode, const EventNotify& event);
    void InitDeviceCfg();
    void NotifyCollaborateEventResult(int32_t resultCode, const EventNotify& event);
    void GetContinueEventInfo(int32_t callingUid, std::vector<EventNotify> &events);
    void GetCollaborateEventInfo(int32_t callingUid, std::vector<EventNotify> &events);
    void GetCollaborateEventsByCallers(int32_t callingUid, const std::string &callingBundleName,
        std::vector<EventNotify> &events);
    void GetCollaborateEventsByCallees(int32_t callingUid, const std::string &callingBundleName,
        std::vector<EventNotify> &events);
    void GetCurSrcCollaborateEvent(const CallerInfo &callerInfo, const AppExecFwk::ElementName &element,
        DSchedEventState state, int32_t ret, EventNotify &event);
    void GetCurDestCollaborateEvent(const CallerInfo &callerInfo, const AppExecFwk::ElementName &element,
        DSchedEventState state, int32_t ret, EventNotify &event);
    void NotifyCollaborateEventWithSessions(const std::list<ConnectAbilitySession> &sessionsList,
        DSchedEventState state, int32_t ret);
    bool CheckCallingUid();

#ifdef DMSFWK_INTERACTIVE_ADAPTER
    int32_t GetDmsInteractiveAdapterProxy();
    int32_t StartRemoteAbilityAdapter(const OHOS::AAFwk::Want& want, int32_t callerUid, int32_t requestCode,
        uint32_t accessToken);
    int32_t ConnectRemoteAbilityAdapter(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect,
        int32_t callerUid, int32_t callerPid, uint32_t accessToken);
    int32_t DisconnectRemoteAbilityAdapter(const sptr<IRemoteObject>& connect, int32_t callerUid,
        uint32_t accessToken);
#endif

private:
    std::shared_ptr<DSchedContinuation> dschedContinuation_;
    std::shared_ptr<DSchedCollaborationCallbackMgr> collaborateCbMgr_;
    std::map<sptr<IRemoteObject>, std::list<ConnectAbilitySession>> distributedConnectAbilityMap_;
    std::map<sptr<IRemoteObject>, ConnectInfo> connectAbilityMap_;
    std::unordered_map<int32_t, uint32_t> trackingUidMap_;
    std::mutex distributedLock_;
    std::mutex connectLock_;
    sptr<IRemoteObject::DeathRecipient> connectDeathRecipient_;
#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
    sptr<IRemoteObject::DeathRecipient> formMgrDeathRecipient_;
    sptr<AppExecFwk::IFormMgr> formMgrProxy_;
    std::mutex formMgrLock_;
#endif
    std::mutex calleeLock_;
    std::map<sptr<IRemoteObject>, ConnectInfo> calleeMap_;
    sptr<IRemoteObject::DeathRecipient> callerDeathRecipient_;
    std::shared_ptr<DmsCallbackTask> dmsCallbackTask_;
    std::shared_ptr<AppExecFwk::EventHandler> componentChangeHandler_;
    std::mutex callerLock_;
    std::map<sptr<IRemoteObject>, std::list<ConnectAbilitySession>> callerMap_;
    sptr<IRemoteObject::DeathRecipient> callerDeathRecipientForLocalDevice_;
    std::mutex observerLock_;
    std::map<sptr<IRemoteObject>, ObserverInfo> observerMap_;
    std::mutex callLock_;
    std::map<sptr<IRemoteObject>, CallInfo> callMap_;
    std::mutex tokenMutex_;
    std::mutex registerMutex_;
    std::atomic<int32_t> token_ {0};
    std::map<std::string, sptr<AppStateObserver>> bundleNameMap_;
    sptr<DistributedMissionFocusedListener> missionFocusedListener_ = nullptr;

#ifdef DMSFWK_INTERACTIVE_ADAPTER
    std::mutex dmsAdapetrLock_;
    void *dllHandle_ = nullptr;
    IDmsInteractiveAdapter dmsAdapetr_ = {
        .StartRemoteAbilityAdapter = nullptr,
        .StartAbilityFromRemoteAdapter = nullptr,
        .StopAbilityFromRemoteAdapter = nullptr,
        .ConnectRemoteAbilityAdapter = nullptr,
        .ConnectAbilityFromRemoteAdapter = nullptr,
        .DisconnectRemoteAbilityAdapter = nullptr,
        .DisconnectAbilityFromRemoteAdapter = nullptr,
        .NotifyAbilityLifecycleChangedFromRemoteAdapter = nullptr,
        .OnDeviceOnlineEx = nullptr,
        .OnDeviceOfflineEx = nullptr,
        .OnDeviceInfoChangedEx = nullptr,
    };
#endif
};

class ConnectAbilitySession {
public:
    ConnectAbilitySession(const std::string& sourceDeviceId, const std::string& destinationDeviceId,
        const CallerInfo& callerInfo, TargetComponent targetComponent = TargetComponent::HARMONY_COMPONENT);
    ~ConnectAbilitySession() = default;

    const std::string& GetSourceDeviceId() const
    {
        return sourceDeviceId_;
    }

    const std::string& GetDestinationDeviceId() const
    {
        return destinationDeviceId_;
    }

    std::list<AppExecFwk::ElementName> GetElementsList() const
    {
        return elementsList_;
    }

    CallerInfo GetCallerInfo() const
    {
        return callerInfo_;
    }

    TargetComponent GetTargetComponent() const
    {
        return targetComponent_;
    }

    bool IsSameCaller(const CallerInfo& callerInfo);
    void AddElement(const AppExecFwk::ElementName& element);

private:
    std::string sourceDeviceId_;
    std::string destinationDeviceId_;
    std::list<AppExecFwk::ElementName> elementsList_;
    CallerInfo callerInfo_;
    TargetComponent targetComponent_;
};

class CallerDeathRecipient : public IRemoteObject::DeathRecipient {
public:
    CallerDeathRecipient() = default;
    explicit CallerDeathRecipient(int32_t deviceType)
    {
        deviceType_ = deviceType;
    }
    ~CallerDeathRecipient() override = default;
    void OnRemoteDied(const wptr<IRemoteObject>& remote) override;
private:
    int32_t deviceType_ = IDistributedSched::CALLEE;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_SCHED_SERVICE_H
