/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#ifndef MOCK_DISTRIBUTED_SCHED_H
#define MOCK_DISTRIBUTED_SCHED_H

#include "distributed_sched_stub.h"

namespace OHOS {
namespace DistributedSchedule {
class MockDistributedSched : public DistributedSchedStub {
public:
    explicit MockDistributedSched(bool expectedTrue = false)
    {
        expectedTrue_ = expectedTrue;
    }
    ~MockDistributedSched() = default;

    int32_t StartRemoteAbility(const OHOS::AAFwk::Want& want, int32_t callerUid, int32_t requestCode,
        uint32_t accessToken) override;
    int32_t StartAbilityFromRemote(const OHOS::AAFwk::Want& want,
        const OHOS::AppExecFwk::AbilityInfo& abilityInfo, int32_t requestCode, const CallerInfo& callerInfo,
        const AccountInfo& accountInfo) override;
    int32_t SendResultFromRemote(OHOS::AAFwk::Want& want, int32_t requestCode, const CallerInfo& callerInfo,
        const AccountInfo& accountInfo, int32_t resultCode) override;
    int32_t ContinueMission(const std::string& srcDeviceId, const std::string& dstDeviceId, int32_t missionId,
        const sptr<IRemoteObject>& callback, const OHOS::AAFwk::WantParams& wantParams) override;
    int32_t StartContinuation(const OHOS::AAFwk::Want& want, int32_t missionId, int32_t callerUid,
        int32_t status, uint32_t accessToken) override;
    void NotifyCompleteContinuation(const std::u16string& devId, int32_t sessionId, bool isSuccess) override;
    int32_t NotifyContinuationResultFromRemote(int32_t sessionId, bool isSuccess, const std::string dstInfo) override;
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
    int32_t StartSyncRemoteMissions(const std::string& devId, bool fixConflict, int64_t tag,
        int32_t callingUid) override;
    int32_t RegisterMissionListener(const std::u16string& devId, const sptr<IRemoteObject>& obj,
        int32_t callingUid) override;
    int32_t UnRegisterMissionListener(const std::u16string& devId, const sptr<IRemoteObject>& obj) override;
    int32_t GetMissionInfos(const std::string& deviceId, int32_t numMissions,
        std::vector<AAFwk::MissionInfo>& missionInfos) override;
    int32_t GetRemoteMissionSnapshotInfo(const std::string& networkId, int32_t missionId,
        std::unique_ptr<AAFwk::MissionSnapshot>& missionSnapshot) override;
    int32_t NotifyMissionsChangedFromRemote(const std::vector<DstbMissionInfo>& missionInfos,
        const CallerInfo& callerInfo) override;
    int32_t StartSyncMissionsFromRemote(const CallerInfo& callerInfo,
        std::vector<DstbMissionInfo>& missionInfos) override;
    int32_t StopSyncMissionsFromRemote(const CallerInfo& callerInfo) override;
    int32_t StopSyncRemoteMissions(const std::string& devId, int32_t callingUid) override;
    int32_t SetMissionContinueState(const int32_t missionId, const OHOS::AAFwk::ContinueState &state,
        int32_t callingUid) override;
#endif
    int32_t StartRemoteAbilityByCall(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect,
        int32_t callerUid, int32_t callerPid, uint32_t accessToken) override;
    int32_t ReleaseRemoteAbility(const sptr<IRemoteObject>& connect,
        const AppExecFwk::ElementName &element) override;
    int32_t StartAbilityByCallFromRemote(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect,
        const CallerInfo& callerInfo, const AccountInfo& accountInfo) override;
    int32_t ReleaseAbilityFromRemote(const sptr<IRemoteObject>& connect, const AppExecFwk::ElementName &element,
        const CallerInfo& callerInfo) override;
    int32_t NotifyStateChangedFromRemote(int32_t abilityState, int32_t missionId,
        const AppExecFwk::ElementName& element) override;
    int32_t GetDistributedComponentList(std::vector<std::string>& distributedComponents) override;
#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
    int32_t StartRemoteShareForm(const std::string& remoteDeviceId,
        const OHOS::AppExecFwk::FormShareInfo& formShareInfo) override;
    int32_t StartShareFormFromRemote(
        const std::string& remoteDeviceId, const OHOS::AppExecFwk::FormShareInfo& formShareInfo) override;
#endif
    int32_t StartRemoteFreeInstall(const OHOS::AAFwk::Want& want, int32_t callerUid, int32_t requestCode,
        uint32_t accessToken, const sptr<IRemoteObject>& callback) override;
    int32_t StartFreeInstallFromRemote(const FreeInstallInfo& info, int64_t taskId) override;
    int32_t NotifyCompleteFreeInstallFromRemote(int64_t taskId, int32_t resultCode) override;
    int32_t NotifyCompleteFreeInstall(const FreeInstallInfo& info, int64_t taskId, int32_t resultCode);
    int32_t StopRemoteExtensionAbility(
        const OHOS::AAFwk::Want& want, int32_t callerUid, uint32_t accessToken, int32_t extensionType) override;
    int32_t StopExtensionAbilityFromRemote(const OHOS::AAFwk::Want& want,
        const CallerInfo& callerInfo, const AccountInfo& accountInfo, int32_t extensionType) override;
#ifdef DMSFWK_INTERACTIVE_ADAPTER
    bool CheckRemoteOsType(const std::string& netwokId) override;
    int32_t StartRemoteAbilityAdapter(const OHOS::AAFwk::Want& want, int32_t callerUid, int32_t requestCode,
        uint32_t accessToken);
    int32_t ConnectRemoteAbilityAdapter(const OHOS::AAFwk::Want& want, const sptr<IRemoteObject>& connect,
        int32_t callerUid, int32_t callerPid, uint32_t accessToken);
    int32_t StartAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply) override;
    int32_t StopAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply) override;
    int32_t ConnectAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply) override;
    int32_t DisconnectAbilityFromRemoteAdapter(MessageParcel& data, MessageParcel& reply) override;
    int32_t NotifyAbilityLifecycleChangedFromRemoteAdapter(MessageParcel& data, MessageParcel& reply) override;
#endif

private:
    bool expectedTrue_ = false;
};
} // namespace DistributedSchedule
} // namespace OHOS

#endif // MOCK_DISTRIBUTED_SCHED_H
