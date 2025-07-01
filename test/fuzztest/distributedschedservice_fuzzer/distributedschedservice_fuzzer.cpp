/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "distributedschedservice_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <fuzzer/FuzzedDataProvider.h>
#include <singleton.h>

#include "distributed_sched_interface.h"
#include "distributed_sched_service.h"
#include "distributed_sched_stub.h"
#include "distributedWant/distributed_want.h"
#include "mock_fuzz_util.h"
#include "mock_distributed_sched.h"
#include "parcel_helper.h"
#include "dms_continue_time_dumper.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
constexpr int32_t ON_DEMAND_REASON_ID_COUNT = 7;
constexpr int32_t GET_DEXTENSION_PROCESS_PARAM_COUNT = 6;
constexpr size_t DUMP_ARGS_MAX_COUNT = 10;
constexpr int SESSION_COUNT_MAX = 10;
constexpr int32_t ON_DEMAND_REASON_ID_COUNT_FOUR = 4;

std::string GetDExtensionName(std::string bundleName, int32_t userId);
std::string GetDExtensionProcess(std::string bundleName, int32_t userId);
void OnStopFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string reasonName = fdp.ConsumeRandomLengthString();
    std::string reasonValue = fdp.ConsumeRandomLengthString();
    int32_t enumIdx = fdp.ConsumeIntegral<int32_t>() % ON_DEMAND_REASON_ID_COUNT;
    OnDemandReasonId reasonId = static_cast<OnDemandReasonId>(enumIdx);
    int32_t extraDataId = fdp.ConsumeIntegral<int32_t>();
    SystemAbilityOnDemandReason reason(reasonId, reasonName, reasonValue, extraDataId);

    DistributedSchedService::GetInstance().OnStop(reason);
}

void OnActiveFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string reasonName = fdp.ConsumeRandomLengthString();
    std::string reasonValue = fdp.ConsumeRandomLengthString();

    int32_t enumIdx = fdp.ConsumeIntegral<int32_t>() % ON_DEMAND_REASON_ID_COUNT;
    OnDemandReasonId reasonId = static_cast<OnDemandReasonId>(enumIdx);

    int32_t extraDataId = fdp.ConsumeIntegral<int32_t>();

    SystemAbilityOnDemandReason reason(reasonId, reasonName, reasonValue, extraDataId);

    DistributedSchedService::GetInstance().OnActive(reason);
}

void HandleBootStartFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string reasonName = fdp.ConsumeRandomLengthString();
    std::string reasonValue = fdp.ConsumeRandomLengthString();

    int32_t enumIdx = fdp.ConsumeIntegral<int32_t>() % ON_DEMAND_REASON_ID_COUNT;
    OnDemandReasonId reasonId = static_cast<OnDemandReasonId>(enumIdx);

    int32_t extraDataId = fdp.ConsumeIntegral<int32_t>();

    SystemAbilityOnDemandReason reason(reasonId, reasonName, reasonValue, extraDataId);

    DistributedSchedService::GetInstance().HandleBootStart(reason);
}

void DoStartFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    DistributedSchedService::GetInstance().DoStart();
}

void DeviceOnlineNotifyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string networkId(reinterpret_cast<const char*>(data), size / 2);

    DistributedSchedService::GetInstance().DeviceOnlineNotify(networkId);
}

void DeviceOfflineNotifyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string networkId(reinterpret_cast<const char*>(data), size / 2);

    DistributedSchedService::GetInstance().DeviceOfflineNotify(networkId);
}

void DeviceOfflineNotifyAfterDeleteFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    std::string networkId(reinterpret_cast<const char*>(data), size / 2);

    DistributedSchedService::GetInstance().DeviceOfflineNotifyAfterDelete(networkId);
}

void InitFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;
    DistributedSchedService::GetInstance().Init();
}

void InitMissionManagerFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;

    DistributedSchedService::GetInstance().InitMissionManager();
}

void InitWifiStateListenerFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;

    DistributedSchedService::GetInstance().InitWifiStateListener();
}

void InitBluetoothStateListenerFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;

    DistributedSchedService::GetInstance().InitBluetoothStateListener();
}

void InitDeviceCfgFuzzTest(const uint8_t* data, size_t size)
{
    (void)data;
    (void)size;

    DistributedSchedService::GetInstance().InitDeviceCfg();
}

void GetDExtensionNameFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    OHOS::DistributedSchedule::GetDExtensionName(bundleName, userId);
}

void GetDExtensionProcessFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < GET_DEXTENSION_PROCESS_PARAM_COUNT * sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString();
    int32_t userId = fdp.ConsumeIntegral<int32_t>();
    OHOS::DistributedSchedule::GetDExtensionProcess(bundleName, userId);
}

void ConnectDExtensionFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < ON_DEMAND_REASON_ID_COUNT_FOUR * sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    DExtSourceInfo sourceInfo;
    sourceInfo.deviceId = fdp.ConsumeRandomLengthString();
    sourceInfo.networkId = fdp.ConsumeRandomLengthString();
    sourceInfo.bundleName = fdp.ConsumeRandomLengthString();
    sourceInfo.moduleName = fdp.ConsumeRandomLengthString();
    sourceInfo.abilityName = fdp.ConsumeRandomLengthString();

    DExtSinkInfo sinkInfo;
    sinkInfo.userId = fdp.ConsumeIntegral<int32_t>();
    sinkInfo.pid = fdp.ConsumeIntegral<int32_t>();
    sinkInfo.bundleName = fdp.ConsumeRandomLengthString();
    sinkInfo.moduleName = fdp.ConsumeRandomLengthString();
    sinkInfo.abilityName = fdp.ConsumeRandomLengthString();
    sinkInfo.serviceName = fdp.ConsumeRandomLengthString();

    std::string tokenId = fdp.ConsumeRandomLengthString();
    std::string delegatee = fdp.ConsumeRandomLengthString();
    DExtConnectInfo connectInfo(sourceInfo, sinkInfo, tokenId, delegatee);

    int32_t resultEnum = fdp.ConsumeIntegralInRange<int32_t>(0, static_cast<int32_t>(DExtConnectResult::FAILED));
    DExtConnectResult result = static_cast<DExtConnectResult>(resultEnum);
    int32_t errCode = fdp.ConsumeIntegral<int32_t>();
    DExtConnectResultInfo resultInfo(connectInfo, result, errCode);

    DistributedSchedService::GetInstance().ConnectDExtensionFromRemote(connectInfo, resultInfo);
}

void OnStartFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t) + sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string reasonName = fdp.ConsumeRandomLengthString();
    std::string reasonValue = fdp.ConsumeRandomLengthString();
    int32_t enumIdx = fdp.ConsumeIntegral<int32_t>() % ON_DEMAND_REASON_ID_COUNT;
    OnDemandReasonId reasonId = static_cast<OnDemandReasonId>(enumIdx);
    int32_t extraDataId = fdp.ConsumeIntegral<int32_t>();
    SystemAbilityOnDemandReason reason(reasonId, reasonName, reasonValue, extraDataId);

    DistributedSchedService::GetInstance().OnStart(reason);
}

void OnAddSystemAbilityFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t systemAbilityId = fdp.ConsumeIntegral<int32_t>();
    std::string deviceId = fdp.ConsumeRandomLengthString();

    DistributedSchedService::GetInstance().OnAddSystemAbility(systemAbilityId, deviceId);
}

void ContinueStateCallbackUnRegisterFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string moduleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();

    DistributedSchedService::GetInstance().ContinueStateCallbackUnRegister(missionId, bundleName,
        moduleName, abilityName);
}

void ContinueMissionFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    std::string srcDeviceId = fdp.ConsumeRandomLengthString();
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    sptr<IRemoteObject> callback = nullptr;
    OHOS::AAFwk::WantParams wantParams;

    DistributedSchedService::GetInstance().ContinueMission(srcDeviceId, dstDeviceId, missionId, callback, wantParams);
}

void ProcessFormMgrDiedFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    wptr<IRemoteObject> remote = nullptr;

    DistributedSchedService::GetInstance().ProcessFormMgrDied(remote);
}

void CheckCollabStartPermissionFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    CallerInfo callerInfo;
    AccountInfo accountInfo;
    bool needQueryExtension = fdp.ConsumeBool();

    DistributedSchedService::GetInstance().CheckCollabStartPermission(want,
        callerInfo, accountInfo, needQueryExtension);
}

void CheckTargetPermission4DiffBundleFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    CallerInfo callerInfo;
    AccountInfo accountInfo;
    int32_t flag = fdp.ConsumeIntegral<int32_t>();
    bool needQueryExtension = fdp.ConsumeBool();

    DistributedSchedService::GetInstance().CheckTargetPermission4DiffBundle(want,
        callerInfo, accountInfo, flag, needQueryExtension);
}

void RegisterAppStateObserverFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    CallerInfo callerInfo;
    sptr<IRemoteObject> srcConnect = nullptr;
    sptr<IRemoteObject> callbackWrapper = nullptr;

    DistributedSchedService::GetInstance().RegisterAppStateObserver(want, callerInfo, srcConnect, callbackWrapper);
}

void NotifyFreeInstallResultFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    CallbackTaskItem item;
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().NotifyFreeInstallResult(item, resultCode);
}
void HandleRemoteNotifyFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t)) + (size < sizeof(int64_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    DistributedSchedService::FreeInstallInfo info;
    int64_t taskId = fdp.ConsumeIntegral<int64_t>();
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().HandleRemoteNotify(info, taskId, resultCode);
}

void StartLocalAbilityFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t)) + (size < sizeof(int64_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    DistributedSchedService::FreeInstallInfo info;
    int64_t taskId = fdp.ConsumeIntegral<int64_t>();
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().StartLocalAbility(info, taskId, resultCode);
}

void SetMissionContinueStateFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t)) + (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    AAFwk::ContinueState state = static_cast<AAFwk::ContinueState>(fdp.ConsumeIntegral<int32_t>());
    int32_t callingUid = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().SetMissionContinueState(missionId, state, callingUid);
}

void TryConnectRemoteAbilityFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    sptr<IRemoteObject> connect = nullptr;
    CallerInfo callerInfo;

    DistributedSchedService::GetInstance().TryConnectRemoteAbility(want, connect, callerInfo);
}

void NotifyContinuateEventResultFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();
    EventNotify eventNotify;

    DistributedSchedService::GetInstance().NotifyContinuateEventResult(resultCode, eventNotify);
}

void DurationStartFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    std::string srcDeviceId = fdp.ConsumeRandomLengthString();
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();

    DistributedSchedService::GetInstance().DurationStart(srcDeviceId, dstDeviceId);
}

void GetCallerInfoFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    std::string localDeviceId = fdp.ConsumeRandomLengthString();
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();

    CallerInfo callerInfo;
    DistributedSchedService::GetInstance().GetCallerInfo(localDeviceId, callerUid, accessToken, callerInfo);
}

void StartRemoteAbilityFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    AAFwk::Want want;
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();
    int32_t requestCode = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().StartRemoteAbility(want, callerUid, requestCode, accessToken);
}

void StartAbilityFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    AAFwk::Want want;
    AppExecFwk::AbilityInfo abilityInfo;

    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();

    AccountInfo accountInfo;

    int32_t requestCode = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().StartAbilityFromRemote(
        want, abilityInfo, requestCode, callerInfo, accountInfo);
}

void SendResultFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    AAFwk::Want want;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element(deviceId, bundleName, abilityName);
    want.SetElement(element);
    want.SetParam("dmsSrcNetworkId", deviceId);
    want.SetParam("dmsMissionId", fdp.ConsumeIntegral<int32_t>());

    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();

    AccountInfo accountInfo;

    int32_t requestCode = fdp.ConsumeIntegral<int32_t>();
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().SendResultFromRemote(want, requestCode, callerInfo, accountInfo, resultCode);
}

void RemoveContinuationTimeoutFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().RemoveContinuationTimeout(missionId);
}

void SetContinuationTimeoutFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    int32_t timeout = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().SetContinuationTimeout(missionId, timeout);
}

void GetContinuationDeviceFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();

    std::string result = DistributedSchedService::GetInstance().GetContinuaitonDevice(missionId);
}

void SetWantForContinuationFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    AAFwk::Want newWant;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element(deviceId, bundleName, abilityName);
    newWant.SetElement(element);

    newWant.SetParam("ohos.extra.param.key.supportContinuePageStack", fdp.ConsumeBool());
    newWant.SetParam("ohos.extra.param.key.supportContinueModuleNameUpdate", fdp.ConsumeRandomLengthString());

    int32_t missionId = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().SetWantForContinuation(newWant, missionId);
}

void DealDSchedEventResultFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element(deviceId, bundleName, abilityName);
    want.SetElement(element);

    int32_t status = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().DealDSchedEventResult(want, status);
}

void GetIsFreeInstallFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().GetIsFreeInstall(missionId);
}

void StartContinuationFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t) + sizeof(int32_t) + sizeof(int32_t) + sizeof(uint32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    AAFwk::Want want;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element(deviceId, bundleName, abilityName);
    want.SetElement(element);
    want.SetFlags(fdp.ConsumeIntegral<uint32_t>());

    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    int32_t status = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();

    DistributedSchedService::GetInstance().StartContinuation(want, missionId, callerUid, status, accessToken);
}

void NotifyContinuationResultFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t sessionId = fdp.ConsumeIntegralInRange<int32_t>(1, INT32_MAX);
    std::string dstInfo = fdp.ConsumeRandomLengthString();
    bool isSuccess = fdp.ConsumeBool();
    DistributedSchedService::GetInstance().NotifyContinuationResultFromRemote(sessionId, isSuccess, dstInfo);
}

void NotifyDSchedEventResultFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    std::string type = fdp.ConsumeRandomLengthString();
    int32_t dSchedEventResult = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().NotifyDSchedEventResultFromRemote(type, dSchedEventResult);
}

void NotifyDSchedEventCallbackResultFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();

    EventNotify event;
    event.eventResult_ = fdp.ConsumeIntegral<int32_t>();
    event.srcNetworkId_ = fdp.ConsumeRandomLengthString();
    event.dstNetworkId_ = fdp.ConsumeRandomLengthString();
    event.srcBundleName_ = fdp.ConsumeRandomLengthString();
    event.srcModuleName_ = fdp.ConsumeRandomLengthString();
    event.srcAbilityName_ = fdp.ConsumeRandomLengthString();
    event.destBundleName_ = fdp.ConsumeRandomLengthString();
    event.destModuleName_ = fdp.ConsumeRandomLengthString();
    event.destAbilityName_ = fdp.ConsumeRandomLengthString();
    event.dSchedEventType_ = static_cast<DSchedEventType>(fdp.ConsumeIntegral<int32_t>());
    event.state_ = static_cast<DSchedEventState>(fdp.ConsumeIntegral<int32_t>());

    DistributedSchedService::GetInstance().NotifyDSchedEventCallbackResult(resultCode, event);
}

void NotifyCollaborateEventWithSessionsFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    std::list<ConnectAbilitySession> sessionsList;
    int sessionCount = fdp.ConsumeIntegralInRange<int>(1, SESSION_COUNT_MAX);
    for (int i = 0; i < sessionCount; ++i) {
        CallerInfo callerInfo;
        callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
        callerInfo.uid = fdp.ConsumeIntegral<int32_t>();

        AppExecFwk::ElementName element(
            fdp.ConsumeRandomLengthString(),
            fdp.ConsumeRandomLengthString(),
            fdp.ConsumeRandomLengthString()
        );

        ConnectAbilitySession session(callerInfo.sourceDeviceId, fdp.ConsumeRandomLengthString(), callerInfo);
        session.AddElement(element);
        sessionsList.emplace_back(session);
    }

    DSchedEventState state = static_cast<DSchedEventState>(fdp.ConsumeIntegral<int32_t>());
    int32_t ret = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().NotifyCollaborateEventWithSessions(sessionsList, state, ret);
}

void GetCurSrcCollaborateEventFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    CallerInfo callerInfo;
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();

    AppExecFwk::ElementName element(
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString()
    );
    element.SetModuleName(fdp.ConsumeRandomLengthString());

    DSchedEventState state = static_cast<DSchedEventState>(fdp.ConsumeIntegral<int32_t>());
    int32_t ret = fdp.ConsumeIntegral<int32_t>();
    EventNotify event;

    DistributedSchedService::GetInstance().GetCurSrcCollaborateEvent(callerInfo, element, state, ret, event);
}

void GetCurDestCollaborateEventFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    CallerInfo callerInfo;
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    callerInfo.extraInfoJson["dmsCallerUidBundleName"] = fdp.ConsumeRandomLengthString();

    AppExecFwk::ElementName element(
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString(),
        fdp.ConsumeRandomLengthString()
    );
    element.SetModuleName(fdp.ConsumeRandomLengthString());

    DSchedEventState state = static_cast<DSchedEventState>(fdp.ConsumeIntegral<int32_t>());
    int32_t ret = fdp.ConsumeIntegral<int32_t>();

    EventNotify event;

    DistributedSchedService::GetInstance().GetCurDestCollaborateEvent(callerInfo, element, state, ret, event);
}

void CheckDistributedConnectLockedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    CallerInfo callerInfo;
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();

    DistributedSchedService::GetInstance().CheckDistributedConnectLocked(callerInfo);
}

void DecreaseConnectLockedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    DistributedSchedService::GetInstance().DecreaseConnectLocked(uid);
}

void GetUidLockedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }

    FuzzedDataProvider fdp(data, size);

    std::list<ConnectAbilitySession> sessionsList;
    int sessionCount = fdp.ConsumeIntegralInRange<int>(0, SESSION_COUNT_MAX);
    for (int i = 0; i < sessionCount; ++i) {
        CallerInfo callerInfo;
        callerInfo.uid = fdp.ConsumeIntegral<int32_t>();
        callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();

        AppExecFwk::ElementName element(
            fdp.ConsumeRandomLengthString(),
            fdp.ConsumeRandomLengthString(),
            fdp.ConsumeRandomLengthString()
        );

        ConnectAbilitySession session(callerInfo.sourceDeviceId, fdp.ConsumeRandomLengthString(), callerInfo);
        session.AddElement(element);
        sessionsList.emplace_back(session);
    }
    DistributedSchedService::GetInstance().GetUidLocked(sessionsList);
}
void RunExtraFuzzTests(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::DurationStartFuzzTest(data, size);
    OHOS::DistributedSchedule::GetCallerInfoFuzzTest(data, size);
    OHOS::DistributedSchedule::StartRemoteAbilityFuzzTest(data, size);
    OHOS::DistributedSchedule::StartAbilityFromRemoteFuzzTest(data, size);
    OHOS::DistributedSchedule::SendResultFromRemoteFuzzTest(data, size);
    OHOS::DistributedSchedule::RemoveContinuationTimeoutFuzzTest(data, size);
    OHOS::DistributedSchedule::SetContinuationTimeoutFuzzTest(data, size);
    OHOS::DistributedSchedule::GetContinuationDeviceFuzzTest(data, size);
    OHOS::DistributedSchedule::SetWantForContinuationFuzzTest(data, size);
    OHOS::DistributedSchedule::DealDSchedEventResultFuzzTest(data, size);
    OHOS::DistributedSchedule::GetIsFreeInstallFuzzTest(data, size);
    OHOS::DistributedSchedule::StartContinuationFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyContinuationResultFromRemoteFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyDSchedEventResultFromRemoteFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyDSchedEventCallbackResultFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyCollaborateEventWithSessionsFuzzTest(data, size);
    OHOS::DistributedSchedule::GetCurSrcCollaborateEventFuzzTest(data, size);
    OHOS::DistributedSchedule::GetCurDestCollaborateEventFuzzTest(data, size);
    OHOS::DistributedSchedule::CheckDistributedConnectLockedFuzzTest(data, size);
    OHOS::DistributedSchedule::DecreaseConnectLockedFuzzTest(data, size);
    OHOS::DistributedSchedule::GetUidLockedFuzzTest(data, size);
}
}
}
/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::OnStopFuzzTest(data, size);
    OHOS::DistributedSchedule::OnActiveFuzzTest(data, size);
    OHOS::DistributedSchedule::HandleBootStartFuzzTest(data, size);
    OHOS::DistributedSchedule::DoStartFuzzTest(data, size);
    OHOS::DistributedSchedule::DeviceOnlineNotifyFuzzTest(data, size);
    OHOS::DistributedSchedule::DeviceOfflineNotifyFuzzTest(data, size);
    OHOS::DistributedSchedule::DeviceOfflineNotifyAfterDeleteFuzzTest(data, size);
    OHOS::DistributedSchedule::InitFuzzTest(data, size);
    OHOS::DistributedSchedule::InitMissionManagerFuzzTest(data, size);
    OHOS::DistributedSchedule::InitWifiStateListenerFuzzTest(data, size);
    OHOS::DistributedSchedule::InitBluetoothStateListenerFuzzTest(data, size);
    OHOS::DistributedSchedule::InitDeviceCfgFuzzTest(data, size);
    OHOS::DistributedSchedule::GetDExtensionNameFuzzTest(data, size);
    OHOS::DistributedSchedule::GetDExtensionProcessFuzzTest(data, size);
    OHOS::DistributedSchedule::ConnectDExtensionFromRemoteFuzzTest(data, size);
    OHOS::DistributedSchedule::OnStartFuzzTest(data, size);
    OHOS::DistributedSchedule::OnAddSystemAbilityFuzzTest(data, size);
    OHOS::DistributedSchedule::ContinueStateCallbackUnRegisterFuzzTest(data, size);
    OHOS::DistributedSchedule::ProcessFormMgrDiedFuzzTest(data, size);
    OHOS::DistributedSchedule::ContinueMissionFuzzTest(data, size);
    OHOS::DistributedSchedule::CheckCollabStartPermissionFuzzTest(data, size);
    OHOS::DistributedSchedule::CheckTargetPermission4DiffBundleFuzzTest(data, size);
    OHOS::DistributedSchedule::RegisterAppStateObserverFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyFreeInstallResultFuzzTest(data, size);
    OHOS::DistributedSchedule::HandleRemoteNotifyFuzzTest(data, size);
    OHOS::DistributedSchedule::StartLocalAbilityFuzzTest(data, size);
    OHOS::DistributedSchedule::SetMissionContinueStateFuzzTest(data, size);
    OHOS::DistributedSchedule::TryConnectRemoteAbilityFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyContinuateEventResultFuzzTest(data, size);
    OHOS::DistributedSchedule::RunExtraFuzzTests(data, size);
    return 0;
}