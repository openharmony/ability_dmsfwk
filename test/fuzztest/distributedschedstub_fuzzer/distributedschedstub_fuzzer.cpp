/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "distributedschedstub_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <singleton.h>

#include "distributed_sched_interface.h"
#include "distributed_sched_service.h"
#include "distributed_sched_stub.h"
#include "fuzz_util.h"
#include "parcel_helper.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::u16string DMS_STUB_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
}

bool StartRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return false;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    Want want;
    int32_t callerUid = *(reinterpret_cast<const int32_t*>(data));
    int32_t requestCode = *(reinterpret_cast<const int32_t*>(data));
    uint32_t accessToken = *(reinterpret_cast<const uint32_t*>(data));
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteParcelable(&want);
    dataParcel.WriteInt32(callerUid);
    dataParcel.WriteInt32(requestCode);
    dataParcel.WriteUint32(accessToken);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
    return true;
}

void ConnectRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::CONNECT_REMOTE_ABILITY);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    Want want;
    int32_t callerUid = *(reinterpret_cast<const int32_t*>(data));
    int32_t callerPid = *(reinterpret_cast<const int32_t*>(data));
    uint32_t accessToken = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteParcelable(&want);
    dataParcel.WriteInt32(callerUid);
    dataParcel.WriteInt32(callerPid);
    dataParcel.WriteUint32(accessToken);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void DisconnectRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::DISCONNECT_REMOTE_ABILITY);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t callerUid = *(reinterpret_cast<const int32_t*>(data));
    uint32_t accessToken = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteInt32(callerUid);
    dataParcel.WriteUint32(accessToken);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void StartContinuationInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_CONTINUATION);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    Want want;
    int32_t missionId = *(reinterpret_cast<const int32_t*>(data));
    int32_t callerUid = *(reinterpret_cast<const int32_t*>(data));
    int32_t status = *(reinterpret_cast<const int32_t*>(data));
    uint32_t accessToken = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteParcelable(&want);
    dataParcel.WriteInt32(missionId);
    dataParcel.WriteInt32(callerUid);
    dataParcel.WriteInt32(status);
    dataParcel.WriteUint32(accessToken);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void NotifyCompleteContinuationInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_COMPLETE_CONTINUATION);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteInt32(sessionId);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void ContinueMissionInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    std::string srcDevId(reinterpret_cast<const char*>(data), size);
    std::string dstDevId(reinterpret_cast<const char*>(data), size);
    int32_t missionId = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteString(srcDevId);
    dataParcel.WriteString(dstDevId);
    dataParcel.WriteInt32(missionId);
    DelayedSingleton<DistributedSchedService>::GetInstance()->ContinueMissionInner(dataParcel, reply);
}

void ContinueMissionOfBundleNameInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    std::string srcDevId(reinterpret_cast<const char*>(data), size);
    std::string dstDevId(reinterpret_cast<const char*>(data), size);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    dataParcel.WriteString(srcDevId);
    dataParcel.WriteString(dstDevId);
    dataParcel.WriteString(bundleName);
    DelayedSingleton<DistributedSchedService>::GetInstance()->ContinueMissionOfBundleNameInner(dataParcel, reply);
}

void GetMissionInfosInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::GET_MISSION_INFOS);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t numMissions = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteInt32(numMissions);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void RegisterMissionListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_MISSION_LISTENER);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void UnRegisterMissionListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::UNREGISTER_MISSION_LISTENER);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void StartSyncRemoteMissionsInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_SYNC_MISSIONS);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void StopSyncRemoteMissionsInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::STOP_SYNC_MISSIONS);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void GetRemoteMissionSnapshotInfoInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::GET_REMOTE_MISSION_SNAPSHOT_INFO);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string networkId(reinterpret_cast<const char*>(data), size);
    int32_t missionId = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteString(networkId);
    dataParcel.WriteInt32(missionId);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void StartRemoteAbilityByCallInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY_BY_CALL);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string networkId(reinterpret_cast<const char*>(data), size);
    int32_t missionId = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteString(networkId);
    dataParcel.WriteInt32(missionId);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void ReleaseRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::RELEASE_REMOTE_ABILITY);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void GetDistributedComponentListInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    DelayedSingleton<DistributedSchedService>::GetInstance()->GetDistributedComponentListInner(dataParcel, reply);
}

void StartRemoteFreeInstallInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_FREE_INSTALL);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t callerUid = *(reinterpret_cast<const int32_t*>(data));
    int32_t requestCode = *(reinterpret_cast<const int32_t*>(data));
    uint32_t accessToken = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteInt32(callerUid);
    dataParcel.WriteInt32(requestCode);
    dataParcel.WriteUint32(accessToken);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void StartRemoteShareFormInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_SHARE_FORM);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteString(deviceId);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void StopRemoteExtensionAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    Want want;
    int32_t callerUid = *(reinterpret_cast<const int32_t*>(data));
    int32_t serviceType = *(reinterpret_cast<const int32_t*>(data));
    uint32_t accessToken = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteParcelable(&want);
    dataParcel.WriteInt32(callerUid);
    dataParcel.WriteInt32(serviceType);
    dataParcel.WriteUint32(accessToken);
    DelayedSingleton<DistributedSchedService>::GetInstance()->StopRemoteExtensionAbilityInner(dataParcel, reply);
}

void RegisterOnListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_ON_LISTENER);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string type(reinterpret_cast<const char*>(data), size);
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteString(type);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void RegisterOffListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_OFF_LISTENER);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string type(reinterpret_cast<const char*>(data), size);
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteString(type);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void RegisterDSchedEventListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::REGISTER_DSCHED_EVENT_LISTENER);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void UnRegisterDSchedEventListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::UNREGISTER_DSCHED_EVENT_LISTENER);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}

void SetMissionContinueStateInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::SET_MISSION_CONTINUE_STATE);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t missionId = *(reinterpret_cast<const int32_t*>(data));
    int32_t state = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteInt32(missionId);
    dataParcel.WriteInt32(state);
    DelayedSingleton<DistributedSchedService>::GetInstance()->OnRemoteRequest(code, dataParcel, reply, option);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::StartRemoteAbilityInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ConnectRemoteAbilityInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::DisconnectRemoteAbilityInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartContinuationInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyCompleteContinuationInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ContinueMissionInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ContinueMissionOfBundleNameInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::GetMissionInfosInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::RegisterMissionListenerInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::UnRegisterMissionListenerInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartSyncRemoteMissionsInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StopSyncRemoteMissionsInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::GetRemoteMissionSnapshotInfoInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartRemoteAbilityByCallInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ReleaseRemoteAbilityInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::GetDistributedComponentListInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartRemoteFreeInstallInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartRemoteShareFormInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StopRemoteExtensionAbilityInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::RegisterOnListenerInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::RegisterOffListenerInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::RegisterDSchedEventListenerInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::UnRegisterDSchedEventListenerInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::SetMissionContinueStateInnerFuzzTest(data, size);
    return 0;
}