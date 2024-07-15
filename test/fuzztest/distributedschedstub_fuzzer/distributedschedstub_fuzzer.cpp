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

#include "distributedschedstub_fuzzer.h"

#include <cstddef>
#include <cstdint>
#include <singleton.h>

#include "distributed_sched_interface.h"
#include "distributed_sched_service.h"
#include "distributed_sched_stub.h"
#include "distributedWant/distributed_want.h"
#include "fuzz_util.h"
#include "parcel_helper.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedSchedFuzzTest";
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void NotifyCompleteContinuationInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_COMPLETE_CONTINUATION);
    std::string devId(reinterpret_cast<const char*>(data), size);
    bool isSuccess = *(reinterpret_cast<const bool*>(data));
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    dataParcel.WriteString(devId);
    dataParcel.WriteInt32(sessionId);
    dataParcel.WriteBool(isSuccess);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().ContinueMissionInner(dataParcel, reply);
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
    DistributedSchedService::GetInstance().ContinueMissionOfBundleNameInner(dataParcel, reply);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void GetDistributedComponentListInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    DistributedSchedService::GetInstance().GetDistributedComponentListInner(dataParcel, reply);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().StopRemoteExtensionAbilityInner(dataParcel, reply);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void StartAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_ABILITY);
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &compatibleAbilityInfo);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void SendResultFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::SEND_RESULT_FROM_REMOTE);
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedWant dstbWant;
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void NotifyDSchedEventResultFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_DSCHED_EVENT_RESULT_FROM_REMOTE);
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void NotifyContinuationResultFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_CONTINUATION_RESULT_FROM_REMOTE);
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    bool boolData = *(reinterpret_cast<const bool*>(data));
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedWant dstbWant;
    PARCEL_WRITE_HELPER_NORET(dataParcel, Bool, boolData);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void ConnectAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::CONNECT_ABILITY_FROM_REMOTE);
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    DistributedWant dstbWant;
    const sptr<IRemoteObject> connect;
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &compatibleAbilityInfo);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void DisconnectAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::DISCONNECT_ABILITY_FROM_REMOTE);
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    sptr<IRemoteObject> connect;
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void NotifyProcessDiedFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_PROCESS_DIED_FROM_REMOTE);
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void GetContinueInfoInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::GET_CONTINUE_INFO);
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string str(reinterpret_cast<const char*>(data), size);
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void NotifyMissionsChangedFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_MISSIONS_CHANGED_FROM_REMOTE);
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    std::vector<DstbMissionInfo> missionInfos;
    CallerInfo callerInfo;
    DistributedWant dstbWant;
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    if (!DstbMissionInfo::WriteDstbMissionInfosToParcel(dataParcel, missionInfos)) {
        return;
    }
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void ReleaseAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::RELEASE_ABILITY_FROM_REMOTE);
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> remote;
    sptr<IRemoteObject> connect;
    const AppExecFwk::ElementName element;
    const CallerInfo callerInfo;
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    if (!dataParcel.WriteParcelable(&element)) {
        HILOGE("ReleaseAbilityFromRemote write element error.");
        return;
    }
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
}

void NotifyStateChangedFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    int32_t code = static_cast<uint32_t>(IDSchedInterfaceCode::NOTIFY_STATE_CHANGED_FROM_REMOTE);
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    const AppExecFwk::ElementName element;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    if (!dataParcel.WriteParcelable(&element)) {
        HILOGE("NotifyStateChangedFromRemote write element error.");
        return;
    }
    DistributedSchedService::GetInstance().OnRemoteRequest(code, dataParcel, reply, option);
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
    OHOS::DistributedSchedule::StartAbilityFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::SendResultFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyDSchedEventResultFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyContinuationResultFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ConnectAbilityFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::DisconnectAbilityFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyProcessDiedFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::GetContinueInfoInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyMissionsChangedFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::ReleaseAbilityFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyStateChangedFromRemoteInnerFuzzTest(data, size);
    return 0;
}