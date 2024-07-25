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
#include "mock_fuzz_util.h"
#include "mock_distributed_sched.h"
#include "parcel_helper.h"
#include "dms_continue_time_dumper.h"

using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedSchedFuzzTest";
namespace {
const std::u16string DMS_STUB_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
const uint32_t ONE = 1;
constexpr size_t FOO_MAX_LEN = 1024;
constexpr size_t U32_AT_SIZE = 4;
}

uint32_t GetU32Data(const uint8_t* ptr, size_t size)
{
    if (size > FOO_MAX_LEN || size < U32_AT_SIZE) {
        return 0;
    }
    char *ch = (char *)malloc(size + 1);
    if (ch == nullptr) {
        std::cout << "malloc failed." << std::endl;
        return 0;
    }
    (void)memset_s(ch, size + 1, 0x00, size + 1);
    if (memcpy_s(ch, size + 1, ptr, size) != EOK) {
        std::cout << "copy failed." << std::endl;
        free(ch);
        ch = nullptr;
        return 0;
    }
    uint32_t data = (ch[0] << 24) | (ch[1] << 16) | (ch[2] << 8) | ch[3];
    free(ch);
    ch = nullptr;
    return data;
}

bool StartRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return false;
    }
    MessageParcel dataParcel;
    MessageParcel reply;
    Want want;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    uint32_t uint32Data = *(reinterpret_cast<const uint32_t*>(data));

    PARCEL_WRITE_HELPER(dataParcel, Parcelable, &want);
    PARCEL_WRITE_HELPER(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER(dataParcel, Uint32, uint32Data);
    DistributedSchedService::GetInstance().StartRemoteAbilityInner(dataParcel, reply);
    FuzzUtil::MockPermission();
    DistributedSchedService::GetInstance().StartRemoteAbilityInner(dataParcel, reply);
    return true;
}

void ConnectRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    Want want;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    uint32_t uint32Data = *(reinterpret_cast<const uint32_t*>(data));

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &want);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, uint32Data);
    DistributedSchedService::GetInstance().ConnectRemoteAbilityInner(dataParcel, reply);
    std::string devId(reinterpret_cast<const char*>(data), size);
    DistributedSchedService::GetInstance().InitDataShareManager();
    DistributedSchedService::GetInstance().InitCommonEventListener();
    DistributedSchedService::GetInstance().InitWifiStateListener();
    DistributedSchedService::GetInstance().GetFormMgrProxy();
    DistributedSchedService::GetInstance().ProcessFreeInstallOffline(devId);
    DistributedSchedService::GetInstance().ProcessCalleeOffline(devId);
}

void DisconnectRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    uint32_t uint32Data = *(reinterpret_cast<const uint32_t*>(data));

    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, uint32Data);
    DistributedSchedService::GetInstance().DisconnectRemoteAbilityInner(dataParcel, reply);
    
    std::string networkId(reinterpret_cast<const char*>(data), size);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    DistributedSchedService::GetInstance().IsRemoteInstall(networkId, bundleName);
    DistributedSchedService::GetInstance().GetContinueInfo(networkId, networkId);
}

void StartContinuationInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    Want want;
    int32_t missionId = *(reinterpret_cast<const int32_t*>(data));
    int32_t callerUid = *(reinterpret_cast<const int32_t*>(data));
    int32_t status = *(reinterpret_cast<const int32_t*>(data));
    uint32_t accessToken = *(reinterpret_cast<const int32_t*>(data));

    dataParcel.WriteParcelable(&want);
    dataParcel.WriteInt32(missionId);
    dataParcel.WriteInt32(callerUid);
    dataParcel.WriteInt32(status);
    dataParcel.WriteUint32(accessToken);
    DistributedSchedService::GetInstance().StartContinuationInner(dataParcel, reply);
    DistributedSchedService::GetInstance().StartAbility(want, callerUid);
    DistributedSchedService::GetInstance().GetAppManager();
}

void NotifyCompleteContinuationInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    std::string devId(reinterpret_cast<const char*>(data), size);
    bool isSuccess = *(reinterpret_cast<const bool*>(data));
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t sessionId = *(reinterpret_cast<const int32_t*>(data));

    dataParcel.WriteString16(Str8ToStr16(devId));
    dataParcel.WriteInt32(sessionId);
    dataParcel.WriteBool(isSuccess);
    DistributedSchedService::GetInstance().NotifyCompleteContinuationInner(dataParcel, reply);
}

void ContinueMissionInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    sptr<IRemoteObject> callback(new MockDistributedSched());
    WantParams wantParams;

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, callback);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &wantParams);
    DistributedSchedService::GetInstance().ContinueMissionInner(dataParcel, reply);
    DistributedSchedService::GetInstance().ContinueLocalMission(deviceId, int32Data, callback, wantParams);
    DistributedSchedService::GetInstance().ContinueRemoteMission(deviceId, deviceId, int32Data, callback, wantParams);
    DistributedSchedService::GetInstance().ContinueMission(deviceId, deviceId, int32Data, callback, wantParams);
}

void ContinueMissionOfBundleNameInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string str(reinterpret_cast<const char*>(data), size);
    std::string deviceId(reinterpret_cast<const char*>(data), size);
    std::string bundleName(reinterpret_cast<const char*>(data), size);
    sptr<IRemoteObject> callback(new MockDistributedSched());
    WantParams wantParams;

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, callback);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &wantParams);
    DistributedSchedService::GetInstance().ContinueMissionOfBundleNameInner(dataParcel, reply);
    DistributedSchedService::GetInstance().ContinueRemoteMission(deviceId, deviceId, bundleName,
        callback, wantParams);
    DistributedSchedService::GetInstance().ProcessContinueLocalMission(deviceId, deviceId, bundleName,
        callback, wantParams);
    DistributedSchedService::GetInstance().ProcessContinueRemoteMission(deviceId, deviceId, bundleName,
        callback, wantParams);
}

void GetMissionInfosInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, String16, Str8ToStr16(str));
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().GetMissionInfosInner(dataParcel, reply);
}

void RegisterMissionListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    Want want;
    int32_t missionId = *(reinterpret_cast<const int32_t*>(data));
    uint32_t uint32Data = *(reinterpret_cast<const uint32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    sptr<IRemoteObject> obj(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, String16, Str8ToStr16(str));
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().RegisterMissionListenerInner(dataParcel, reply);
    DistributedSchedService::GetInstance().ContinueLocalMissionDealFreeInstall(want, missionId, str, obj);
    DistributedSchedService::GetInstance().ContinueAbilityWithTimeout(str, missionId, obj, uint32Data);
}

void UnRegisterMissionListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string str(reinterpret_cast<const char*>(data), size);
    sptr<IRemoteObject> obj(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, String16, Str8ToStr16(str));
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().UnRegisterMissionListenerInner(dataParcel, reply);
}

void StartSyncRemoteMissionsInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    bool boolData = *(reinterpret_cast<const bool*>(data));
    int64_t int64Data = static_cast<int64_t>(GetU32Data(data, size));
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, String16, Str8ToStr16(str));
    PARCEL_WRITE_HELPER_NORET(dataParcel, Bool, boolData);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int64, int64Data);
    DistributedSchedService::GetInstance().StartSyncRemoteMissionsInner(dataParcel, reply);
}

void StopSyncRemoteMissionsInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, String16, Str8ToStr16(str));
    DistributedSchedService::GetInstance().StopSyncRemoteMissionsInner(dataParcel, reply);

    Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t flag = *(reinterpret_cast<const int32_t*>(data));
    DistributedSchedService::GetInstance().CheckTargetPermission(want, callerInfo, accountInfo, flag, true);
}

void GetRemoteMissionSnapshotInfoInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string networkId(reinterpret_cast<const char*>(data), size);
    int32_t missionId = *(reinterpret_cast<const int32_t*>(data));

    dataParcel.WriteString(networkId);
    dataParcel.WriteInt32(missionId);
    DistributedSchedService::GetInstance().GetRemoteMissionSnapshotInfoInner(dataParcel, reply);
    DistributedSchedService::GetInstance().DurationStart(networkId, networkId);
}

void StartRemoteAbilityByCallInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    Want want;
    sptr<IRemoteObject> obj(new MockDistributedSched());
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    uint32_t uint32Data = *(reinterpret_cast<const uint32_t*>(data));

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &want);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, uint32Data);
    DistributedSchedService::GetInstance().StartRemoteAbilityByCallInner(dataParcel, reply);
    DistributedSchedService::GetInstance().SetWantForContinuation(want, int32Data);
}

void ReleaseRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    Want want;
    AppExecFwk::ElementName element;
    CallerInfo callerInfo;
    std::string deviceId(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &element);
    DistributedSchedService::GetInstance().ReleaseRemoteAbilityInner(dataParcel, reply);
    callerInfo.uid = ONE;
    DistributedSchedService::GetInstance().CheckDistributedConnectLocked(callerInfo);
    DistributedSchedService::GetInstance().DecreaseConnectLocked(ONE);
    DistributedSchedService::GetInstance().RemoteConnectAbilityMappingLocked(connect, deviceId,
        deviceId, element, callerInfo, TargetComponent::HARMONY_COMPONENT);
    DistributedSchedService::GetInstance().NotifyProcessDied(deviceId, callerInfo, TargetComponent::HARMONY_COMPONENT);
    DistributedSchedService::GetInstance().ProcessDeviceOffline(deviceId);
}

void GetDistributedComponentListInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;

    DistributedSchedService::GetInstance().GetDistributedComponentListInner(dataParcel, reply);
}

void StartRemoteFreeInstallInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    uint32_t uint32Data = *(reinterpret_cast<const uint32_t*>(data));
    sptr<IRemoteObject> obj(new MockDistributedSched());
    Want want;

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &want);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, uint32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().StartRemoteFreeInstallInner(dataParcel, reply);
    DistributedSchedService::GetInstance().ProcessCallResult(obj, obj);
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
    std::string str(reinterpret_cast<const char*>(data), size);
    Want want;
    dataParcel.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &want);
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
    MessageOption option;
    Want want;
    int32_t callerUid = *(reinterpret_cast<const int32_t*>(data));
    int32_t serviceType = *(reinterpret_cast<const int32_t*>(data));
    uint32_t accessToken = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteParcelable(&want);
    dataParcel.WriteInt32(callerUid);
    dataParcel.WriteUint32(accessToken);
    dataParcel.WriteInt32(serviceType);
    DistributedSchedService::GetInstance().StopRemoteExtensionAbilityInner(dataParcel, reply);

    CallerInfo callerInfo;
    std::string localDeviceId(reinterpret_cast<const char*>(data), size);
    DistributedSchedService::GetInstance().GetCallerInfo(localDeviceId, callerUid, accessToken, callerInfo);
    DistributedSchedService::GetInstance().CheckDeviceIdFromRemote(localDeviceId, localDeviceId, localDeviceId);
}

void RegisterOnListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string str(reinterpret_cast<const char*>(data), size);
    sptr<IRemoteObject> obj(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().RegisterOnListenerInner(dataParcel, reply);
    DistributedSchedService::GetInstance().HandleLocalCallerDied(obj);
    DistributedSchedService::GetInstance().RemoveCallerComponent(obj);
    DistributedSchedService::GetInstance().RemoveConnectAbilityInfo(str);
    DistributedSchedService::GetInstance().DumpConnectInfo(str);
}

void RegisterOffListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string str(reinterpret_cast<const char*>(data), size);
    sptr<IRemoteObject> obj(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().RegisterOffListenerInner(dataParcel, reply);
}

void RegisterDSchedEventListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    uint8_t uint8Data = *(reinterpret_cast<const uint8_t*>(data));
    sptr<IRemoteObject> obj(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint8, uint8Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().RegisterDSchedEventListenerInner(dataParcel, reply);
}

void UnRegisterDSchedEventListenerInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    uint8_t uint8Data = *(reinterpret_cast<const uint8_t*>(data));
    sptr<IRemoteObject> obj(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint8, uint8Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, obj);
    DistributedSchedService::GetInstance().UnRegisterDSchedEventListenerInner(dataParcel, reply);
}

void SetMissionContinueStateInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t missionId = *(reinterpret_cast<const int32_t*>(data));
    int32_t state = *(reinterpret_cast<const int32_t*>(data));
    int32_t timeout = *(reinterpret_cast<const int32_t*>(data));

    dataParcel.WriteInt32(missionId);
    dataParcel.WriteInt32(state);
    DistributedSchedService::GetInstance().SetMissionContinueStateInner(dataParcel, reply);
    DistributedSchedService::GetInstance().RemoveContinuationTimeout(missionId);
    DistributedSchedService::GetInstance().SetContinuationTimeout(missionId, timeout);
    DistributedSchedService::GetInstance().GetContinuaitonDevice(missionId);
}

void StartAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    DistributedWant dstbWant;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &compatibleAbilityInfo);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().StartAbilityFromRemoteInner(dataParcel, reply);
}

void SendResultFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
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
    DistributedSchedService::GetInstance().SendResultFromRemoteInner(dataParcel, reply);
}

void NotifyDSchedEventResultFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().NotifyDSchedEventResultFromRemoteInner(dataParcel, reply);
}

void NotifyContinuationResultFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    DmsContinueTime::GetInstance().Init();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    bool boolData = *(reinterpret_cast<const bool*>(data));
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Bool, boolData);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().NotifyContinuationResultFromRemoteInner(dataParcel, reply);
}

void ConnectAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    DistributedWant dstbWant;
    const sptr<IRemoteObject> connect(new MockDistributedSched());

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
    DistributedSchedService::GetInstance().ConnectAbilityFromRemoteInner(dataParcel, reply);
}

void DisconnectAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    AppExecFwk::CompatibleAbilityInfo compatibleAbilityInfo;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);

    sptr<IRemoteObject> connect(new MockDistributedSched());
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().DisconnectAbilityFromRemoteInner(dataParcel, reply);
    DistributedSchedService::GetInstance().ProcessCallerDied(connect, int32Data);
    DistributedSchedService::GetInstance().ProcessCalleeDied(connect);
}

void NotifyProcessDiedFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().NotifyProcessDiedFromRemoteInner(dataParcel, reply);
}

void GetContinueInfoInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().GetContinueInfoInner(dataParcel, reply);
}

void NotifyMissionsChangedFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<DstbMissionInfo> missionInfos;
    CallerInfo callerInfo;
    DistributedWant dstbWant;

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    if (!DstbMissionInfo::WriteDstbMissionInfosToParcel(dataParcel, missionInfos)) {
        return;
    }
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().NotifyMissionsChangedFromRemoteInner(dataParcel, reply);
}

void ReleaseAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    AppExecFwk::ElementName element;
    Want want;
    const CallerInfo callerInfo;
    std::string str(reinterpret_cast<const char*>(data), size);
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));

    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &element);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().ReleaseAbilityFromRemoteInner(dataParcel, reply);
    DistributedSchedService::GetInstance().TryStartRemoteAbilityByCall(want, connect, callerInfo);
    DistributedSchedService::GetInstance().SaveCallerComponent(want, connect, callerInfo);
    DistributedSchedService::GetInstance().SaveConnectToken(want, connect);
    DistributedSchedService::GetInstance().NotifyStateChanged(int32Data, element, connect);
    DistributedSchedService::GetInstance().SetCleanMissionFlag(want, int32Data);
}

void NotifyStateChangedFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    const AppExecFwk::ElementName element;
    sptr<IRemoteObject> connect(new MockDistributedSched());
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &element);
    DistributedSchedService::GetInstance().NotifyStateChangedFromRemoteInner(dataParcel, reply);
    DistributedSchedService::GetInstance().NotifyApp(connect, element, int32Data);
}

void StartFreeInstallFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    int64_t int64Data = static_cast<int64_t>(GetU32Data(data, size));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    DistributedWant dstbWant;

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int64, int64Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().StartFreeInstallFromRemoteInner(dataParcel, reply);
}

void NotifyCompleteFreeInstallFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    int64_t int64Data = static_cast<int64_t>(GetU32Data(data, size));

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int64, int64Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().NotifyCompleteFreeInstallFromRemoteInner(dataParcel, reply);
}

void GetDSchedEventInfoInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data)) % DMS_ALL;

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().GetDSchedEventInfoInner(dataParcel, reply);
}

void StartAbilityByCallFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    DistributedWant dstbWant;
    sptr<IRemoteObject> connect(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    DistributedSchedService::GetInstance().StartAbilityByCallFromRemoteInner(dataParcel, reply);
    DistributedSchedService::GetInstance().ProcessConnectDied(connect);
    DistributedSchedService::GetInstance().DisconnectEachRemoteAbilityLocked(str, str, connect);
}

void StartSyncMissionsFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    DistributedSchedService::GetInstance().StartSyncMissionsFromRemoteInner(dataParcel, reply);
}

void StopSyncMissionsFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);

    DistributedSchedService::GetInstance().StopSyncMissionsFromRemoteInner(dataParcel, reply);
}

void StartShareFormFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    std::string str(reinterpret_cast<const char*>(data), size);
    DistributedWant dstbWant;
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    DistributedSchedService::GetInstance().StartShareFormFromRemoteInner(dataParcel, reply);
}

void StopExtensionAbilityFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    int32_t int32Data = *(reinterpret_cast<const int32_t*>(data));
    std::string str(reinterpret_cast<const char*>(data), size);
    std::vector<std::string> strVector = {str};
    DistributedWant dstbWant;

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &dstbWant);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, int32Data);
    PARCEL_WRITE_HELPER_NORET(dataParcel, StringVector, strVector);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, str);
    DistributedSchedService::GetInstance().StopExtensionAbilityFromRemoteInner(dataParcel, reply);
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
    OHOS::DistributedSchedule::StartFreeInstallFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyCompleteFreeInstallFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::GetDSchedEventInfoInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartAbilityByCallFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartSyncMissionsFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StopSyncMissionsFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StartShareFormFromRemoteInnerFuzzTest(data, size);
    OHOS::DistributedSchedule::StopExtensionAbilityFromRemoteInnerFuzzTest(data, size);
    return 0;
}