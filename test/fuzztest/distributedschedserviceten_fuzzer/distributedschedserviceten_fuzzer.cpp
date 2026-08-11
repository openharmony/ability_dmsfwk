/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "distributedschedserviceten_fuzzer.h"

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

constexpr uint32_t FUZZ_TEST_API_COUNT = 12;
constexpr size_t BITS_PER_BYTE = 8;

enum class FuzzTestApiIndex : uint32_t {
    CONNECT_REMOTE_ABILITY = 0,
    DISCONNECT_REMOTE_ABILITY = 1,
    RELEASE_ABILITY_FROM_REMOTE = 2,
    START_REMOTE_ABILITY_BY_CALL = 3,
    SET_CALLER_EXTRA_INFO = 4,
    GET_BUNDLE_NAME_FROM_TOKEN = 5,
    CONTINUE_LOCAL_MISSION = 6,
    CONTINUE_ABILITY_WITH_TIMEOUT = 7,
    SET_D_EXTENSION_CONNECTED = 8,
    NOTIFY_STATE_CHANGED = 9,
    CHECK_MDM_CONTROL_BY_UID = 10,
    IS_TARGET_PERMISSION = 11,
};

void ConnectRemoteAbilityFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    ElementName element(deviceId, bundleName, abilityName);
    want.SetElement(element);

    sptr<IRemoteObject> connect(new MockDistributedSched());
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    int32_t callerPid = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();

    DistributedSchedService::GetInstance().ConnectRemoteAbility(
        want, connect, callerUid, callerPid, accessToken);
}

void DisconnectRemoteAbilityFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();

    DistributedSchedService::GetInstance().DisconnectRemoteAbility(connect, callerUid, accessToken);
}

void ReleaseAbilityFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element(deviceId, bundleName, abilityName);
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().ReleaseAbilityFromRemote(connect, element, callerInfo);
}

void StartRemoteAbilityByCallFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    ElementName element(deviceId, bundleName, abilityName);
    want.SetElement(element);

    sptr<IRemoteObject> connect(new MockDistributedSched());
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    int32_t callerPid = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();

    DistributedSchedService::GetInstance().StartRemoteAbilityByCall(
        want, connect, callerUid, callerPid, accessToken);
}

void SetCallerExtraInfoFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    CallerInfo callerInfo;
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();
    uint32_t specifyTokenId = fdp.ConsumeIntegral<uint32_t>();

    DistributedSchedService::GetInstance().SetCallerExtraInfo(callerInfo, accessToken, specifyTokenId);
}

void GetBundleNameFromTokenFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();
    uint32_t specifyTokenId = fdp.ConsumeIntegral<uint32_t>();

    DistributedSchedService::GetInstance().GetBundleNameFromToken(accessToken, specifyTokenId);
}

void ContinueLocalMissionFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    sptr<IRemoteObject> callback(new MockDistributedSched());
    WantParams wantParams;

    DistributedSchedService::GetInstance().ContinueLocalMission(dstDeviceId, missionId, callback, wantParams);
}

void ContinueAbilityWithTimeoutFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    std::string dstDeviceId = fdp.ConsumeRandomLengthString();
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    sptr<IRemoteObject> callback(new MockDistributedSched());
    uint32_t remoteBundleVersion = fdp.ConsumeIntegral<uint32_t>();

    DistributedSchedService::GetInstance().ContinueAbilityWithTimeout(
        dstDeviceId, missionId, callback, remoteBundleVersion);
}

void SetDExtensionConnectedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(bool)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    bool connected = fdp.ConsumeBool();

    DistributedSchedService::GetInstance().SetDExtensionConnected(connected);
}

void NotifyStateChangedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    int32_t abilityState = fdp.ConsumeIntegral<int32_t>();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element("", bundleName, abilityName);
    sptr<IRemoteObject> token(new MockDistributedSched());

    DistributedSchedService::GetInstance().NotifyStateChanged(abilityState, element, token);
}

void CheckMDMControlByUidFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    int32_t uid = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().CheckMDMControlByUid(uid);
}

void IsTargetPermissionFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    ElementName element("", bundleName, abilityName);
    want.SetElement(element);

    DistributedSchedService::GetInstance().IsTargetPermission(want);
}

static void ExecuteFuzzTest(uint32_t index, const uint8_t* data, size_t size)
{
    switch (index) {
        case static_cast<uint32_t>(FuzzTestApiIndex::CONNECT_REMOTE_ABILITY):
            ConnectRemoteAbilityFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::DISCONNECT_REMOTE_ABILITY):
            DisconnectRemoteAbilityFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::RELEASE_ABILITY_FROM_REMOTE):
            ReleaseAbilityFromRemoteFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::START_REMOTE_ABILITY_BY_CALL):
            StartRemoteAbilityByCallFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::SET_CALLER_EXTRA_INFO):
            SetCallerExtraInfoFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::GET_BUNDLE_NAME_FROM_TOKEN):
            GetBundleNameFromTokenFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::CONTINUE_LOCAL_MISSION):
            ContinueLocalMissionFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::CONTINUE_ABILITY_WITH_TIMEOUT):
            ContinueAbilityWithTimeoutFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::SET_D_EXTENSION_CONNECTED):
            SetDExtensionConnectedFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::NOTIFY_STATE_CHANGED):
            NotifyStateChangedFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::CHECK_MDM_CONTROL_BY_UID):
            CheckMDMControlByUidFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::IS_TARGET_PERMISSION):
            IsTargetPermissionFuzzTest(data, size);
            break;
        default:
            break;
    }
}

}  // namespace DistributedSchedule
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(uint32_t)) {
        return 0;
    }
    uint32_t index = 0;
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        index = (index << OHOS::DistributedSchedule::BITS_PER_BYTE) | data[i];
    }
    index = index % OHOS::DistributedSchedule::FUZZ_TEST_API_COUNT;
    OHOS::DistributedSchedule::ExecuteFuzzTest(index, data, size);
    return 0;
}
