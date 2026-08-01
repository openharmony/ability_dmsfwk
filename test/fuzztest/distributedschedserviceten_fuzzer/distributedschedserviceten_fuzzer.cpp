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
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::ConnectRemoteAbilityFuzzTest(data, size);
    OHOS::DistributedSchedule::DisconnectRemoteAbilityFuzzTest(data, size);
    OHOS::DistributedSchedule::ReleaseAbilityFromRemoteFuzzTest(data, size);
    OHOS::DistributedSchedule::StartRemoteAbilityByCallFuzzTest(data, size);
    OHOS::DistributedSchedule::SetCallerExtraInfoFuzzTest(data, size);
    OHOS::DistributedSchedule::GetBundleNameFromTokenFuzzTest(data, size);
    OHOS::DistributedSchedule::ContinueLocalMissionFuzzTest(data, size);
    OHOS::DistributedSchedule::ContinueAbilityWithTimeoutFuzzTest(data, size);
    OHOS::DistributedSchedule::SetDExtensionConnectedFuzzTest(data, size);
    OHOS::DistributedSchedule::NotifyStateChangedFuzzTest(data, size);
    OHOS::DistributedSchedule::CheckMDMControlByUidFuzzTest(data, size);
    OHOS::DistributedSchedule::IsTargetPermissionFuzzTest(data, size);
    return 0;
}
