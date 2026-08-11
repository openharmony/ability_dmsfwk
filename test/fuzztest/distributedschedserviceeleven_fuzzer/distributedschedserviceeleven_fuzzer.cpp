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

#include "distributedschedserviceeleven_fuzzer.h"

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

constexpr uint32_t FUZZ_TEST_API_COUNT = 13;
constexpr size_t BITS_PER_BYTE = 8;

enum class FuzzTestApiIndex : uint32_t {
    START_REMOTE_FREE_INSTALL = 0,
    START_FREE_INSTALL_FROM_REMOTE = 1,
    CHECK_SINK_ACCESS_CONTROL_USER = 2,
    SEND_RESULT_FROM_REMOTE_REMOTE_DIED = 3,
    DUMP_TEST = 4,
    SAVE_CALLER_COMPONENT = 5,
    SAVE_CONNECT_TOKEN = 6,
    PROCESS_CALLER_DIED = 7,
    PROCESS_CALLEE_DIED = 8,
    NOTIFY_STATE_CHANGED_FROM_REMOTE = 9,
    NOTIFY_COMPLETE_FREE_INSTALL_FROM_REMOTE = 10,
    CONTINUE_STATE_CALLBACK_REGISTER = 11,
    CONTINUE_STATE_CALLBACK_UNREGISTER = 12,
};

void StartRemoteFreeInstallFuzzTest(const uint8_t* data, size_t size)
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

    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    int32_t requestCode = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();
    sptr<IRemoteObject> callback(new MockDistributedSched());

    DistributedSchedService::GetInstance().StartRemoteFreeInstall(
        want, callerUid, requestCode, accessToken, callback);
}

void StartFreeInstallFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    DistributedSchedService::FreeInstallInfo info;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    ElementName element(deviceId, bundleName, abilityName);
    info.want.SetElement(element);
    info.requestCode = fdp.ConsumeIntegral<int32_t>();
    info.callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    info.callerInfo.uid = fdp.ConsumeIntegral<int32_t>();
    info.callerInfo.callerType = fdp.ConsumeIntegral<int32_t>();
    info.accountInfo.accountType = fdp.ConsumeIntegral<int32_t>();
    info.accountInfo.userId = fdp.ConsumeIntegral<int32_t>();
    int64_t taskId = fdp.ConsumeIntegral<int64_t>();

    DistributedSchedService::GetInstance().StartFreeInstallFromRemote(info, taskId);
}

void CheckSinkAccessControlUserFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    DistributedSchedService::FreeInstallInfo info;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    ElementName element(deviceId, bundleName, abilityName);
    info.want.SetElement(element);
    info.requestCode = fdp.ConsumeIntegral<int32_t>();
    info.callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    info.callerInfo.uid = fdp.ConsumeIntegral<int32_t>();
    info.accountInfo.accountType = fdp.ConsumeIntegral<int32_t>();
    info.accountInfo.userId = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().CheckSinkAccessControlUser(info);
}

void SendResultFromRemoteRemoteDiedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    AAFwk::Want want;
    want.SetParam("dmsSrcNetworkId", fdp.ConsumeRandomLengthString());
    want.SetParam("dmsMissionId", fdp.ConsumeIntegral<int32_t>());

    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();

    AccountInfo accountInfo;
    int32_t requestCode = fdp.ConsumeIntegral<int32_t>();
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().SendResultFromRemote(
        want, requestCode, callerInfo, accountInfo, resultCode);
}

void DumpFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    std::vector<std::u16string> args;
    std::string arg1 = fdp.ConsumeRandomLengthString();
    std::string arg2 = fdp.ConsumeRandomLengthString();
    args.push_back(Str8ToStr16(arg1));
    args.push_back(Str8ToStr16(arg2));
    int32_t fd = 1;

    DistributedSchedService::GetInstance().Dump(fd, args);
}

void SaveCallerComponentFuzzTest(const uint8_t* data, size_t size)
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
    CallerInfo callerInfo;
    callerInfo.sourceDeviceId = fdp.ConsumeRandomLengthString();
    callerInfo.uid = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().SaveCallerComponent(want, connect, callerInfo);
}

void SaveConnectTokenFuzzTest(const uint8_t* data, size_t size)
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

    DistributedSchedService::GetInstance().SaveConnectToken(want, connect);
}

void ProcessCallerDiedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    int32_t deviceType = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().ProcessCallerDied(connect, deviceType);
}

void ProcessCalleeDiedFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    
    // Consume data to satisfy fuzz test requirements even though ProcessCalleeDied
    // doesn't directly use fuzz data (it requires an IRemoteObject)
    (void)fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().ProcessCalleeDied(connect);
}

void NotifyStateChangedFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    int32_t abilityState = fdp.ConsumeIntegral<int32_t>();
    int32_t connectToken = fdp.ConsumeIntegral<int32_t>();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element("", bundleName, abilityName);

    DistributedSchedService::GetInstance().NotifyStateChangedFromRemote(abilityState, connectToken, element);
}

void NotifyCompleteFreeInstallFromRemoteFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int64_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    int64_t taskId = fdp.ConsumeIntegral<int64_t>();
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();

    DistributedSchedService::GetInstance().NotifyCompleteFreeInstallFromRemote(taskId, resultCode);
}

void ContinueStateCallbackRegisterFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string moduleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    sptr<IRemoteObject> callback(new MockDistributedSched());

    DistributedSchedService::GetInstance().ContinueStateCallbackRegister(
        missionId, bundleName, moduleName, abilityName, callback);
}

void ContinueStateCallbackUnRegisterFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string moduleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();

    DistributedSchedService::GetInstance().ContinueStateCallbackUnRegister(
        missionId, bundleName, moduleName, abilityName);
}

void CallerDeathRecipientFuzzTest(const uint8_t* data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    int32_t deviceType = fdp.ConsumeIntegral<int32_t>();
    CallerDeathRecipient recipient(deviceType);
    sptr<IRemoteObject> remote(new MockDistributedSched());
    wptr<IRemoteObject> weakRemote(remote);
    recipient.OnRemoteDied(weakRemote);
}

static void ExecuteFuzzTest(uint32_t index, const uint8_t* data, size_t size)
{
    switch (index) {
        case static_cast<uint32_t>(FuzzTestApiIndex::START_REMOTE_FREE_INSTALL):
            StartRemoteFreeInstallFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::START_FREE_INSTALL_FROM_REMOTE):
            StartFreeInstallFromRemoteFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::CHECK_SINK_ACCESS_CONTROL_USER):
            CheckSinkAccessControlUserFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::SEND_RESULT_FROM_REMOTE_REMOTE_DIED):
            SendResultFromRemoteRemoteDiedFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::DUMP_TEST):
            DumpFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::SAVE_CALLER_COMPONENT):
            SaveCallerComponentFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::SAVE_CONNECT_TOKEN):
            SaveConnectTokenFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::PROCESS_CALLER_DIED):
            ProcessCallerDiedFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::PROCESS_CALLEE_DIED):
            ProcessCalleeDiedFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::NOTIFY_STATE_CHANGED_FROM_REMOTE):
            NotifyStateChangedFromRemoteFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::NOTIFY_COMPLETE_FREE_INSTALL_FROM_REMOTE):
            NotifyCompleteFreeInstallFromRemoteFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::CONTINUE_STATE_CALLBACK_REGISTER):
            ContinueStateCallbackRegisterFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::CONTINUE_STATE_CALLBACK_UNREGISTER):
            ContinueStateCallbackUnRegisterFuzzTest(data, size);
            break;
        default:
            CallerDeathRecipientFuzzTest(data, size);
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
