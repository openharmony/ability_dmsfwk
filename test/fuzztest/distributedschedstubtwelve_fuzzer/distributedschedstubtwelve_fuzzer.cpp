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

#include "distributedschedstubtwelve_fuzzer.h"

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

constexpr uint32_t FUZZ_TEST_API_COUNT = 10;
constexpr size_t BITS_PER_BYTE = 8;

enum class FuzzTestApiIndex : uint32_t {
    CONNECT_REMOTE_ABILITY_INNER = 0,
    DISCONNECT_REMOTE_ABILITY_INNER = 1,
    RELEASE_ABILITY_FROM_REMOTE_INNER = 2,
    NOTIFY_COMPLETE_FREE_INSTALL_FROM_REMOTE_INNER = 3,
    CONTINUE_STATE_CALLBACK_REGISTER_INNER = 4,
    CONTINUE_STATE_CALLBACK_UNREGISTER_INNER = 5,
    NOTIFY_MISSIONS_CHANGED_FROM_REMOTE_INNER = 6,
    START_REMOTE_MESSAGE_INNER = 7,
    SEND_MESSAGE_RESULT_INNER = 8,
    IS_MDM_CONTROL_INNER = 9,
};

const std::string TAG = "DistributedSchedStubTwelveFuzzTest";

void ConnectRemoteAbilityInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    Want want;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    ElementName element(deviceId, bundleName, abilityName);
    want.SetElement(element);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    int32_t callerPid = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &want);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, callerUid);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, callerPid);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, accessToken);
    DistributedSchedService::GetInstance().ConnectRemoteAbilityInner(dataParcel, reply);
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
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();

    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, callerUid);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, accessToken);
    DistributedSchedService::GetInstance().DisconnectRemoteAbilityInner(dataParcel, reply);
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
    FuzzedDataProvider fdp(data, size);
    sptr<IRemoteObject> connect(new MockDistributedSched());
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    AppExecFwk::ElementName element(deviceId, bundleName, abilityName);
    std::string sourceDeviceId = fdp.ConsumeRandomLengthString();
    std::string extraInfo = fdp.ConsumeRandomLengthString();

    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, connect);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &element);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, sourceDeviceId);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, extraInfo);
    DistributedSchedService::GetInstance().ReleaseAbilityFromRemoteInner(dataParcel, reply);
}

void NotifyCompleteFreeInstallFromRemoteInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int64_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    int64_t taskId = fdp.ConsumeIntegral<int64_t>();
    int32_t resultCode = fdp.ConsumeIntegral<int32_t>();

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int64, taskId);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, resultCode);
    DistributedSchedService::GetInstance().NotifyCompleteFreeInstallFromRemoteInner(dataParcel, reply);
}

void ContinueStateCallbackRegisterInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString();
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    std::string moduleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    sptr<IRemoteObject> callback(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, bundleName);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, missionId);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, moduleName);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, abilityName);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, callback);
    static_cast<DistributedSchedStub&>(DistributedSchedService::GetInstance())
        .ContinueStateCallbackRegister(dataParcel, reply);
}

void ContinueStateCallbackUnRegisterInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    std::string bundleName = fdp.ConsumeRandomLengthString();
    int32_t missionId = fdp.ConsumeIntegral<int32_t>();
    std::string moduleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();

    PARCEL_WRITE_HELPER_NORET(dataParcel, String, bundleName);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, missionId);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, moduleName);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, abilityName);
    static_cast<DistributedSchedStub&>(DistributedSchedService::GetInstance())
        .ContinueStateCallbackUnRegister(dataParcel, reply);
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
    FuzzedDataProvider fdp(data, size);
    int32_t version = fdp.ConsumeIntegral<int32_t>();
    std::string sourceDeviceId = fdp.ConsumeRandomLengthString();
    int32_t uid = fdp.ConsumeIntegral<int32_t>();
    int32_t pid = fdp.ConsumeIntegral<int32_t>();
    int32_t dmsVersion = fdp.ConsumeIntegral<int32_t>();

    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, version);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, sourceDeviceId);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, uid);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, pid);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, dmsVersion);
    DistributedSchedService::GetInstance().NotifyMissionsChangedFromRemoteInner(dataParcel, reply);
}

void StartRemoteIntentInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    Want want;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    ElementName element(deviceId, bundleName, abilityName);
    want.SetElement(element);
    std::string moduleName = fdp.ConsumeRandomLengthString();
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    uint64_t requestCode = fdp.ConsumeIntegral<uint64_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();
    uint32_t specifyTokenId = fdp.ConsumeIntegral<uint32_t>();
    sptr<IRemoteObject> resultCallback(new MockDistributedSched());

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &want);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, moduleName);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, callerUid);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint64, requestCode);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, accessToken);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, specifyTokenId);
    PARCEL_WRITE_HELPER_NORET(dataParcel, RemoteObject, resultCallback);
    DistributedSchedService::GetInstance().StartRemoteIntentInner(dataParcel, reply);
}

void SendIntentResultInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    FuzzedDataProvider fdp(data, size);
    Want want;
    std::string deviceId = fdp.ConsumeRandomLengthString();
    std::string bundleName = fdp.ConsumeRandomLengthString();
    std::string abilityName = fdp.ConsumeRandomLengthString();
    ElementName element(deviceId, bundleName, abilityName);
    want.SetElement(element);
    int32_t callerUid = fdp.ConsumeIntegral<int32_t>();
    uint64_t requestCode = fdp.ConsumeIntegral<uint64_t>();
    uint32_t accessToken = fdp.ConsumeIntegral<uint32_t>();
    uint32_t specifyTokenId = fdp.ConsumeIntegral<uint32_t>();
    std::string msg = fdp.ConsumeRandomLengthString();

    PARCEL_WRITE_HELPER_NORET(dataParcel, Parcelable, &want);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Int32, callerUid);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint64, requestCode);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, accessToken);
    PARCEL_WRITE_HELPER_NORET(dataParcel, Uint32, specifyTokenId);
    PARCEL_WRITE_HELPER_NORET(dataParcel, String, msg);
    DistributedSchedService::GetInstance().SendIntentResultInner(dataParcel, reply);
}

void IsMDMControlInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return;
    }
    FuzzUtil::MockPermission();
    FuzzedDataProvider fdp(data, size);
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    
    // Consume data to satisfy fuzz test requirements
    // Note: IsMDMControlInner doesn't actually read from dataParcel
    (void)fdp.ConsumeIntegral<uint32_t>();

    DistributedSchedService::GetInstance().IsMDMControlInner(dataParcel, reply);
}
}  // namespace DistributedSchedule
}  // namespace OHOS

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    using OHOS::DistributedSchedule::BITS_PER_BYTE;
    using OHOS::DistributedSchedule::FUZZ_TEST_API_COUNT;
    using OHOS::DistributedSchedule::FuzzTestApiIndex;
    
    if (data == nullptr || size < sizeof(uint32_t)) {
        return 0;
    }
    uint32_t index = 0;
    for (size_t i = 0; i < sizeof(uint32_t); ++i) {
        index = (index << BITS_PER_BYTE) | data[i];
    }
    index = index % FUZZ_TEST_API_COUNT;
    switch (index) {
        case static_cast<uint32_t>(FuzzTestApiIndex::CONNECT_REMOTE_ABILITY_INNER):
            OHOS::DistributedSchedule::ConnectRemoteAbilityInnerFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::DISCONNECT_REMOTE_ABILITY_INNER):
            OHOS::DistributedSchedule::DisconnectRemoteAbilityInnerFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::RELEASE_ABILITY_FROM_REMOTE_INNER):
            OHOS::DistributedSchedule::ReleaseAbilityFromRemoteInnerFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::NOTIFY_COMPLETE_FREE_INSTALL_FROM_REMOTE_INNER):
            OHOS::DistributedSchedule::NotifyCompleteFreeInstallFromRemoteInnerFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::CONTINUE_STATE_CALLBACK_REGISTER_INNER):
            OHOS::DistributedSchedule::ContinueStateCallbackRegisterInnerFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::CONTINUE_STATE_CALLBACK_UNREGISTER_INNER):
            OHOS::DistributedSchedule::ContinueStateCallbackUnRegisterInnerFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::NOTIFY_MISSIONS_CHANGED_FROM_REMOTE_INNER):
            OHOS::DistributedSchedule::NotifyMissionsChangedFromRemoteInnerFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::START_REMOTE_MESSAGE_INNER):
            OHOS::DistributedSchedule::StartRemoteIntentInnerFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::SEND_MESSAGE_RESULT_INNER):
            OHOS::DistributedSchedule::SendIntentResultInnerFuzzTest(data, size);
            break;
        case static_cast<uint32_t>(FuzzTestApiIndex::IS_MDM_CONTROL_INNER):
            OHOS::DistributedSchedule::IsMDMControlInnerFuzzTest(data, size);
            break;
        default:
            break;
    }
    return 0;
}
