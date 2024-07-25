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

#include "bundlemanagercallbackstub_fuzzer.h"

#include "bundle/bundle_manager_callback_stub.h"
#include "mock_fuzz_util.h"

namespace OHOS {
namespace DistributedSchedule {

bool OnQueryInstallationFinishedInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return false;
    }
    FuzzUtil::MockPermission();
    std::shared_ptr<DmsBundleManagerCallbackStub> bundleManager_ =
        std::make_shared<DmsBundleManagerCallbackStub>();
    uint32_t code = 0;
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    bundleManager_->OnRemoteRequest(code, dataParcel, reply, option);

    std::u16string descriptor = bundleManager_->GetDescriptor();
    dataParcel.WriteInterfaceToken(descriptor);
    bundleManager_->OnRemoteRequest(code, dataParcel, reply, option);

    code = static_cast<uint32_t>(IDBundleManagerCallbackInterfaceCod::ON_QUERY_INSTALLATION_DONE);
    int32_t resultCode = *(reinterpret_cast<const int32_t*>(data));
    uint32_t versionCode = *(reinterpret_cast<const uint32_t*>(data));
    int32_t missionId = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInt32(resultCode);
    dataParcel.WriteUint32(versionCode);
    dataParcel.WriteInt32(missionId);
    bundleManager_->OnRemoteRequest(code, dataParcel, reply, option);
    bundleManager_->OnQueryInstallationFinishedInner(dataParcel, reply);
    return true;
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::OnQueryInstallationFinishedInnerFuzzTest(data, size);
    return 0;
}