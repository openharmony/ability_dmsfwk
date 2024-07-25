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

#include "dmsfreeinstallcallbackstub_fuzzer.h"

#include "dms_free_install_callback.h"
#include "distributed_sched_interface.h"
#include "mock_fuzz_util.h"
#include "parcel_helper.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const uint32_t ONE = 1;
}
bool OnInstallFinishedInnerFuzzTest(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(int32_t))) {
        return false;
    }
    FuzzUtil::MockPermission();
    int64_t taskId = 0;
    IDistributedSched::FreeInstallInfo info;
    std::shared_ptr<DmsFreeInstallCallback> freeInstall_ =
        std::make_shared<DmsFreeInstallCallback>(taskId, info);
    uint32_t code = ONE;
    MessageParcel dataParcel;
    MessageParcel reply;
    MessageOption option;
    std::u16string descriptor = DmsFreeInstallCallbackStub::GetDescriptor();
    freeInstall_->OnRemoteRequest(code, dataParcel, reply, option);

    dataParcel.WriteInterfaceToken(descriptor);
    freeInstall_->OnRemoteRequest(code, dataParcel, reply, option);
    
    code = static_cast<uint32_t>(IDRreeInstallCallbackInterfaceCode::ON_FREE_INSTALL_DONE);
    int32_t resultCode = *(reinterpret_cast<const int32_t*>(data));
    int32_t requestCode = *(reinterpret_cast<const int32_t*>(data));
    dataParcel.WriteInt32(resultCode);
    dataParcel.WriteInt32(requestCode);
    freeInstall_->OnRemoteRequest(code, dataParcel, reply, option);

    AAFwk::Want want;
    dataParcel.WriteParcelable(&want);
    freeInstall_->OnRemoteRequest(code, dataParcel, reply, option);
    return true;
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::OnInstallFinishedInnerFuzzTest(data, size);
    return 0;
}