/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#include "continuationmanager_fuzzer.h"

#include <cstddef>
#include <cstdint>

#include "dtbschedmgr_log.h"
#include "distributed_ability_manager_interface.h"
#include "distributed_ability_manager_stub.h"
#include "distributed_ability_manager_service.h"
#include "fuzz_util.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
    constexpr int32_t DISTRIBUTED_SCHED_SA_ID = 1401;
    constexpr size_t THRESHOLD = 10;
    constexpr uint16_t MAX_CALL_TRANSACTION = 510;
    constexpr int32_t OFFSET = 4;
    const std::u16string DMS_INTERFACE_TOKEN = u"OHOS.DistributedSchedule.IDistributedAbilityManager";
    const std::u16string DMS_STUB_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
    const std::string TAG = "ContinuationFuzz";
}

uint32_t Convert2Uint32(const uint8_t* ptr)
{
    if (ptr == nullptr) {
        return 0;
    }
    return (ptr[0] << 24) | (ptr[1] << 16) | (ptr[2] << 8) | (ptr[3]); // this is a general method of converting in fuzz
}

void FuzzUnregister(const uint8_t* rawData, size_t size)
{
    FuzzUtil::MockPermission();
    uint32_t code = Convert2Uint32(rawData);
    rawData = rawData + OFFSET;
    size = size - OFFSET;
    MessageParcel data;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    data.WriteBuffer(rawData, size);
    data.RewindRead(0);
    MessageParcel reply;
    MessageOption option;
    auto systemAbilityMgr = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityMgr == nullptr) {
        HILOGE("system ability manager is nullptr.");
        return;
    }
    auto remoteObj = systemAbilityMgr->GetSystemAbility(DISTRIBUTED_SCHED_SA_ID);
    if (remoteObj == nullptr) {
        HILOGE("failed to get form manager service");
        return;
    }
    remoteObj->SendRequest(code % MAX_CALL_TRANSACTION, data, reply, option);
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    if (size < OHOS::DistributedSchedule::THRESHOLD) {
        return 0;
    }

    OHOS::DistributedSchedule::FuzzUnregister(data, size);
    return 0;
}