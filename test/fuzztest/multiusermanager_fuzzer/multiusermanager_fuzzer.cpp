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

#include "multiusermanager_fuzzer.h"

#include <fuzzer/FuzzedDataProvider.h>

#include "multi_user_manager.h"
#include "bundlemgr/bundle_mgr_interface.h"

namespace OHOS {
namespace DistributedSchedule {
void FuzzMultiUserManager(const uint8_t* data, size_t size)
{
    if ((data == nullptr) || (size < sizeof(uint32_t))) {
        return;
    }
    FuzzedDataProvider fdp(data, size);
    int32_t accountId = fdp.ConsumeIntegral<int32_t>();
    MultiUserManager::GetInstance().Init();
    MultiUserManager::GetInstance().OnUserSwitched(accountId);
    MultiUserManager::GetInstance().OnUserRemoved(accountId);
    MultiUserManager::GetInstance().GetSendMgrByCallingUid(accountId);
    MultiUserManager::GetInstance().GetRecvMgrByCallingUid(accountId);
    MultiUserManager::GetInstance().UnInit();
}
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    OHOS::DistributedSchedule::FuzzMultiUserManager(data, size);
    return 0;
}
