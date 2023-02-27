/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "distributed_sched_util.h"

#include "accesstoken_kit.h"
#include "dtbschedmgr_log.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "nativetoken_kit.h"
#include "system_ability_definition.h"
#include "token_setproc.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string TAG = "DistributedSchedUtil";
const char* DISTSCHED_PROCESS_NAME = "distributedsched";
constexpr int32_t DMS_LOAD_SA_TIMEOUT_MS = 10000;
}

sptr<IRemoteObject> DistributedSchedUtil::remote_ = nullptr;
std::mutex DistributedSchedUtil::remoteMutex_;
std::condition_variable DistributedSchedUtil::remoteConVar_;

void DistributedSchedUtil::MockPermission()
{
    static const char *PERMS[] = {
        "ohos.permission.DISTRIBUTED_DATASYNC"
    };
    MockProcessAndPermission(DISTSCHED_PROCESS_NAME, PERMS, 1);
}

void DistributedSchedUtil::MockProcess(const char* processName)
{
    MockProcessAndPermission(processName);
}

void DistributedSchedUtil::MockProcessAndPermission(const char* processName, const char *perms[], int32_t permsNum)
{
    uint64_t tokenId;
    NativeTokenInfoParams infoInstance = {
        .dcapsNum = 0,
        .permsNum = permsNum,
        .aclsNum = 0,
        .dcaps = nullptr,
        .perms = perms,
        .acls = nullptr,
        .processName = processName,
        .aplStr = "system_core",
    };
    tokenId = GetAccessTokenId(&infoInstance);
    SetSelfTokenID(tokenId);
    OHOS::Security::AccessToken::AccessTokenKit::ReloadNativeTokenInfo();
}

bool DistributedSchedUtil::LoadDistributedSchedService()
{
    std::unique_lock<std::mutex> lock(remoteMutex_);
    sptr<DistributedSchedLoadCallback> loadCallback = new DistributedSchedLoadCallback();
    if (loadCallback == nullptr) {
        HILOGE("loadCallback is nullptr");
        return false;
    }
    auto samgrProxy = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (samgrProxy == nullptr) {
        HILOGE("get samgr failed");
        return false;
    }
    int32_t ret = samgrProxy->LoadSystemAbility(DISTRIBUTED_SCHED_SA_ID, loadCallback);
    if (ret != ERR_OK) {
        HILOGE("load dms SA failed");
        return false;
    }
    auto waitStatus = remoteConVar_.wait_for(lock, std::chrono::milliseconds(DMS_LOAD_SA_TIMEOUT_MS),
        []() { return remote_ != nullptr; });
    if (!waitStatus) {
        HILOGE("dms SA load timeout");
        return false;
    }
    return true;
}

void DistributedSchedUtil::LoadSystemAbilitySuccessNotify(const sptr<IRemoteObject>& remoteObject)
{
    std::lock_guard<std::mutex> lock(remoteMutex_);
    remote_ = remoteObject;
    remoteConVar_.notify_one();
}

void DistributedSchedUtil::LoadSystemAbilityFailNotify()
{
    std::lock_guard<std::mutex> lock(remoteMutex_);
    remote_ = nullptr;
}

void DistributedSchedLoadCallback::OnLoadSystemAbilitySuccess(
    int32_t systemAbilityId, const sptr<IRemoteObject> &remoteObject)
{
    HILOGD("called.");
    DistributedSchedUtil::LoadSystemAbilitySuccessNotify(remoteObject);
}

void DistributedSchedLoadCallback::OnLoadSystemAbilityFail(int32_t systemAbilityId)
{
    HILOGD("called.");
    DistributedSchedUtil::LoadSystemAbilityFailNotify();
}
}
}