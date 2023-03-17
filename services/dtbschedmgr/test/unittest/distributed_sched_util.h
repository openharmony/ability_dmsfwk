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

#ifndef DISTRIBUTED_SCHED_UTIL_H
#define DISTRIBUTED_SCHED_UTIL_H

#include <cstdint>
#include <mutex>

#include "bundle_mgr_interface.h"
#include "iremote_object.h"
#include "system_ability_load_callback_stub.h"

namespace OHOS {
namespace DistributedSchedule {
class DistributedSchedUtil {
public:
    static void MockPermission();
    static void MockProcess(const char* processName);
    static void MockProcessAndPermission(const char* processName,
        const char *perms[] = nullptr, int32_t permsNum = 0);
    static bool LoadDistributedSchedService();
    static void LoadSystemAbilitySuccessNotify(const sptr<IRemoteObject>& remoteObject);
    static void LoadSystemAbilityFailNotify();
    static sptr<AppExecFwk::IBundleMgr> GetBundleManager();
    static int32_t InstallThirdPartyHap();

    static std::mutex remoteMutex_;
    static sptr<IRemoteObject> remote_;
    static std::condition_variable remoteConVar_;
};

class DistributedSchedLoadCallback : public SystemAbilityLoadCallbackStub {
public:
    DistributedSchedLoadCallback() = default;
    ~DistributedSchedLoadCallback() = default;

    void OnLoadSystemAbilitySuccess(int32_t systemAbilityId,
        const sptr<IRemoteObject> &remoteObject) override;
    void OnLoadSystemAbilityFail(int32_t systemAbilityId) override;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DISTRIBUTED_SCHED_UTIL_H