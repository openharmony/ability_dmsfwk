/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "bundle_manager_internal_mock.h"
#include "bundle/bundle_manager_internal.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

IMPLEMENT_SINGLE_INSTANCE(BundleManagerInternal);

bool BundleManagerInternal::GetCallerAppIdFromBms(int32_t callingUid, std::string& appId)
{
    if (AppExecFwk::IBundleManagerInternal::bundleMock == nullptr) {
        return false;
    }
    return AppExecFwk::IBundleManagerInternal::bundleMock->GetCallerAppIdFromBms(callingUid, appId);
}

bool BundleManagerInternal::GetBundleNameListFromBms(int32_t callingUid, std::vector<std::string>& bundleNameList)
{
    if (AppExecFwk::IBundleManagerInternal::bundleMock == nullptr) {
        return false;
    }
    return AppExecFwk::IBundleManagerInternal::bundleMock->GetBundleNameListFromBms(callingUid, bundleNameList);
}

} // namespace DistributedSchedule
} // namespace OHOS