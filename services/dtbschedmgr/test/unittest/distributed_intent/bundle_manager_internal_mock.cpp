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
namespace AppExecFwk {

bool GetCallerAppIdFromBms(int32_t uid, std::string& appId)
{
    if (IBundleManagerInternal::bundleMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMock->GetCallerAppIdFromBms(uid, appId);
}

bool GetBundleNameListFromBms(int32_t uid, std::vector<std::string>& bundleNames)
{
    if (IBundleManagerInternal::bundleMock == nullptr) {
        return false;
    }
    return IBundleManagerInternal::bundleMock->GetBundleNameListFromBms(uid, bundleNames);
}

} // namespace AppExecFwk
} // namespace OHOS