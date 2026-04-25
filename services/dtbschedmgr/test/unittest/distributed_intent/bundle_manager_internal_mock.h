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

#ifndef BUNDLE_MANAGER_INTERNAL_MOCK_H
#define BUNDLE_MANAGER_INTERNAL_MOCK_H

#include <gmock/gmock.h>
#include <string>
#include <vector>

namespace OHOS {
namespace AppExecFwk {

class IBundleManagerInternal {
public:
    virtual ~IBundleManagerInternal() = default;
    virtual bool GetCallerAppIdFromBms(int32_t uid, std::string& appId) = 0;
    virtual bool GetBundleNameListFromBms(int32_t uid, std::vector<std::string>& bundleNames) = 0;
public:
    static inline std::shared_ptr<IBundleManagerInternal> bundleMock = nullptr;
};

class BundleManagerInternalMock : public IBundleManagerInternal {
public:
    MOCK_METHOD2(GetCallerAppIdFromBms, bool(int32_t uid, std::string& appId));
    MOCK_METHOD2(GetBundleNameListFromBms, bool(int32_t uid, std::vector<std::string>& bundleNames));
};

} // namespace AppExecFwk
} // namespace OHOS
#endif // BUNDLE_MANAGER_INTERNAL_MOCK_H