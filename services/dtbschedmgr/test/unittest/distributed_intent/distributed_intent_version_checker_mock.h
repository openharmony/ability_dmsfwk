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

#ifndef OHOS_DISTRIBUTED_INTENT_VERSION_CHECKER_MOCK_H
#define OHOS_DISTRIBUTED_INTENT_VERSION_CHECKER_MOCK_H

#include <gmock/gmock.h>
#include <string>
#include "distributed_intent_error_code.h"

namespace OHOS {
namespace DistributedSchedule {

class IDistributedIntentVersionChecker {
public:
    virtual ~IDistributedIntentVersionChecker() = default;
    virtual int32_t CheckRemoteDistributedIntentSupport(const std::string& remoteDeviceId) = 0;
    static inline std::shared_ptr<IDistributedIntentVersionChecker> versionCheckerMock = nullptr;
};

class DistributedIntentVersionCheckerMock : public IDistributedIntentVersionChecker {
public:
    MOCK_METHOD1(CheckRemoteDistributedIntentSupport, int32_t(const std::string& remoteDeviceId));
};

} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_INTENT_VERSION_CHECKER_MOCK_H