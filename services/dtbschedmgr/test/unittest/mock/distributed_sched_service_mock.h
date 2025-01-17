/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_DISTRIBUTED_SCHED_SERVICE_MOCK_H
#define OHOS_DISTRIBUTED_SCHED_SERVICE_MOCK_H

#include <gmock/gmock.h>

#include "distributed_sched_service.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace OHOS::AppExecFwk;
class IDistributedSchedService {
public:
    virtual ~IDistributedSchedService() = default;
    virtual int32_t CheckTargetPermission(const OHOS::AAFwk::Want& want,
        const CallerInfo& callerInfo, const AccountInfo& accountInfo, int32_t flag,
        bool needQueryExtension) = 0;
public:
    static inline std::shared_ptr<IDistributedSchedService> dmsSrvMock = nullptr;
};

class DistributedSchedServiceMock : public IDistributedSchedService {
public:
    MOCK_METHOD5(CheckTargetPermission, int32_t(const OHOS::AAFwk::Want& want,
        const CallerInfo& callerInfo, const AccountInfo& accountInfo, int32_t flag,
        bool needQueryExtension));
};
}
}
#endif