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
#ifndef DISTRIBUTED_SCHED_ADAPTER_MOCK_H
#define DISTRIBUTED_SCHED_ADAPTER_MOCK_H

#include <gmock/gmock.h>

#include "distributed_sched_adapter.h"

namespace OHOS {
namespace DistributedSchedule {
class IDistributedSchedAdapter {
public:
    virtual ~IDistributedSchedAdapter() = default;
    virtual bool CheckAccessToGroup(const std::string& groupId, const std::string& targetBundleName) = 0;
public:
    static inline std::shared_ptr<IDistributedSchedAdapter> adapter = nullptr;
};

class DistributedSchedAdapterMock : public IDistributedSchedAdapter {
public:
    MOCK_METHOD2(CheckAccessToGroup, bool(const std::string& groupId, const std::string& targetBundleName));
};
}
}
#endif
