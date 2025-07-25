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
#ifndef DNETWORK_ADAPTER_MOCK_H
#define DNETWORK_ADAPTER_MOCK_H

#include <gmock/gmock.h>

#include "adapter/dnetwork_adapter.h"

namespace OHOS {
namespace DistributedSchedule {
class IDnetworkAdapter {
public:
    virtual ~IDnetworkAdapter() = default;
    virtual std::string GetUdidByNetworkId(const std::string& networkId) = 0;
public:
    static inline std::shared_ptr<IDnetworkAdapter> netAdapter = nullptr;
};

class DnetworkAdapterMock : public IDnetworkAdapter {
public:
    MOCK_METHOD1(GetUdidByNetworkId, std::string(const std::string& networkId));
};
}
}
#endif
