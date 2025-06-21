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
#ifndef SVC_DISTRIBUTED_CONNECTION_MOCK_H
#define SVC_DISTRIBUTED_CONNECTION_MOCK_H

#include <gmock/gmock.h>

#include "svc_distributed_connection.h"

namespace OHOS {
namespace DistributedSchedule {

class ISvcDistributedConnection {
public:
    virtual ~ISvcDistributedConnection() = default;
    virtual ErrCode ConnectDExtAbility(AAFwk::Want &want, int32_t userId, bool isCleanCalled,
        const std::string& delegatee, bool &isDelay) = 0;
    virtual sptr<IDExtension> GetDistributedExtProxy() = 0;
public:
    static inline std::shared_ptr<ISvcDistributedConnection> connMock = nullptr;
};

class SvcDistributedConnectionMock : public ISvcDistributedConnection {
public:
    MOCK_METHOD5(ConnectDExtAbility, ErrCode(AAFwk::Want &want, int32_t userId, bool isCleanCalled,
        const std::string& delegatee, bool &isDelay));
    MOCK_METHOD0(GetDistributedExtProxy, sptr<IDExtension>());
};
}
}
#endif
