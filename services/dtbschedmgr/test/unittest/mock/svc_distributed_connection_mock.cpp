/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "svc_distributed_connection_mock.h"

namespace OHOS {
namespace DistributedSchedule {
ErrCode SvcDistributedConnection::ConnectDExtAbility(AAFwk::Want &want, int32_t userId, bool isCleanCalled,
    const std::string& delegatee, bool &isDelay)
{
    return ISvcDistributedConnection::connMock->ConnectDExtAbility(want, userId, isCleanCalled, delegatee, isDelay);
}

sptr<IDExtension> SvcDistributedConnection::GetDistributedExtProxy()
{
    return ISvcDistributedConnection::connMock->GetDistributedExtProxy();
}
}
}
