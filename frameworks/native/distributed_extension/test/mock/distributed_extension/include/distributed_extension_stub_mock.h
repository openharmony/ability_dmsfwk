/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_EXTENSION_INTERFACE_MOCK_H
#define DISTRIBUTED_EXTENSION_INTERFACE_MOCK_H

#include <gmock/gmock.h>

#include "i_distributed_extension.h"
#include "iremote_stub.h"

namespace OHOS::DistributedSchedule {
class DistributedExtensionStubMock : public IRemoteStub<IDExtension> {
public:
    int code_ = 0;
    DistributedExtensionStubMock() : code_(0) {}
    virtual ~DistributedExtensionStubMock() {}

    MOCK_METHOD4(SendRequest, int(uint32_t, MessageParcel &, MessageParcel &, MessageOption &));

    int32_t TriggerOnCreate(AAFwk::Want &want) override
    {
        return 0;
    }

    int32_t TriggerOnDestroy() override
    {
        return 0;
    }

    int32_t TriggerOnCollaborate(AAFwk::WantParams &wantParam) override
    {
        return 0;
    }
};
} // namespace OHOS::DistributedSchedule
#endif // DISTRIBUTED_EXTENSION_INTERFACE_MOCK_H
