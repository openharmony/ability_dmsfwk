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

#ifndef OHOS_APPMGMT_DISTRIBUTED_EXTENSION_SERVICE_H
#define OHOS_APPMGMT_DISTRIBUTED_EXTENSION_SERVICE_H

#include <string>

#include "distributed_extension_js.h"
#include "distributed_extension_stub.h"

namespace OHOS {
namespace DistributedSchedule {
class DistributedExtensionService : public DExtensionStub {
public:
    int32_t TriggerOnCreate(AAFwk::Want &want) override;
    int32_t TriggerOnDestroy() override;
    int32_t TriggerOnCollaborate(AAFwk::WantParams &wantParam) override;

public:
    void Clear();

public:
    explicit DistributedExtensionService(const std::shared_ptr<DistributedExtension> &dExtension,
        const std::string &bundleName) : distributedExtension_(dExtension)
    {
        if (distributedExtension_ != nullptr) {
            distributedExtension_->SetDistributedExtensionService(this);
        }

        bundleName_ = bundleName;
    }
    ~DistributedExtensionService()
    {
    }

private:
    std::shared_ptr<DistributedExtension> distributedExtension_;
    std::string bundleName_;
};
}
}

#endif // OHOS_APPMGMT_DISTRIBUTED_EXTENSION_SERVICE_H
