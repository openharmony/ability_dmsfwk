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

#ifndef OHOS_DISTRIBUTED_EXTENSION_H
#define OHOS_DISTRIBUTED_EXTENSION_H

#include "distributed_extension_context_js.h"
#include "extension_base.h"
#include "runtime.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
class DistributedExtensionService;

class DistributedExtension : public AbilityRuntime::ExtensionBase<DistributedExtensionContext> {
public:
    void Init(const std::shared_ptr<AbilityRuntime::AbilityLocalRecord> &record,
              const std::shared_ptr<AbilityRuntime::OHOSApplication> &application,
              std::shared_ptr<AbilityRuntime::AbilityHandler> &handler,
              const sptr<IRemoteObject> &token) override;

    void OnStart(const AAFwk::Want &want) override;

    void OnCommand(const AAFwk::Want &want, bool restart, int startId) override;

    sptr<IRemoteObject> OnConnect(const AAFwk::Want &want) override;

    void OnDisconnect(const AAFwk::Want &want) override;

public:
    static DistributedExtension *Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime);

public:
    void SetDistributedExtensionService(const wptr<DistributedExtensionService> &distributedExtensionService);

public:
    virtual int32_t TriggerOnCreate(AAFwk::Want& want);
    virtual int32_t TriggerOnDestroy();
    virtual int32_t TriggerOnCollaborate(AAFwk::WantParams &wantParam);

private:
    wptr<DistributedExtensionService> distributedExtensionService_;
};
}
}

#endif // OHOS_DISTRIBUTED_EXTENSION_H
