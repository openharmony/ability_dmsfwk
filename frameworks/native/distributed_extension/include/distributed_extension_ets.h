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

#ifndef OHOS_APPMGMT_DISTRIBUTED_EXTENSION_ETS_H
#define OHOS_APPMGMT_DISTRIBUTED_EXTENSION_ETS_H

#include <vector>

#include "distributed_extension.h"
#include "ets_runtime.h"
#include "ability_handler.h"
#include "ets_native_reference.h"

namespace OHOS {
namespace DistributedSchedule {
class DistributedExtensionETS : public DistributedExtension {
public:
    void Init(const std::shared_ptr<AppExecFwk::AbilityLocalRecord> &record,
              const std::shared_ptr<AppExecFwk::OHOSApplication> &application,
              std::shared_ptr<AppExecFwk::AbilityHandler> &handler,
              const sptr<IRemoteObject> &token) override;

public:
    static DistributedExtensionETS *Create(const std::unique_ptr<AbilityRuntime::Runtime> &runtime);

    virtual int32_t TriggerOnCreate(AAFwk::Want& want) override;
    virtual int32_t TriggerOnDestroy() override;
    virtual int32_t TriggerOnCollaborate(AAFwk::WantParams &wantParam) override;

public:
    explicit DistributedExtensionETS(AbilityRuntime::ETSRuntime &etsRuntime);
    ~DistributedExtensionETS();

private:
    void BindContext(std::shared_ptr<AbilityInfo> &abilityInfo, std::shared_ptr<AAFwk::Want> want,
        const std::string &moduleName, const std::string &srcPath);
    void UpdateDistributedExtensionObj(std::shared_ptr<AbilityInfo> &abilityInfo,
        const std::string &moduleName, const std::string &srcPath);
    void GetSrcPath(std::string &srcPath);
private:
    AbilityRuntime::ETSRuntime &etsRuntime_;
    std::shared_ptr<AppExecFwk::ETSNativeReference> etsAbilityObj_;
    ani_vm *etsVm_ = nullptr;
};

DistributedExtension *CreateDistributedExtensionETS(const std::unique_ptr<Runtime> &runtime);
}
}
#endif // OHOS_APPMGMT_DISTRIBUTED_EXTENSION_ETS_H
