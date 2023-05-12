/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTEDWANT_OPERATION_BUILDER_H
#define OHOS_DISTRIBUTEDWANT_OPERATION_BUILDER_H

#include <memory>
#include <string>
#include <vector>
#include "uri.h"

namespace OHOS {
namespace DistributedSchedule {
class DistributedOperation;
class DistributedOperationBuilder {
public:
    DistributedOperationBuilder();
    ~DistributedOperationBuilder();

    /**
     * @description: Sets a AbilityName in an DistributedOperationBuilder.
     * @return Returns this DistributedOperationBuilder object containing the AbilityName.
     */
    DistributedOperationBuilder& WithAbilityName(const std::string& abilityName);

    /**
     * @description: Sets a BundleName in an DistributedOperationBuilder.
     * @return Returns this DistributedOperationBuilder object containing the BundleName.
     */
    DistributedOperationBuilder& WithBundleName(const std::string& bundleName);

    /**
     * @description: Sets a DeviceId in an DistributedOperationBuilder.
     * @return Returns this DistributedOperationBuilder object containing the DeviceId.
     */
    DistributedOperationBuilder& WithDeviceId(const std::string& deviceID);

    /**
     * @description: Sets a Action in an DistributedOperationBuilder.
     * @return Returns this DistributedOperationBuilder object containing the Action.
     */
    DistributedOperationBuilder& WithAction(const std::string& action);

    /**
     * @description: Sets a Entities in an DistributedOperationBuilder.
     * @return Returns this DistributedOperationBuilder object containing the Entities.
     */
    DistributedOperationBuilder& WithEntities(const std::vector<std::string>& entities);

    /**
     * @description: Sets a Flags in an DistributedOperationBuilder.
     * @return Returns this DistributedOperationBuilder object containing the Flags.
     */
    DistributedOperationBuilder& WithFlags(unsigned int flags);

    /**
     * @description: Sets a Uri in an DistributedOperationBuilder.
     * @return Returns this DistributedOperationBuilder object containing the Uri.
     */
    DistributedOperationBuilder& WithUri(const OHOS::Uri& uri);
    std::shared_ptr<DistributedOperation> build();

private:
    std::string abilityName_ = "";
    std::string action_ = "";
    std::string bundleName_ = "";
    std::string deviceId_ = "";
    std::vector<std::string> entities_ = {};
    unsigned int flags_ = 0;
    OHOS::Uri uri_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS

#endif  // OHOS_DISTRIBUTEDWANT_OPERATION_BUILDER_H