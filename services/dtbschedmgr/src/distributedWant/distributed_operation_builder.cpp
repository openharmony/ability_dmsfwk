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

#include "distributedWant/distributed_operation_builder.h"
#include "distributedWant/distributed_operation.h"

namespace OHOS {
namespace AAFwk {
DistributedOperationBuilder::DistributedOperationBuilder()
    : abilityName_(""), action_(""), bundleName_(""), deviceId_(""), flags_(0), uri_("")
{
    entities_.clear();
}

DistributedOperationBuilder::~DistributedOperationBuilder()
{}

/**
 * @description: Sets a AbilityName in an DistributedOperationBuilder.
 * @return Returns this DistributedOperationBuilder object containing the AbilityName.
 */
DistributedOperationBuilder& DistributedOperationBuilder::WithAbilityName(const std::string& abilityName)
{
    abilityName_ = abilityName;
    return *this;
}

/**
 * @description: Sets a BundleName in an DistributedOperationBuilder.
 * @return Returns this DistributedOperationBuilder object containing the BundleName.
 */
DistributedOperationBuilder& DistributedOperationBuilder::WithBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
    return *this;
}

/**
 * @description: Sets a DeviceId in an DistributedOperationBuilder.
 * @return Returns this DistributedOperationBuilder object containing the DeviceId.
 */
DistributedOperationBuilder& DistributedOperationBuilder::WithDeviceId(const std::string& deviceID)
{
    deviceId_ = deviceID;
    return *this;
}

/**
 * @description: Sets a Action in an DistributedOperationBuilder.
 * @return Returns this DistributedOperationBuilder object containing the Action.
 */
DistributedOperationBuilder& DistributedOperationBuilder::WithAction(const std::string& action)
{
    action_ = action;
    return *this;
}

/**
 * @description: Sets a Entities in an DistributedOperationBuilder.
 * @return Returns this DistributedOperationBuilder object containing the Entities.
 */
DistributedOperationBuilder& DistributedOperationBuilder::WithEntities(const std::vector<std::string>& entities)
{
    entities_ = entities;
    return *this;
}

/**
 * @description: Sets a Flags in an DistributedOperationBuilder.
 * @return Returns this DistributedOperationBuilder object containing the Flags.
 */
DistributedOperationBuilder& DistributedOperationBuilder::WithFlags(unsigned int flags)
{
    flags_ = flags;
    return *this;
}

/**
 * @description: Sets a Uri in an DistributedOperationBuilder.
 * @return Returns this DistributedOperationBuilder object containing the Uri.
 */
DistributedOperationBuilder& DistributedOperationBuilder::WithUri(const Uri& uri)
{
    uri_ = uri;
    return *this;
}

std::shared_ptr<DistributedOperation> DistributedOperationBuilder::build()
{
    std::shared_ptr<DistributedOperation> operation = std::make_shared<DistributedOperation>();
    operation->abilityName_ = abilityName_;
    operation->bundleName_ = bundleName_;
    operation->deviceId_ = deviceId_;
    operation->action_ = action_;
    operation->entities_ = entities_;
    operation->flags_ = flags_;
    operation->uri_ = uri_;

    return operation;
}
}  // namespace AAFwk
}  // namespace OHOS