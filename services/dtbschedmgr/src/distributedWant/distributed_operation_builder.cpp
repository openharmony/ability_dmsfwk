/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "distributed_operation.h"
#include "distributed_operation_builder.h"

namespace OHOS {
namespace DistributedSchedule {
DistributedOperationBuilder::DistributedOperationBuilder()
    : abilityName_(""), action_(""), bundleName_(""), deviceId_(""), flags_(0), uri_("")
{
    entities_.clear();
}

DistributedOperationBuilder::~DistributedOperationBuilder()
{}

DistributedOperationBuilder& DistributedOperationBuilder::WithAbilityName(const std::string& abilityName)
{
    abilityName_ = abilityName;
    return *this;
}

DistributedOperationBuilder& DistributedOperationBuilder::WithBundleName(const std::string& bundleName)
{
    bundleName_ = bundleName;
    return *this;
}

DistributedOperationBuilder& DistributedOperationBuilder::WithDeviceId(const std::string& deviceID)
{
    deviceId_ = deviceID;
    return *this;
}

DistributedOperationBuilder& DistributedOperationBuilder::WithAction(const std::string& action)
{
    action_ = action;
    return *this;
}

DistributedOperationBuilder& DistributedOperationBuilder::WithEntities(const std::vector<std::string>& entities)
{
    entities_ = entities;
    return *this;
}

DistributedOperationBuilder& DistributedOperationBuilder::WithFlags(unsigned int flags)
{
    flags_ = flags;
    return *this;
}

DistributedOperationBuilder& DistributedOperationBuilder::WithUri(const Uri& uri)
{
    uri_ = uri;
    return *this;
}

std::shared_ptr<DistributedOperation> DistributedOperationBuilder::build()
{
    std::shared_ptr<DistributedOperation> dOperation = std::make_shared<DistributedOperation>();
    dOperation->abilityName_ = abilityName_;
    dOperation->bundleName_ = bundleName_;
    dOperation->deviceId_ = deviceId_;
    dOperation->action_ = action_;
    dOperation->entities_ = entities_;
    dOperation->flags_ = flags_;
    dOperation->uri_ = uri_;

    return dOperation;
}
} // namespace DistributedSchedule
} // namespace OHOS