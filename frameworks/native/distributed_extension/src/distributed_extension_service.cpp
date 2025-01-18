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

#include "distributed_extension_service.h"

#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedExtensionService";

int32_t DistributedExtensionService::TriggerOnCreate(AAFwk::Want& want)
{
    HILOG_INFO("DistributedExtensionService::TriggerOnCreate enter");
    if (distributedExtension_ == nullptr) {
        HILOG_ERROR("distributedExtension is nullptr");
        return ERR_INVALID_VALUE;
    }

    distributedExtension_->TriggerOnCreate(want);
    return ERR_OK;
}

int32_t DistributedExtensionService::TriggerOnDestroy()
{
    HILOG_INFO("DistributedExtensionService::TriggerOnDestroy enter");
    if (distributedExtension_ == nullptr) {
        HILOG_ERROR("distributedExtension is nullptr");
        return ERR_INVALID_VALUE;
    }

    distributedExtension_->TriggerOnDestroy();
    return ERR_OK;
}

int32_t DistributedExtensionService::TriggerOnCollaborate(AAFwk::WantParams &wantParam)
{
    HILOG_INFO("DistributedExtensionService::TriggerOnCollaborate enter");
    if (distributedExtension_ == nullptr) {
        HILOG_ERROR("distributedExtension is nullptr");
        return ERR_INVALID_VALUE;
    }

    distributedExtension_->TriggerOnCollaborate(wantParam);
    return ERR_OK;
}

void DistributedExtensionService::Clear()
{}
}
}
