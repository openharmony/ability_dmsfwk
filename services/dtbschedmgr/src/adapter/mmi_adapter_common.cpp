/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "adapter/mmi_adapter.h"

#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "MMIAdapter";
}
IMPLEMENT_SINGLE_INSTANCE(MMIAdapter);

void MMIAdapter::Init()
{
    HILOGI("%{public}s common called. ", __func__);
}

void MMIAdapter::UnInit()
{
    HILOGI("%{public}s common called. ", __func__);
}

int32_t MMIAdapter::AddMMIListener()
{
    HILOGI("%{public}s common called. ", __func__);
    return 0;
}

void MMIAdapter::RemoveMMIListener(int32_t monitorId)
{
    HILOGI("%{public}s common called. ", __func__);
}
} // namespace DistributedSchedule
} // namespace OHOS