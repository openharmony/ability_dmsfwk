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

#include "dtbschedmgr_log.h"
#include "distributed_extension_ets_loader.h"
#include "distributed_extension_ets.h"


namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedExtensionLoader";
} // namespace

DistributedExtension *CreateDistributedExtensionETS(const std::unique_ptr<Runtime> &runtime)
{
    return DistributedExtensionETS::Create(runtime);
}
} // namespace DistributedSchedule
} // namespace OHOS