/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "distributed_intent_error_code.h"

#include "ability_manager_errors.h"

namespace OHOS {
namespace DistributedSchedule {

int32_t ConvertDiErrCode(int32_t diErrCode)
{
    switch (diErrCode) {
        case ERR_DI_PERMISSION_DENIED:
            return AAFwk::CHECK_PERMISSION_FAILED;
        case ERR_DI_ABILITY_VISIBLE_FALSE_DENY_REQUEST:
            return AAFwk::ABILITY_VISIBLE_FALSE_DENY_REQUEST;
        case ERR_DI_STATIC_CFG_PERMISSION:
            return AAFwk::ERR_STATIC_CFG_PERMISSION;
        case ERR_DI_CAPABILITY_NOT_SUPPORT:
            return AAFwk::ERR_CAPABILITY_NOT_SUPPORT;
        default:
            return diErrCode;
    }
}

} // namespace DistributedSchedule
} // namespace OHOS