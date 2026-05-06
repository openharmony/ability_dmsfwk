/*
 * Copyright (c) 2025-2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_EXTENSION_ERROR_UTILS_H
#define OHOS_DISTRIBUTED_EXTENSION_ERROR_UTILS_H

#include <string>

namespace OHOS {
namespace DistributedSchedule {

enum class DistributedErrorCode {
    ERROR_OK = 0,
    ERROR_CODE_PERMISSION_DENIED = 201,
    ERROR_CODE_INVALID_PARAM = 401,
    ERROR_CODE_INNER = 16000050,
    ERROR_CODE_RESOLVE_ABILITY = 16000001,
    ERROR_CODE_INVALID_ABILITY_TYPE = 16000002,
    ERROR_CODE_INVALID_ID = 16000003,
    ERROR_CODE_NO_INVISIBLE_PERMISSION = 16000004,
    ERROR_CODE_STATIC_CFG_PERMISSION = 16000005,
    ERROR_CODE_CROSS_USER = 16000006,
    ERROR_CODE_CROWDTEST_EXPIRED = 16000008,
    ERROR_CODE_INVALID_CONTEXT = 16000011,
    ERROR_CODE_CONTROLLED = 16000012,
    ERROR_CODE_EDM_CONTROLLED = 16000013,
    ERROR_CODE_NOT_TOP_ABILITY = 16000053,
    ERROR_CODE_FREE_INSTALL_TIMEOUT = 16000055,
};

DistributedErrorCode GetJsErrorCodeByNativeError(int32_t errCode);
std::string GetErrorMsg(const DistributedErrorCode &errCode);
int32_t ToInt32(const DistributedErrorCode &errCode);

} // namespace DistributedSchedule
} // namespace OHOS

#endif // OHOS_DISTRIBUTED_EXTENSION_ERROR_UTILS_H
