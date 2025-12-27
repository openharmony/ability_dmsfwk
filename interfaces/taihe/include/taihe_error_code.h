/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef SERVICES_DTBSCHEDMGR_TAIHE_ERROR_CODE_H_
#define SERVICES_DTBSCHEDMGR_TAIHE_ERROR_CODE_H_

namespace OHOS {
namespace DistributedCollab {
enum BussinessErrorCode {
    // Permission verification failed.
    ERR_INVALID_PERMISSION = 201,
    // The caller is not a system application.
    ERR_NOT_SYSTEM_APP = 202,
    // Input parameter error.
    ERR_INVALID_PARAMS = 401,
    // Capability not support.
    ERR_CAPABILITY_NOT_SUPPORT = 801,
    // Multiple streams can not be created.
    ERR_ONLY_SUPPORT_ONE_STREAM = 32300001,
    // The stream at the receive end is not started.
    ERR_RECEIVE_STREAM_NOT_START = 32300002,
    // Multiple streams can not be created.
    ERR_BITATE_NOT_SUPPORTED = 32300003,
    // The stream at the receive end is not started.
    ERR_COLOR_SPACE_NOT_SUPPORTED = 32300004,
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // SERVICES_DTBSCHEDMGR_TAIHE_ERROR_CODE_H_