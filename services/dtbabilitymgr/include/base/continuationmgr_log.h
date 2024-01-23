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

#ifndef CONTINUATION_MANAGER_LOG_H_
#define CONTINUATION_MANAGER_LOG_H_

#include "errors.h"
#include "hilog/log_c.h"
#include "hilog/log_cpp.h"
#include "inttypes.h"

namespace OHOS {
namespace DistributedSchedule {
static constexpr OHOS::HiviewDFX::HiLogLabel CONTINUATION_MANAGER_LABEL = {LOG_CORE, 0xD004170,
    "ContinuationMgrService"};

#ifdef HILOGD
#undef HILOGD
#endif

#ifdef HILOGF
#undef HILOGF
#endif

#ifdef HILOGE
#undef HILOGE
#endif

#ifdef HILOGW
#undef HILOGW
#endif

#ifdef HILOGI
#undef HILOGI
#endif

#define DMS_LOG(level, fmt, ...) HiviewDFX::HiLog::level(CONTINUATION_MANAGER_LABEL, \
    "%{public}s::%{public}s " fmt, TAG.c_str(), __FUNCTION__, ##__VA_ARGS__)

#define HILOGF(fmt, ...) DMS_LOG(Fatal, fmt, ##__VA_ARGS__)
#define HILOGE(fmt, ...) DMS_LOG(Error, fmt, ##__VA_ARGS__)
#define HILOGW(fmt, ...) DMS_LOG(Warn,  fmt, ##__VA_ARGS__)
#define HILOGI(fmt, ...) DMS_LOG(Info,  fmt, ##__VA_ARGS__)
#define HILOGD(fmt, ...) DMS_LOG(Debug, fmt, ##__VA_ARGS__)

enum {
    /**
     * Module type: Distributed schedule Service side
     */
    DMS_MODULE_TYPE_SERVICE = 0,
};

// offset of dms error, only be used in this file.
constexpr ErrCode DMS_SERVICE_ERR_OFFSET = ErrCodeOffset(SUBSYS_DISTRIBUTEDSCHEDULE, DMS_MODULE_TYPE_SERVICE);

enum {
    /**
     * Result(29360128) for invalid parameters.
     */
    INVALID_PARAMETERS_ERR = DMS_SERVICE_ERR_OFFSET,
    /**
     * Result(29360141) for dump write file error.
     */
    DMS_WRITE_FILE_FAILED_ERR = 29360141,
    /**
     * Result(29360157) for permission denied.
     */
    DMS_PERMISSION_DENIED = 29360157,
    /*
     * Result(29360207) for app registered exceed max times.
     */
    REGISTER_EXCEED_MAX_TIMES = 29360207,
    /*
     * Result(29360208) for token has not registered.
     */
    TOKEN_HAS_NOT_REGISTERED = 29360208,
    /*
     * Result(29360209) for callback has registered.
     */
    CALLBACK_HAS_REGISTERED = 29360209,
    /*
     * Result(29360210) for callback has not registered.
     */
    CALLBACK_HAS_NOT_REGISTERED = 29360210,
    /*
     * Result(29360211) for connect ability failed.
     */
    CONNECT_ABILITY_FAILED = 29360211,
    /*
     * Result(29360212) for disconnect ability failed.
     */
    DISCONNECT_ABILITY_FAILED = 29360212,
    /*
     * Result(29360214) for unknown callback type.
     */
    UNKNOWN_CALLBACK_TYPE = 29360214,
    /*
     * Result(29360215) for invalid connect status.
     */
    INVALID_CONNECT_STATUS = 29360215,
    /*
     * Result(29360216) for invalid continuation mode.
     */
    INVALID_CONTINUATION_MODE = 29360216,
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // CONTINUATION_MANAGER_LOG_H_
