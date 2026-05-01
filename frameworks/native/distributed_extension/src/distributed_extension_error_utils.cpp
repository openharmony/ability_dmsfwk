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

#include "distributed_extension_error_utils.h"

#include <unordered_map>

namespace OHOS {
namespace DistributedSchedule {
namespace {
// Error messages matching the .d.ts declarations
const char *ERROR_MSG_OK = "OK.";
const char *ERROR_MSG_PERMISSION_DENIED = "The application does not have permission to call the interface.";
const char *ERROR_MSG_INVALID_PARAM = "Parameter error. Possible causes: 1. Mandatory parameters are left unspecified;"
    " 2. Incorrect parameter types; 3. Parameter verification failed.";
const char *ERROR_MSG_INNER = "Internal error.";
const char *ERROR_MSG_RESOLVE_ABILITY = "The specified ability does not exist.";
const char *ERROR_MSG_INVALID_ABILITY_TYPE = "Incorrect ability type.";
const char *ERROR_MSG_INVISIBLE = "Cannot start an invisible component.";
const char *ERROR_MSG_STATIC_CFG_PERMISSION = "The specified process does not have the permission.";
const char *ERROR_MSG_CROSS_USER = "Cross-user operations are not allowed.";
const char *ERROR_MSG_CROWDTEST_EXPIRED = "The crowdtesting application expires.";
const char *ERROR_MSG_INVALID_CONTEXT = "The context does not exist.";
const char *ERROR_MSG_CONTROLLED = "The application is controlled.";
const char *ERROR_MSG_EDM_CONTROLLED = "The application is controlled by EDM.";
const char *ERROR_MSG_NOT_TOP_ABILITY = "The ability is not on the top of the UI.";
const char *ERROR_MSG_FREE_INSTALL_TIMEOUT = "Installation-free timed out.";

std::unordered_map<DistributedErrorCode, const char *> ERR_CODE_MAP = {
    { DistributedErrorCode::ERROR_OK, ERROR_MSG_OK },
    { DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED, ERROR_MSG_PERMISSION_DENIED },
    { DistributedErrorCode::ERROR_CODE_INVALID_PARAM, ERROR_MSG_INVALID_PARAM },
    { DistributedErrorCode::ERROR_CODE_INNER, ERROR_MSG_INNER },
    { DistributedErrorCode::ERROR_CODE_RESOLVE_ABILITY, ERROR_MSG_RESOLVE_ABILITY },
    { DistributedErrorCode::ERROR_CODE_INVALID_ABILITY_TYPE, ERROR_MSG_INVALID_ABILITY_TYPE },
    { DistributedErrorCode::ERROR_CODE_NO_INVISIBLE_PERMISSION, ERROR_MSG_INVISIBLE },
    { DistributedErrorCode::ERROR_CODE_STATIC_CFG_PERMISSION, ERROR_MSG_STATIC_CFG_PERMISSION },
    { DistributedErrorCode::ERROR_CODE_CROSS_USER, ERROR_MSG_CROSS_USER },
    { DistributedErrorCode::ERROR_CODE_CROWDTEST_EXPIRED, ERROR_MSG_CROWDTEST_EXPIRED },
    { DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT, ERROR_MSG_INVALID_CONTEXT },
    { DistributedErrorCode::ERROR_CODE_CONTROLLED, ERROR_MSG_CONTROLLED },
    { DistributedErrorCode::ERROR_CODE_EDM_CONTROLLED, ERROR_MSG_EDM_CONTROLLED },
    { DistributedErrorCode::ERROR_CODE_NOT_TOP_ABILITY, ERROR_MSG_NOT_TOP_ABILITY },
    { DistributedErrorCode::ERROR_CODE_FREE_INSTALL_TIMEOUT, ERROR_MSG_FREE_INSTALL_TIMEOUT },
};

// Native error code values from ability_manager_errors.h (AAFwk service error offset = 2097152)
// and DMS error codes. Using numeric values directly to avoid header dependency issues.
constexpr int32_t NATIVE_RESOLVE_ABILITY_ERR = 2097152;
constexpr int32_t NATIVE_CONNECTION_NOT_EXIST = 2097161;
constexpr int32_t NATIVE_MISSION_NOT_FOUND = 2097174;
constexpr int32_t NATIVE_TARGET_ABILITY_NOT_SERVICE = 2097170;
constexpr int32_t NATIVE_RESOLVE_CALL_ABILITY_TYPE_ERR = 2097188;
constexpr int32_t NATIVE_CHECK_PERMISSION_FAILED = 2097177;
constexpr int32_t NATIVE_ABILITY_VISIBLE_FALSE_DENY_REQUEST = 2097179;
constexpr int32_t NATIVE_ERR_WRONG_INTERFACE_CALL = 2097202;
constexpr int32_t NATIVE_ERR_CROWDTEST_EXPIRED = 2097203;
constexpr int32_t NATIVE_ERR_APP_CONTROLLED = 2097204;
constexpr int32_t NATIVE_ERR_INVALID_CALLER = 2097205;
constexpr int32_t NATIVE_ERR_CROSS_USER = 2097207;
constexpr int32_t NATIVE_ERR_STATIC_CFG_PERMISSION = 2097208;
constexpr int32_t NATIVE_ERR_EDM_APP_CONTROLLED = 2097216;
constexpr int32_t NATIVE_ERR_INVALID_CONTEXT = 2097323;
constexpr int32_t NATIVE_ERR_NOT_ALLOW_IMPLICIT_START = 2097231;
constexpr int32_t NATIVE_ERR_TARGET_BUNDLE_NOT_EXIST = 2097241;

// DMS error codes
constexpr int32_t NATIVE_DMS_PERMISSION_DENIED = 29360157;
constexpr int32_t NATIVE_DMS_COMPONENT_ACCESS_PERMISSION_DENIED = 29360176;
constexpr int32_t NATIVE_INVALID_PARAMETERS_ERR = 29360128;
constexpr int32_t NATIVE_DMS_ACCOUNT_ACCESS_PERMISSION_DENIED = 29360175;

// Free install error codes
constexpr int32_t NATIVE_NOT_TOP_ABILITY = 0x500001;
constexpr int32_t NATIVE_FREE_INSTALL_TIMEOUT = 29360300;
constexpr int32_t NATIVE_FA_TIMEOUT = 0x820103;
constexpr int32_t NATIVE_HAP_PACKAGE_DOWNLOAD_TIMED_OUT = -9;
constexpr int32_t NATIVE_FA_PACKAGE_DOES_NOT_SUPPORT_FREE_INSTALL = -10;
constexpr int32_t NATIVE_CONCURRENT_TASKS_WAITING_FOR_RETRY = -6;
constexpr int32_t NATIVE_NOT_ALLOWED_TO_PULL_THIS_FA = -901;
constexpr int32_t NATIVE_NOT_SUPPORT_CROSS_DEVICE_FREE_INSTALL_PA = -12;

// Bundle framework error code
constexpr int32_t NATIVE_ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST = 8521220;

std::unordered_map<int32_t, DistributedErrorCode> INNER_TO_JS_ERROR_CODE_MAP = {
    { 0, DistributedErrorCode::ERROR_OK },
    // Permission errors
    { NATIVE_CHECK_PERMISSION_FAILED, DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED },
    { NATIVE_DMS_PERMISSION_DENIED, DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED },
    { NATIVE_DMS_COMPONENT_ACCESS_PERMISSION_DENIED, DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED },
    { NATIVE_DMS_ACCOUNT_ACCESS_PERMISSION_DENIED, DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED },
    // Parameter errors
    { NATIVE_INVALID_PARAMETERS_ERR, DistributedErrorCode::ERROR_CODE_INVALID_PARAM },
    // Ability not found
    { NATIVE_RESOLVE_ABILITY_ERR, DistributedErrorCode::ERROR_CODE_RESOLVE_ABILITY },
    { NATIVE_ERR_TARGET_BUNDLE_NOT_EXIST, DistributedErrorCode::ERROR_CODE_RESOLVE_ABILITY },
    { NATIVE_ERR_NOT_ALLOW_IMPLICIT_START, DistributedErrorCode::ERROR_CODE_RESOLVE_ABILITY },
    // Ability type errors
    { NATIVE_ERR_WRONG_INTERFACE_CALL, DistributedErrorCode::ERROR_CODE_INVALID_ABILITY_TYPE },
    { NATIVE_TARGET_ABILITY_NOT_SERVICE, DistributedErrorCode::ERROR_CODE_INVALID_ABILITY_TYPE },
    { NATIVE_RESOLVE_CALL_ABILITY_TYPE_ERR, DistributedErrorCode::ERROR_CODE_INVALID_ABILITY_TYPE },
    // Invisible ability
    { NATIVE_ABILITY_VISIBLE_FALSE_DENY_REQUEST, DistributedErrorCode::ERROR_CODE_NO_INVISIBLE_PERMISSION },
    // Static permission
    { NATIVE_ERR_STATIC_CFG_PERMISSION, DistributedErrorCode::ERROR_CODE_STATIC_CFG_PERMISSION },
    // Cross user
    { NATIVE_ERR_CROSS_USER, DistributedErrorCode::ERROR_CODE_CROSS_USER },
    // Crowdtest expired
    { NATIVE_ERR_CROWDTEST_EXPIRED, DistributedErrorCode::ERROR_CODE_CROWDTEST_EXPIRED },
    // Context invalid
    { NATIVE_ERR_INVALID_CONTEXT, DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT },
    // App controlled
    { NATIVE_ERR_APP_CONTROLLED, DistributedErrorCode::ERROR_CODE_CONTROLLED },
    // EDM controlled
    { NATIVE_ERR_EDM_APP_CONTROLLED, DistributedErrorCode::ERROR_CODE_EDM_CONTROLLED },
    // Not top ability
    { NATIVE_NOT_TOP_ABILITY, DistributedErrorCode::ERROR_CODE_NOT_TOP_ABILITY },
    // Free install timeout
    { NATIVE_FREE_INSTALL_TIMEOUT, DistributedErrorCode::ERROR_CODE_FREE_INSTALL_TIMEOUT },
    { NATIVE_FA_TIMEOUT, DistributedErrorCode::ERROR_CODE_FREE_INSTALL_TIMEOUT },
    // Inner errors (no specific mapping needed)
    { NATIVE_ERR_INVALID_CALLER, DistributedErrorCode::ERROR_CODE_INNER },
    { NATIVE_CONNECTION_NOT_EXIST, DistributedErrorCode::ERROR_CODE_INNER },
    { NATIVE_MISSION_NOT_FOUND, DistributedErrorCode::ERROR_CODE_INNER },
    { NATIVE_HAP_PACKAGE_DOWNLOAD_TIMED_OUT, DistributedErrorCode::ERROR_CODE_INNER },
    { NATIVE_FA_PACKAGE_DOES_NOT_SUPPORT_FREE_INSTALL, DistributedErrorCode::ERROR_CODE_INNER },
    { NATIVE_CONCURRENT_TASKS_WAITING_FOR_RETRY, DistributedErrorCode::ERROR_CODE_INNER },
    { NATIVE_NOT_ALLOWED_TO_PULL_THIS_FA, DistributedErrorCode::ERROR_CODE_INNER },
    { NATIVE_NOT_SUPPORT_CROSS_DEVICE_FREE_INSTALL_PA, DistributedErrorCode::ERROR_CODE_INNER },
    { NATIVE_ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST, DistributedErrorCode::ERROR_CODE_INNER },
};
} // namespace

DistributedErrorCode GetJsErrorCodeByNativeError(int32_t errCode)
{
    auto it = INNER_TO_JS_ERROR_CODE_MAP.find(errCode);
    if (it != INNER_TO_JS_ERROR_CODE_MAP.end()) {
        return it->second;
    }
    return DistributedErrorCode::ERROR_CODE_INNER;
}

std::string GetErrorMsg(const DistributedErrorCode &errCode)
{
    auto it = ERR_CODE_MAP.find(errCode);
    if (it != ERR_CODE_MAP.end()) {
        return it->second;
    }
    return "";
}

int32_t ToInt32(const DistributedErrorCode &errCode)
{
    return static_cast<int32_t>(errCode);
}
} // namespace DistributedSchedule
} // namespace OHOS
