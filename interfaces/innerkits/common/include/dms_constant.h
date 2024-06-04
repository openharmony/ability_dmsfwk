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

#ifndef OHOS_DMS_CONSTANT_H
#define OHOS_DMS_CONSTANT_H

namespace OHOS {
namespace DistributedSchedule {
namespace Constants {
constexpr int32_t OH_OS_TYPE = 10;
constexpr int32_t HO_OS_TYPE = 11;
constexpr int32_t HO_OS_TYPE_EX = -1;

constexpr const char* PARAM_KEY_OS_TYPE = "OS_TYPE";
constexpr const char* PARAM_KEY_OS_VERSION = "OS_VERSION";
constexpr const char* DMS_NAME = "dmsfwk";
constexpr const char* DMS_VERSION = "5.0.0";
constexpr const char* DMS_SERVICE_ID = "dmsfwk_svr_id";
constexpr const char* DMS_CHAR_ID = "static_capability";
constexpr const char* PACKAGE_NAMES = "packageNames";
constexpr const char* VERSIONS = "versions";
constexpr const char* DMS_SERVICE_TYPE = "appInfo";
} // Constants
} // DistributedSchedule
} // OHOS
#endif // OHOS_DMS_CONSTANT_H
