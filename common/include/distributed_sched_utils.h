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

#ifndef OHOS_DISTRIBUTED_SCHED_UTILS_H
#define OHOS_DISTRIBUTED_SCHED_UTILS_H

#include "cJSON.h"
#include <initializer_list>
#include <string>

#include "parcel.h"

namespace OHOS {
namespace DistributedSchedule {
constexpr static int32_t INVALID_MISSION_ID = -1;
const std::string BASE_64_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

bool IsValidPath(const std::string &inFilePath, std::string &realFilePath);
bool UpdateAllowAppList(const std::string &cfgJsonStr);
int32_t LoadContinueConfig();
bool CheckBundleContinueConfig(const std::string &bundleName);
int32_t GetCurrentMissionId();
std::string ParcelToBase64Str(const Parcel& parcel);
int32_t Base64StrToParcel(const std::string& rawStr, Parcel& parcel);
std::string Base64Encode(const unsigned char *toEncode, unsigned int len);
std::string Base64Decode(const std::string& basicString);
bool IsBase64(unsigned char c);
std::string GetAnonymStr(const std::string &value);
std::string GetAnonymInt32(const int32_t value);
bool IsInt32(const cJSON *paramValue);
bool IsString(const cJSON *paramValue);
bool CJsonParamCheck(const cJSON *jsonObj, const std::initializer_list<std::string> &keys);
bool GetOsInfoFromDM(const std::string &dmInfoEx, int32_t &osType, std::string &osVersion);
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_SCHED_UTILS_H
