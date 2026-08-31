/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTEDSCHEDULE_PARSE_TOKEN_INT_H
#define OHOS_DISTRIBUTEDSCHEDULE_PARSE_TOKEN_INT_H

#include <charconv>
#include <cstdint>
#include <string>
#include <system_error>

namespace OHOS {
namespace DistributedSchedule {
inline bool ParseTokenInt32(const std::string &text, int32_t &out)
{
    if (text.empty()) {
        return false;
    }
    int32_t value = 0;
    const char *first = text.data();
    const char *last = first + text.size();
    auto result = std::from_chars(first, last, value);
    if (result.ec != std::errc() || result.ptr != last) {
        return false;
    }
    out = value;
    return true;
}
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTEDSCHEDULE_PARSE_TOKEN_INT_H
