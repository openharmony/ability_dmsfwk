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

#ifndef OHOS_DISTRIBUTED_SCHED_MEMORY_UTILS_H
#define OHOS_DISTRIBUTED_SCHED_MEMORY_UTILS_H

#include <string>
#include <cstdint>

namespace OHOS {
namespace DistributedSchedule {
class DistributedSchedMemoryUtils {
public:
    static DistributedSchedMemoryUtils& GetInstance();
    DistributedSchedMemoryUtils();
    DistributedSchedMemoryUtils(const DistributedSchedMemoryUtils&) = delete;
    DistributedSchedMemoryUtils& operator= (const DistributedSchedMemoryUtils&) = delete;
    DistributedSchedMemoryUtils(DistributedSchedMemoryUtils&&) = delete;
    DistributedSchedMemoryUtils& operator= (DistributedSchedMemoryUtils&&) = delete;

    void ReclaimNow();
    int32_t GetCurrentProcessMemoryUsedKB();

private:
    void WriteToProcFile(const std::string &path, const std::string &content);
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_SCHED_MEMORY_UTILS_H