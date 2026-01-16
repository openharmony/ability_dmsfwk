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

#include "util/distributed_sched_memory_utils.h"
#include <fstream>
#include <fcntl.h>
#include <sstream>
#include <unistd.h>
#include "parameters.h"

#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string TAG = "DistributedSchedMemoryUtils";
    constexpr const char *RECLAIM_FILEPAGE_STRING_FOR_HM = "1";
    constexpr const char *RECLAIM_FILEPAGE_STRING_FOR_LINUX = "file";
    constexpr const char *KERNEL_PARAM_KEY = "ohos.boot.kernel";
    constexpr const char *KERNEL_TYPE_HM = "hongmeng";
}

DistributedSchedMemoryUtils& DistributedSchedMemoryUtils::GetInstance()
{
    static auto instance = new DistributedSchedMemoryUtils();
    return *instance;
}

DistributedSchedMemoryUtils::DistributedSchedMemoryUtils()
{
}

void DistributedSchedMemoryUtils::ReclaimNow()
{
    int32_t pid = getpid();
    std::string path = "/proc/" + std::to_string(pid) + "/reclaim";
    std::string content = RECLAIM_FILEPAGE_STRING_FOR_LINUX;
    if (system::GetParameter(KERNEL_PARAM_KEY, "") == KERNEL_TYPE_HM) {
        content = RECLAIM_FILEPAGE_STRING_FOR_HM;
    }
    WriteToProcFile(path, content);
}

void DistributedSchedMemoryUtils::WriteToProcFile(const std::string &path,
    const std::string &content)
{
    int fd = open(path.c_str(), O_WRONLY);
    if (fd == -1) {
        HILOGE("Failed to open %{public}s", path.c_str());
        return;
    }
    ssize_t written = write(fd, content.c_str(), content.length());
    close(fd);
}
} // namespace DistributedSchedule
} // namespace OHOS
