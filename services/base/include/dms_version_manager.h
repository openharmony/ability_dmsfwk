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
#ifndef OHOS_DMS_VERSION_MANAGER_H
#define OHOS_DMS_VERSION_MANAGER_H

#include <string>
#include "ipc_skeleton.h"

namespace OHOS {
namespace DistributedSchedule {
#define IN_PROCESS_CALL(theCall)                                     \
    ([&]() {                                                         \
        std::string identity = IPCSkeleton::ResetCallingIdentity();  \
        auto retVal = theCall;                                       \
        IPCSkeleton::SetCallingIdentity(identity);                   \
        return retVal;                                               \
    }())

struct DmsVersion {
    uint32_t majorVersionNum = 0;
    uint32_t minorVersionNum = 0;
    uint32_t featureVersionNum = 0;
};

class DmsVersionManager {

public:
    static bool IsRemoteDmsVersionLower(const std::string& remoteDeviceId, const DmsVersion& thresholdDmsVersion);
private:
    static int32_t GetRemoteDmsVersion(const std::string& deviceId, DmsVersion& dmsVersion);
    static int32_t GetAppInfoFromDP(const std::string& deviceId, std::string& packageNamesData,
        std::string& versionsData);
    static int32_t GetDmsVersionDataFromAppInfo(const std::string& packageNamesData, const std::string& versionsData,
        std::string& dmsVersionData);
    static bool ParseDmsVersion(const std::string& dmsVersionData, DmsVersion& dmsVersion);
    static bool CompareDmsVersion(const DmsVersion& dmsVersion, const DmsVersion& thresholdDmsVersion);
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DMS_VERSION_MANAGER_H