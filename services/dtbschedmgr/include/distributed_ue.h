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

#ifndef OHOS_DISTRIBUTED_UE_H
#define OHOS_DISTRIBUTED_UE_H

#include <cstdint>
#include <chrono>
#include <string>
#include <vector>

#include "dsched_continue.h"
#include "dtbschedmgr_device_info_storage.h"
#include "dtbschedmgr_log.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string CONTINUATION_BEHAVIOR = "CONTINUATION_BEHAVIOR";
const std::string ERROR_CODE_UE = "ERROR_CODE_UE";
const std::string PNAMEID = "PNAMEID";
const std::string PVERSIONID = "PVERSIONID";
const std::string BUNDLE_NAME = "BUNDLE_NAME";
const std::string ABILITY_NAME = "ABILITY_NAME";
const std::string SOURCE_DEVICE_TYPE = "SOURCE_DEVICE_TYPE";

const std::string CONTINUATION_STATE = "CONTINUATION_STATE";
const std::string FAILED_EXTRAINFO = "FAILED_EXTRAINFO";
const std::string CONTINUATION_DURATION = "CONTINUATION_DURATION";

const std::string SWITCH_STATE = "SWITCH_STATE";

const std::string SHOW_CONTINUATION_ICON = "SHOW_CONTINUATION_ICON";
const std::string CLICK_CONTINUATION_ICON = "CLICK_CONTINUATION_ICON";
const std::string COMPLETE_OF_CONTINUATION = "COMPLETE_OF_CONTINUATION";
const std::string ORIGINAL_SWITCH_STATE = "ORIGINAL_SWITCH_STATE";
const std::string CHANGED_SWITCH_STATE = "CHANGED_SWITCH_STATE";

constexpr char CONTINUATION_DOMAIN[] = "CONTINUATION_UE";

enum class continuationState : int32_t {
    CONTINUATION_SUCC = 0,
    CONTINUATION_FAIL = -1,
};

class DmsUE {
    DECLARE_SINGLE_INSTANCE(DmsUE);
public:
    bool NotifyDockShowIcon(const std::string& bundleName, const std::string& abilityName,
        const std::string& networkId, int32_t errCode);
    bool TriggerDmsContinue(const std::string& bundleName, const std::string& abilityName,
        const std::string& networkId, int32_t errCode);
    bool DmsContinueComplete(const std::string& bundleName, const std::string& abilityName,
        const std::string& networkId, int32_t errCode);
    bool OriginalSwitchState(const std::string& switchState, int32_t errCode);
    bool ChangedSwitchState(const std::string& switchState, int32_t errCode);

    int32_t GetDeviceTypeByNetworkId(std::string networkId);
    std::string ConvertErrCodeToStr(int32_t errorCode);
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_UE_H