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

#ifndef OHOS_DSCHED_CONTINUE_EVENT_H
#define OHOS_DSCHED_CONTINUE_EVENT_H

#include <string>

#include "ability_info.h"
#include "caller_info.h"
#include "distributed_sched_interface.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
typedef enum {
    DSCHED_CONTINUE_REQ_PULL_EVENT = 0,
    DSCHED_CONTINUE_REPLY_EVENT = 1,
    DSCHED_CONTINUE_DATA_EVENT = 2,

    DSHCED_CONTINUE_REQ_PUSH_EVENT = 3,
    DSHCED_CONTINUE_ABILITY_EVENT = 4,
    DSHCED_CONTINUE_SEND_DATA_EVENT = 5,

    DSCHED_CONTINUE_END_EVENT = 6
} DSchedContinueEventType;

class DSchedContinueCmdBase {
public:
    int32_t version_;
    int32_t serviceType_;
    int32_t subServiceType_;
    int32_t command_;
    std::string srcDeviceId_;
    std::string srcBundleName_;
    std::string dstDeviceId_;
    std::string dstBundleName_;
    std::string continueType_;
    int32_t continueByType_;
    int32_t sourceMissionId_;
    int32_t dmsVersion_;
};

class DSchedContinueStartCmd {
public:
    int32_t Marshal(std::string &jsonStr);
    int32_t Unmarshal(const std::string &jsonStr);

public:
    DSchedContinueCmdBase cmdBase_;
    int32_t direction_;
    int32_t appVersion_;
    OHOS::AAFwk::WantParams wantParams_;
};

class DSchedContinueDataCmd {
public:
    int32_t Marshal(std::string &jsonStr);
    int32_t Unmarshal(const std::string &jsonStr);

public:
    using AccountInfo = IDistributedSched::AccountInfo;

    DSchedContinueCmdBase cmdBase_;
    OHOS::AAFwk::Want want_;
    AppExecFwk::CompatibleAbilityInfo abilityInfo_;
    int32_t requestCode_;
    CallerInfo callerInfo_;
    AccountInfo accountInfo_;
};

class DSchedContinueReplyCmd {
public:
    int32_t Marshal(std::string &jsonStr);
    int32_t Unmarshal(const std::string &jsonStr);

public:
    DSchedContinueCmdBase cmdBase_;
    int32_t replyCmd_;
    int32_t appVersion_;
    int32_t result_;
    std::string reason_;
};

class DSchedContinueEndCmd {
public:
    int32_t Marshal(std::string &jsonStr);
    int32_t Unmarshal(const std::string &jsonStr);

public:
    DSchedContinueCmdBase cmdBase_;
    int32_t result_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_CONTINUE_EVENT_H