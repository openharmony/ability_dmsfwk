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
#include "distributedWant/distributed_want_params.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
typedef enum {
    DSCHED_CONTINUE_INVALID_EVENT = -1,
    DSCHED_CONTINUE_REQ_PULL_EVENT = 0,
    DSCHED_CONTINUE_REPLY_EVENT = 1,
    DSCHED_CONTINUE_DATA_EVENT = 2,

    DSHCED_CONTINUE_REQ_PUSH_EVENT = 3,
    DSHCED_CONTINUE_ABILITY_EVENT = 4,
    DSHCED_CONTINUE_SEND_DATA_EVENT = 5,

    DSCHED_CONTINUE_COMPLETE_EVENT = 6,
    DSCHED_CONTINUE_END_EVENT = 7
} DSchedContinueEventType;

typedef enum {
    DSCHED_CONTINUE_CMD_MIN = 0,
    DSCHED_CONTINUE_CMD_START = 1,
    DSCHED_CONTINUE_CMD_DATA = 2,
    DSCHED_CONTINUE_CMD_REPLY = 3,
    DSCHED_CONTINUE_CMD_END = 4,
} DSchedContinueCommand;

class DSchedContinueCmdBase {
public:
    DSchedContinueCmdBase() = default;
    virtual ~DSchedContinueCmdBase() = default;
    virtual int32_t Marshal(std::string &jsonStr);
    virtual int32_t Unmarshal(const std::string &jsonStr);
public:
    int32_t version_ = 0;
    int32_t serviceType_ = 0;
    int32_t subServiceType_ = 0;
    int32_t command_ = 0;
    std::string srcDeviceId_;
    std::string srcBundleName_;
    std::string srcDeveloperId_ = "";
    std::string dstDeviceId_;
    std::string dstBundleName_;
    std::string dstDeveloperId_ = "";
    std::string continueType_;
    int32_t continueByType_ = 0;
    int32_t sourceMissionId_ = 0;
    int32_t dmsVersion_ = 0;
};

class DSchedContinueStartCmd : public DSchedContinueCmdBase {
public:
    int32_t Marshal(std::string &jsonStr);
    int32_t Unmarshal(const std::string &jsonStr);

public:
    int32_t direction_ = 0;
    int32_t appVersion_ = 0;
    DistributedWantParams wantParams_;
};

class DSchedContinueDataCmd : public DSchedContinueCmdBase {
public:
    int32_t Marshal(std::string &jsonStr);
    int32_t Unmarshal(const std::string &jsonStr);

private:
    int32_t MarshalCallerInfo(std::string &jsonStr);
    int32_t MarshalAccountInfo(std::string &jsonStr);
    int32_t UnmarshalParcel(const std::string &jsonStr);
    int32_t UnmarshalWantStr(const std::string &jsonStr);
    int32_t UnmarshalCallerInfo(const std::string &jsonStr);
    int32_t UnmarshalCallerInfoExtra(const std::string &jsonStr);
    int32_t UnmarshalAccountInfo(const std::string &jsonStr);

public:
    using AccountInfo = IDistributedSched::AccountInfo;

    OHOS::AAFwk::Want want_;
    AppExecFwk::CompatibleAbilityInfo abilityInfo_;
    int32_t requestCode_;
    CallerInfo callerInfo_;
    AccountInfo accountInfo_;
};

class DSchedContinueReplyCmd : public DSchedContinueCmdBase {
public:
    int32_t Marshal(std::string &jsonStr);
    int32_t Unmarshal(const std::string &jsonStr);

public:
    int32_t replyCmd_ = 0;
    int32_t appVersion_ = 0;
    int32_t result_ = 0;
    std::string reason_;
};

class DSchedContinueEndCmd : public DSchedContinueCmdBase {
public:
    int32_t Marshal(std::string &jsonStr);
    int32_t Unmarshal(const std::string &jsonStr);

public:
    int32_t result_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_CONTINUE_EVENT_H
