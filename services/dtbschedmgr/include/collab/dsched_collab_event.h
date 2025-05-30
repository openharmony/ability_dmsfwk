/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DSCHED_COLLAB_EVENT_H
#define OHOS_DSCHED_COLLAB_EVENT_H

#include <string>

#include "ability_info.h"
#include "caller_info.h"
#include "cJSON.h"
#include "distributed_sched_interface.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
typedef enum {
    SOURCE_GET_PEER_VERSION_EVENT = 0,
    SOURCE_GET_VERSION_EVENT,
    SOURCE_START_EVENT,
    NOTIFY_RESULT_EVENT,
    GET_SINK_VERSION_EVENT,
    START_ABILITY_EVENT,
    NOTIFY_PREPARE_RESULT_EVENT,
    ERR_END_EVENT,
    END_EVENT,
    ABILITY_REJECT_EVENT,
} DSchedCollabEventType;

typedef enum {
    MIN_CMD = 0,
    SINK_GET_VERSION_CMD,
    SOURCE_GET_VERSION_CMD,
    SINK_START_CMD,
    NOTIFY_RESULT_CMD,
    DISCONNECT_CMD,
    MAX_CMD,
} DSchedCollabCommand;

class BaseCmd {
public:
    BaseCmd() = default;
    virtual ~BaseCmd() = default;
    virtual int32_t Marshal(std::string &jsonStr);
    virtual int32_t Unmarshal(const std::string &jsonStr);
public:
    bool needSendBigData_ = false;
    bool needSendStream_ = false;
    bool needRecvStream_ = false;
    int32_t collabVersion_ = -1;
    int32_t dmsVersion_ = -1;
    int32_t command_ = -1;
    int32_t srcCollabSessionId_ = -1;
    int32_t appVersion_ = -1;
    std::string collabToken_;
    std::string srcDeviceId_;
    std::string srcBundleName_;
    std::string srcAbilityName_;
    std::string srcModuleName_;
    std::string srcServerId_;
    std::string sinkDeviceId_;
    std::string sinkBundleName_;
    std::string sinkAbilityName_;
    std::string sinkModuleName_;
    std::string sinkServerId_;
};

class GetSinkCollabVersionCmd : public BaseCmd {
    public:
        int32_t Marshal(std::string &jsonStr);
        int32_t Unmarshal(const std::string &jsonStr);
     
    public:
        int32_t srcPid_ = -1;
        int32_t srcUid_ = -1;
        int32_t srcAccessToken_ = -1;
        int32_t sinkCollabVersion_ = -1;
};

class SinkStartCmd : public BaseCmd {
public:
    int32_t Marshal(std::string &jsonStr);
    int32_t Unmarshal(const std::string &jsonStr);

private:
    int32_t MarshalCallerInfo(std::string &jsonStr);
    int32_t MarshalAccountInfo(std::string &jsonStr);
    int32_t UnmarshalParcel(const std::string &jsonStr);
    int32_t UnmarshalPartParcel(cJSON *rootValue);
    int32_t UnmarshalOptParams(cJSON *rootValue);
    int32_t UnmarshalCallerInfo(std::string &jsonStr);
    int32_t UnmarshalCallerInfoExtra(std::string &jsonStr);
    int32_t UnmarshalAccountInfo(std::string &jsonStr);

public:
    int32_t srcPid_ = -1;
    int32_t srcUid_ = -1;
    int32_t srcAccessToken_ = -1;
    int32_t appVersion_ = -1;
    CallerInfo callerInfo_;
    IDistributedSched::AccountInfo accountInfo_;
    AAFwk::WantParams startParams_;
    AAFwk::WantParams messageParams_;
};

class NotifyResultCmd : public BaseCmd {
public:
    int32_t Marshal(std::string &jsonStr);
    int32_t Unmarshal(const std::string &jsonStr);
    int32_t UnmarshalSinkInfo(cJSON *rootValue);

public:
    int32_t result_ = -1;
    int32_t sinkCollabSessionId_ = -1;
    int32_t sinkPid_ = -1;
    int32_t sinkAccessToken_ = -1;
    int32_t sinkUserId_ = -1;
    int32_t sinkAccountId_ = -1;
    std::string sinkSocketName_;
    std::string abilityRejectReason_;
};

class DisconnectCmd : public BaseCmd {
public:
    int32_t Marshal(std::string &jsonStr);
    int32_t Unmarshal(const std::string &jsonStr);

public:
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_COLLAB_EVENT_H
