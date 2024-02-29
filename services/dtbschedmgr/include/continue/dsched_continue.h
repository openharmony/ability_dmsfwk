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

#ifndef OHOS_DSCHED_CONTINUE_H
#define OHOS_DSCHED_CONTINUE_H

#include <condition_variable>
#include <mutex>
#include <thread>
#include <string>

#include "dsched_data_buffer.h"
#include "dsched_continue_event_handler.h"
#include "dsched_continue_state_machine.h"
#include "event_handler.h"

namespace OHOS {
namespace DistributedSchedule {
class DSchedContinueInfo {
public:
    DSchedContinueInfo() = default;
    explicit DSchedContinueInfo(std::string sourceNetworkId, std::string sourceBundleName, std::string sinkNetworkId,
        std::string sinkBundleName, std::string continueType)
        : sourceNetworkId_(sourceNetworkId), sourceBundleName_(sourceBundleName), sinkNetworkId_(sinkNetworkId),
        sinkBundleName_(sinkBundleName), continueType_(continueType) {}

    explicit DSchedContinueInfo(std::string sourceNetworkId, std::string sinkNetworkId, int32_t missionId)
        : sourceNetworkId_(sourceNetworkId), sinkNetworkId_(sinkNetworkId), missionId_(missionId) {}
    ~DSchedContinueInfo() = default;

    bool operator < (const DSchedContinueInfo &index) const
    {
        std::string compareInfo = this->sourceNetworkId_ + this->sourceBundleName_ + this->sinkNetworkId_ +
            this->sinkBundleName_ + this->continueType_ + std::to_string(this->missionId_);
        std::string otherCompareInfo = index.sourceNetworkId_ + index.sourceBundleName_ + index.sinkNetworkId_ +
            index.sinkBundleName_ + index.continueType_ + std::to_string(index.missionId_);
        return compareInfo < otherCompareInfo;
    }

    std::string sourceNetworkId_;
    std::string sourceBundleName_;
    std::string sinkNetworkId_;
    std::string sinkBundleName_;
    std::string continueType_;
    int32_t missionId_ = -1;
};

typedef enum {
    CONTINUE_SOURCE = 0,
    CONTINUE_SINK = 1
} DSchedContinueDirection;

class DSchedContinue : public std::enable_shared_from_this<DSchedContinue> {
public:
    explicit DSchedContinue(int32_t direction, DSchedContinueInfo &continueInfo);
    ~DSchedContinue();

    int32_t Init();
    void ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event);

    int32_t PostStartTask();
    int32_t PostReplyTask();
    int32_t PostCotinueAbilityTask();
    int32_t PostContinueSendTask();
    int32_t PostContinueDataTask();
    int32_t PostNotifyCompleteTask();
    int32_t PostContinueEndTask();

    int32_t ExecuteContinueReq();
    int32_t ExecuteContinueAbility();
    int32_t ExecuteContinueCommReply();
    int32_t ExecuteContinueSend();
    int32_t ExecuteContinueData();
    int32_t ExecuteNotifyComplete();
    int32_t ExecuteContinueEnd();

    void OnDataRecv(std::shared_ptr<DSchedDataBuffer> data);
    void OnShutDown();
    void OnBind();

private:
    void StartEventHandler();

private:
    std::shared_ptr<DSchedContinueStateMachine> stateMachine_;
    std::shared_ptr<DSchedContinueEventHandler> eventHandler_;
    std::condition_variable eventCon_;
    std::thread eventThread_;
    std::mutex eventMutex_;

    int32_t version_;
    int32_t subServiceType_;
    int32_t continueByType_;
    int32_t direction_;
    DSchedContinueInfo continueInfo_;
    bool isSourceExit_;
    int32_t softbusSessionId_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_CONTINUE_H