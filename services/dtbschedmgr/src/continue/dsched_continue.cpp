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

#include "dsched_continue.h"

#include <sys/prctl.h>

#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedContinue";
}

DSchedContinue::DSchedContinue(int32_t direction, DSchedContinueInfo &continueInfo)
{
    HILOGI("DSchedContinue create");
    version_ = 0;
    subServiceType_ = 0;
    continueByType_ = 0;
    direction_ = 0;
    isSourceExit_ = false;
    softbusSessionId_ = -1;
}

DSchedContinue::~DSchedContinue()
{
    HILOGI("DSchedContinue delete enter");
    if ((eventHandler_ != nullptr) && (eventHandler_->GetEventRunner() != nullptr)) {
        eventHandler_->GetEventRunner()->Stop();
    }
    eventThread_.join();
    eventHandler_ = nullptr;
    HILOGI("DSchedContinue delete end");
}

int32_t DSchedContinue::Init()
{
    HILOGI("DSchedContinue init start");
    auto dContinue = std::shared_ptr<DSchedContinue>(shared_from_this());
    stateMachine_ = std::make_shared<DSchedContinueStateMachine>(dContinue);
    if (direction_ == CONTINUE_SOURCE) {
        stateMachine_->UpdateState(DSCHED_CONTINUE_SOURCE_START_STATE);
    } else {
        stateMachine_->UpdateState(DSCHED_CONTINUE_SINK_START_STATE);
    }

    eventThread_ = std::thread(&DSchedContinue::StartEventHandler, this);
    std::unique_lock<std::mutex> lock(eventMutex_);
    eventCon_.wait(lock, [this] {
        return eventHandler_ != nullptr;
    });
    HILOGI("DSchedContinue init end");
    return ERR_OK;
}

void DSchedContinue::StartEventHandler()
{
    std::string eventThreadName = "DSchedContinue_EventHandler";
    prctl(PR_SET_NAME, eventThreadName.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    if (runner == nullptr) {
        HILOGE("continue start eventHandler failed.");
        return;
    }

    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<DSchedContinueEventHandler>(runner, shared_from_this());
    }
    eventCon_.notify_one();
    runner->Run();
}

int32_t DSchedContinue::PostStartTask()
{
    return ERR_OK;
}

int32_t DSchedContinue::PostReplyTask()
{
    return ERR_OK;
}

int32_t DSchedContinue::PostCotinueAbilityTask()
{
    return ERR_OK;
}

int32_t DSchedContinue::PostContinueSendTask()
{
    return ERR_OK;
}

int32_t DSchedContinue::PostContinueDataTask()
{
    return ERR_OK;
}

int32_t DSchedContinue::PostNotifyCompleteTask()
{
    return ERR_OK;
}

int32_t DSchedContinue::PostContinueEndTask()
{
    return ERR_OK;
}

void DSchedContinue::ProcessEvent(const AppExecFwk::InnerEvent::Pointer &event)
{
}

int32_t DSchedContinue::ExecuteContinueReq()
{
    return ERR_OK;
}

int32_t DSchedContinue::ExecuteContinueAbility()
{
    return ERR_OK;
}

int32_t DSchedContinue::ExecuteContinueCommReply()
{
    return ERR_OK;
}

int32_t DSchedContinue::ExecuteContinueSend()
{
    return ERR_OK;
}

int32_t DSchedContinue::ExecuteContinueData()
{
    return ERR_OK;
}

int32_t DSchedContinue::ExecuteNotifyComplete()
{
    return ERR_OK;
}

int32_t DSchedContinue::ExecuteContinueEnd()
{
    return ERR_OK;
}

void DSchedContinue::OnDataRecv(std::shared_ptr<DSchedDataBuffer> data)
{
}

void DSchedContinue::OnShutDown()
{
}

void DSchedContinue::OnBind()
{
}
}  // namespace DistributedSchedule
}  // namespace OHOS