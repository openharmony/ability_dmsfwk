/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "mission/distributed_mission_focused_listener.h"

#include <sys/prctl.h>

#include "continue/dsched_continue_manager.h"
#include "dfx/distributed_radar.h"
#include "dtbschedmgr_log.h"
#include "ipc_skeleton.h"
#include "mission/notification/dms_continue_send_manager.h"
#include "multi_user_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedMissionFocusedListener";
}

void DistributedMissionFocusedListener::Init()
{
    HILOGI("Init start");
    if (eventHandler_ != nullptr) {
        HILOGI("Already inited, end.");
        return;
    }
    {
        eventThread_ = std::thread(&DistributedMissionFocusedListener::StartEvent, this);
        std::unique_lock<std::mutex> lock(eventMutex_);
        eventCon_.wait(lock, [this] {
            return eventHandler_ != nullptr;
        });
    }
    HILOGI("Init end");
}

void DistributedMissionFocusedListener::StartEvent()
{
    HILOGI("StartEvent start");
    prctl(PR_SET_NAME, TAG.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    CHECK_POINTER_RETURN(runner, "runner");
    runner->Run();
    HILOGI("StartEvent end");
}


void DistributedMissionFocusedListener::UnInit()
{
    HILOGI("UnInit start");
    if (eventHandler_ != nullptr && eventHandler_->GetEventRunner() != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        if (eventThread_.joinable()) {
            eventThread_.join();
        }
        eventHandler_ = nullptr;
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("UnInit end");
}

void DistributedMissionFocusedListener::OnMissionCreated(int32_t missionId)
{
    HILOGD("OnMissionCreated, missionId = %{public}d", missionId);
}

void DistributedMissionFocusedListener::OnMissionDestroyed(int32_t missionId)
{
    HILOGD("OnMissionDestroyed, missionId = %{public}d", missionId);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (!MultiUserManager::GetInstance().IsCallerForeground(callingUid)) {
        HILOGW("Current process is not foreground. callingUid = %{public}d", callingUid);
        return;
    }
    auto feedfunc = [this, missionId, callingUid]() {
        DSchedContinueManager::GetInstance().NotifyTerminateContinuation(missionId);
        auto sendMgr = MultiUserManager::GetInstance().GetSendMgrByCallingUid(callingUid);
        CHECK_POINTER_RETURN(sendMgr, "sendMgr");
        sendMgr->OnMissionStatusChanged(missionId, MISSION_EVENT_DESTORYED);

        int32_t currentAccountId = MultiUserManager::GetInstance().GetForegroundUser();
        DmsContinueConditionMgr::GetInstance().UpdateMissionStatus(
            currentAccountId, missionId, MISSION_EVENT_DESTORYED);
    };
    CHECK_POINTER_RETURN(eventHandler_, "eventHandler_");
    eventHandler_->PostTask(feedfunc);
}

void DistributedMissionFocusedListener::OnMissionSnapshotChanged(int32_t missionId)
{
    HILOGD("OnMissionSnapshotChanged, missionId = %{public}d", missionId);
}

void DistributedMissionFocusedListener::OnMissionMovedToFront(int32_t missionId)
{
    HILOGD("OnMissionMovedToFront, missionId = %{public}d", missionId);
}

void DistributedMissionFocusedListener::OnMissionFocused(int32_t missionId)
{
    HILOGD("OnMissionFocused, missionId = %{public}d", missionId);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (!MultiUserManager::GetInstance().IsCallerForeground(callingUid)) {
        HILOGW("Current process is not foreground. callingUid = %{public}d", callingUid);
        return;
    }

    auto feedfunc = [this, missionId, callingUid]() {
        int32_t currentAccountId = MultiUserManager::GetInstance().GetForegroundUser();
        DmsContinueConditionMgr::GetInstance().UpdateMissionStatus(currentAccountId, missionId, MISSION_EVENT_FOCUSED);

        auto sendMgr = MultiUserManager::GetInstance().GetSendMgrByCallingUid(callingUid);
        CHECK_POINTER_RETURN(sendMgr, "sendMgr");
        sendMgr->OnMissionStatusChanged(missionId, MISSION_EVENT_FOCUSED);
    };
    CHECK_POINTER_RETURN(eventHandler_, "eventHandler_");
    eventHandler_->PostTask(feedfunc);
}

void DistributedMissionFocusedListener::OnMissionUnfocused(int32_t missionId)
{
    HILOGD("OnMissionUnFocused, missionId = %{public}d", missionId);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (!MultiUserManager::GetInstance().IsCallerForeground(callingUid)) {
        HILOGW("Current process is not foreground. callingUid = %{public}d", callingUid);
        return;
    }

    auto feedfunc = [this, missionId, callingUid]() {
        auto sendMgr = MultiUserManager::GetInstance().GetSendMgrByCallingUid(callingUid);
        CHECK_POINTER_RETURN(sendMgr, "sendMgr");

        sendMgr->OnMissionStatusChanged(missionId, MISSION_EVENT_UNFOCUSED);
        int32_t currentAccountId = MultiUserManager::GetInstance().GetForegroundUser();
        DmsContinueConditionMgr::GetInstance().UpdateMissionStatus(
            currentAccountId, missionId, MISSION_EVENT_UNFOCUSED);
    };
    CHECK_POINTER_RETURN(eventHandler_, "eventHandler_");
    eventHandler_->PostTask(feedfunc);
}

#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
void DistributedMissionFocusedListener::OnMissionIconUpdated([[maybe_unused]]int32_t missionId,
    [[maybe_unused]]const std::shared_ptr<OHOS::Media::PixelMap> &icon)
{
}
#endif

void DistributedMissionFocusedListener::OnMissionClosed(int32_t missionId)
{
    HILOGD("OnMissionClosed, missionId = %{public}d", missionId);
    int32_t callingUid = IPCSkeleton::GetCallingUid();
    if (!MultiUserManager::GetInstance().IsCallerForeground(callingUid)) {
        HILOGW("Current process is not foreground. callingUid = %{public}d", callingUid);
        return;
    }

    auto feedfunc = [this, missionId, callingUid]() {
    auto sendMgr = MultiUserManager::GetInstance().GetCurrentSendMgr();
        CHECK_POINTER_RETURN(sendMgr, "sendMgr");

        sendMgr->OnMissionStatusChanged(missionId, MISSION_EVENT_DESTORYED);
        int32_t currentAccountId = MultiUserManager::GetInstance().GetForegroundUser();
        DmsContinueConditionMgr::GetInstance().UpdateMissionStatus(
            currentAccountId, missionId, MISSION_EVENT_DESTORYED);
    };
    CHECK_POINTER_RETURN(eventHandler_, "eventHandler_");
    eventHandler_->PostTask(feedfunc);
}

void DistributedMissionFocusedListener::OnMissionLabelUpdated([[maybe_unused]]int32_t missionId)
{
}
} // namespace DistributedSchedule
} // namespace OHOS
