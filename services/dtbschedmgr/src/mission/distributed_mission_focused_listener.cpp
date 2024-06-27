/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "continue/dsched_continue_manager.h"
#include "distributed_radar.h"
#include "dtbschedmgr_log.h"
#include "mission/dms_continue_send_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedMissionFocusedListener";
}
void DistributedMissionFocusedListener::OnMissionCreated(int32_t missionId)
{
    HILOGD("OnMissionCreated, missionId = %{public}d", missionId);
}

void DistributedMissionFocusedListener::OnMissionDestroyed(int32_t missionId)
{
    HILOGD("OnMissionDestroyed, missionId = %{public}d", missionId);
    DMSContinueSendMgr::GetInstance().NotifyMissionUnfocused(missionId, UnfocusedReason::DESTORY);
    DSchedContinueManager::GetInstance().NotifyTerminateContinuation(missionId);
    DMSContinueSendMgr::GetInstance().DeleteAliveMissionInfo(missionId);
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
    DmsRadar::GetInstance().DmsFocused("OnMissionFocused", NORMAL);
    DMSContinueSendMgr::GetInstance().NotifyMissionFocused(missionId, FocusedReason::NORMAL);
}

void DistributedMissionFocusedListener::OnMissionUnfocused(int32_t missionId)
{
    HILOGD("OnMissionUnFocused, missionId = %{public}d", missionId);
    DMSContinueSendMgr::GetInstance().NotifyMissionUnfocused(missionId, UnfocusedReason::NORMAL);
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
    DMSContinueSendMgr::GetInstance().NotifyMissionUnfocused(missionId, UnfocusedReason::CLOSE);
}

void DistributedMissionFocusedListener::OnMissionLabelUpdated([[maybe_unused]]int32_t missionId)
{
}
} // namespace DistributedSchedule
} // namespace OHOS
