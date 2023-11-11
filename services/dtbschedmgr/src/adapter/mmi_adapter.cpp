/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "adapter/mmi_adapter.h"

#include "dtbschedmgr_log.h"
#include "mission/distributed_sched_continue_manager.h"

namespace OHOS {
namespace DistributedSchedule {

namespace {
const std::string TAG = "MMIAdapter";
}

IMPLEMENT_SINGLE_INSTANCE(MMIAdapter);

void MMIAdapter::Init()
{
    HILOGI("Init");
    mmiCallback_ = std::make_shared<MMIAdapter::MMIEventCallback>();
}

void MMIAdapter::MMIEventCallback::OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const
{
    DistributedSchedContinueManager::GetInstance().onMMIEvent();
}

void MMIAdapter::MMIEventCallback::OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
    DistributedSchedContinueManager::GetInstance().onMMIEvent();
}

void MMIAdapter::MMIEventCallback::OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const
{
    DistributedSchedContinueManager::GetInstance().onMMIEvent();
}

int32_t MMIAdapter::AddMMIListener()
{
    HILOGD("AddMMIListener called");
    int32_t ret = MMI::InputManager::GetInstance()->AddMonitor(mmiCallback_);
    HILOGD("AddMMIListener result: %{public}d", ret);
    return ret;
}

void MMIAdapter::RemoveMMIListener(int32_t monitorId)
{
    HILOGD("RemoveMMIListener called, monitor id = %{public}u", monitorId);
    MMI::InputManager::GetInstance()->RemoveMonitor(monitorId);
    return;
}
} // namespace DistributedSchedule
} // namespace OHOS
