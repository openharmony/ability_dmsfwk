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

#include "adapter/mmi_adapter.h"

#include <mutex>
#include <thread>
#include <sys/prctl.h>

#include "dtbschedmgr_log.h"
#include "mission/dms_continue_send_manager.h"

namespace OHOS {
namespace DistributedSchedule {

namespace {
const std::string TAG = "MMIAdapter";
const std::string MMI_ADAPTER = "mmi_adapter";
const std::string FREEZE_MMI_EVENT_TASK = "task_freeze_mmi_event";
constexpr int32_t FREEZE_MMI_EVENT_INTERVAL = 5000;
}

IMPLEMENT_SINGLE_INSTANCE(MMIAdapter);

void MMIAdapter::Init()
{
    HILOGI("Init");
    mmiCallback_ = std::make_shared<MMIAdapter::MMIEventCallback>();
    eventThread_ = std::thread(&MMIAdapter::StartEvent, this);
    std::unique_lock<std::mutex> lock(eventMutex_);
    eventCon_.wait(lock, [this] {
        return eventHandler_ != nullptr;
    });
}

void MMIAdapter::StartEvent()
{
    HILOGI("StartEvent start");
    prctl(PR_SET_NAME, MMI_ADAPTER.c_str());
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<OHOS::AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    runner->Run();
    HILOGI("StartEvent end");
}

void MMIAdapter::UnInit()
{
    HILOGI("UnInit start");
    if (eventHandler_ != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        eventThread_.join();
        eventHandler_ = nullptr;
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
    HILOGI("UnInit end");
}

int32_t MMIAdapter::AddMMIListener()
{
    HILOGD("AddMMIListener called");
    int32_t ret = MMI::InputManager::GetInstance()->AddMonitor(mmiCallback_);
    HILOGD("AddMMIListener result: %{public}d", ret);
    isMMIFreezed_ = false;
    return ret;
}

void MMIAdapter::RemoveMMIListener(int32_t monitorId)
{
    HILOGD("RemoveMMIListener called, monitor id = %{public}d", monitorId);
    MMI::InputManager::GetInstance()->RemoveMonitor(monitorId);
    return;
}

void MMIAdapter::PostRawMMIEvent()
{
    auto func = [this]() {
        HandleRawMMIEvent();
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(func);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
}

void MMIAdapter::PostUnfreezeMMIEvent()
{
    auto func = [this]() {
        HandleUnfreezeMMIEvent();
    };
    if (eventHandler_ != nullptr) {
        eventHandler_->PostTask(func, FREEZE_MMI_EVENT_TASK, FREEZE_MMI_EVENT_INTERVAL);
    } else {
        HILOGE("eventHandler_ is nullptr");
    }
}

void MMIAdapter::HandleRawMMIEvent()
{
    if (isMMIFreezed_) {
        return;
    }
    isMMIFreezed_ = true;
    DMSContinueSendMgr::GetInstance().OnMMIEvent();
    PostUnfreezeMMIEvent();
}

void MMIAdapter::HandleUnfreezeMMIEvent()
{
    isMMIFreezed_ = false;
}

void MMIAdapter::MMIEventCallback::OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const
{
    MMIAdapter::GetInstance().PostRawMMIEvent();
}

void MMIAdapter::MMIEventCallback::OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const
{
    MMIAdapter::GetInstance().PostRawMMIEvent();
}

void MMIAdapter::MMIEventCallback::OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const
{
    MMIAdapter::GetInstance().PostRawMMIEvent();
}
} // namespace DistributedSchedule
} // namespace OHOS
