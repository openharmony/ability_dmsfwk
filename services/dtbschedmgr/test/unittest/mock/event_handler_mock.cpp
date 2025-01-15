/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "event_handler_mock.h"

using namespace std;
using namespace OHOS::AppExecFwk;
using namespace OHOS::DistributedSchedule;

EventHandler::EventHandler(const std::shared_ptr<EventRunner> &runner) : eventRunner_(runner)
{
}

EventHandler::~EventHandler()
{
}

bool EventHandler::SendEvent(InnerEvent::Pointer &event, int64_t delayTime, EventQueue::Priority priority)
{
    if (IEventHandler::handlerMock == nullptr) {
        return true;
    }
    return IEventHandler::handlerMock->SendEvent(event, delayTime, priority);
}
