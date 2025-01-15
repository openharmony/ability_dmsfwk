/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef DMSFWK_EVENT_HANDLER_MOCK_H
#define DMSFWK_EVENT_HANDLER_MOCK_H

#include <gmock/gmock.h>

#include "event_handler.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace OHOS::AppExecFwk;
class IEventHandler {
public:
    virtual ~IEventHandler() = default;
    virtual bool SendEvent(InnerEvent::Pointer &event, int64_t delayTime, EventQueue::Priority priority) = 0;
public:
    static inline std::shared_ptr<IEventHandler> handlerMock = nullptr;
};

class EventHandlerMock : public IEventHandler {
public:
    MOCK_METHOD3(SendEvent, bool(InnerEvent::Pointer &event, int64_t delayTime, EventQueue::Priority priority));
};
}
}
#endif