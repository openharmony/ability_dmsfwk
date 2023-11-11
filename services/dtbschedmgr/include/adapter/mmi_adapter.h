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

#ifndef OHOS_DTBSCHEDMGR_MMI_ADAPTER_H
#define OHOS_DTBSCHEDMGR_MMI_ADAPTER_H

#include "i_input_event_consumer.h"
#include "input_manager.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

class MMIAdapter {
public:
    DECLARE_SINGLE_INSTANCE_BASE(MMIAdapter);
public:
    MMIAdapter() = default;
    virtual ~MMIAdapter() = default;

class MMIEventCallback : public MMI::IInputEventConsumer {
    void OnInputEvent(std::shared_ptr<MMI::KeyEvent> keyEvent) const override;
    void OnInputEvent(std::shared_ptr<MMI::PointerEvent> pointerEvent) const override;
    void OnInputEvent(std::shared_ptr<MMI::AxisEvent> axisEvent) const override;
};
    void Init();
    int32_t AddMMIListener();
    void RemoveMMIListener(int32_t monitorId);

private:
    std::shared_ptr<MMI::IInputEventConsumer> mmiCallback_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DTBSCHEDMGR_MMI_ADAPTER_H
