/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef PARAM_COMMON_EVENT_SUBSCRIBER_H
#define PARAM_COMMON_EVENT_SUBSCRIBER_H

#include <functional>
#include <map>
#include <memory>
#include <singleton.h>
#include <string>
#include <iostream>
#include <fstream>
#include <nlohmann/json.hpp>

#include "common_event_subscriber.h"
#include "cJSON.h"
#include "want.h"

namespace OHOS {
namespace DistributedSchedule {
class ParamCommonEvent {
    DECLARE_SINGLETON(ParamCommonEvent)
public:
    void SubscriberEvent();
    void UnSubscriberEvent();
    void OnReceiveEvent(const AAFwk::Want &want);
    bool UpdateBlacklist() const;
    bool UpdateBlacklistInner(cJSON *root) const;
    bool CheckBlacklist(std::string bundleName, uint32_t versionCode);

private:
    class ParamCommonEventSubscriber : public EventFwk::CommonEventSubscriber {
    public:
        explicit ParamCommonEventSubscriber(const EventFwk::CommonEventSubscribeInfo &subscriberInfo,
            ParamCommonEvent &registry)
            : CommonEventSubscriber(subscriberInfo), registry_(registry)
        {}
        ~ParamCommonEventSubscriber() = default;

        void OnReceiveEvent(const EventFwk::CommonEventData &data) override
        {
            registry_.OnReceiveEvent(data.GetWant());
        }

    private:
        ParamCommonEvent &registry_;
    };
    using EventHandle = std::function<void(const OHOS::AAFwk::Want &)>;
    void HandleParamUpdate(const AAFwk::Want &want) const;
    typedef void (ParamCommonEvent::*HandleEventFunc)(const AAFwk::Want &) const;
    std::map<std::string, EventHandle> eventHandles_;
    std::map<std::string, HandleEventFunc> handleEventFunc_;
    std::shared_ptr<ParamCommonEventSubscriber> subscriber_ = nullptr;
    mutable std::unordered_map<std::string, std::vector<std::pair<uint32_t, uint32_t>>> blackListMap_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif
