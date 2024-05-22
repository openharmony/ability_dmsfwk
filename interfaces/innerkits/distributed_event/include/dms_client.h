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

#ifndef OHOS_DMS_CLIENT_H
#define OHOS_DMS_CLIENT_H

#include <string>

#include "ability_manager_errors.h"
#include "distributed_event_listener.h"
#include "iremote_broker.h"

namespace OHOS {
namespace DistributedSchedule {
class ContinueInfo {
public:
    std::string srcNetworkId_;
    std::string dstNetworkId_;
};

class DistributedClient {
public:
    int32_t RegisterDSchedEventListener(const uint8_t& type, const sptr<IDSchedEventListener>& obj);
    int32_t UnRegisterDSchedEventListener(const uint8_t& type, const sptr<IDSchedEventListener>& obj);
    int32_t GetContinueInfo(ContinueInfo &continueInfo);
    enum {
        REGISTER_DSCHED_EVENT_LISTENER = 262,
        UNREGISTER_DSCHED_EVENT_LISTENER = 263,
        GET_CONTINUE_INFO = 264,
    };
private:
    sptr<IRemoteObject> GetDmsProxy();
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif