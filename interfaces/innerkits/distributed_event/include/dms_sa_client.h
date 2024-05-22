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

#ifndef OHOS_DMS_SA_CLIENT_H
#define OHOS_DMS_SA_CLIENT_H

#include <mutex>

#include "distributed_event_listener.h"
#include "dms_client.h"
#include "dms_handler.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "sam_log.h"
#include "system_ability_status_change_stub.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedSchedule {
class DmsSaClient : public SystemAbilityStatusChangeStub {
public:
    static DmsSaClient &GetInstance();
    bool SubscribeDmsSA();
    int32_t AddDSchedEventListener(const uint8_t& type, const sptr<IDSchedEventListener>& listener);
    int32_t DelDSchedEventListener(const uint8_t& type, const sptr<IDSchedEventListener>& listener);
    int32_t GetContinueInfo(ContinueInfo &continueInfo);
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
private:
    DmsSaClient() {};
    ~DmsSaClient() {};
    bool hasSubscribeDmsSA_ = false;
    OHOS::sptr<ISystemAbilityManager> saMgrProxy_;
    std::map<uint8_t, sptr<IDSchedEventListener>> listeners_;
    std::mutex eventMutex_;
};

class DmsSystemAbilityStatusChange : public SystemAbilityStatusChangeStub {
public:
    DmsSystemAbilityStatusChange();
    ~DmsSystemAbilityStatusChange();
    void OnAddSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
    void OnRemoveSystemAbility(int32_t systemAbilityId, const std::string& deviceId) override;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif