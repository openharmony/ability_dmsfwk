/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef OHOS_DMS_SA_CLIENT_TEST_H
#define OHOS_DMS_SA_CLIENT_TEST_H

#include "dms_sa_client.h"

#include <mutex>

#include "distributed_event_listener.h"
#include "dms_client.h"
#include "dms_handler.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "gtest/gtest.h"
#include "sam_log.h"
#include "system_ability_status_change_stub.h"
#include "system_ability_definition.h"

namespace OHOS {
namespace DistributedSchedule {
class DmsSaClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::shared_ptr<DmsSaClient> dmssaClient_;
    std::shared_ptr<DmsSystemAbilityStatusChange> dmsSaStatusChange_;
};

class IDSchedEventListenerTest : public IDSchedEventListener {
public:
    IDSchedEventListenerTest() = default;
    ~IDSchedEventListenerTest() = default;
    void DSchedEventNotify(EventNotify &notify) override;
    sptr<IRemoteObject> AsObject() override;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DMS_SA_CLIENT_TEST_H