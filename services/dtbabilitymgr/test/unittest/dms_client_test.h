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

#ifndef OHOS_DMS_CLIENT_TEST_H
#define OHOS_DMS_CLIENT_TEST_H

#include "dms_client.h"

#include <string>

#include "ability_manager_errors.h"
#include "distributed_event_listener.h"
#include "dms_sdk_demo.h"
#include "gtest/gtest.h"
#include "iremote_broker.h"


namespace OHOS {
namespace DistributedSchedule {
class DistributedClientTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

protected:
    DistributedClient distributedClient_;
};

class BusinessHandlerTest : public DSchedEventListenerStub {
public:
    BusinessHandlerTest() = default;
    ~BusinessHandlerTest() = default;

    void DSchedEventNotify(EventNotify &notify);
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DMS_CLIENT_TEST_H