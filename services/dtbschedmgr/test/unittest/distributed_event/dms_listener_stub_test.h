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

#ifndef OHOS_DMS_LISTENER_STUB_TEST_H
#define OHOS_DMS_LISTENER_STUB_TEST_H

#include "dms_listener_stub.h"

#include <cstdint>
#include <map>

#include "distributed_event_listener.h"
#include "dtbschedmgr_log.h"
#include "gtest/gtest.h"
#include "iremote_stub.h"
#include "message_parcel.h"
#include "refbase.h"
#include "sam_log.h"

namespace OHOS {
namespace DistributedSchedule {
class DSchedEventListenerStubTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    sptr<DSchedEventListenerStub> dschedeventlistenerStub_;
};

class DSchedEventListenerStubPub : public DSchedEventListenerStub {
public:
    void DSchedEventNotify(EventNotify &notify);
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DMS_LISTENER_STUB_TEST_H