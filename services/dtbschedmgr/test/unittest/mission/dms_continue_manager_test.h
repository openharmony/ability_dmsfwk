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

#ifndef SERVICES_DTBSCHEDMGR_TEST_UNITTEST_MISSION_DMS_CONTINUE_MANAGER_TEST_H
#define SERVICES_DTBSCHEDMGR_TEST_UNITTEST_MISSION_DMS_CONTINUE_MANAGER_TEST_H

#include "gtest/gtest.h"

#include "remote_on_listener_stub.h"

namespace OHOS {
namespace DistributedSchedule {
class DMSContinueManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

class RemoteOnListenerStubTest : public AAFwk::RemoteOnListenerStub {
public:
    void OnCallback(const uint32_t ContinueState, const std::string& srcDeviceId,
        const std::string& bundleName) override;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif /* SERVICES_DTBSCHEDMGR_TEST_UNITTEST_MISSION_DMS_CONTINUE_MANAGER_TEST_H */