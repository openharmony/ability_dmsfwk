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

#ifndef MULTI_USER_MANAGER_TEST_H
#define MULTI_USER_MANAGER_TEST_H

#include "gtest/gtest.h"

#include "remote_on_listener_stub.h"

namespace OHOS {
namespace DistributedSchedule {
class MultiUserManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

class RemoteOnListenerStubTest : public AAFwk::RemoteOnListenerStub {
public:
    void OnCallback(const uint32_t ContinueState, const std::string& srcDeviceId,
        const std::string &bundleName, const std::string &continueType, const std::string &srcBundleName) override;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // MULTI_USER_MANAGER_TEST_H