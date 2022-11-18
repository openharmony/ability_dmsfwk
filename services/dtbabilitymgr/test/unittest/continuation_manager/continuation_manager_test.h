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

#ifndef OHOS_DISTRIBUTED_ABILITY_MANAGER_CONTINUATION_MANAGER_TEST_H
#define OHOS_DISTRIBUTED_ABILITY_MANAGER_CONTINUATION_MANAGER_TEST_H

#include "gtest/gtest.h"

#include "device_selection_notifier_stub.h"
#define private public
#include "continuation_manager/app_device_callback_stub.h"
#include "continuation_manager/device_selection_notifier_proxy.h"
#include "distributed_ability_manager_service.h"
#undef private

namespace OHOS {
namespace DistributedSchedule {
class ContinuationManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    sptr<DistributedAbilityManagerService> dtbabilitymgrService_;
};

class DeviceSelectionNotifierTest : public DeviceSelectionNotifierStub {
public:
    DeviceSelectionNotifierTest() = default;
    ~DeviceSelectionNotifierTest() = default;

    void OnDeviceConnect(const std::vector<ContinuationResult>& continuationResults) override;
    void OnDeviceDisconnect(const std::vector<std::string>& deviceIds) override;
};

class MockDmsNotifier : public DmsNotifier {
public:
    MockDmsNotifier() = default;
    ~MockDmsNotifier() = default;

    void DeviceOnlineNotify(const std::string& deviceId) override;
    void DeviceOfflineNotify(const std::string& deviceId) override;
    void ProcessNotifierDied(const sptr<IRemoteObject>& notifier) override;
    void ScheduleStartDeviceManager(const sptr<IRemoteObject>& appProxy, int32_t token,
        const std::shared_ptr<ContinuationExtraParams>& continuationExtraParams = nullptr) override;
    int32_t OnDeviceConnect(int32_t token, const std::vector<ContinuationResult>& continuationResults) override;
    int32_t OnDeviceDisconnect(int32_t token, const std::vector<std::string>& deviceIds) override;
    int32_t OnDeviceCancel() override;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // OHOS_DISTRIBUTED_ABILITY_MANAGER_CONTINUATION_MANAGER_TEST_H