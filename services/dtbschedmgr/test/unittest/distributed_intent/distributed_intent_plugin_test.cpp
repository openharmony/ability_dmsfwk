/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <gmock/gmock.h>

#include "distributed_intent_error_code.h"
#include "distributed_intent_plugin.h"
#include "distributed_intent_provider_mock.h"
#include "test_log.h"
#include "want.h"

#define private public
#include "distributed_intent_dsoftbus_adapter.h"
#include "intent_permission_checker.h"
#include "remote_intent_manager.h"
#undef private

#include "distributed_intent_dsoftbus_adapter_mock.h"
#include "dtbschedmgr_device_info_storage_mock.h"
#include "softbus_mock.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace DistributedSchedule {

namespace {
const std::string DEVICE_ID = "device_id_12345";
}

class DistributedIntentPluginTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

protected:
    std::shared_ptr<MockIntentProvider> providerMock_;
    std::shared_ptr<DistributedIntentDsoftbusAdapterMock> adapterMock_;
    std::shared_ptr<DtbschedmgrDeviceInfoStorageMock> deviceInfoMock_;
    std::shared_ptr<SoftbusMock> softbusMock_;
};

void DistributedIntentPluginTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedIntentPluginTest::SetUpTestCase" << std::endl;
}

void DistributedIntentPluginTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedIntentPluginTest::TearDownTestCase" << std::endl;
}

void DistributedIntentPluginTest::SetUp()
{
    DTEST_LOG << "DistributedIntentPluginTest::SetUp" << std::endl;
    providerMock_ = std::make_shared<MockIntentProvider>();
    adapterMock_ = std::make_shared<DistributedIntentDsoftbusAdapterMock>();
    IDistributedIntentDsoftbusAdapter::adapterMock = adapterMock_;
    deviceInfoMock_ = std::make_shared<DtbschedmgrDeviceInfoStorageMock>();
    IDtbschedmgrDeviceInfoStorage::storageMock = deviceInfoMock_;
    softbusMock_ = std::make_shared<SoftbusMock>();
    ISoftbusInterface::softbusMock = softbusMock_;
}

void DistributedIntentPluginTest::TearDown()
{
    DTEST_LOG << "DistributedIntentPluginTest::TearDown" << std::endl;
    IntentPermissionChecker::GetInstance().SetProvider(nullptr);
    IDistributedIntentDsoftbusAdapter::adapterMock = nullptr;
    IDtbschedmgrDeviceInfoStorage::storageMock = nullptr;
    ISoftbusInterface::softbusMock = nullptr;
    providerMock_ = nullptr;
    adapterMock_ = nullptr;
    deviceInfoMock_ = nullptr;
    softbusMock_ = nullptr;
}

/**
 * @tc.name: CreateIntentPlugin_NullProvider_001
 * @tc.desc: Test CreateIntentPlugin with null provider returns nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentPluginTest, CreateIntentPlugin_NullProvider, TestSize.Level3)
{
    void* result = CreateIntentPlugin(nullptr);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: CreateIntentPlugin_Success_001
 * @tc.desc: Test CreateIntentPlugin with valid provider returns non-null plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentPluginTest, CreateIntentPlugin_Success, TestSize.Level3)
{
    IIntentPlugin* plugin = static_cast<IIntentPlugin*>(
        CreateIntentPlugin(providerMock_.get()));
    EXPECT_NE(plugin, nullptr);
    delete plugin;
}

/**
 * @tc.name: OnDeviceOffline_NoSessions_001
 * @tc.desc: Test OnDeviceOffline when no sessions exist for the device
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentPluginTest, OnDeviceOffline_NoSessions, TestSize.Level3)
{
    IIntentPlugin* plugin = static_cast<IIntentPlugin*>(
        CreateIntentPlugin(providerMock_.get()));
    ASSERT_NE(plugin, nullptr);

    EXPECT_CALL(*adapterMock_, ForceCleanupDeviceSessions(_, _))
        .WillOnce(Invoke([](const std::string& deviceId, std::vector<int32_t>& closedSockets) {
            closedSockets.clear();
        }));

    EXPECT_NO_FATAL_FAILURE(plugin->OnDeviceOffline(DEVICE_ID));
    delete plugin;
}

/**
 * @tc.name: GetSocketListener_NotNull_001
 * @tc.desc: Test GetSocketListener returns non-null listener for valid plugin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentPluginTest, GetSocketListener_NotNull, TestSize.Level3)
{
    IIntentPlugin* plugin = static_cast<IIntentPlugin*>(
        CreateIntentPlugin(providerMock_.get()));
    ASSERT_NE(plugin, nullptr);

    IIntentSocketEventListener* listener = plugin->GetSocketListener();
    EXPECT_NE(listener, nullptr);
    delete plugin;
}

} // namespace DistributedSchedule
} // namespace OHOS
