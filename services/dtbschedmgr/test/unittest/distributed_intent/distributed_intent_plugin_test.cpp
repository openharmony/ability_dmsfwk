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
#include "parcel.h"
#include "message_option.h"
#include "distributedsched_ipc_interface_code.h"
#include "mock_remote_stub.h"

#define private public
#include "distributed_intent_dsoftbus_adapter.h"
#include "distributed_intent_service_stub.h"
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
const std::string DST_DEVICE_ID = "dst_device_id_67890";
const std::string BUNDLE_NAME = "com.test.bundle";
const std::string ABILITY_NAME = "MainAbility";
const std::string RESULT_MSG = "test_result";
const std::u16string INTENT_SERVICE_INTERFACE_TOKEN = u"ohos.distributedschedule.IDistributedIntentService";
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

/**
 * @tc.name: OnRemoteRequest_LazyInit_001
 * @tc.desc: Test OnRemoteRequest lazily initializes intentService_ (nullptr branch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentPluginTest, OnRemoteRequest_LazyInit, TestSize.Level3)
{
    IIntentPlugin* plugin = static_cast<IIntentPlugin*>(
        CreateIntentPlugin(providerMock_.get()));
    ASSERT_NE(plugin, nullptr);

    EXPECT_CALL(*adapterMock_, ForceCleanupDeviceSessions(_, _))
        .WillRepeatedly(Invoke([](const std::string&, std::vector<int32_t>& closed) {
            closed.clear();
        }));

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);

    int32_t result = plugin->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data, reply, option);
    EXPECT_NE(result, ERR_OK);

    MessageParcel data2;
    MessageParcel reply2;
    MessageOption option2;
    data2.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    int32_t result2 = plugin->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::START_REMOTE_INTENT), data2, reply2, option2);
    EXPECT_NE(result2, ERR_OK);

    delete plugin;
}

/**
 * @tc.name: OnRemoteRequest_InvalidCode_001
 * @tc.desc: Test OnRemoteRequest with unknown code after lazy init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentPluginTest, OnRemoteRequest_InvalidCode, TestSize.Level3)
{
    IIntentPlugin* plugin = static_cast<IIntentPlugin*>(
        CreateIntentPlugin(providerMock_.get()));
    ASSERT_NE(plugin, nullptr);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);

    int32_t result = plugin->OnRemoteRequest(9999, data, reply, option);
    EXPECT_NE(result, ERR_OK);

    delete plugin;
}

/**
 * @tc.name: StartRemoteIntent_LazyInit_001
 * @tc.desc: Test StartRemoteIntent lazily initializes intentService_ (nullptr branch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentPluginTest, StartRemoteIntent_LazyInit, TestSize.Level3)
{
    IIntentPlugin* plugin = static_cast<IIntentPlugin*>(
        CreateIntentPlugin(providerMock_.get()));
    ASSERT_NE(plugin, nullptr);

    EXPECT_CALL(*deviceInfoMock_, GetLocalDeviceId(_))
        .WillRepeatedly(Return(false));

    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = 1000;
    sptr<IRemoteObject> callback = nullptr;

    int32_t result = plugin->StartRemoteIntent(want, callerInfo, callback);
    EXPECT_NE(result, ERR_OK);

    EXPECT_CALL(*deviceInfoMock_, GetLocalDeviceId(_))
        .WillRepeatedly(Return(false));

    int32_t result2 = plugin->StartRemoteIntent(want, callerInfo, callback);
    EXPECT_NE(result2, ERR_OK);

    delete plugin;
}

/**
 * @tc.name: StartRemoteIntent_WithCallback_001
 * @tc.desc: Test StartRemoteIntent with non-null callback (non-null intentService_ branch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentPluginTest, StartRemoteIntent_WithCallback, TestSize.Level3)
{
    IIntentPlugin* plugin = static_cast<IIntentPlugin*>(
        CreateIntentPlugin(providerMock_.get()));
    ASSERT_NE(plugin, nullptr);

    EXPECT_CALL(*deviceInfoMock_, GetLocalDeviceId(_))
        .WillRepeatedly(DoAll(SetArgReferee<0>("local_device_id"), Return(true)));

    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = 1000;
    callerInfo.requestCode = 100;
    callerInfo.accessToken = 200;
    sptr<IRemoteObject> callback = new MockRemoteStub();

    int32_t result = plugin->StartRemoteIntent(want, callerInfo, callback);
    EXPECT_NE(result, ERR_DI_PERMISSION_DENIED);

    delete plugin;
}

/**
 * @tc.name: SendIntentResult_LazyInit_001
 * @tc.desc: Test SendIntentResult lazily initializes intentService_ (nullptr branch)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentPluginTest, SendIntentResult_LazyInit, TestSize.Level3)
{
    IIntentPlugin* plugin = static_cast<IIntentPlugin*>(
        CreateIntentPlugin(providerMock_.get()));
    ASSERT_NE(plugin, nullptr);

    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = 1000;
    callerInfo.requestCode = 100;

    int32_t result = plugin->SendIntentResult(want, callerInfo, RESULT_MSG);
    EXPECT_NE(result, ERR_OK);

    int32_t result2 = plugin->SendIntentResult(want, callerInfo, RESULT_MSG);
    EXPECT_NE(result2, ERR_OK);

    delete plugin;
}

/**
 * @tc.name: SendIntentResult_EmptyMsg_001
 * @tc.desc: Test SendIntentResult with empty resultMsg after lazy init
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentPluginTest, SendIntentResult_EmptyMsg, TestSize.Level3)
{
    IIntentPlugin* plugin = static_cast<IIntentPlugin*>(
        CreateIntentPlugin(providerMock_.get()));
    ASSERT_NE(plugin, nullptr);

    OHOS::AAFwk::Want want;
    IntentCallerInfo callerInfo;
    std::string emptyMsg;

    int32_t result = plugin->SendIntentResult(want, callerInfo, emptyMsg);
    EXPECT_NE(result, ERR_OK);

    delete plugin;
}

/**
 * @tc.name: CrossMethod_LazyInit_001
 * @tc.desc: Test that intentService_ created by one method is reused by another
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentPluginTest, CrossMethod_LazyInit, TestSize.Level3)
{
    IIntentPlugin* plugin = static_cast<IIntentPlugin*>(
        CreateIntentPlugin(providerMock_.get()));
    ASSERT_NE(plugin, nullptr);

    EXPECT_CALL(*deviceInfoMock_, GetLocalDeviceId(_))
        .WillRepeatedly(Return(false));

    OHOS::AAFwk::Want want;
    want.SetElementName(DST_DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentCallerInfo callerInfo;
    callerInfo.callerUid = 1000;
    sptr<IRemoteObject> callback = nullptr;

    int32_t result = plugin->StartRemoteIntent(want, callerInfo, callback);
    EXPECT_NE(result, ERR_OK);

    int32_t result2 = plugin->SendIntentResult(want, callerInfo, RESULT_MSG);
    EXPECT_NE(result2, ERR_OK);

    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(INTENT_SERVICE_INTERFACE_TOKEN);
    int32_t result3 = plugin->OnRemoteRequest(
        static_cast<uint32_t>(IDSchedInterfaceCode::SEND_INTENT_RESULT), data, reply, option);
    EXPECT_NE(result3, ERR_OK);

    delete plugin;
}

} // namespace DistributedSchedule
} // namespace OHOS
