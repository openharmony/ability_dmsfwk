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

#include "app_connection_stub_test.h"
#include "mock_remote_stub.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::u16string MOCK_INVALID_DESCRIPTOR = u"invalid descriptor";
}

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
    int32_t OnDeviceDisconnect(int32_t token, const std::vector<ContinuationResult>& continuationResults) override;
    int32_t OnDeviceCancel() override;
};

void MockDmsNotifier::DeviceOnlineNotify(const std::string& deviceId)
{
}

void MockDmsNotifier::DeviceOfflineNotify(const std::string& deviceId)
{
}

void MockDmsNotifier::ProcessNotifierDied(const sptr<IRemoteObject>& notifier)
{
}

void MockDmsNotifier::ScheduleStartDeviceManager(const sptr<IRemoteObject>& appProxy, int32_t token,
    const std::shared_ptr<ContinuationExtraParams>& continuationExtraParams)
{
}

int32_t MockDmsNotifier::OnDeviceConnect(int32_t token, const std::vector<ContinuationResult>& continuationResults)
{
    return 0;
}

int32_t MockDmsNotifier::OnDeviceDisconnect(int32_t token, const std::vector<ContinuationResult>& continuationResults)
{
    return 0;
}

int32_t MockDmsNotifier::OnDeviceCancel()
{
    return 0;
}

void AppConnectionStubTest::SetUpTestCase()
{
    DTEST_LOG << "AppConnectionStubTest::SetUpTestCase" << std::endl;
}

void AppConnectionStubTest::TearDownTestCase()
{
    DTEST_LOG << "AppConnectionStubTest::TearDownTestCase" << std::endl;
}

void AppConnectionStubTest::TearDown()
{
    DTEST_LOG << "AppConnectionStubTest::TearDown" << std::endl;
}

void AppConnectionStubTest::SetUp()
{
    sptr<DmsNotifier> dmsNotifier(new MockDmsNotifier());
    int32_t token = 0;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams = std::make_shared<ContinuationExtraParams>();
    appConnectionStub_ = new AppConnectionStub(dmsNotifier, token, continuationExtraParams);
    DTEST_LOG << "AppConnectionStubTest::SetUp" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_001
 * @tc.desc: invalid descriptor
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_001, TestSize.Level3)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_001 begin" << std::endl;
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    
    data.WriteInterfaceToken(MOCK_INVALID_DESCRIPTOR);
    int32_t result = appConnectionStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_STATE);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_001 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_002
 * @tc.desc: invalid element name
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_002, TestSize.Level3)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_002 begin" << std::endl;
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AppConnectionStub::GetDescriptor());
    int32_t result = appConnectionStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_002 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_003
 * @tc.desc: test connect done
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_003, TestSize.Level3)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_003 begin" << std::endl;
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AppConnectionStub::GetDescriptor());
    AppExecFwk::ElementName element;
    data.WriteParcelable(&element);
    code = AppConnectionStub::ON_ABILITY_CONNECT_DONE;
    int32_t result = appConnectionStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_INVALID_DATA);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_003 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_004
 * @tc.desc: test disconnect done
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_004, TestSize.Level3)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_004 begin" << std::endl;
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AppConnectionStub::GetDescriptor());
    AppExecFwk::ElementName element;
    data.WriteParcelable(&element);
    code = AppConnectionStub::ON_ABILITY_DISCONNECT_DONE;
    int32_t result = appConnectionStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_004 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_005
 * @tc.desc: invalid code
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_005, TestSize.Level3)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_005 begin" << std::endl;
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AppConnectionStub::GetDescriptor());
    AppExecFwk::ElementName element;
    data.WriteParcelable(&element);
    code = -1;
    int32_t result = appConnectionStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_NE(result, ERR_NONE);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_005 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_006
 * @tc.desc: test connect done
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_006, TestSize.Level3)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_006 begin" << std::endl;
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AppConnectionStub::GetDescriptor());
    AppExecFwk::ElementName element;
    data.WriteParcelable(&element);
    data.WriteRemoteObject((new MockRemoteStub())->AsObject());
    code = AppConnectionStub::ON_ABILITY_CONNECT_DONE;
    int32_t result = appConnectionStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_006 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_007
 * @tc.desc: nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_007, TestSize.Level3)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_007 begin" << std::endl;
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AppConnectionStub::GetDescriptor());
    AppExecFwk::ElementName element;
    data.WriteParcelable(&element);
    data.WriteRemoteObject((new MockRemoteStub())->AsObject());
    code = AppConnectionStub::ON_ABILITY_CONNECT_DONE;
    appConnectionStub_->dmsNotifier_ = nullptr;
    int32_t result = appConnectionStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_007 end" << std::endl;
}

/**
 * @tc.name: AppConnectionStubTest_008
 * @tc.desc: nullptr
 * @tc.type: FUNC
 */
HWTEST_F(AppConnectionStubTest, AppConnectionStubTest_008, TestSize.Level3)
{
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_008 begin" << std::endl;
    int32_t code = 0;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(AppConnectionStub::GetDescriptor());
    AppExecFwk::ElementName element;
    data.WriteParcelable(&element);
    code = AppConnectionStub::ON_ABILITY_DISCONNECT_DONE;
    appConnectionStub_->dmsNotifier_ = nullptr;
    int32_t result = appConnectionStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "AppConnectionStubTest AppConnectionStubTest_008 end" << std::endl;
}
}
}