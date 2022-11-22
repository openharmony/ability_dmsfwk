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

#include "continuation_manager_test.h"

#include "distributed_ability_manager_client.h"
#include "dtbschedmgr_log.h"
#include "mock_remote_stub.h"
#include "test_log.h"

namespace OHOS {
namespace DistributedSchedule {
using namespace std;
using namespace testing;
using namespace testing::ext;
namespace {
constexpr int32_t DISTRIBUTED_SCHED_SA_ID = 1401;
constexpr int32_t INVALID_LEN = -1;
constexpr int32_t UNREGISTER_TOKEN = 10000;
constexpr int32_t TEST_TOKEN = 1000;
constexpr int32_t TEST_ACCESS_TOKEN = 10000000;
constexpr int32_t ERROR_CONNECT_STATUS = 10;
constexpr int32_t ERROR_CONTINUATION_MODE = 10;
constexpr uint32_t SELECTED_DEVICE_SIZE = 2;
constexpr uint32_t UNSELECTED_DEVICE_SIZE = 3;
const std::string TEST_DEVICE_ID = "test deviceId";
const std::string EMPTY_DEVICE_ID = "";
const std::string CALLBACK_TYPE1 = "deviceConnect";
const std::string CALLBACK_TYPE2 = "deviceDisconnect";
const std::string INVALID_CALLBACK_TYPE = "deviceCancel";
const std::string SELECTED_DEVICE_ID1 = "selected deviceId1";
const std::string SELECTED_DEVICE_ID2 = "selected deviceId2";
const std::string SELECTED_DEVICE_ID3 = "selected deviceId3";
const std::string SELECTED_DEVICE_TYPE1 = "selected deviceType1";
const std::string SELECTED_DEVICE_TYPE2 = "selected deviceType2";
const std::string SELECTED_DEVICE_NAME1 = "selected deviceName1";
const std::string SELECTED_DEVICE_NAME2 = "selected deviceName2";
const std::string UNSELECTED_DEVICE_ID1 = "unselected deviceId1";
const std::string UNSELECTED_DEVICE_ID2 = "unselected deviceId2";
const std::string UNSELECTED_DEVICE_ID3 = "unselected deviceId3";
const std::string TEST_DEVICE_TYPE = "test deviceType";
const std::string TEST_TARGETBUNDLE = "test targetBundle";
const std::string TEST_DESCRIPTION = "test description";
const std::string TEST_FILTER = "test filter";
const std::string TEST_AUTHINFO = "test authInfo";
const std::u16string TEST_INPUT1 = u"test input1";
const std::u16string TEST_INPUT2 = u"test input2";
const std::u16string TEST_INVALID_REMOTEDESCRIPTOR = u"invalid remoteDescriptor";
const std::string TEST_INPUT3 = "test input1";
const std::string TEST_INPUT4 = "test input2";
const std::uint32_t INVALID_EVENT_DEVICE_CODE = 0;
}

void DeviceSelectionNotifierTest::OnDeviceConnect(const std::vector<ContinuationResult>& continuationResults)
{
    EXPECT_EQ(SELECTED_DEVICE_SIZE, continuationResults.size());
    for (size_t i = 0; i < continuationResults.size(); ++i) {
        DTEST_LOG << "DeviceSelectionNotifierTest::OnDeviceConnect selected deviceId:"<<
            continuationResults[i].GetDeviceId() << std::endl;
        DTEST_LOG << "DeviceSelectionNotifierTest::OnDeviceConnect selected deviceType:" <<
            continuationResults[i].GetDeviceType() << std::endl;
        DTEST_LOG << "DeviceSelectionNotifierTest::OnDeviceConnect selected deviceNane:" <<
            continuationResults[i].GetDeviceName() << std::endl;
    }
}

void DeviceSelectionNotifierTest::OnDeviceDisconnect(const std::vector<std::string>& deviceIds)
{
    EXPECT_EQ(UNSELECTED_DEVICE_SIZE, deviceIds.size());
    for (size_t i = 0; i < deviceIds.size(); ++i) {
        DTEST_LOG << "DeviceSelectionNotifierTest::OnDeviceDisconnect unselected deviceId:"<<
            deviceIds[i] << std::endl;
	}
}
			
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

int32_t MockDmsNotifier::OnDeviceDisconnect(int32_t token, const std::vector<std::string>& deviceIds)
{
    return 0;
}

int32_t MockDmsNotifier::OnDeviceCancel()
{
    return 0;
}

void ContinuationManagerTest::SetUpTestCase()
{
    DTEST_LOG << "ContinuationManagerTest::SetUpTestCase" << std::endl;
}

void ContinuationManagerTest::TearDownTestCase()
{
    DTEST_LOG << "ContinuationManagerTest::TearDownTestCase" << std::endl;
}

void ContinuationManagerTest::SetUp()
{
    dtbabilitymgrService_ = new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    DTEST_LOG << "ContinuationManagerTest::SetUp" << std::endl;
}

void ContinuationManagerTest::TearDown()
{
    DTEST_LOG << "ContinuationManagerTest::TearDown" << std::endl;
}

/**
 * @tc.name: RegisterTest_001
 * @tc.desc: test register token
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterTest_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterTest_001 start" << std::endl;
    int32_t token1 = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token1);
    DTEST_LOG << "result1:" << result1 << std::endl;
    int32_t token2 = -1;
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token2);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(ERR_OK, result2);
    EXPECT_EQ(1, token2 - token1);
    DTEST_LOG << "ContinuationManagerTest RegisterTest_001 end" << std::endl;
}

/**
 * @tc.name: RegisterTest_002
 * @tc.desc: test register token with extra param
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterTest_002, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterTest_002 start" << std::endl;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams =
        std::make_shared<ContinuationExtraParams>();
    int32_t token1 = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(continuationExtraParams, token1);
    DTEST_LOG << "result1:" << result1 << std::endl;
    int32_t token2 = -1;
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().Register(continuationExtraParams, token2);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(ERR_OK, result2);
    EXPECT_EQ(1, token2 - token1);
    DTEST_LOG << "ContinuationManagerTest RegisterTest_002 end" << std::endl;
}

/**
 * @tc.name: UnregisterTest_001
 * @tc.desc: test unregister token
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, UnregisterTest_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest UnregisterTest_001 start" << std::endl;
    int32_t token = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().Unregister(token);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(ERR_OK, result2);
    DTEST_LOG << "ContinuationManagerTest UnregisterTest_001 end" << std::endl;
}

/**
 * @tc.name: UnregisterTest_002
 * @tc.desc: test unregister token with invalid token
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, UnregisterTest_002, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest UnregisterTest_002 start" << std::endl;
    int32_t result = DistributedAbilityManagerClient::GetInstance().Unregister(UNREGISTER_TOKEN);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(TOKEN_HAS_NOT_REGISTERED, result);
    DTEST_LOG << "ContinuationManagerTest UnregisterTest_002 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackTest_001
 * @tc.desc: test register device selection callback
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterDeviceSelectionCallbackTest_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_001 start" << std::endl;
    int32_t token = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().RegisterDeviceSelectionCallback(
        token, CALLBACK_TYPE1, notifier);
    DTEST_LOG << "result2:" << result2 << std::endl;
    int32_t result3 = DistributedAbilityManagerClient::GetInstance().RegisterDeviceSelectionCallback(
        token, CALLBACK_TYPE2, notifier);
    DTEST_LOG << "result3:" << result3 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(ERR_OK, result2);
    EXPECT_EQ(ERR_OK, result3);
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_001 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackTest_002
 * @tc.desc: test register device selection callback with invalid token
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterDeviceSelectionCallbackTest_002, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_002 start" << std::endl;
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().RegisterDeviceSelectionCallback(
        UNREGISTER_TOKEN, CALLBACK_TYPE1, notifier);
    DTEST_LOG << "result1:" << result1 << std::endl;
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().RegisterDeviceSelectionCallback(
        UNREGISTER_TOKEN, CALLBACK_TYPE2, notifier);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(TOKEN_HAS_NOT_REGISTERED, result1);
    EXPECT_EQ(TOKEN_HAS_NOT_REGISTERED, result2);
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_002 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackTest_003
 * @tc.desc: test register device selection callback with invalid callback type
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterDeviceSelectionCallbackTest_003, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_003 start" << std::endl;
    int32_t token = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().RegisterDeviceSelectionCallback(
        token, INVALID_CALLBACK_TYPE, notifier);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(UNKNOWN_CALLBACK_TYPE, result2);
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_003 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackTest_004
 * @tc.desc: test dms deviceConnect callback called when device selection callback has registered.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterDeviceSelectionCallbackTest_004, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_004 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    int32_t token = -1;
    int32_t result1 = dtbabilitymgrService_->Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    int32_t result2 = dtbabilitymgrService_->RegisterDeviceSelectionCallback(
        token, CALLBACK_TYPE1, notifier);
    DTEST_LOG << "result2:" << result2 << std::endl;
    std::vector<ContinuationResult> continuationResults;
    ContinuationResult continuationResult1;
    continuationResult1.SetDeviceId(SELECTED_DEVICE_ID1);
    continuationResult1.SetDeviceType(SELECTED_DEVICE_TYPE1);
    continuationResult1.SetDeviceName(SELECTED_DEVICE_NAME1);
    ContinuationResult continuationResult2;
    continuationResult2.SetDeviceId(SELECTED_DEVICE_ID2);
    continuationResult2.SetDeviceType(SELECTED_DEVICE_TYPE2);
    continuationResult2.SetDeviceName(SELECTED_DEVICE_NAME2);
    continuationResults.emplace_back(continuationResult1);
    continuationResults.emplace_back(continuationResult2);
    int32_t result3 = dtbabilitymgrService_->OnDeviceConnect(token, continuationResults);
    DTEST_LOG << "result3:" << result3 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(ERR_OK, result2);
    EXPECT_EQ(DISCONNECT_ABILITY_FAILED, result3);
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_004 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackTest_005
 * @tc.desc: test dms deviceConnect callback called when device selection callback has not registered.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterDeviceSelectionCallbackTest_005, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_005 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    int32_t token = -1;
    int32_t result1 = dtbabilitymgrService_->Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    int32_t result2 = dtbabilitymgrService_->RegisterDeviceSelectionCallback(
        token, CALLBACK_TYPE2, notifier);
    DTEST_LOG << "result2:" << result2 << std::endl;
    std::vector<ContinuationResult> continuationResults;
    ContinuationResult continuationResult1;
    continuationResult1.SetDeviceId(SELECTED_DEVICE_ID1);
    continuationResult1.SetDeviceType(SELECTED_DEVICE_TYPE1);
    continuationResult1.SetDeviceName(SELECTED_DEVICE_NAME1);
    ContinuationResult continuationResult2;
    continuationResult2.SetDeviceId(SELECTED_DEVICE_ID2);
    continuationResult2.SetDeviceType(SELECTED_DEVICE_TYPE2);
    continuationResult2.SetDeviceName(SELECTED_DEVICE_NAME2);
    continuationResults.emplace_back(continuationResult1);
    continuationResults.emplace_back(continuationResult2);
    int32_t result3 = dtbabilitymgrService_->OnDeviceConnect(token, continuationResults);
    DTEST_LOG << "result3:" << result3 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(ERR_OK, result2);
    EXPECT_EQ(DISCONNECT_ABILITY_FAILED, result3);
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_005 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackTest_006
 * @tc.desc: test dms deviceDisconnect callback called when device selection callback has registered.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterDeviceSelectionCallbackTest_006, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_006 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    int32_t token = -1;
    int32_t result1 = dtbabilitymgrService_->Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    int32_t result2 = dtbabilitymgrService_->RegisterDeviceSelectionCallback(
        token, CALLBACK_TYPE2, notifier);
    DTEST_LOG << "result2:" << result2 << std::endl;
    std::vector<std::string> deviceIds;
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID1);
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID2);
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID3);
    int32_t result3 = dtbabilitymgrService_->OnDeviceDisconnect(token, deviceIds);
    DTEST_LOG << "result3:" << result3 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(ERR_OK, result2);
    EXPECT_EQ(DISCONNECT_ABILITY_FAILED, result3);
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_006 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackTest_007
 * @tc.desc: test dms deviceDisconnect callback called when device selection callback has not registered.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterDeviceSelectionCallbackTest_007, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_007 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    int32_t token = -1;
    int32_t result1 = dtbabilitymgrService_->Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    int32_t result2 = dtbabilitymgrService_->RegisterDeviceSelectionCallback(
        token, CALLBACK_TYPE1, notifier);
    DTEST_LOG << "result2:" << result2 << std::endl;
    std::vector<std::string> deviceIds;
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID1);
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID2);
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID3);
    int32_t result3 = dtbabilitymgrService_->OnDeviceDisconnect(token, deviceIds);
    DTEST_LOG << "result3:" << result3 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(ERR_OK, result2);
    EXPECT_EQ(DISCONNECT_ABILITY_FAILED, result3);
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_007 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackTest_008
 * @tc.desc: test dms callback called when device selection callback has not registered.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterDeviceSelectionCallbackTest_008, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_008 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    int32_t token = -1;
    int32_t result1 = dtbabilitymgrService_->Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    std::vector<ContinuationResult> continuationResults;
    ContinuationResult continuationResult1;
    continuationResult1.SetDeviceId(SELECTED_DEVICE_ID1);
    continuationResult1.SetDeviceType(SELECTED_DEVICE_TYPE1);
    continuationResult1.SetDeviceName(SELECTED_DEVICE_NAME1);
    ContinuationResult continuationResult2;
    continuationResult2.SetDeviceId(SELECTED_DEVICE_ID2);
    continuationResult2.SetDeviceType(SELECTED_DEVICE_TYPE2);
    continuationResult2.SetDeviceName(SELECTED_DEVICE_NAME2);
    continuationResults.emplace_back(continuationResult1);
    continuationResults.emplace_back(continuationResult2);
    int32_t result2 = dtbabilitymgrService_->OnDeviceConnect(token, continuationResults);
    DTEST_LOG << "result2:" << result2 << std::endl;
    std::vector<std::string> deviceIds;
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID1);
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID2);
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID3);
    int32_t result3 = dtbabilitymgrService_->OnDeviceDisconnect(token, deviceIds);
    DTEST_LOG << "result3:" << result3 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(DISCONNECT_ABILITY_FAILED, result2);
    EXPECT_EQ(DISCONNECT_ABILITY_FAILED, result3);
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_008 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackTest_009
 * @tc.desc: test dms callback called when token has not registered.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterDeviceSelectionCallbackTest_009, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_009 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    int32_t result1 = dtbabilitymgrService_->RegisterDeviceSelectionCallback(
        UNREGISTER_TOKEN, CALLBACK_TYPE1, notifier);
    DTEST_LOG << "result1:" << result1 << std::endl;
    int32_t result2 = dtbabilitymgrService_->RegisterDeviceSelectionCallback(
        UNREGISTER_TOKEN, CALLBACK_TYPE2, notifier);
    DTEST_LOG << "result2:" << result2 << std::endl;
    std::vector<ContinuationResult> continuationResults;
    ContinuationResult continuationResult1;
    continuationResult1.SetDeviceId(SELECTED_DEVICE_ID1);
    continuationResult1.SetDeviceType(SELECTED_DEVICE_TYPE1);
    continuationResult1.SetDeviceName(SELECTED_DEVICE_NAME1);
    ContinuationResult continuationResult2;
    continuationResult2.SetDeviceId(SELECTED_DEVICE_ID2);
    continuationResult2.SetDeviceType(SELECTED_DEVICE_TYPE2);
    continuationResult2.SetDeviceName(SELECTED_DEVICE_NAME2);
    continuationResults.emplace_back(continuationResult1);
    continuationResults.emplace_back(continuationResult2);
    int32_t result3 = dtbabilitymgrService_->OnDeviceConnect(
        UNREGISTER_TOKEN, continuationResults);
    DTEST_LOG << "result3:" << result3 << std::endl;
    std::vector<std::string> deviceIds;
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID1);
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID2);
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID3);
    int32_t result4 = dtbabilitymgrService_->OnDeviceDisconnect(UNREGISTER_TOKEN, deviceIds);
    DTEST_LOG << "result4:" << result4 << std::endl;
    EXPECT_EQ(TOKEN_HAS_NOT_REGISTERED, result1);
    EXPECT_EQ(TOKEN_HAS_NOT_REGISTERED, result2);
    EXPECT_EQ(DISCONNECT_ABILITY_FAILED, result3);
    EXPECT_EQ(DISCONNECT_ABILITY_FAILED, result4);
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_009 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackTest_010
 * @tc.desc: test dms callback called when token and device selection callback has not registered.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, RegisterDeviceSelectionCallbackTest_010, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_010 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::vector<ContinuationResult> continuationResults;
    ContinuationResult continuationResult1;
    continuationResult1.SetDeviceId(SELECTED_DEVICE_ID1);
    continuationResult1.SetDeviceType(SELECTED_DEVICE_TYPE1);
    continuationResult1.SetDeviceName(SELECTED_DEVICE_NAME1);
    ContinuationResult continuationResult2;
    continuationResult2.SetDeviceId(SELECTED_DEVICE_ID2);
    continuationResult2.SetDeviceType(SELECTED_DEVICE_TYPE2);
    continuationResult2.SetDeviceName(SELECTED_DEVICE_NAME2);
    continuationResults.emplace_back(continuationResult1);
    continuationResults.emplace_back(continuationResult2);
    int32_t result1 = dtbabilitymgrService_->OnDeviceConnect(
        UNREGISTER_TOKEN, continuationResults);
    DTEST_LOG << "result1:" << result1 << std::endl;
    std::vector<std::string> deviceIds;
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID1);
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID2);
    deviceIds.emplace_back(UNSELECTED_DEVICE_ID3);
    int32_t result2 = dtbabilitymgrService_->OnDeviceDisconnect(UNREGISTER_TOKEN, deviceIds);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(DISCONNECT_ABILITY_FAILED, result1);
    EXPECT_EQ(DISCONNECT_ABILITY_FAILED, result2);
    DTEST_LOG << "ContinuationManagerTest RegisterDeviceSelectionCallbackTest_010 end" << std::endl;
}

/**
 * @tc.name: UnregisterDeviceSelectionCallbackTest_001
 * @tc.desc: test unregister device selection callback
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, UnregisterDeviceSelectionCallbackTest_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest UnregisterDeviceSelectionCallbackTest_001 start" << std::endl;
    int32_t token = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().RegisterDeviceSelectionCallback(
        token, CALLBACK_TYPE1, notifier);
    DTEST_LOG << "result2:" << result2 << std::endl;
    int32_t result3 = DistributedAbilityManagerClient::GetInstance().RegisterDeviceSelectionCallback(
        token, CALLBACK_TYPE2, notifier);
    DTEST_LOG << "result3:" << result3 << std::endl;
    int32_t result4 = DistributedAbilityManagerClient::GetInstance().UnregisterDeviceSelectionCallback(
        token, CALLBACK_TYPE1);
    DTEST_LOG << "result4:" << result4 << std::endl;
    int32_t result5 = DistributedAbilityManagerClient::GetInstance().UnregisterDeviceSelectionCallback(
        token, CALLBACK_TYPE2);
    DTEST_LOG << "result5:" << result5 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(ERR_OK, result2);
    EXPECT_EQ(ERR_OK, result3);
    EXPECT_EQ(ERR_OK, result4);
    EXPECT_EQ(ERR_OK, result5);
    DTEST_LOG << "ContinuationManagerTest UnregisterDeviceSelectionCallbackTest_001 end" << std::endl;
}

/**
 * @tc.name: UnregisterDeviceSelectionCallbackTest_002
 * @tc.desc: test unregister device selection callback that has not been registered
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, UnregisterDeviceSelectionCallbackTest_002, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest UnregisterDeviceSelectionCallbackTest_002 start" << std::endl;
    int32_t token = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().UnregisterDeviceSelectionCallback(
        token, CALLBACK_TYPE1);
    DTEST_LOG << "result2:" << result2 << std::endl;
    int32_t result3 = DistributedAbilityManagerClient::GetInstance().UnregisterDeviceSelectionCallback(
        token, CALLBACK_TYPE2);
    DTEST_LOG << "result3:" << result3 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(CALLBACK_HAS_NOT_REGISTERED, result2);
    EXPECT_EQ(CALLBACK_HAS_NOT_REGISTERED, result3);
    DTEST_LOG << "ContinuationManagerTest UnregisterDeviceSelectionCallbackTest_002 end" << std::endl;
}

/**
 * @tc.name: UnregisterDeviceSelectionCallbackTest_003
 * @tc.desc: test register device selection callback with invalid token
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, UnregisterDeviceSelectionCallbackTest_003, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest UnregisterDeviceSelectionCallbackTest_003 start" << std::endl;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().UnregisterDeviceSelectionCallback(
        UNREGISTER_TOKEN, CALLBACK_TYPE1);
    DTEST_LOG << "result1:" << result1 << std::endl;
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().UnregisterDeviceSelectionCallback(
        UNREGISTER_TOKEN, CALLBACK_TYPE2);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(TOKEN_HAS_NOT_REGISTERED, result1);
    EXPECT_EQ(TOKEN_HAS_NOT_REGISTERED, result2);
    DTEST_LOG << "ContinuationManagerTest UnregisterDeviceSelectionCallbackTest_003 end" << std::endl;
}

/**
 * @tc.name: UnregisterDeviceSelectionCallbackTest_004
 * @tc.desc: test register device selection callback with invalid callback type
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, UnregisterDeviceSelectionCallbackTest_004, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest UnregisterDeviceSelectionCallbackTest_004 start" << std::endl;
    int32_t token = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().UnregisterDeviceSelectionCallback(
        token, INVALID_CALLBACK_TYPE);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(UNKNOWN_CALLBACK_TYPE, result2);
    DTEST_LOG << "ContinuationManagerTest UnregisterDeviceSelectionCallbackTest_004 end" << std::endl;
}

/**
 * @tc.name: StartDeviceManagerTest_001
 * @tc.desc: test start device manager
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, StartDeviceManagerTest_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest StartDeviceManagerTest_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    int32_t token = -1;
    int32_t result1 = dtbabilitymgrService_->Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    int32_t result2 = dtbabilitymgrService_->StartDeviceManager(token);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(CALLBACK_HAS_NOT_REGISTERED, result2);
    DTEST_LOG << "ContinuationManagerTest StartDeviceManagerTest_001 end" << std::endl;
}

/**
 * @tc.name: StartDeviceManagerTest_002
 * @tc.desc: test start device manager with extra param
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, StartDeviceManagerTest_002, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest StartDeviceManagerTest_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    int32_t token = -1;
    int32_t result1 = dtbabilitymgrService_->Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams =
        std::make_shared<ContinuationExtraParams>();
    int32_t result2 = dtbabilitymgrService_->StartDeviceManager(
        token, continuationExtraParams);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(CALLBACK_HAS_NOT_REGISTERED, result2);
    DTEST_LOG << "ContinuationManagerTest StartDeviceManagerTest_002 end" << std::endl;
}

/**
 * @tc.name: StartDeviceManagerTest_003
 * @tc.desc: test start device manager with invalid token
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, StartDeviceManagerTest_003, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest StartDeviceManagerTest_003 start" << std::endl;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().StartDeviceManager(UNREGISTER_TOKEN);
    DTEST_LOG << "result1:" << result1 << std::endl;
    std::shared_ptr<ContinuationExtraParams> continuationExtraParams =
        std::make_shared<ContinuationExtraParams>();
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().StartDeviceManager(
        UNREGISTER_TOKEN, continuationExtraParams);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(TOKEN_HAS_NOT_REGISTERED, result1);
    EXPECT_EQ(TOKEN_HAS_NOT_REGISTERED, result2);
    DTEST_LOG << "ContinuationManagerTest StartDeviceManagerTest_003 end" << std::endl;
}

/**
 * @tc.name: UpdateConnectStatusTest_001
 * @tc.desc: test update connect status when device selection callback has registered.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, UpdateConnectStatusTest_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest UpdateConnectStatusTest_001 start" << std::endl;
    int32_t token = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().RegisterDeviceSelectionCallback(
        token, CALLBACK_TYPE1, notifier);
    DTEST_LOG << "result2:" << result2 << std::endl;
    std::string deviceId = TEST_DEVICE_ID;
    DeviceConnectStatus deviceConnectStatus = DeviceConnectStatus::CONNECTING;
    int32_t result3 = DistributedAbilityManagerClient::GetInstance().UpdateConnectStatus(
        token, deviceId, deviceConnectStatus);
    DTEST_LOG << "result3:" << result3 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(ERR_OK, result2);
    EXPECT_EQ(ERR_OK, result3);
    DTEST_LOG << "ContinuationManagerTest UpdateConnectStatusTest_001 end" << std::endl;
}

/**
 * @tc.name: UpdateConnectStatusTest_002
 * @tc.desc: test update connect status when device selection callback has not registered.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, UpdateConnectStatusTest_002, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest UpdateConnectStatusTest_002 start" << std::endl;
    int32_t token = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    std::string deviceId = TEST_DEVICE_ID;
    DeviceConnectStatus deviceConnectStatus = DeviceConnectStatus::CONNECTING;
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().UpdateConnectStatus(
        token, deviceId, deviceConnectStatus);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(CALLBACK_HAS_NOT_REGISTERED, result2);
    DTEST_LOG << "ContinuationManagerTest UpdateConnectStatusTest_002 end" << std::endl;
}

/**
 * @tc.name: UpdateConnectStatusTest_003
 * @tc.desc: test update connect status with invalid token
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, UpdateConnectStatusTest_003, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest UpdateConnectStatusTest_003 start" << std::endl;
    std::string deviceId = TEST_DEVICE_ID;
    DeviceConnectStatus deviceConnectStatus = DeviceConnectStatus::CONNECTING;
    int32_t result = DistributedAbilityManagerClient::GetInstance().UpdateConnectStatus(
        UNREGISTER_TOKEN, deviceId, deviceConnectStatus);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(TOKEN_HAS_NOT_REGISTERED, result);
    DTEST_LOG << "ContinuationManagerTest UpdateConnectStatusTest_003 end" << std::endl;
}

/**
 * @tc.name: UpdateConnectStatusTest_004
 * @tc.desc: test update connect status with empty deviceId
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, UpdateConnectStatusTest_004, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest UpdateConnectStatusTest_004 start" << std::endl;
    int32_t token = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    std::string deviceId = EMPTY_DEVICE_ID;
    DeviceConnectStatus deviceConnectStatus = DeviceConnectStatus::CONNECTING;
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().UpdateConnectStatus(
        token, deviceId, deviceConnectStatus);
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(ERR_NULL_OBJECT, result2);
    DTEST_LOG << "ContinuationManagerTest UpdateConnectStatusTest_004 end" << std::endl;
}

/**
 * @tc.name: UpdateConnectStatusTest_005
 * @tc.desc: test update connect status with invalid status
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, UpdateConnectStatusTest_005, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest UpdateConnectStatusTest_005 start" << std::endl;
    int32_t token = -1;
    int32_t result1 = DistributedAbilityManagerClient::GetInstance().Register(nullptr, token);
    DTEST_LOG << "result1:" << result1 << std::endl;
    std::string deviceId = TEST_DEVICE_ID;
    int32_t result2 = DistributedAbilityManagerClient::GetInstance().UpdateConnectStatus(
        token, deviceId, static_cast<DeviceConnectStatus>(ERROR_CONNECT_STATUS));
    DTEST_LOG << "result2:" << result2 << std::endl;
    EXPECT_EQ(ERR_OK, result1);
    EXPECT_EQ(INVALID_CONNECT_STATUS, result2);
    DTEST_LOG << "ContinuationManagerTest UpdateConnectStatusTest_005 end" << std::endl;
}

/**
 * @tc.name: IsExceededRegisterMaxNumTest_001
 * @tc.desc: test IsExceededRegisterMaxNum function.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsExceededRegisterMaxNumTest_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsExceededRegisterMaxNumTest_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::vector<int32_t> tokenVec;
    tokenVec.emplace_back(TEST_TOKEN);
    uint32_t accessToken = TEST_ACCESS_TOKEN;
    dtbabilitymgrService_->tokenMap_[accessToken] = tokenVec;
    bool result = dtbabilitymgrService_->IsExceededRegisterMaxNum(TEST_ACCESS_TOKEN);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest IsExceededRegisterMaxNumTest_001 end" << std::endl;
}

/**
 * @tc.name: IsContinuationModeValidTest_001
 * @tc.desc: test IsContinuationModeValid function with invalid continuation mode.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsContinuationModeValidTest_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsContinuationModeValidTest_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    ContinuationMode continuationMode = static_cast<ContinuationMode>(ERROR_CONTINUATION_MODE);
    bool result = dtbabilitymgrService_->IsContinuationModeValid(continuationMode);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest IsContinuationModeValidTest_001 end" << std::endl;
}

/**
 * @tc.name: IsContinuationModeValidTest_002
 * @tc.desc: test IsContinuationModeValid function with correct continuation mode.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsContinuationModeValidTest_002, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsContinuationModeValidTest_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    ContinuationMode continuationMode = ContinuationMode::COLLABORATION_MUTIPLE;
    bool result = dtbabilitymgrService_->IsContinuationModeValid(continuationMode);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(true, result);
    DTEST_LOG << "ContinuationManagerTest IsContinuationModeValidTest_002 end" << std::endl;
}

/**
 * @tc.name: IsConnectStatusValidTest_001
 * @tc.desc: test IsConnectStatusValid function with invalid connect status.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsConnectStatusValidTest_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsConnectStatusValidTest_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    DeviceConnectStatus deviceConnectStatus = static_cast<DeviceConnectStatus>(ERROR_CONNECT_STATUS);
    bool result = dtbabilitymgrService_->IsConnectStatusValid(deviceConnectStatus);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest IsConnectStatusValidTest_001 end" << std::endl;
}

/**
 * @tc.name: IsConnectStatusValidTest_002
 * @tc.desc: test IsConnectStatusValid function with correct connect status.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsConnectStatusValidTest_002, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsConnectStatusValidTest_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    DeviceConnectStatus deviceConnectStatus = DeviceConnectStatus::CONNECTING;
    bool result = dtbabilitymgrService_->IsConnectStatusValid(deviceConnectStatus);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(true, result);
    DTEST_LOG << "ContinuationManagerTest IsConnectStatusValidTest_002 end" << std::endl;
}

/**
 * @tc.name: IsTokenRegisteredTest_001
 * @tc.desc: test IsTokenRegistered function with invalid token.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsTokenRegisteredTest_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsTokenRegisteredTest_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::vector<int32_t> tokenVec;
    uint32_t accessToken = TEST_ACCESS_TOKEN;
    dtbabilitymgrService_->tokenMap_[accessToken] = tokenVec;
    bool result = dtbabilitymgrService_->IsTokenRegistered(TEST_ACCESS_TOKEN, TEST_TOKEN);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest IsTokenRegisteredTest_002 end" << std::endl;
}

/**
 * @tc.name: IsTokenRegisteredTest_002
 * @tc.desc: test IsTokenRegistered function with correct token.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsTokenRegisteredTest_002, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsTokenRegisteredTest_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::vector<int32_t> tokenVec;
    tokenVec.emplace_back(TEST_TOKEN);
    uint32_t accessToken = TEST_ACCESS_TOKEN;
    dtbabilitymgrService_->tokenMap_[accessToken] = tokenVec;
    bool result = dtbabilitymgrService_->IsTokenRegistered(TEST_ACCESS_TOKEN, TEST_TOKEN);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(true, result);
    DTEST_LOG << "ContinuationManagerTest IsTokenRegisteredTest_002 end" << std::endl;
}

/**
 * @tc.name: IsNotifierRegisteredTest_001
 * @tc.desc: test IsNotifierRegistered function with invalid token.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsNotifierRegisteredTest_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredTest_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    bool result = dtbabilitymgrService_->IsNotifierRegistered(TEST_TOKEN);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredTest_001 end" << std::endl;
}

/**
 * @tc.name: IsNotifierRegisteredLockedTest_002
 * @tc.desc: test IsNotifierRegisteredLocked function with invalid token.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsNotifierRegisteredLockedTest_002, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredLockedTest_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    bool result = dtbabilitymgrService_->IsNotifierRegisteredLocked(TEST_TOKEN, CALLBACK_TYPE1);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredLockedTest_002 end" << std::endl;
}

/**
 * @tc.name: IsNotifierRegisteredLockedTest_003
 * @tc.desc: test IsNotifierRegisteredLocked function with invalid callback type.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsNotifierRegisteredLockedTest_003, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredLockedTest_003 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    bool result = dtbabilitymgrService_->IsNotifierRegisteredLocked(TEST_TOKEN, INVALID_CALLBACK_TYPE);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredLockedTest_003 end" << std::endl;
}

/**
 * @tc.name: IsNotifierRegisteredTest_004
 * @tc.desc: test IsNotifierRegistered function with correct token.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsNotifierRegisteredTest_004, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredTest_004 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    notifierInfo->SetNotifier(CALLBACK_TYPE1, notifier);
    dtbabilitymgrService_->callbackMap_[TEST_TOKEN] = std::move(notifierInfo);
    bool result = dtbabilitymgrService_->IsNotifierRegistered(TEST_TOKEN);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(true, result);
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredTest_004 end" << std::endl;
}

/**
 * @tc.name: IsNotifierRegisteredLockedTest_005
 * @tc.desc: test IsNotifierRegisteredLocked function with incorrect callback type.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsNotifierRegisteredLockedTest_005, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredLockedTest_005 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    notifierInfo->SetNotifier(CALLBACK_TYPE1, notifier);
    dtbabilitymgrService_->callbackMap_[TEST_TOKEN] = std::move(notifierInfo);
    bool result = dtbabilitymgrService_->IsNotifierRegisteredLocked(TEST_TOKEN, CALLBACK_TYPE2);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredLockedTest_005 end" << std::endl;
}

/**
 * @tc.name: IsNotifierRegisteredLockedTest_006
 * @tc.desc: test IsNotifierRegisteredLocked function with incorrect token.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, IsNotifierRegisteredLockedTest_006, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredLockedTest_006 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    notifierInfo->SetNotifier(CALLBACK_TYPE1, notifier);
    dtbabilitymgrService_->callbackMap_[TEST_TOKEN] = std::move(notifierInfo);
    bool result = dtbabilitymgrService_->IsNotifierRegisteredLocked(UNREGISTER_TOKEN, CALLBACK_TYPE1);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredLockedTest_006 end" << std::endl;
}

/**
 * @tc.name: IsNotifierRegisteredLockedTest_007
 * @tc.desc: test IsNotifierRegisteredLocked function with correct token and callback type.
 * @tc.type: FUNC

 */
HWTEST_F(ContinuationManagerTest, IsNotifierRegisteredLockedTest_007, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredLockedTest_007 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    notifierInfo->SetNotifier(CALLBACK_TYPE1, notifier);
    dtbabilitymgrService_->callbackMap_[TEST_TOKEN] = std::move(notifierInfo);
    bool result = dtbabilitymgrService_->IsNotifierRegisteredLocked(TEST_TOKEN, CALLBACK_TYPE1);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(true, result);
    DTEST_LOG << "ContinuationManagerTest IsNotifierRegisteredLockedTest_007 end" << std::endl;
}

/**
 * @tc.name: QueryTokenByNotifier_001
 * @tc.desc: test QueryTokenByNotifier function with incorrect notifier.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, QueryTokenByNotifier_001, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest QueryTokenByNotifier_001 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    notifierInfo->SetNotifier(CALLBACK_TYPE1, notifier);
    dtbabilitymgrService_->callbackMap_[TEST_TOKEN] = std::move(notifierInfo);
    int32_t token = -1;
    bool result = dtbabilitymgrService_->QueryTokenByNotifier(nullptr, token);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(false, result);
    DTEST_LOG << "ContinuationManagerTest QueryTokenByNotifier_001 end" << std::endl;
}

/**
 * @tc.name: QueryTokenByNotifier_002
 * @tc.desc: test QueryTokenByNotifier function with correct notifier.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, QueryTokenByNotifier_002, TestSize.Level1)
{
    DTEST_LOG << "ContinuationManagerTest QueryTokenByNotifier_002 start" << std::endl;
    if (dtbabilitymgrService_ == nullptr) {
        DTEST_LOG << "dtbabilitymgrService_ is nullptr" << std::endl;
        return;
    }
    std::unique_ptr<NotifierInfo> notifierInfo = std::make_unique<NotifierInfo>();
    sptr<DeviceSelectionNotifierTest> notifier = new DeviceSelectionNotifierTest();
    notifierInfo->SetNotifier(CALLBACK_TYPE1, notifier);
    dtbabilitymgrService_->callbackMap_[TEST_TOKEN] = std::move(notifierInfo);
    int32_t token = -1;
    bool result = dtbabilitymgrService_->QueryTokenByNotifier(notifier, token);
    DTEST_LOG << "result:" << result << std::endl;
    EXPECT_EQ(true, result);
    EXPECT_EQ(TEST_TOKEN, token);
    DTEST_LOG << "ContinuationManagerTest QueryTokenByNotifier_002 end" << std::endl;
}

/**
 * @tc.name: GetSetDeviceInfo_001
 * @tc.desc: test  SetDeviceId SetDeviceType SetDeviceName GetDeviceId GetDeviceType GetDeviceName function.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, GetSetDeviceInfo_001, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest GetSetDeviceInfo_001 start" << std::endl;

    ContinuationResult continuationResult;
    continuationResult.SetDeviceId(SELECTED_DEVICE_ID1);
    continuationResult.SetDeviceType(SELECTED_DEVICE_TYPE1);
    continuationResult.SetDeviceName(SELECTED_DEVICE_NAME1);

    string deviceId1 = continuationResult.GetDeviceId();
    string deviceType1 = continuationResult.GetDeviceType();
    string deviceName1 = continuationResult.GetDeviceName();

    EXPECT_EQ(SELECTED_DEVICE_ID1, deviceId1);
    EXPECT_EQ(SELECTED_DEVICE_TYPE1, deviceType1);
    EXPECT_EQ(SELECTED_DEVICE_NAME1, deviceName1);

    DTEST_LOG << "ContinuationManagerTest GetSetDeviceInfo_001 end" << std::endl;
}

/**
 * @tc.name: MarshallingUnmarshalling_001
 * @tc.desc: test Marshalling and Unmarshalling function.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, MarshallingUnmarshalling_001, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest MarshallingUnmarshalling_001 start" << std::endl;
    
    ContinuationResult continuationResult1;
    continuationResult1.SetDeviceId(SELECTED_DEVICE_ID1);
    continuationResult1.SetDeviceType(SELECTED_DEVICE_TYPE1);
    continuationResult1.SetDeviceName(SELECTED_DEVICE_NAME1);
    
    Parcel parcel;
    bool result1 = continuationResult1.Marshalling(parcel);
    if (!result1) {
        DTEST_LOG << " Marshalling failed" << std::endl;
        return;
    }
    DTEST_LOG << "result1:" << result1 << endl;

    sptr<ContinuationResult> continuationResult2 = continuationResult1.Unmarshalling(parcel);
    if (continuationResult2 == nullptr) {
        DTEST_LOG << "continuationResult is nullptr" << endl;
        return;
    }

    string deviceId1 = continuationResult2->GetDeviceId();
    string deviceType1 = continuationResult2->GetDeviceType();
    string deviceName1 = continuationResult2->GetDeviceName();
    EXPECT_EQ(true, result1);
    EXPECT_EQ(SELECTED_DEVICE_ID1, deviceId1);
    EXPECT_EQ(SELECTED_DEVICE_TYPE1, deviceType1);
    EXPECT_EQ(SELECTED_DEVICE_NAME1, deviceName1);

    DTEST_LOG << "ContinuationManagerTest MarshallingUnmarshalling_001 end" << std::endl;
}

/**
 * @tc.name: ReadFromParcel_001
 * @tc.desc: test ReadFromParcel function.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, ReadFromParcel_001, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ReadFromParcel_001 start" << std::endl;
    ContinuationResult continuationResult;
    continuationResult.SetDeviceId(SELECTED_DEVICE_ID1);
    continuationResult.SetDeviceType(SELECTED_DEVICE_TYPE1);
    continuationResult.SetDeviceName(SELECTED_DEVICE_NAME1);
    
    Parcel parcel;
    bool result1 = continuationResult.Marshalling(parcel);
    if (!result1) {
        DTEST_LOG << "Marshalling failed" << std::endl;
        return;
    }
    bool result2 = continuationResult.ReadFromParcel(parcel);
    if (!result2) {
        DTEST_LOG << "ReadFromParcel failed" << std::endl;
        return;
    }

    string deviceId1 = continuationResult.GetDeviceId();
    string deviceType1 = continuationResult.GetDeviceType();
    string deviceName1 = continuationResult.GetDeviceName();
    EXPECT_EQ(true, result1);
    EXPECT_EQ(true, result2);
    EXPECT_EQ(SELECTED_DEVICE_ID1, deviceId1);
    EXPECT_EQ(SELECTED_DEVICE_TYPE1, deviceType1);
    EXPECT_EQ(SELECTED_DEVICE_NAME1, deviceName1);

    DTEST_LOG << "ContinuationManagerTest ReadFromParcel_001 end" << std::endl;
}

/**
 * @tc.name: Write_Read_ContinuationResultsFromParcel_001
 * @tc.desc: test WriteContinuationResultsToParcel and ReadContinuationResultsFromParcel function.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, Write_Read_ContinuationResultsFromParcel_001, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest WriteContinuationResultsFromParcel_001 start" << std::endl;

    std::vector<ContinuationResult> continuationResults1;
    ContinuationResult continuationResult1;
    continuationResult1.SetDeviceId(SELECTED_DEVICE_ID1);
    continuationResult1.SetDeviceType(SELECTED_DEVICE_TYPE1);
    continuationResult1.SetDeviceName(SELECTED_DEVICE_NAME1);
    ContinuationResult continuationResult2;
    continuationResult2.SetDeviceId(SELECTED_DEVICE_ID2);
    continuationResult2.SetDeviceType(SELECTED_DEVICE_TYPE2);
    continuationResult2.SetDeviceName(SELECTED_DEVICE_NAME2);
    continuationResults1.emplace_back(continuationResult1);
    continuationResults1.emplace_back(continuationResult2);

    Parcel parcel;
    std::vector<ContinuationResult> continuationResults2;
    bool result1 = ContinuationResult::WriteContinuationResultsToParcel(parcel, continuationResults1);
    if (!result1) {
        DTEST_LOG << "WriteContinuationResultsToParcel failed" << std::endl;
        return;
    }
    bool result2 = ContinuationResult::ReadContinuationResultsFromParcel(parcel, continuationResults2);
    if (!result2) {
        DTEST_LOG << "ReadContinuationResultsFromParcel failed" << std::endl;
        return;
    }

    size_t size1 = continuationResults1.size();
    size_t size2 = continuationResults2.size();
    if (size1 != size2) {
        DTEST_LOG << "continuationResults1.size != continuationResults2.size" << std::endl;
        return;
    }

    EXPECT_EQ(true, result1);
    EXPECT_EQ(true, result2);
    for (size_t i = 0; i < size1; ++i) {
        EXPECT_EQ(continuationResults1[i].GetDeviceId(), continuationResults2[i].GetDeviceId());
        EXPECT_EQ(continuationResults1[i].GetDeviceType(), continuationResults2[i].GetDeviceType());
        EXPECT_EQ(continuationResults1[i].GetDeviceName(), continuationResults2[i].GetDeviceName());
    }

    DTEST_LOG << "ContinuationManagerTest WriteContinuationResultsFromParcel_001 end" << std::endl;
}

/**
 * @tc.name: ReadContinuationResultsFromParcel_001
 * @tc.desc: test ReadContinuationResultsFromParcel when len is less than 0.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, ReadContinuationResultsFromParcel_001, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_001 start" << std::endl;
    Parcel parcel;
    std::vector<ContinuationResult> continuationResults;
    parcel.WriteInt32(VALUE_OBJECT);
    parcel.WriteInt32(-1);
    bool result = ContinuationResult::ReadContinuationResultsFromParcel(parcel, continuationResults);
    EXPECT_FALSE(result);
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_001 end" << std::endl;
}

/**
 * @tc.name: ReadContinuationResultsFromParcel_002
 * @tc.desc: test ReadContinuationResultsFromParcel when size > parcel.GetReadableBytes().
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, ReadContinuationResultsFromParcel_002, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_002 start" << std::endl;
    Parcel parcel;
    std::vector<ContinuationResult> continuationResults;
    parcel.WriteInt32(VALUE_OBJECT);
    parcel.WriteInt32(parcel.GetReadableBytes() + 1);
    bool result = ContinuationResult::ReadContinuationResultsFromParcel(parcel, continuationResults);
    EXPECT_FALSE(result);
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_002 end" << std::endl;
}

/**
 * @tc.name: ReadContinuationResultsFromParcel_003
 * @tc.desc: test ReadContinuationResultsFromParcel when continuationResults.max_size() < size.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, ReadContinuationResultsFromParcel_003, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_003 start" << std::endl;
    Parcel parcel;
    std::vector<ContinuationResult> continuationResults;
    parcel.WriteInt32(VALUE_OBJECT);
    parcel.WriteInt32(continuationResults.max_size() + 1);
    bool result = ContinuationResult::ReadContinuationResultsFromParcel(parcel, continuationResults);
    EXPECT_FALSE(result);
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_003 end" << std::endl;
}

/**
 * @tc.name: ReadContinuationResultsFromParcel_004
 * @tc.desc: test ReadContinuationResultsFromParcel when continuationResults.max_size() > size.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, ReadContinuationResultsFromParcel_004, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_004 start" << std::endl;
    Parcel parcel;
    std::vector<ContinuationResult> continuationResults;
    parcel.WriteInt32(VALUE_OBJECT);
    parcel.WriteInt32(continuationResults.max_size() - 1);
    bool result = ContinuationResult::ReadContinuationResultsFromParcel(parcel, continuationResults);
    EXPECT_FALSE(result);
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_004 end" << std::endl;
}

/**
 * @tc.name: ReadContinuationResultsFromParcel_005
 * @tc.desc: test ReadContinuationResultsFromParcel when continuationResult is nullptr.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, ReadContinuationResultsFromParcel_005, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_005 start" << std::endl;
    Parcel parcel;
    ContinuationResult *continuationResult = nullptr;
    std::vector<ContinuationResult> continuationResults;
    parcel.WriteInt32(VALUE_OBJECT);
    parcel.WriteInt32(1);
    parcel.WriteParcelable(continuationResult);
    bool result = ContinuationResult::ReadContinuationResultsFromParcel(parcel, continuationResults);
    EXPECT_FALSE(result);
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_005 end" << std::endl;
}

/**
 * @tc.name: ReadContinuationResultsFromParcel_006
 * @tc.desc: test ReadContinuationResultsFromParcel when size <= parcel.GetReadableBytes().
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, ReadContinuationResultsFromParcel_006, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_006 start" << std::endl;
    Parcel parcel;
    std::vector<ContinuationResult> continuationResults;
    parcel.WriteInt32(VALUE_OBJECT);
    parcel.WriteInt32(parcel.GetReadableBytes());
    bool result = ContinuationResult::ReadContinuationResultsFromParcel(parcel, continuationResults);
    EXPECT_FALSE(result);
    DTEST_LOG << "ContinuationManagerTest ReadContinuationResultsFromParcel_006 end" << std::endl;
}

/**
 * @tc.name: WriteContinuationResultsToParcel_001
 * @tc.desc: test WriteContinuationResultsToParcel when size == 0.
 * @tc.type: FUNC
 */
HWTEST_F(ContinuationManagerTest, WriteContinuationResultsToParcel_001, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest WriteContinuationResultsToParcel_001 start" << std::endl;
    Parcel parcel;
    std::vector<ContinuationResult> continuationResults;
    bool result = ContinuationResult::WriteContinuationResultsToParcel(parcel, continuationResults);
    EXPECT_TRUE(result);
    DTEST_LOG << "ContinuationManagerTest WriteContinuationResultsToParcel_001 end" << std::endl;
}

/**
 * @tc.name: Str16VecToStr8Vec_001
 * @tc.desc: test Str16VecToStr8Vec function.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, Str16VecToStr8Vec_001, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest Str16VecToStr8Vec_001 start" << std::endl;
    
    std::vector<std::u16string> input1;
    input1.emplace_back(TEST_INPUT1);
    input1.emplace_back(TEST_INPUT2);
    std::vector<std::string> input2;
    input2.emplace_back(TEST_INPUT3);
    input2.emplace_back(TEST_INPUT4);

    std::vector<std::string> input3 = ContinationManagerUtils::Str16VecToStr8Vec(input1);
    
    size_t size1 = input2.size();
    size_t size2 = input3.size();
    if (size1 != size2) {
        DTEST_LOG << "input2.size != input3.size" << std::endl;
        return;
    }
    for (size_t i = 0; i < size1; ++i) {
        EXPECT_EQ(input2[i], input3[i]);
    }

    DTEST_LOG << "ContinuationManagerTest Str16VecToStr8Vec_001 end" << std::endl;
}

/**
 * @tc.name: SetFunction_001
 * @tc.desc: test SetFunction function.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, SetFunction_001, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest SetFunction_001 start" << std::endl;
    ContinuationExtraParams continuationExtraParams;
    
    std::vector<std::string> deviceTypeVec1;
    deviceTypeVec1.emplace_back(SELECTED_DEVICE_TYPE1);
    deviceTypeVec1.emplace_back(SELECTED_DEVICE_TYPE2);
    ContinuationMode continuationMode = ContinuationMode::COLLABORATION_MUTIPLE;

    continuationExtraParams.SetDeviceType(deviceTypeVec1);
    continuationExtraParams.SetTargetBundle(TEST_TARGETBUNDLE);
    continuationExtraParams.SetDescription(TEST_DESCRIPTION);
    continuationExtraParams.SetFilter(TEST_FILTER);
    continuationExtraParams.SetContinuationMode(continuationMode);
    continuationExtraParams.SetAuthInfo(TEST_AUTHINFO);

    std::vector<std::string> deviceTypeVec2 = continuationExtraParams.GetDeviceType();
    size_t size1 = deviceTypeVec1.size();
    size_t size2 = deviceTypeVec2.size();
    if (size1 != size2) {
        DTEST_LOG << "deviceTypeVec1.size != deviceTypeVec2.size" << std::endl;
        return;
    }
    for (size_t i = 0; i < size1; ++i) {
        EXPECT_EQ(deviceTypeVec1[i], deviceTypeVec2[i]);
    }
    EXPECT_EQ(TEST_TARGETBUNDLE, continuationExtraParams.GetTargetBundle());
    EXPECT_EQ(TEST_DESCRIPTION, continuationExtraParams.GetDescription());
    EXPECT_EQ(TEST_FILTER, continuationExtraParams.GetFilter());
    EXPECT_EQ(continuationMode, continuationExtraParams.GetContinuationMode());
    EXPECT_EQ(TEST_AUTHINFO, continuationExtraParams.GetAuthInfo());

    DTEST_LOG << "ContinuationManagerTest SetFunction_001 end" << std::endl;
}

/**
 * @tc.name: ReadFromParcel_002
 * @tc.desc: test ContinuationExtraParams::ReadFromParcel function.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, ReadFromParcel_002, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest ReadFromParcel_002 start" << std::endl;
    ContinuationExtraParams continuationExtraParams;

    std::vector<std::string> deviceTypeVec1;
    deviceTypeVec1.emplace_back(SELECTED_DEVICE_TYPE1);
    deviceTypeVec1.emplace_back(SELECTED_DEVICE_TYPE2);
    ContinuationMode continuationMode = ContinuationMode::COLLABORATION_MUTIPLE;

    continuationExtraParams.SetDeviceType(deviceTypeVec1);
    continuationExtraParams.SetTargetBundle(TEST_TARGETBUNDLE);
    continuationExtraParams.SetDescription(TEST_DESCRIPTION);
    continuationExtraParams.SetFilter(TEST_FILTER);
    continuationExtraParams.SetContinuationMode(continuationMode);
    continuationExtraParams.SetAuthInfo(TEST_AUTHINFO);
    
    Parcel parcel;
    bool result1 = continuationExtraParams.Marshalling(parcel);
    if (!result1) {
        DTEST_LOG << "Marshalling failed" << std::endl;
        return;
    }
    bool result2 = continuationExtraParams.ReadFromParcel(parcel);
    if (!result2) {
        DTEST_LOG << "ReadFromParcel failed" << std::endl;
        return;
    }

    EXPECT_EQ(true, result1);
    EXPECT_EQ(true, result2);
    std::vector<std::string> deviceTypeVec2 = continuationExtraParams.GetDeviceType();
    size_t size1 = deviceTypeVec1.size();
    size_t size2 = deviceTypeVec2.size();
    if (size1 != size2) {
        DTEST_LOG << "deviceTypeVec1.size != deviceTypeVec2.size" << std::endl;
        return;
    }
    for (size_t i = 0; i < size1; ++i) {
        EXPECT_EQ(deviceTypeVec1[i], deviceTypeVec2[i]);
    }
    EXPECT_EQ(TEST_TARGETBUNDLE, continuationExtraParams.GetTargetBundle());
    EXPECT_EQ(TEST_DESCRIPTION, continuationExtraParams.GetDescription());
    EXPECT_EQ(TEST_FILTER, continuationExtraParams.GetFilter());
    EXPECT_EQ(continuationMode, continuationExtraParams.GetContinuationMode());
    EXPECT_EQ(TEST_AUTHINFO, continuationExtraParams.GetAuthInfo());

    DTEST_LOG << "ContinuationManagerTest ReadFromParcel_002 end" << std::endl;
}

/**
 * @tc.name: Unmarshalling_001
 * @tc.desc: test Unmarshalling_001 function.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, Unmarshalling_001, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest Unmarshalling_001 start" << std::endl;
    ContinuationExtraParams continuationExtraParams1;

    std::vector<std::string> deviceTypeVec1;
    deviceTypeVec1.emplace_back(SELECTED_DEVICE_TYPE1);
    deviceTypeVec1.emplace_back(SELECTED_DEVICE_TYPE2);
    ContinuationMode continuationMode = ContinuationMode::COLLABORATION_MUTIPLE;

    continuationExtraParams1.SetDeviceType(deviceTypeVec1);
    continuationExtraParams1.SetTargetBundle(TEST_TARGETBUNDLE);
    continuationExtraParams1.SetDescription(TEST_DESCRIPTION);
    continuationExtraParams1.SetFilter(TEST_FILTER);
    continuationExtraParams1.SetContinuationMode(continuationMode);
    continuationExtraParams1.SetAuthInfo(TEST_AUTHINFO);

    Parcel parcel;

    bool result1 = continuationExtraParams1.Marshalling(parcel);
    if (!result1) {
        DTEST_LOG << "Marshalling failed" << std::endl;
        return;
    }
    sptr<ContinuationExtraParams> continuationExtraParams2 = continuationExtraParams1.Unmarshalling(parcel);
    if (continuationExtraParams2 == nullptr) {
        DTEST_LOG << "continuationExtraParams is nullptr" << std::endl;
        return;
    }

    std::vector<std::string> deviceTypeVec2 = continuationExtraParams2->GetDeviceType();

    EXPECT_EQ(true, result1);
    size_t size1 = deviceTypeVec1.size();
    size_t size2 = deviceTypeVec2.size();
    if (size1 != size2) {
        DTEST_LOG << "deviceTypeVec1.size != deviceTypeVec2.size" << std::endl;
        return;
    }
    for (size_t i = 0; i < size1; ++i) {
        EXPECT_EQ(deviceTypeVec1[i], deviceTypeVec2[i]);
    }
    EXPECT_EQ(TEST_TARGETBUNDLE, continuationExtraParams2->GetTargetBundle());
    EXPECT_EQ(TEST_DESCRIPTION, continuationExtraParams2->GetDescription());
    EXPECT_EQ(TEST_FILTER, continuationExtraParams2->GetFilter());
    EXPECT_EQ(continuationMode, continuationExtraParams2->GetContinuationMode());
    EXPECT_EQ(TEST_AUTHINFO, continuationExtraParams2->GetAuthInfo());

    DTEST_LOG << "ContinuationManagerTest Unmarshalling_001 end" << std::endl;
}

/**
 * @tc.name: Unmarshalling_002
 * @tc.desc: test Unmarshalling_002 when ontinuationExtraParams->ReadFromParcel failed;
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, Unmarshalling_002, TestSize.Level3)
{
    DTEST_LOG << "ContinuationManagerTest Unmarshalling_002 start" << std::endl;
    ContinuationExtraParams continuationExtraParams;
    Parcel parcel;
    parcel.WriteInt32(INVALID_LEN);
    ContinuationExtraParams* result = continuationExtraParams.Unmarshalling(parcel);
    EXPECT_EQ(nullptr, result);
    DTEST_LOG << "ContinuationManagerTest Unmarshalling_002 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: test OnRemoteRequest, invalid interface token.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_001, TestSize.Level3)
{
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    DeviceSelectionNotifierTest deviceSelectionNotifierTest;
    int32_t result = deviceSelectionNotifierTest.OnRemoteRequest(IDeviceSelectionNotifier::EVENT_DEVICE_CONNECT,
        data, reply, option);
    EXPECT_EQ(ERR_INVALID_VALUE, result);
}

/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: test OnRemoteRequest, invalid code.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_002, TestSize.Level3)
{
    MessageParcel data;
    data.WriteInterfaceToken(IDeviceSelectionNotifier::GetDescriptor());
    MessageParcel reply;
    MessageOption option;
    DeviceSelectionNotifierTest deviceSelectionNotifierTest;
    int32_t result = deviceSelectionNotifierTest.OnRemoteRequest(INVALID_EVENT_DEVICE_CODE,
        data, reply, option);
    EXPECT_NE(ERR_OK, result);
}

/**
 * @tc.name: OnRemoteRequest_003
 * @tc.desc: test OnRemoteRequest, code = EVENT_DEVICE_CONNECT
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_003, TestSize.Level3)
{
    MessageParcel data;
    data.WriteInterfaceToken(IDeviceSelectionNotifier::GetDescriptor());
    std::vector<ContinuationResult> continuationResults;
    ContinuationResult continuationResult1;
    continuationResult1.SetDeviceId(SELECTED_DEVICE_ID1);
    continuationResult1.SetDeviceType(SELECTED_DEVICE_TYPE1);
    continuationResult1.SetDeviceName(SELECTED_DEVICE_NAME1);
    ContinuationResult continuationResult2;
    continuationResult2.SetDeviceId(SELECTED_DEVICE_ID2);
    continuationResult2.SetDeviceType(SELECTED_DEVICE_TYPE2);
    continuationResult2.SetDeviceName(SELECTED_DEVICE_NAME2);
    continuationResults.emplace_back(continuationResult1);
    continuationResults.emplace_back(continuationResult2);

    bool result1 = ContinuationResult::WriteContinuationResultsToParcel(data, continuationResults);
    if (!result1) {
        DTEST_LOG << "WriteContinuationResultsToParcel failed" << std::endl;
        return;
    }

    MessageParcel reply;
    MessageOption option;
    DeviceSelectionNotifierTest deviceSelectionNotifierTest;
    int32_t result2 = deviceSelectionNotifierTest.OnRemoteRequest(IDeviceSelectionNotifier::EVENT_DEVICE_CONNECT,
        data, reply, option);

    EXPECT_EQ(true, result1);
    EXPECT_EQ(ERR_OK, result2);
}

/**
 * @tc.name: OnRemoteRequest_004
 * @tc.desc: test OnRemoteRequest, invalid interface token.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_004, TestSize.Level3)
{
    /**
     * @tc.steps: step1. test OnRemoteRequest with invalid interface token.
     */
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    DeviceSelectionNotifierTest deviceSelectionNotifierTest;
    int32_t result = deviceSelectionNotifierTest.OnRemoteRequest(IDeviceSelectionNotifier::EVENT_DEVICE_DISCONNECT,
        data, reply, option);
    EXPECT_EQ(ERR_INVALID_VALUE, result);
    /**
     * @tc.steps: step2. test OnRemoteDied when dmsNotifier_ == nullptr.
     */
    sptr<DmsNotifier> dmsNotifier = new MockDmsNotifier();
    NotifierDeathRecipient notifierDeathRecipient(dmsNotifier);
    notifierDeathRecipient.dmsNotifier_ = nullptr;
    wptr<IRemoteObject> remote = nullptr;
    notifierDeathRecipient.OnRemoteDied(remote);
}

/**
 * @tc.name: OnRemoteRequest_005
 * @tc.desc: test OnRemoteRequest, code = EVENT_DEVICE_DISCONNECT
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_005, TestSize.Level3)
{
    MessageParcel data;
    data.WriteInterfaceToken(IDeviceSelectionNotifier::GetDescriptor());
    std::vector<std::string> deviceIds;
    deviceIds.emplace_back(SELECTED_DEVICE_ID1);
    deviceIds.emplace_back(SELECTED_DEVICE_ID2);
    deviceIds.emplace_back(SELECTED_DEVICE_ID3);
    data.WriteStringVector(deviceIds);

    MessageParcel reply;
    MessageOption option;
    DeviceSelectionNotifierTest deviceSelectionNotifierTest;
    int32_t result = deviceSelectionNotifierTest.OnRemoteRequest(IDeviceSelectionNotifier::EVENT_DEVICE_DISCONNECT,
        data, reply, option);

    EXPECT_EQ(ERR_OK, result);
}

/**
 * @tc.name: OnRemoteRequest_006
 * @tc.desc: test OnRemoteRequest, code = EVENT_DEVICE_CONNECT but read from parcel failed
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_006, TestSize.Level3)
{
    MessageParcel data;
    data.WriteInterfaceToken(IDeviceSelectionNotifier::GetDescriptor());
    data.WriteInt32(VALUE_OBJECT);
    data.WriteInt32(INVALID_LEN);
    MessageParcel reply;
    MessageOption option;
    DeviceSelectionNotifierTest deviceSelectionNotifierTest;
    int32_t result = deviceSelectionNotifierTest.OnRemoteRequest(IDeviceSelectionNotifier::EVENT_DEVICE_CONNECT,
        data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, result);
}

/**
 * @tc.name: OnRemoteRequest_007
 * @tc.desc: test OnRemoteRequest, code = EVENT_DEVICE_DISCONNECT but read from parcel failed
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_007, TestSize.Level3)
{
    MessageParcel data;
    data.WriteInterfaceToken(IDeviceSelectionNotifier::GetDescriptor());
    data.WriteInt32(VALUE_OBJECT);
    data.WriteInt32(INVALID_LEN);
    MessageParcel reply;
    MessageOption option;
    DeviceSelectionNotifierTest deviceSelectionNotifierTest;
    int32_t result = deviceSelectionNotifierTest.OnRemoteRequest(IDeviceSelectionNotifier::EVENT_DEVICE_DISCONNECT,
        data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, result);
}

/**
 * @tc.name: OnRemoteRequest_008
 * @tc.desc: test OnRemoteRequest when descriptor != remoteDescriptor.
 * @tc.type: FUNC
 * @tc.require: I5M4CD
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_008, TestSize.Level3)
{
    sptr<DmsNotifier> dmsNotifier = new MockDmsNotifier();
    AppDeviceCallbackStub appDeviceCallbackStub(dmsNotifier);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(TEST_INVALID_REMOTEDESCRIPTOR);
    /**
     * @tc.steps: step1. AppDeviceCallbackStub::OnRemoteRequest
     */
    int32_t ret = appDeviceCallbackStub.OnRemoteRequest(1, data, reply, option);
    EXPECT_EQ(ERR_INVALID_STATE, ret);
    /**
     * @tc.steps: step2. DeviceSelectionNotifierProxy::OnDeviceConnect when continuationResults is nullptr.
     */
    sptr<IRemoteObject> impl = new MockRemoteStub();
    DeviceSelectionNotifierProxy deviceSelectionNotifierProxy(impl);
    std::vector<ContinuationResult> continuationResults;
    deviceSelectionNotifierProxy.OnDeviceConnect(continuationResults);
    /**
     * @tc.steps: step3. DeviceSelectionNotifierProxy::OnDeviceDisconnect when continuationResults is nullptr.
     */
    std::vector<std::string> deviceIds;
    deviceSelectionNotifierProxy.OnDeviceDisconnect(deviceIds);

    /**
     * @tc.steps: step4. DeviceSelectionNotifierProxy::OnDeviceConnect.
     */
    ContinuationResult continuationResult1;
    continuationResult1.SetDeviceId(SELECTED_DEVICE_ID1);
    continuationResult1.SetDeviceType(SELECTED_DEVICE_TYPE1);
    continuationResult1.SetDeviceName(SELECTED_DEVICE_NAME1);
    ContinuationResult continuationResult2;
    continuationResult2.SetDeviceId(SELECTED_DEVICE_ID2);
    continuationResult2.SetDeviceType(SELECTED_DEVICE_TYPE2);
    continuationResult2.SetDeviceName(SELECTED_DEVICE_NAME2);
    continuationResults.emplace_back(continuationResult1);
    continuationResults.emplace_back(continuationResult2);
    deviceSelectionNotifierProxy.OnDeviceConnect(continuationResults);
    /**
     * @tc.steps: step5. DeviceSelectionNotifierProxy::OnDeviceDisconnect.
     */
    deviceIds.emplace_back(SELECTED_DEVICE_ID1);
    deviceIds.emplace_back(SELECTED_DEVICE_ID2);
    deviceIds.emplace_back(SELECTED_DEVICE_ID3);
    deviceSelectionNotifierProxy.OnDeviceDisconnect(deviceIds);
}

/**
 * @tc.name: OnRemoteRequest_009
 * @tc.desc: test OnRemoteRequest when code = AppDeviceCallbackInterface::EVENT_DEVICE_CONNECT.
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_009, TestSize.Level3)
{
    sptr<DmsNotifier> dmsNotifier = new MockDmsNotifier();
    AppDeviceCallbackStub appDeviceCallbackStub(dmsNotifier);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(AppDeviceCallbackInterface::GetDescriptor());
    data.WriteInt32(TEST_TOKEN);
    int32_t ret = appDeviceCallbackStub.OnRemoteRequest(
        AppDeviceCallbackInterface::EVENT_DEVICE_CONNECT, data, reply, option);
    EXPECT_EQ(ERR_NONE, ret);
}

/**
 * @tc.name: OnRemoteRequest_0010
 * @tc.desc: test OnRemoteRequest when ContinuationResult read from parcel failed.
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_0010, TestSize.Level3)
{
    sptr<DmsNotifier> dmsNotifier = new MockDmsNotifier();
    AppDeviceCallbackStub appDeviceCallbackStub(dmsNotifier);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(AppDeviceCallbackInterface::GetDescriptor());
    data.WriteInt32(TEST_TOKEN);
    data.WriteInt32(VALUE_OBJECT);
    data.WriteInt32(INVALID_LEN);
    int32_t ret = appDeviceCallbackStub.OnRemoteRequest(
        AppDeviceCallbackInterface::EVENT_DEVICE_CONNECT, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: OnRemoteRequest_011
 * @tc.desc: test OnRemoteRequest when code = AppDeviceCallbackInterface::EVENT_DEVICE_CONNECT.
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_011, TestSize.Level3)
{
    sptr<DmsNotifier> dmsNotifier = new MockDmsNotifier();
    AppDeviceCallbackStub appDeviceCallbackStub(dmsNotifier);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(AppDeviceCallbackInterface::GetDescriptor());
    data.WriteInt32(TEST_TOKEN);
    int32_t ret = appDeviceCallbackStub.OnRemoteRequest(
        AppDeviceCallbackInterface::EVENT_DEVICE_DISCONNECT, data, reply, option);
    EXPECT_EQ(ERR_NONE, ret);
}

/**
 * @tc.name: OnRemoteRequest_0012
 * @tc.desc: test OnRemoteRequest when ContinuationResult read from parcel failed.
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_0012, TestSize.Level3)
{
    sptr<DmsNotifier> dmsNotifier = new MockDmsNotifier();
    AppDeviceCallbackStub appDeviceCallbackStub(dmsNotifier);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(AppDeviceCallbackInterface::GetDescriptor());
    data.WriteInt32(TEST_TOKEN);
    data.WriteInt32(VALUE_OBJECT);
    data.WriteInt32(INVALID_LEN);
    int32_t ret = appDeviceCallbackStub.OnRemoteRequest(
        AppDeviceCallbackInterface::EVENT_DEVICE_DISCONNECT, data, reply, option);
    EXPECT_EQ(ERR_FLATTEN_OBJECT, ret);
}

/**
 * @tc.name: OnRemoteRequest_013
 * @tc.desc: test OnRemoteRequest when code = AppDeviceCallbackInterface::EVENT_DEVICE_CANCEL.
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_013, TestSize.Level3)
{
    sptr<DmsNotifier> dmsNotifier = new MockDmsNotifier();
    AppDeviceCallbackStub appDeviceCallbackStub(dmsNotifier);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(AppDeviceCallbackInterface::GetDescriptor());
    int32_t ret = appDeviceCallbackStub.OnRemoteRequest(
        AppDeviceCallbackInterface::EVENT_DEVICE_CANCEL, data, reply, option);
    EXPECT_EQ(ERR_NONE, ret);
}

/**
 * @tc.name: OnRemoteRequest_014
 * @tc.desc: test OnRemoteRequest when code = INVALID_EVENT_DEVICE_CODE.
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, OnRemoteRequest_014, TestSize.Level3)
{
    sptr<DmsNotifier> dmsNotifier = new MockDmsNotifier();
    AppDeviceCallbackStub appDeviceCallbackStub(dmsNotifier);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(AppDeviceCallbackInterface::GetDescriptor());
    int32_t ret = appDeviceCallbackStub.OnRemoteRequest(INVALID_EVENT_DEVICE_CODE, data, reply, option);
    EXPECT_NE(ERR_NONE, ret);
}

/**
 * @tc.name: OnDeviceEvent_001
 * @tc.desc: test OnDeviceConnect, OnDeviceDisconnect and OnDeviceCancel.
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, OnDeviceEvent_001, TestSize.Level3)
{
    sptr<DmsNotifier> dmsNotifier = new MockDmsNotifier();
    AppDeviceCallbackStub appDeviceCallbackStub(dmsNotifier);
    /**
     * @tc.steps: step1. test OnDeviceConnect
     */
    std::vector<ContinuationResult> continuationResults;
    int32_t ret = appDeviceCallbackStub.OnDeviceConnect(TEST_TOKEN, continuationResults);
    EXPECT_EQ(ERR_NONE, ret);
    /**
     * @tc.steps: step2. test OnDeviceDisconnect
     */
    std::vector<std::string> deviceIds;
    ret = appDeviceCallbackStub.OnDeviceDisconnect(TEST_TOKEN, deviceIds);
    EXPECT_EQ(ERR_NONE, ret);
    /**
     * @tc.steps: step3. test OnDeviceCancel
     */
    ret = appDeviceCallbackStub.OnDeviceCancel();
    EXPECT_EQ(ERR_NONE, ret);
}

/**
 * @tc.name: GetConnectStatusInfo_001
 * @tc.desc: test GetConnectStatusInfo
 * @tc.type: FUNC
 * @tc.require: I621C1
 */
HWTEST_F(ContinuationManagerTest, GetConnectStatusInfo_001, TestSize.Level3)
{
    NotifierInfo notifierInfo;
    /**
     * @tc.steps: step1. test DeleteNotifier when cbType is not in notifierMap_
     */
    notifierInfo.notifierMap_.clear();
    notifierInfo.DeleteNotifier(INVALID_CALLBACK_TYPE);
    /**
     * @tc.steps: step2. test RemoveDeathRecipient when cbType is not in notifierMap_
     */
    sptr<IRemoteObject::DeathRecipient> deathRecipient = nullptr;
    notifierInfo.RemoveDeathRecipient(deathRecipient, INVALID_CALLBACK_TYPE);
    /**
     * @tc.steps: step3. test GetConnectStatusInfo
     */
    notifierInfo.connectStatusInfo_ = nullptr;
    std::shared_ptr<ConnectStatusInfo> result = notifierInfo.GetConnectStatusInfo();
    EXPECT_EQ(nullptr, result);
}
} // namespace DistributedSchedule
} // namespace OHOS