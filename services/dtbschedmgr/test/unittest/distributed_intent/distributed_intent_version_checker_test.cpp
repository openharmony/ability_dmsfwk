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

#include "distributed_device_profile_client_mock.h"
#include "distributed_intent_error_code.h"
#include "distributed_intent_provider_mock.h"
#include "distributed_intent_version_checker.h"
#include "test_log.h"

#define private public
#include "intent_permission_checker.h"
#include "distributed_intent_provider.h"
#undef private

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string DEVICE_ID = "device_id_12345";
const std::string EMPTY_DEVICE_ID;
const std::string UDID = "udid_12345";
const std::string PROFILE_DATA_SUPPORTED = R"({"supportDistributedIntent":1,"IntentVersionId":2})";
const std::string PROFILE_DATA_NOT_SUPPORTED = R"({"supportDistributedIntent":0,"IntentVersionId":1})";
const std::string PROFILE_DATA_INVALID = "invalid_json";
}

class DistributedIntentVersionCheckerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

protected:
    std::shared_ptr<MockIntentProvider> providerMock_;
    std::shared_ptr<DistributedDeviceProfile::DistributedDeviceProfileClientMock> dpClientMock_;
};

void DistributedIntentVersionCheckerTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedIntentVersionCheckerTest::SetUpTestCase" << std::endl;
}

void DistributedIntentVersionCheckerTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedIntentVersionCheckerTest::TearDownTestCase" << std::endl;
}

void DistributedIntentVersionCheckerTest::SetUp()
{
    DTEST_LOG << "DistributedIntentVersionCheckerTest::SetUp" << std::endl;
    providerMock_ = std::make_shared<MockIntentProvider>();
    IntentPermissionChecker::GetInstance().SetProvider(providerMock_.get());
    dpClientMock_ = std::make_shared<DistributedDeviceProfile::DistributedDeviceProfileClientMock>();
    DistributedDeviceProfile::IDistributedDeviceProfileClient::dpClientMock = dpClientMock_;
}

void DistributedIntentVersionCheckerTest::TearDown()
{
    DTEST_LOG << "DistributedIntentVersionCheckerTest::TearDown" << std::endl;
    IntentPermissionChecker::GetInstance().SetProvider(nullptr);
    DistributedDeviceProfile::IDistributedDeviceProfileClient::dpClientMock = nullptr;
    dpClientMock_ = nullptr;
    providerMock_ = nullptr;
}

/**
 * @tc.name: CheckRemoteDistributedIntentSupport_EmptyDeviceId_001
 * @tc.desc: Check RemoteDistributedIntentSupport with empty device id
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentVersionCheckerTest, CheckRemoteDistributedIntentSupport_EmptyDeviceId, TestSize.Level3)
{
    EXPECT_EQ(DistributedIntentVersionChecker::CheckRemoteDistributedIntentSupport(EMPTY_DEVICE_ID),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: CheckRemoteDistributedIntentSupport_NullProvider_001
 * @tc.desc: Check RemoteDistributedIntentSupport with null provider
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentVersionCheckerTest, CheckRemoteDistributedIntentSupport_NullProvider, TestSize.Level3)
{
    IntentPermissionChecker::GetInstance().SetProvider(nullptr);
    EXPECT_EQ(DistributedIntentVersionChecker::CheckRemoteDistributedIntentSupport(DEVICE_ID),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: CheckRemoteDistributedIntentSupport_EmptyUdid_001
 * @tc.desc: Check RemoteDistributedIntentSupport when GetUdidByNetworkId returns empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentVersionCheckerTest, CheckRemoteDistributedIntentSupport_EmptyUdid, TestSize.Level3)
{
    EXPECT_CALL(*providerMock_, GetUdidByNetworkId(_)).WillOnce(Return(""));
    EXPECT_EQ(DistributedIntentVersionChecker::CheckRemoteDistributedIntentSupport(DEVICE_ID),
        ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: CheckRemoteDistributedIntentSupport_DpClientFailed_001
 * @tc.desc: Check RemoteDistributedIntentSupport when device profile client returns error
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentVersionCheckerTest, CheckRemoteDistributedIntentSupport_DpClientFailed, TestSize.Level3)
{
    EXPECT_CALL(*providerMock_, GetUdidByNetworkId(_)).WillOnce(Return(UDID));
    EXPECT_CALL(*dpClientMock_, GetCharacteristicProfile(_, _, _, _)).WillOnce(Return(-1));
    EXPECT_EQ(DistributedIntentVersionChecker::CheckRemoteDistributedIntentSupport(DEVICE_ID),
        ERR_DI_VERSION_NOT_COMPATIBLE);
}

/**
 * @tc.name: CheckRemoteDistributedIntentSupport_EmptyProfileData_001
 * @tc.desc: Check RemoteDistributedIntentSupport when profile data is empty
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentVersionCheckerTest, CheckRemoteDistributedIntentSupport_EmptyProfileData, TestSize.Level3)
{
    EXPECT_CALL(*providerMock_, GetUdidByNetworkId(_)).WillOnce(Return(UDID));
    EXPECT_CALL(*dpClientMock_, GetCharacteristicProfile(_, _, _, _))
        .WillOnce(Invoke([](const std::string&, const std::string&, const std::string&,
            DistributedDeviceProfile::CharacteristicProfile& profile) {
            return 0;
        }));
    EXPECT_EQ(DistributedIntentVersionChecker::CheckRemoteDistributedIntentSupport(DEVICE_ID),
        ERR_DI_VERSION_NOT_COMPATIBLE);
}

/**
 * @tc.name: CheckRemoteDistributedIntentSupport_ParseFailed_001
 * @tc.desc: Check RemoteDistributedIntentSupport when ParseIntentVersionProfile fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentVersionCheckerTest, CheckRemoteDistributedIntentSupport_ParseFailed, TestSize.Level3)
{
    EXPECT_CALL(*providerMock_, GetUdidByNetworkId(_)).WillOnce(Return(UDID));
    EXPECT_CALL(*dpClientMock_, GetCharacteristicProfile(_, _, _, _))
        .WillOnce(Invoke([](const std::string&, const std::string&, const std::string&,
            DistributedDeviceProfile::CharacteristicProfile& profile) {
            profile.SetCharacteristicValue(PROFILE_DATA_INVALID);
            return 0;
        }));
    EXPECT_CALL(*providerMock_, ParseIntentVersionProfile(_, _, _)).WillOnce(Return(false));
    EXPECT_EQ(DistributedIntentVersionChecker::CheckRemoteDistributedIntentSupport(DEVICE_ID),
        ERR_DI_VERSION_NOT_COMPATIBLE);
}

/**
 * @tc.name: CheckRemoteDistributedIntentSupport_NotSupported_001
 * @tc.desc: Check RemoteDistributedIntentSupport when remote device does not support intent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentVersionCheckerTest, CheckRemoteDistributedIntentSupport_NotSupported, TestSize.Level3)
{
    EXPECT_CALL(*providerMock_, GetUdidByNetworkId(_)).WillOnce(Return(UDID));
    EXPECT_CALL(*dpClientMock_, GetCharacteristicProfile(_, _, _, _))
        .WillOnce(Invoke([](const std::string&, const std::string&, const std::string&,
            DistributedDeviceProfile::CharacteristicProfile& profile) {
            profile.SetCharacteristicValue(PROFILE_DATA_NOT_SUPPORTED);
            return 0;
        }));
    EXPECT_CALL(*providerMock_, ParseIntentVersionProfile(_, _, _))
        .WillOnce(Invoke([](const std::string&, int32_t& supportFlag, int32_t& intentVersionId) {
            supportFlag = 0;
            intentVersionId = 1;
            return true;
        }));
    EXPECT_EQ(DistributedIntentVersionChecker::CheckRemoteDistributedIntentSupport(DEVICE_ID),
        ERR_DI_VERSION_NOT_COMPATIBLE);
}

/**
 * @tc.name: CheckRemoteDistributedIntentSupport_VersionTooLow_001
 * @tc.desc: Check RemoteDistributedIntentSupport when remote intent version id is too low
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentVersionCheckerTest, CheckRemoteDistributedIntentSupport_VersionTooLow, TestSize.Level3)
{
    EXPECT_CALL(*providerMock_, GetUdidByNetworkId(_)).WillOnce(Return(UDID));
    EXPECT_CALL(*dpClientMock_, GetCharacteristicProfile(_, _, _, _))
        .WillOnce(Invoke([](const std::string&, const std::string&, const std::string&,
            DistributedDeviceProfile::CharacteristicProfile& profile) {
            profile.SetCharacteristicValue(PROFILE_DATA_SUPPORTED);
            return 0;
        }));
    EXPECT_CALL(*providerMock_, ParseIntentVersionProfile(_, _, _))
        .WillOnce(Invoke([](const std::string&, int32_t& supportFlag, int32_t& intentVersionId) {
            supportFlag = 1;
            intentVersionId = 0;
            return true;
        }));
    EXPECT_EQ(DistributedIntentVersionChecker::CheckRemoteDistributedIntentSupport(DEVICE_ID),
        ERR_DI_VERSION_NOT_COMPATIBLE);
}

/**
 * @tc.name: CheckRemoteDistributedIntentSupport_Success_001
 * @tc.desc: Check RemoteDistributedIntentSupport succeeds when remote device supports intent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentVersionCheckerTest, CheckRemoteDistributedIntentSupport_Success, TestSize.Level3)
{
    EXPECT_CALL(*providerMock_, GetUdidByNetworkId(_)).WillOnce(Return(UDID));
    EXPECT_CALL(*dpClientMock_, GetCharacteristicProfile(_, _, _, _))
        .WillOnce(Invoke([](const std::string&, const std::string&, const std::string&,
            DistributedDeviceProfile::CharacteristicProfile& profile) {
            profile.SetCharacteristicValue(PROFILE_DATA_SUPPORTED);
            return 0;
        }));
    EXPECT_CALL(*providerMock_, ParseIntentVersionProfile(_, _, _))
        .WillOnce(Invoke([](const std::string&, int32_t& supportFlag, int32_t& intentVersionId) {
            supportFlag = 1;
            intentVersionId = 2;
            return true;
        }));
    EXPECT_EQ(DistributedIntentVersionChecker::CheckRemoteDistributedIntentSupport(DEVICE_ID),
        ERR_DI_OK);
}

/**
 * @tc.name: ParseIntentSupportInfo_NullProvider_001
 * @tc.desc: Verify ParseIntentSupportInfo returns false when provider is null
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentVersionCheckerTest, ParseIntentSupportInfo_NullProvider, TestSize.Level3)
{
    IntentPermissionChecker::GetInstance().SetProvider(nullptr);
    int32_t intentVersionId = 0;
    EXPECT_FALSE(DistributedIntentVersionChecker::ParseIntentSupportInfo(PROFILE_DATA_SUPPORTED, intentVersionId));
}

} // namespace DistributedSchedule
} // namespace OHOS
