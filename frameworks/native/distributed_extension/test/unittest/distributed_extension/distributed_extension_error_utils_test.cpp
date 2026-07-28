/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include "distributed_extension_error_utils.h"

namespace OHOS::DistributedSchedule {
using namespace testing;

class DistributedExtensionErrorUtilsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp() override {};
    void TearDown() override {};
};

void DistributedExtensionErrorUtilsTest::SetUpTestCase()
{
}

void DistributedExtensionErrorUtilsTest::TearDownTestCase()
{
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0100
 * @tc.name: Test GetJsErrorCodeByNativeError with valid error codes
 * @tc.desc: Test mapping from native error codes to JS error codes
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0100, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_ERROR_OK = static_cast<int32_t>(DistributedErrorCode::ERROR_OK);
    auto result = GetJsErrorCodeByNativeError(NATIVE_ERROR_OK);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_OK);

    constexpr int32_t NATIVE_CHECK_PERMISSION_FAILED = 2097177;
    result = GetJsErrorCodeByNativeError(NATIVE_CHECK_PERMISSION_FAILED);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED);

    constexpr int32_t NATIVE_DMS_PERMISSION_DENIED = 29360157;
    result = GetJsErrorCodeByNativeError(NATIVE_DMS_PERMISSION_DENIED);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED);

    constexpr int32_t NATIVE_DMS_COMPONENT_ACCESS_PERMISSION_DENIED = 29360176;
    result = GetJsErrorCodeByNativeError(NATIVE_DMS_COMPONENT_ACCESS_PERMISSION_DENIED);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED);

    constexpr int32_t NATIVE_DMS_ACCOUNT_ACCESS_PERMISSION_DENIED = 29360175;
    result = GetJsErrorCodeByNativeError(NATIVE_DMS_ACCOUNT_ACCESS_PERMISSION_DENIED);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0200
 * @tc.name: Test GetJsErrorCodeByNativeError with invalid param error codes
 * @tc.desc: Test mapping for invalid parameter errors
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0200, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_INVALID_PARAMETERS_ERR = 29360128;
    auto result = GetJsErrorCodeByNativeError(NATIVE_INVALID_PARAMETERS_ERR);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INVALID_PARAM);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0300
 * @tc.name: Test GetJsErrorCodeByNativeError with ability not found error codes
 * @tc.desc: Test mapping for ability resolution errors
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0300, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_RESOLVE_ABILITY_ERR = 2097152;
    auto result = GetJsErrorCodeByNativeError(NATIVE_RESOLVE_ABILITY_ERR);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_RESOLVE_ABILITY);

    constexpr int32_t NATIVE_ERR_TARGET_BUNDLE_NOT_EXIST = 2097241;
    result = GetJsErrorCodeByNativeError(NATIVE_ERR_TARGET_BUNDLE_NOT_EXIST);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_RESOLVE_ABILITY);

    constexpr int32_t NATIVE_ERR_NOT_ALLOW_IMPLICIT_START = 2097231;
    result = GetJsErrorCodeByNativeError(NATIVE_ERR_NOT_ALLOW_IMPLICIT_START);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_RESOLVE_ABILITY);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0400
 * @tc.name: Test GetJsErrorCodeByNativeError with ability type errors
 * @tc.desc: Test mapping for ability type errors
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0400, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_ERR_WRONG_INTERFACE_CALL = 2097202;
    auto result = GetJsErrorCodeByNativeError(NATIVE_ERR_WRONG_INTERFACE_CALL);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INVALID_ABILITY_TYPE);

    constexpr int32_t NATIVE_TARGET_ABILITY_NOT_SERVICE = 2097170;
    result = GetJsErrorCodeByNativeError(NATIVE_TARGET_ABILITY_NOT_SERVICE);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INVALID_ABILITY_TYPE);

    constexpr int32_t NATIVE_RESOLVE_CALL_ABILITY_TYPE_ERR = 2097188;
    result = GetJsErrorCodeByNativeError(NATIVE_RESOLVE_CALL_ABILITY_TYPE_ERR);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INVALID_ABILITY_TYPE);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0500
 * @tc.name: Test GetJsErrorCodeByNativeError with invisible ability error
 * @tc.desc: Test mapping for invisible ability permission error
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0500, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_ABILITY_VISIBLE_FALSE_DENY_REQUEST = 2097179;
    auto result = GetJsErrorCodeByNativeError(NATIVE_ABILITY_VISIBLE_FALSE_DENY_REQUEST);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_NO_INVISIBLE_PERMISSION);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0600
 * @tc.name: Test GetJsErrorCodeByNativeError with static permission error
 * @tc.desc: Test mapping for static config permission error
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0600, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_ERR_STATIC_CFG_PERMISSION = 2097208;
    auto result = GetJsErrorCodeByNativeError(NATIVE_ERR_STATIC_CFG_PERMISSION);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_STATIC_CFG_PERMISSION);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0700
 * @tc.name: Test GetJsErrorCodeByNativeError with cross user error
 * @tc.desc: Test mapping for cross user operation error
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0700, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_ERR_CROSS_USER = 2097207;
    auto result = GetJsErrorCodeByNativeError(NATIVE_ERR_CROSS_USER);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_CROSS_USER);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0800
 * @tc.name: Test GetJsErrorCodeByNativeError with crowdtest expired error
 * @tc.desc: Test mapping for crowdtest expired error
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0800, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_ERR_CROWDTEST_EXPIRED = 2097203;
    auto result = GetJsErrorCodeByNativeError(NATIVE_ERR_CROWDTEST_EXPIRED);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_CROWDTEST_EXPIRED);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0900
 * @tc.name: Test GetJsErrorCodeByNativeError with invalid context error
 * @tc.desc: Test mapping for invalid context error
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_0900, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_ERR_INVALID_CONTEXT = 2097323;
    auto result = GetJsErrorCodeByNativeError(NATIVE_ERR_INVALID_CONTEXT);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_1000
 * @tc.name: Test GetJsErrorCodeByNativeError with app controlled errors
 * @tc.desc: Test mapping for app controlled errors
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_1000, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_ERR_APP_CONTROLLED = 2097204;
    auto result = GetJsErrorCodeByNativeError(NATIVE_ERR_APP_CONTROLLED);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_CONTROLLED);

    constexpr int32_t NATIVE_ERR_EDM_APP_CONTROLLED = 2097216;
    result = GetJsErrorCodeByNativeError(NATIVE_ERR_EDM_APP_CONTROLLED);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_EDM_CONTROLLED);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_1100
 * @tc.name: Test GetJsErrorCodeByNativeError with not top ability error
 * @tc.desc: Test mapping for not top ability error
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_1100, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_NOT_TOP_ABILITY = 0x500001;
    auto result = GetJsErrorCodeByNativeError(NATIVE_NOT_TOP_ABILITY);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_NOT_TOP_ABILITY);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_1200
 * @tc.name: Test GetJsErrorCodeByNativeError with free install timeout errors
 * @tc.desc: Test mapping for free install timeout errors
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_1200, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_FREE_INSTALL_TIMEOUT = 29360300;
    auto result = GetJsErrorCodeByNativeError(NATIVE_FREE_INSTALL_TIMEOUT);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_FREE_INSTALL_TIMEOUT);

    constexpr int32_t NATIVE_FA_TIMEOUT = 0x820103;
    result = GetJsErrorCodeByNativeError(NATIVE_FA_TIMEOUT);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_FREE_INSTALL_TIMEOUT);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_1300
 * @tc.name: Test GetJsErrorCodeByNativeError with inner errors
 * @tc.desc: Test mapping for inner errors
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_1300, testing::ext::TestSize.Level1)
{
    constexpr int32_t NATIVE_ERR_INVALID_CALLER = 2097205;
    auto result = GetJsErrorCodeByNativeError(NATIVE_ERR_INVALID_CALLER);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INNER);

    constexpr int32_t NATIVE_CONNECTION_NOT_EXIST = 2097161;
    result = GetJsErrorCodeByNativeError(NATIVE_CONNECTION_NOT_EXIST);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INNER);

    constexpr int32_t NATIVE_MISSION_NOT_FOUND = 2097174;
    result = GetJsErrorCodeByNativeError(NATIVE_MISSION_NOT_FOUND);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INNER);

    constexpr int32_t NATIVE_HAP_PACKAGE_DOWNLOAD_TIMED_OUT = -9;
    result = GetJsErrorCodeByNativeError(NATIVE_HAP_PACKAGE_DOWNLOAD_TIMED_OUT);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INNER);

    constexpr int32_t NATIVE_FA_PACKAGE_DOES_NOT_SUPPORT_FREE_INSTALL = -10;
    result = GetJsErrorCodeByNativeError(NATIVE_FA_PACKAGE_DOES_NOT_SUPPORT_FREE_INSTALL);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INNER);

    constexpr int32_t NATIVE_CONCURRENT_TASKS_WAITING_FOR_RETRY = -6;
    result = GetJsErrorCodeByNativeError(NATIVE_CONCURRENT_TASKS_WAITING_FOR_RETRY);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INNER);

    constexpr int32_t NATIVE_NOT_ALLOWED_TO_PULL_THIS_FA = -901;
    result = GetJsErrorCodeByNativeError(NATIVE_NOT_ALLOWED_TO_PULL_THIS_FA);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INNER);

    constexpr int32_t NATIVE_NOT_SUPPORT_CROSS_DEVICE_FREE_INSTALL_PA = -12;
    result = GetJsErrorCodeByNativeError(NATIVE_NOT_SUPPORT_CROSS_DEVICE_FREE_INSTALL_PA);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INNER);

    constexpr int32_t NATIVE_ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST = 8521220;
    result = GetJsErrorCodeByNativeError(NATIVE_ERR_BUNDLE_MANAGER_BUNDLE_NOT_EXIST);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INNER);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_1400
 * @tc.name: Test GetJsErrorCodeByNativeError with unknown error code
 * @tc.desc: Test mapping for unknown error codes returns ERROR_CODE_INNER
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetJsErrorCodeByNativeError_1400, testing::ext::TestSize.Level1)
{
    constexpr int32_t UNKNOWN_ERROR = 99999999;
    auto result = GetJsErrorCodeByNativeError(UNKNOWN_ERROR);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INNER);

    constexpr int32_t NEGATIVE_ERROR = -999999;
    result = GetJsErrorCodeByNativeError(NEGATIVE_ERROR);
    EXPECT_EQ(result, DistributedErrorCode::ERROR_CODE_INNER);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetErrorMsg_0100
 * @tc.name: Test GetErrorMsg with valid error codes
 * @tc.desc: Test getting error messages for known error codes
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetErrorMsg_0100, testing::ext::TestSize.Level1)
{
    auto result = GetErrorMsg(DistributedErrorCode::ERROR_OK);
    EXPECT_EQ(result, "OK.");

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED);
    EXPECT_TRUE(result.find("permission") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_INVALID_PARAM);
    EXPECT_TRUE(result.find("Parameter error") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_INNER);
    EXPECT_TRUE(result.find("Internal error") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_RESOLVE_ABILITY);
    EXPECT_TRUE(result.find("ability does not exist") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_INVALID_ABILITY_TYPE);
    EXPECT_TRUE(result.find("ability type") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_NO_INVISIBLE_PERMISSION);
    EXPECT_TRUE(result.find("invisible") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_STATIC_CFG_PERMISSION);
    EXPECT_TRUE(result.find("permission") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_CROSS_USER);
    EXPECT_TRUE(result.find("Cross-user") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_CROWDTEST_EXPIRED);
    EXPECT_TRUE(result.find("crowdtesting") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT);
    EXPECT_TRUE(result.find("context does not exist") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_CONTROLLED);
    EXPECT_TRUE(result.find("controlled") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_EDM_CONTROLLED);
    EXPECT_TRUE(result.find("EDM") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_NOT_TOP_ABILITY);
    EXPECT_TRUE(result.find("top of the UI") != std::string::npos);

    result = GetErrorMsg(DistributedErrorCode::ERROR_CODE_FREE_INSTALL_TIMEOUT);
    EXPECT_TRUE(result.find("Installation-free timed out") != std::string::npos);
}

/**
 * @tc.number: DistributedExtensionErrorUtils_GetErrorMsg_0200
 * @tc.name: Test GetErrorMsg with unknown error code
 * @tc.desc: Test getting error message for unknown error code returns empty string
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_GetErrorMsg_0200, testing::ext::TestSize.Level1)
{
    constexpr DistributedErrorCode UNKNOWN_ERROR = static_cast<DistributedErrorCode>(999999);
    auto result = GetErrorMsg(UNKNOWN_ERROR);
    EXPECT_TRUE(result.empty());
}

/**
 * @tc.number: DistributedExtensionErrorUtils_ToInt32_0100
 * @tc.name: Test ToInt32 conversion
 * @tc.desc: Test converting DistributedErrorCode to int32_t
 */
HWTEST_F(DistributedExtensionErrorUtilsTest,
    DistributedExtensionErrorUtils_ToInt32_0100, testing::ext::TestSize.Level1)
{
    auto result = ToInt32(DistributedErrorCode::ERROR_OK);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_OK));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_PERMISSION_DENIED));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_INVALID_PARAM);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_INVALID_PARAM));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_INNER);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_INNER));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_RESOLVE_ABILITY);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_RESOLVE_ABILITY));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_INVALID_ABILITY_TYPE);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_INVALID_ABILITY_TYPE));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_INVALID_ID);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_INVALID_ID));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_NO_INVISIBLE_PERMISSION);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_NO_INVISIBLE_PERMISSION));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_STATIC_CFG_PERMISSION);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_STATIC_CFG_PERMISSION));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_CROSS_USER);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_CROSS_USER));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_CROWDTEST_EXPIRED);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_CROWDTEST_EXPIRED));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_INVALID_CONTEXT));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_CONTROLLED);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_CONTROLLED));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_EDM_CONTROLLED);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_EDM_CONTROLLED));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_NOT_TOP_ABILITY);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_NOT_TOP_ABILITY));

    result = ToInt32(DistributedErrorCode::ERROR_CODE_FREE_INSTALL_TIMEOUT);
    EXPECT_EQ(result, static_cast<int32_t>(DistributedErrorCode::ERROR_CODE_FREE_INSTALL_TIMEOUT));
}
} // namespace OHOS::DistributedSchedule