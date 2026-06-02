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

#include "distributedIntent/distributed_intent_provider_impl.h"
#include "distributed_intent_error_code.h"
#include "distributed_sched_utils.h"
#include "distributed_want_v2.h"
#include "nlohmann/json.hpp"
#include "remote_intent_manager.h"
#include "test_log.h"
#include "want.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string BUNDLE_NAME = "com.test.bundle";
const std::string ABILITY_NAME = "MainAbility";
const std::string DEVICE_ID = "device_id_12345";
const std::string RESULT_MSG = "test_result_msg";
constexpr uint64_t TEST_REQUEST_CODE = 100;
constexpr int32_t TEST_UID = 1000;
constexpr int32_t TEST_PID = 2000;
constexpr uint32_t TEST_ACCESS_TOKEN = 200;
}

class DistributedIntentProviderImplTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

protected:
    std::shared_ptr<DmsIntentProviderImpl> provider_;
};

void DistributedIntentProviderImplTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedIntentProviderImplTest::SetUpTestCase" << std::endl;
}

void DistributedIntentProviderImplTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedIntentProviderImplTest::TearDownTestCase" << std::endl;
}

void DistributedIntentProviderImplTest::SetUp()
{
    DTEST_LOG << "DistributedIntentProviderImplTest::SetUp" << std::endl;
    provider_ = std::make_shared<DmsIntentProviderImpl>();
}

void DistributedIntentProviderImplTest::TearDown()
{
    DTEST_LOG << "DistributedIntentProviderImplTest::TearDown" << std::endl;
    provider_ = nullptr;
}

/**
 * @tc.name: SerializeIntentData_Success_001
 * @tc.desc: Verify SerializeIntentData succeeds with valid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, SerializeIntentData_Success, TestSize.Level3)
{
    Want want;
    want.SetElementName(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.requestCode = TEST_REQUEST_CODE;
    ctx.callerInfo.uid = TEST_UID;
    ctx.callerInfo.pid = TEST_PID;
    ctx.callerInfo.sourceDeviceId = DEVICE_ID;
    std::string data;

    EXPECT_EQ(provider_->SerializeIntentData(want, ctx, data, ""), ERR_DI_OK);
    EXPECT_FALSE(data.empty());

    nlohmann::json root = nlohmann::json::parse(data, nullptr, false);
    EXPECT_TRUE(root.is_object());
    EXPECT_TRUE(root.contains("wantData"));
    EXPECT_TRUE(root.contains("requestCode"));
    EXPECT_EQ(root["requestCode"].get<uint64_t>(), TEST_REQUEST_CODE);
    EXPECT_TRUE(root.contains("uid"));
    EXPECT_TRUE(root.contains("sourceDeviceId"));
}

/**
 * @tc.name: SerializeIntentData_WithResultMsg_001
 * @tc.desc: Verify SerializeIntentData with result message
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, SerializeIntentData_WithResultMsg, TestSize.Level3)
{
    Want want;
    want.SetElementName(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.requestCode = TEST_REQUEST_CODE;
    ctx.callerInfo.uid = TEST_UID;
    std::string data;

    EXPECT_EQ(provider_->SerializeIntentData(want, ctx, data, RESULT_MSG), ERR_DI_OK);
    EXPECT_FALSE(data.empty());

    nlohmann::json root = nlohmann::json::parse(data, nullptr, false);
    EXPECT_TRUE(root.is_object());
    EXPECT_TRUE(root.contains("resultMsg"));
    EXPECT_EQ(root["resultMsg"].get<std::string>(), RESULT_MSG);
}

/**
 * @tc.name: DeserializeIntentData_InvalidJson_001
 * @tc.desc: Verify DeserializeIntentData returns error with invalid json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DeserializeIntentData_InvalidJson, TestSize.Level3)
{
    Want want;
    IntentContext ctx;
    std::string resultMsg;

    EXPECT_EQ(provider_->DeserializeIntentData("invalid_json", want, ctx, resultMsg),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: DeserializeIntentData_MissingRequestCode_001
 * @tc.desc: Verify DeserializeIntentData returns error when requestCode is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DeserializeIntentData_MissingRequestCode, TestSize.Level3)
{
    Want want;
    IntentContext ctx;
    std::string resultMsg;
    std::string data = R"({"wantData":"AQID","uid":100})";

    EXPECT_EQ(provider_->DeserializeIntentData(data, want, ctx, resultMsg),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: DeserializeIntentData_MissingWantData_001
 * @tc.desc: Verify DeserializeIntentData returns error when wantData is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DeserializeIntentData_MissingWantData, TestSize.Level3)
{
    Want want;
    IntentContext ctx;
    std::string resultMsg;
    std::string data = R"({"requestCode":100,"uid":100})";

    EXPECT_EQ(provider_->DeserializeIntentData(data, want, ctx, resultMsg),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: SerializeResultData_Success_001
 * @tc.desc: Verify SerializeResultData succeeds with valid input
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, SerializeResultData_Success, TestSize.Level3)
{
    std::string data;
    EXPECT_EQ(provider_->SerializeResultData(ERR_DI_OK, RESULT_MSG, TEST_REQUEST_CODE, data), ERR_DI_OK);
    EXPECT_FALSE(data.empty());

    nlohmann::json root = nlohmann::json::parse(data, nullptr, false);
    EXPECT_TRUE(root.is_object());
    EXPECT_TRUE(root.contains("requestCode"));
    EXPECT_EQ(root["requestCode"].get<uint64_t>(), TEST_REQUEST_CODE);
    EXPECT_TRUE(root.contains("result"));
    EXPECT_TRUE(root.contains("resultMsg"));
    EXPECT_EQ(root["resultMsg"].get<std::string>(), RESULT_MSG);
}

/**
 * @tc.name: ParseDisconnectData_InvalidJson_001
 * @tc.desc: Verify ParseDisconnectData handles invalid json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, ParseDisconnectData_InvalidJson, TestSize.Level3)
{
    int32_t resultCode = 42;
    std::string resultMsg = "original";

    EXPECT_NO_FATAL_FAILURE(provider_->ParseDisconnectData("not_json", resultCode, resultMsg));
    EXPECT_EQ(resultCode, 42);
    EXPECT_EQ(resultMsg, "original");
}

/**
 * @tc.name: ParseDisconnectData_Success_001
 * @tc.desc: Verify ParseDisconnectData succeeds with valid json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, ParseDisconnectData_Success, TestSize.Level3)
{
    int32_t resultCode = 0;
    std::string resultMsg;
    std::string data = R"({"result":123,"resultMsg":"disconnect_msg"})";

    provider_->ParseDisconnectData(data, resultCode, resultMsg);
    EXPECT_EQ(resultCode, 123);
    EXPECT_EQ(resultMsg, "disconnect_msg");
}

/**
 * @tc.name: ParseResultData_InvalidJson_001
 * @tc.desc: Verify ParseResultData returns false with invalid json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, ParseResultData_InvalidJson, TestSize.Level3)
{
    uint64_t requestCode = 0;
    int32_t resultCode = 0;
    std::string resultMsg;

    EXPECT_FALSE(provider_->ParseResultData("invalid", requestCode, resultCode, resultMsg));
}

/**
 * @tc.name: ParseResultData_Success_001
 * @tc.desc: Verify ParseResultData succeeds with valid json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, ParseResultData_Success, TestSize.Level3)
{
    uint64_t requestCode = 0;
    int32_t resultCode = 0;
    std::string resultMsg;
    std::string data = R"({"requestCode":100,"result":5,"resultMsg":"parsed_msg"})";

    EXPECT_TRUE(provider_->ParseResultData(data, requestCode, resultCode, resultMsg));
    EXPECT_EQ(requestCode, TEST_REQUEST_CODE);
    EXPECT_EQ(resultCode, 5);
    EXPECT_EQ(resultMsg, "parsed_msg");
}

/**
 * @tc.name: ParseIntentVersionProfile_InvalidJson_001
 * @tc.desc: Verify ParseIntentVersionProfile returns false with invalid json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, ParseIntentVersionProfile_InvalidJson, TestSize.Level3)
{
    int32_t supportFlag = 0;
    int32_t intentVersionId = 0;

    EXPECT_FALSE(provider_->ParseIntentVersionProfile("not_json", supportFlag, intentVersionId));
}

/**
 * @tc.name: ParseIntentVersionProfile_MissingKey_001
 * @tc.desc: Verify ParseIntentVersionProfile returns false when key is missing
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, ParseIntentVersionProfile_MissingKey, TestSize.Level3)
{
    int32_t supportFlag = 0;
    int32_t intentVersionId = 0;
    std::string data = R"({"otherKey":1})";

    EXPECT_FALSE(provider_->ParseIntentVersionProfile(data, supportFlag, intentVersionId));
}

/**
 * @tc.name: ParseIntentVersionProfile_NotSupported_001
 * @tc.desc: Verify ParseIntentVersionProfile with support flag 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, ParseIntentVersionProfile_NotSupported, TestSize.Level3)
{
    int32_t supportFlag = 0;
    int32_t intentVersionId = 0;
    std::string data = R"({"supportDistributedIntent":0,"IntentVersionId":1})";

    EXPECT_TRUE(provider_->ParseIntentVersionProfile(data, supportFlag, intentVersionId));
    EXPECT_EQ(supportFlag, 0);
}

/**
 * @tc.name: ParseIntentVersionProfile_Success_001
 * @tc.desc: Verify ParseIntentVersionProfile succeeds with valid json
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, ParseIntentVersionProfile_Success, TestSize.Level3)
{
    int32_t supportFlag = 0;
    int32_t intentVersionId = 0;
    std::string data = R"({"supportDistributedIntent":1,"IntentVersionId":2})";

    EXPECT_TRUE(provider_->ParseIntentVersionProfile(data, supportFlag, intentVersionId));
    EXPECT_EQ(supportFlag, 1);
    EXPECT_EQ(intentVersionId, 2);
}

/**
 * @tc.name: DecodeWantFromBase64_EmptyString_001
 * @tc.desc: Verify DecodeWantFromBase64 returns nullptr with empty string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DecodeWantFromBase64_EmptyString, TestSize.Level3)
{
    auto result = provider_->DecodeWantFromBase64("");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: DecodeWantFromBase64_InvalidBase64_001
 * @tc.desc: Verify DecodeWantFromBase64 returns nullptr with invalid base64 data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DecodeWantFromBase64_InvalidBase64, TestSize.Level3)
{
    auto result = provider_->DecodeWantFromBase64("!!!invalid!!!");
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: DecodeWantFromBase64_CorruptedData_001
 * @tc.desc: Verify DecodeWantFromBase64 returns nullptr with corrupted binary data
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DecodeWantFromBase64_CorruptedData, TestSize.Level3)
{
    std::string corruptedData = "AAAA";
    auto result = provider_->DecodeWantFromBase64(corruptedData);
    EXPECT_EQ(result, nullptr);
}

/**
 * @tc.name: DecodeWantFromBase64_Success_001
 * @tc.desc: Verify DecodeWantFromBase64 succeeds with valid encoded Want
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DecodeWantFromBase64_Success, TestSize.Level3)
{
    Want want;
    want.SetElementName(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    std::string encoded = provider_->EncodeWantToBase64(want);
    EXPECT_FALSE(encoded.empty());

    auto decoded = provider_->DecodeWantFromBase64(encoded);
    ASSERT_NE(decoded, nullptr);
    EXPECT_EQ(decoded->GetElement().GetDeviceID(), DEVICE_ID);
    EXPECT_EQ(decoded->GetElement().GetBundleName(), BUNDLE_NAME);
    EXPECT_EQ(decoded->GetElement().GetAbilityName(), ABILITY_NAME);
}

/**
 * @tc.name: DeserializeIntentData_RequestCodeNotNumber_001
 * @tc.desc: Verify DeserializeIntentData returns error when requestCode is not a number
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DeserializeIntentData_RequestCodeNotNumber, TestSize.Level3)
{
    Want want;
    IntentContext ctx;
    std::string resultMsg;
    std::string data = R"({"requestCode":"not_a_number","wantData":"AQID"})";

    EXPECT_EQ(provider_->DeserializeIntentData(data, want, ctx, resultMsg),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: DeserializeIntentData_WantDataNotString_001
 * @tc.desc: Verify DeserializeIntentData returns error when wantData is not a string
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DeserializeIntentData_WantDataNotString, TestSize.Level3)
{
    Want want;
    IntentContext ctx;
    std::string resultMsg;
    std::string data = R"({"requestCode":100,"wantData":123})";

    EXPECT_EQ(provider_->DeserializeIntentData(data, want, ctx, resultMsg),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: DeserializeIntentData_DecodeWantFail_001
 * @tc.desc: Verify DeserializeIntentData returns error when wantData base64 decode fails
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DeserializeIntentData_DecodeWantFail, TestSize.Level3)
{
    Want want;
    IntentContext ctx;
    std::string resultMsg;
    std::string data = R"({"requestCode":100,"wantData":"!!!invalid!!!"})";

    EXPECT_EQ(provider_->DeserializeIntentData(data, want, ctx, resultMsg),
        ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: DeserializeIntentData_Success_FullFields_001
 * @tc.desc: Verify DeserializeIntentData with full fields including bundleNames, extraInfoJson, resultMsg
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DeserializeIntentData_Success_FullFields, TestSize.Level3)
{
    Want srcWant;
    srcWant.SetElementName(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    std::string wantBase64 = provider_->EncodeWantToBase64(srcWant);
    EXPECT_FALSE(wantBase64.empty());

    IntentContext srcCtx;
    srcCtx.requestCode = TEST_REQUEST_CODE;
    srcCtx.callerInfo.uid = TEST_UID;
    srcCtx.callerInfo.pid = TEST_PID;
    srcCtx.callerInfo.callerType = 1;
    srcCtx.callerInfo.sourceDeviceId = DEVICE_ID;
    srcCtx.callerInfo.duid = 999;
    srcCtx.callerInfo.callerAppId = "com.test.appid";
    srcCtx.callerInfo.bundleNames = {"bundle1", "bundle2"};
    srcCtx.callerInfo.dmsVersion = 2;
    srcCtx.callerInfo.accessToken = TEST_ACCESS_TOKEN;
    srcCtx.callerInfo.extraInfoJson = nlohmann::json::object({{"key1", "value1"}});
    srcCtx.accountInfo.userId = 100;
    srcCtx.accountInfo.activeAccountId = "active_id_123";

    std::string serialized;
    EXPECT_EQ(provider_->SerializeIntentData(srcWant, srcCtx, serialized, RESULT_MSG), ERR_DI_OK);

    Want dstWant;
    IntentContext dstCtx;
    std::string dstResultMsg;
    EXPECT_EQ(provider_->DeserializeIntentData(serialized, dstWant, dstCtx, dstResultMsg), ERR_DI_OK);

    EXPECT_EQ(dstWant.GetElement().GetDeviceID(), DEVICE_ID);
    EXPECT_EQ(dstWant.GetElement().GetBundleName(), BUNDLE_NAME);
    EXPECT_EQ(dstWant.GetElement().GetAbilityName(), ABILITY_NAME);
    EXPECT_EQ(dstCtx.requestCode, TEST_REQUEST_CODE);
    EXPECT_EQ(dstCtx.callerInfo.uid, TEST_UID);
    EXPECT_EQ(dstCtx.callerInfo.pid, TEST_PID);
    EXPECT_EQ(dstCtx.callerInfo.callerType, 1);
    EXPECT_EQ(dstCtx.callerInfo.sourceDeviceId, DEVICE_ID);
    EXPECT_EQ(dstCtx.callerInfo.duid, 999);
    EXPECT_EQ(dstCtx.callerInfo.callerAppId, "com.test.appid");
    EXPECT_EQ(dstCtx.callerInfo.bundleNames.size(), 2u);
    EXPECT_EQ(dstCtx.callerInfo.dmsVersion, 2);
    EXPECT_EQ(dstCtx.callerInfo.accessToken, TEST_ACCESS_TOKEN);
    EXPECT_TRUE(dstCtx.callerInfo.extraInfoJson.is_object());
    EXPECT_EQ(dstCtx.accountInfo.userId, 100);
    EXPECT_EQ(dstCtx.accountInfo.activeAccountId, "active_id_123");
    EXPECT_EQ(dstResultMsg, RESULT_MSG);
}

/**
 * @tc.name: DeserializeIntentData_Success_MinimalFields_001
 * @tc.desc: Verify DeserializeIntentData with minimal fields (no bundleNames, extraInfoJson, resultMsg)
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, DeserializeIntentData_Success_MinimalFields, TestSize.Level3)
{
    Want srcWant;
    srcWant.SetElementName(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    std::string wantBase64 = provider_->EncodeWantToBase64(srcWant);
    EXPECT_FALSE(wantBase64.empty());

    IntentContext srcCtx;
    srcCtx.requestCode = TEST_REQUEST_CODE;

    std::string serialized;
    EXPECT_EQ(provider_->SerializeIntentData(srcWant, srcCtx, serialized, ""), ERR_DI_OK);

    Want dstWant;
    IntentContext dstCtx;
    std::string dstResultMsg;
    EXPECT_EQ(provider_->DeserializeIntentData(serialized, dstWant, dstCtx, dstResultMsg), ERR_DI_OK);

    EXPECT_EQ(dstCtx.requestCode, TEST_REQUEST_CODE);
    EXPECT_TRUE(dstCtx.callerInfo.bundleNames.empty());
    EXPECT_TRUE(dstCtx.callerInfo.extraInfoJson.is_null() || dstCtx.callerInfo.extraInfoJson.is_object());
    EXPECT_TRUE(dstResultMsg.empty());
}

/**
 * @tc.name: SerializeIntentData_EmptyResultMsg_001
 * @tc.desc: Verify SerializeIntentData with empty resultMsg does not include resultMsg key
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(DistributedIntentProviderImplTest, SerializeIntentData_EmptyResultMsg, TestSize.Level3)
{
    Want want;
    want.SetElementName(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    IntentContext ctx;
    ctx.requestCode = TEST_REQUEST_CODE;
    std::string data;

    EXPECT_EQ(provider_->SerializeIntentData(want, ctx, data, ""), ERR_DI_OK);
    EXPECT_FALSE(data.empty());

    nlohmann::json root = nlohmann::json::parse(data, nullptr, false);
    EXPECT_TRUE(root.is_object());
    EXPECT_FALSE(root.contains("resultMsg"));
}

} // namespace DistributedSchedule
} // namespace OHOS
