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

#include "distributed_sched_utils_test.h"

#include <string>

#include "config_policy_utils.h"

#include "distributed_sched_utils.h"
#include "dtbschedmgr_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedSchedUtilsTest";
constexpr const char* PARAM_KEY_OS_TYPE = "OS_TYPE";
constexpr const char* PARAM_KEY_OS_VERSION = "OS_VERSION";
constexpr int32_t MAX_TEST_PATH_LEN = 1024;
const std::string TEST_CONFIG_RELATIVE_PATH = "etc/distributedhardware/distributed_hardware_components_cfg.json";

void DistributedSchedUtilsTest::SetUpTestCase()
{
    HILOGI("DistributedSchedUtilsTest::SetUpTestCase");
}

void DistributedSchedUtilsTest::TearDownTestCase()
{
    HILOGI("DistributedSchedUtilsTest::TearDownTestCase");
}

void DistributedSchedUtilsTest::TearDown()
{
    HILOGI("DistributedSchedUtilsTest::TearDown");
}

void DistributedSchedUtilsTest::SetUp()
{
    HILOGI("DistributedSchedUtilsTest::SetUp");
}

/**
 * @tc.name: IsValidPath_001
 * @tc.desc: File path is invalid
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, IsValidPath_001, TestSize.Level1)
{
    std::string inFilePath = "invalid_path";
    std::string realFilePath = "";
    EXPECT_FALSE(IsValidPath(inFilePath, realFilePath));
    EXPECT_EQ("", realFilePath);

    inFilePath = "/data/123_test.json";
    EXPECT_FALSE(IsValidPath(inFilePath, realFilePath));
    EXPECT_EQ("", realFilePath);
}

/**
 * @tc.name: IsValidPath_002
 * @tc.desc: File path is valid
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, IsValidPath_002, TestSize.Level1)
{
    char cfgPathBuf[MAX_TEST_PATH_LEN] = { 0 };
    char *filePath  = GetOneCfgFile(TEST_CONFIG_RELATIVE_PATH.c_str(), cfgPathBuf, MAX_TEST_PATH_LEN);
    EXPECT_NE(nullptr, filePath);
    EXPECT_EQ(cfgPathBuf, filePath);

    std::string inFilePath = std::string(cfgPathBuf);
    std::string realFilePath = "";
    EXPECT_TRUE(IsValidPath(inFilePath, realFilePath));
    EXPECT_FALSE(realFilePath.empty());
}

/**
 * @tc.name: IsValidPath_003
 * @tc.desc: File path is invalid
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, IsValidPath_003, TestSize.Level1)
{
    std::string inFilePath = "";
    std::string realFilePath = "";
    EXPECT_FALSE(IsValidPath(inFilePath, realFilePath));

    inFilePath = "/data/123_test.json";
    EXPECT_FALSE(IsValidPath(inFilePath, realFilePath));
}

/**
 * @tc.name: CheckBundleContinueConfig_001
 * @tc.desc: Check bundle continue config when existing config file
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, CheckBundleContinueConfig_001, TestSize.Level1)
{
    std::string cfgJsonStr = R"({
        "allow_applist":["test_bundle_0"]
    })";
    EXPECT_TRUE(UpdateAllowAppList(cfgJsonStr));

    std::string bundleName = "test";
    EXPECT_FALSE(CheckBundleContinueConfig(bundleName));

    bundleName = "test_bundle_0";
    EXPECT_TRUE(CheckBundleContinueConfig(bundleName));
}

/**
 * @tc.name: UpdateAllowAppList_001
 * @tc.desc: Update allow app list with invalid cfgJsonStr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, UpdateAllowAppList_001, TestSize.Level1)
{
    std::string cfgJsonStr = "";
    EXPECT_FALSE(UpdateAllowAppList(cfgJsonStr));

    cfgJsonStr = "12345";
    EXPECT_FALSE(UpdateAllowAppList(cfgJsonStr));

    cfgJsonStr = R"({
        "Name":["test_one"],
        "ID":"12345"
    })";
    EXPECT_FALSE(UpdateAllowAppList(cfgJsonStr));

    cfgJsonStr = R"({
        "allow_applist":"12345"
    })";
    EXPECT_FALSE(UpdateAllowAppList(cfgJsonStr));
}

/**
 * @tc.name: UpdateAllowAppList_002
 * @tc.desc: Update allow app list with valid cfgJsonStr
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, UpdateAllowAppList_002, TestSize.Level1)
{
    std::string cfgJsonStr = R"({
        "allow_applist":["test_bundle_1"]
    })";
    EXPECT_TRUE(UpdateAllowAppList(cfgJsonStr));
}

/**
 * @tc.name: LoadContinueConfig_001
 * @tc.desc: Load continue config success
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, LoadContinueConfig_001, TestSize.Level1)
{
    EXPECT_EQ(ERR_OK, LoadContinueConfig());
    EXPECT_EQ(ERR_OK, LoadContinueConfig());
}

/**
 * @tc.name: CheckBundleContinueConfig_002
 * @tc.desc: Check bundle continue config when missing config file
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, CheckBundleContinueConfig_002, TestSize.Level1)
{
    EXPECT_EQ(ERR_OK, LoadContinueConfig());

    std::string bundleName = "test_bundle_1";
    EXPECT_TRUE(CheckBundleContinueConfig(bundleName));
}

/**
 * @tc.name: ParcelToBase64Str_001
 * @tc.desc: ParcelToBase64Str
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, ParcelToBase64Str_001, TestSize.Level1)
{
    EXPECT_EQ(INVALID_MISSION_ID, GetCurrentMissionId());

    Parcel parcel;
    std::string rawStr;
    EXPECT_EQ("", ParcelToBase64Str(parcel));

    EXPECT_EQ(INVALID_PARAMETERS_ERR, Base64StrToParcel(rawStr, parcel));

    unsigned char *toEncode = nullptr;
    unsigned int len = 0;
    EXPECT_EQ("", Base64Encode(toEncode, len));

    len = 1;
    EXPECT_EQ("", Base64Encode(toEncode, len));

    std::string basicString;
    EXPECT_EQ("", Base64Decode(basicString));

    EXPECT_EQ(true, IsBase64('+'));
    EXPECT_EQ(true, IsBase64('/'));
    EXPECT_EQ(true, IsBase64('3'));
}

/**
 * @tc.name: Base64Encode_001
 * @tc.desc: Base64Encode
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, Base64Encode_001, TestSize.Level1)
{
    unsigned char *toEncode = nullptr;
    unsigned int len = 0;
    std::string basicString;

    EXPECT_EQ(Base64Encode(toEncode, len), "");
    len = 1;
    EXPECT_EQ(Base64Encode(toEncode, len), "");

    EXPECT_EQ(Base64Decode(basicString), "");
}

/**
 * @tc.name: IsInt32_001
 * @tc.desc: IsInt32
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, IsInt32_001, TestSize.Level1)
{
    bool ret = IsInt32(nullptr);
    EXPECT_FALSE(ret);

    cJSON *paramValue = cJSON_CreateObject();
    if (paramValue == nullptr) {
        return;
    }
    int32_t data = MAX_TEST_PATH_LEN;
    cJSON_AddNumberToObject(paramValue, "data", data);
    ret = IsInt32(paramValue);
    EXPECT_FALSE(ret);
    cJSON *dataValue = cJSON_GetObjectItem(paramValue, "data");
    ret = IsInt32(dataValue);
    EXPECT_TRUE(ret);
    if (paramValue != nullptr) {
        cJSON_Delete(paramValue);
        paramValue = nullptr;
    }
}

/**
 * @tc.name: IsString_001
 * @tc.desc: IsString
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, IsString_001, TestSize.Level1)
{
    bool ret = IsString(nullptr);
    EXPECT_FALSE(ret);

    cJSON *paramValue = nullptr;
    std::string str("string");
    paramValue = cJSON_Parse(str.c_str());
    if (paramValue == nullptr) {
        return;
    }
    ret = IsString(paramValue);
    EXPECT_TRUE(ret);
    if (paramValue != nullptr) {
        cJSON_Delete(paramValue);
        paramValue = nullptr;
    }
}

/**
 * @tc.name: IsString_002
 * @tc.desc: IsString
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, IsString_002, TestSize.Level1)
{
    cJSON *paramValue = cJSON_CreateObject();
    if (paramValue == nullptr) {
        return;
    }
    int32_t data = MAX_TEST_PATH_LEN;
    cJSON_AddNumberToObject(paramValue, "data", data);
    bool ret = IsString(paramValue);
    EXPECT_FALSE(ret);
    if (paramValue != nullptr) {
        cJSON_Delete(paramValue);
        paramValue = nullptr;
    }
}

/**
 * @tc.name: CJsonParamCheck_001
 * @tc.desc: CJsonParamCheck
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, CJsonParamCheck_001, TestSize.Level1)
{
    bool ret = CJsonParamCheck(nullptr, {PARAM_KEY_OS_TYPE, PARAM_KEY_OS_VERSION});
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: GetOsInfoFromDM_001
 * @tc.desc: GetOsInfoFromDM
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DistributedSchedUtilsTest, GetOsInfoFromDM_001, TestSize.Level1)
{
    std::string dmInfoEx;
    int32_t osType;
    std::string osVersion;
    bool ret = GetOsInfoFromDM(dmInfoEx, osType, osVersion);
    EXPECT_FALSE(ret);
}
} // namespace DistributedSchedule
} // namespace OHOS
