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

#include "dsched_continue_event_test.h"

#include "distributed_sched_utils.h"
#include "dms_constant.h"
#include "dsched_continue_event.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
const char* EXTRO_INFO_JSON_KEY_ACCESS_TOKEN = "accessTokenID";
const char* DMS_VERSION_ID = "dmsVersion";

void DSchedContinueEventTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedContinueEventTest::SetUpTestCase" << std::endl;
}

void DSchedContinueEventTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedContinueEventTest::TearDownTestCase" << std::endl;
}

void DSchedContinueEventTest::TearDown()
{
    DTEST_LOG << "DSchedContinueEventTest::TearDown" << std::endl;
}

void DSchedContinueEventTest::SetUp()
{
    DTEST_LOG << "DSchedContinueEventTest::SetUp" << std::endl;
}

/**
 * @tc.name: DSchedContinueEventTest_001_1
 * @tc.desc: DSchedContinueCmdBase Marshal and Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueEventTest_001_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_001_1 begin" << std::endl;
    DSchedContinueCmdBase cmd;
    cmd.version_ = 0;
    cmd.serviceType_ = 0;
    cmd.subServiceType_ = 0;
    cmd.command_ = 0;
    cmd.srcDeviceId_ = "123";
    cmd.srcBundleName_ = "test";
    cmd.dstDeviceId_ = "test";
    cmd.dstBundleName_ = "test";
    cmd.continueType_ = "test";
    cmd.continueByType_ = 0;
    cmd.sourceMissionId_ = 0;
    cmd.dmsVersion_ = 0;

    std::string cmdStr;
    int32_t ret = cmd.Marshal(cmdStr);
    EXPECT_EQ(ret, ERR_OK);
    ret = cmd.Unmarshal(cmdStr);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_001_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueEventTest_002_1
 * @tc.desc: DSchedContinueStartCmd Marshal and Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueEventTest_002_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_002_1 begin" << std::endl;
    DSchedContinueStartCmd cmd;
    cmd.version_ = 0;
    cmd.serviceType_ = 0;
    cmd.subServiceType_ = 0;
    cmd.command_ = 0;
    cmd.srcDeviceId_ = "123";
    cmd.srcBundleName_ = "test";
    cmd.dstDeviceId_ = "test";
    cmd.dstBundleName_ = "test";
    cmd.continueType_ = "test";
    cmd.continueByType_ = 0;
    cmd.sourceMissionId_ = 0;
    cmd.dmsVersion_ = 0;

    cmd.direction_ = 0;
    cmd.appVersion_ = 0;
    DistributedWantParams wantParams;
    cmd.wantParams_ = wantParams;

    std::string cmdStr;
    int32_t ret = cmd.Marshal(cmdStr);
    EXPECT_EQ(ret, ERR_OK);
    ret = cmd.Unmarshal(cmdStr);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_002_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueEventTest_003_1
 * @tc.desc: DSchedContinueDataCmd Marshal and Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueEventTest_003_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_003_1 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    cmd.version_ = 0;
    cmd.serviceType_ = 0;
    cmd.subServiceType_ = 0;
    cmd.command_ = 0;
    cmd.srcDeviceId_ = "123";
    cmd.srcBundleName_ = "test";
    cmd.dstDeviceId_ = "test";
    cmd.dstBundleName_ = "test";
    cmd.continueType_ = "test";
    cmd.continueByType_ = 0;
    cmd.sourceMissionId_ = 0;
    cmd.dmsVersion_ = 0;

    OHOS::AAFwk::Want want;
    cmd.want_ = want;
    AppExecFwk::CompatibleAbilityInfo abilityInfo;
    cmd.abilityInfo_ = abilityInfo;
    cmd.requestCode_ = 0;
    CallerInfo callerInfo;
    cmd.callerInfo_ = callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    cmd.accountInfo_ = accountInfo;

    std::string cmdStr;
    int32_t ret = cmd.Marshal(cmdStr);
    EXPECT_EQ(ret, ERR_OK);
    ret = cmd.Unmarshal(cmdStr);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_003_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueEventTest_004_1
 * @tc.desc: DSchedContinueReplyCmd Marshal and Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueEventTest_004_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_004_1 begin" << std::endl;
    DSchedContinueReplyCmd cmd;
    cmd.version_ = 0;
    cmd.serviceType_ = 0;
    cmd.subServiceType_ = 0;
    cmd.command_ = 0;
    cmd.srcDeviceId_ = "123";
    cmd.srcBundleName_ = "test";
    cmd.dstDeviceId_ = "test";
    cmd.dstBundleName_ = "test";
    cmd.continueType_ = "test";
    cmd.continueByType_ = 0;
    cmd.sourceMissionId_ = 0;
    cmd.dmsVersion_ = 0;

    cmd.replyCmd_ = 0;
    cmd.appVersion_ = 0;
    cmd.result_ = 0;
    cmd.reason_ = "reason";

    std::string cmdStr;
    int32_t ret = cmd.Marshal(cmdStr);
    EXPECT_EQ(ret, ERR_OK);
    ret = cmd.Unmarshal(cmdStr);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_004_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueEventTest_005_1
 * @tc.desc: DSchedContinueEndCmd Marshal and Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueEventTest_005_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_005_1 begin" << std::endl;
    DSchedContinueEndCmd cmd;
    cmd.version_ = 0;
    cmd.serviceType_ = 0;
    cmd.subServiceType_ = 0;
    cmd.command_ = 0;
    cmd.srcDeviceId_ = "123";
    cmd.srcBundleName_ = "test";
    cmd.dstDeviceId_ = "test";
    cmd.dstBundleName_ = "test";
    cmd.continueType_ = "test";
    cmd.continueByType_ = 0;
    cmd.sourceMissionId_ = 0;
    cmd.dmsVersion_ = 0;

    cmd.result_ = 0;

    std::string cmdStr;
    int32_t ret = cmd.Marshal(cmdStr);
    EXPECT_EQ(ret, ERR_OK);
    ret = cmd.Unmarshal(cmdStr);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_005_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueEventTest_006_1
 * @tc.desc: DSchedContinueDataCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueEventTest_006_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_006_1 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    std::string cmdStr = "test";
    auto ret = cmd.Unmarshal(cmdStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "BaseCmd", 0);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_FALSE(true);
    }
    cmdStr = std::string(data);
    ret = cmd.Unmarshal(cmdStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "BaseCmd");
    cJSON_AddStringToObject(rootValue, "BaseCmd", "test");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_FALSE(true);
    }
    cmdStr = std::string(data);
    ret = cmd.Unmarshal(cmdStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_006_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueEventTest_007_1
 * @tc.desc: DSchedContinueDataCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueEventTest_007_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_007_1 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    std::string baseJsonStr;
    DSchedContinueCmdBase baseCmd;
    if (baseCmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_FALSE(true);
    }

    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());
    Parcel wantParcel;
    OHOS::AAFwk::Want want;
    if (!want.Marshalling(wantParcel)) {
        cJSON_Delete(rootValue);
        ASSERT_FALSE(true);
    }
    std::string wantStr = ParcelToBase64Str(wantParcel);
    cJSON_AddStringToObject(rootValue, "Want", wantStr.c_str());
    cJSON_AddNumberToObject(rootValue, "AbilityInfo", 0);
    auto data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_FALSE(true);
    }
    auto cmdStr = std::string(data);
    auto ret = cmd.Unmarshal(cmdStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "AbilityInfo");
    cJSON_AddStringToObject(rootValue, "AbilityInfo", "test");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_FALSE(true);
    }
    cmdStr = std::string(data);
    ret = cmd.Unmarshal(cmdStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_007_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueEventTest_011_1
 * @tc.desc: DSchedContinueDataCmd UnmarshalWantParcel
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueEventTest_011_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_011_1 begin" << std::endl;
    cJSON *rootValue = nullptr;
    DSchedContinueDataCmd cmd;
    auto ret = cmd.UnmarshalWantParcel(rootValue);
    EXPECT_FALSE(ret);

    rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    ret = cmd.UnmarshalWantParcel(rootValue);
    EXPECT_FALSE(ret);

    cJSON_AddNumberToObject(rootValue, "Want", 0);
    ret = cmd.UnmarshalWantParcel(rootValue);
    EXPECT_FALSE(ret);

    cJSON_DeleteItemFromObject(rootValue, "Want");
    cJSON_AddStringToObject(rootValue, "Want", "test");
    ret = cmd.UnmarshalWantParcel(rootValue);
    EXPECT_FALSE(ret);

    cJSON_DeleteItemFromObject(rootValue, "Want");
    Parcel wantParcel;
    if (!cmd.want_.Marshalling(wantParcel)) {
        cJSON_Delete(rootValue);
        ASSERT_FALSE(true);
    }
    std::string wantStr = ParcelToBase64Str(wantParcel);
    cJSON_AddStringToObject(rootValue, "Want", wantStr.c_str());
    ret = cmd.UnmarshalWantParcel(rootValue);
    EXPECT_TRUE(ret);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_008_1 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueDataCmd_UnmarshalParcel_001
 * @tc.desc: DSchedContinueDataCmd UnmarshalParcel
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueDataCmd_UnmarshalParcel_001, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueDataCmd_UnmarshalParcel_001 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    std::string jsonStr = "test";
    auto ret = cmd.UnmarshalParcel(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalParcel(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    Parcel wantParcel;
    if (!cmd.want_.Marshalling(wantParcel)) {
        cJSON_Delete(rootValue);
        ASSERT_FALSE(true);
    }
    std::string wantStr = ParcelToBase64Str(wantParcel);
    cJSON_AddStringToObject(rootValue, "Want", wantStr.c_str());
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalParcel(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "AbilityInfo", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalParcel(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueDataCmd_UnmarshalParcel_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueDataCmd_UnmarshalParcel_002
 * @tc.desc: DSchedContinueDataCmd UnmarshalParcel
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueDataCmd_UnmarshalParcel_002, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueDataCmd_UnmarshalParcel_002 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    Parcel wantParcel;
    if (!cmd.want_.Marshalling(wantParcel)) {
        cJSON_Delete(rootValue);
        ASSERT_FALSE(true);
    }
    std::string wantStr = ParcelToBase64Str(wantParcel);
    cJSON_AddStringToObject(rootValue, "Want", wantStr.c_str());
    cJSON_AddStringToObject(rootValue, "AbilityInfo", "test");

    auto jsonStr = std::string(data);
    auto ret = cmd.UnmarshalParcel(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "AbilityInfo");
    Parcel abilityParcel;
    if (!cmd.abilityInfo_.Marshalling(abilityParcel)) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    std::string abilityInfoStr = ParcelToBase64Str(abilityParcel);
    cJSON_AddStringToObject(rootValue, "AbilityInfo", abilityInfoStr.c_str());
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalParcel(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueDataCmd_UnmarshalParcel_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalCallerInfo_001
 * @tc.desc: DSchedContinueDataCmd UnmarshalCallerInfo
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalCallerInfo_001, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfo_001 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    std::string jsonStr = "test";
    auto ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddStringToObject(rootValue, "Uid", "test");
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    
    cJSON_AddNumberToObject(rootValue, "SourceDeviceId", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfo_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalCallerInfo_002
 * @tc.desc: DSchedContinueDataCmd UnmarshalCallerInfo_002
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalCallerInfo_002, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfo_002 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddStringToObject(rootValue, "SourceDeviceId", "SourceDeviceId");
    cJSON_AddStringToObject(rootValue, "CallerAppId", "CallerAppId");
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    auto jsonStr = std::string(data);
    auto ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "Uid", "Uid");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfo_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalCallerInfo_003
 * @tc.desc: DSchedContinueDataCmd UnmarshalCallerInfo_003
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalCallerInfo_003, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfo_003 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "Uid", 0);
    cJSON_AddNumberToObject(rootValue, "Pid", 0);
    cJSON_AddNumberToObject(rootValue, "CallerType", 0);
    cJSON_AddStringToObject(rootValue, "SourceDeviceId", "SourceDeviceId");
    cJSON_AddNumberToObject(rootValue, "Duid", 0);
    cJSON_AddStringToObject(rootValue, "CallerAppId", "CallerAppId");
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    auto jsonStr = std::string(data);
    auto ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfo_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalCallerInfoExtra_001
 * @tc.desc: DSchedContinueDataCmd UnmarshalCallerInfoExtra_001
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalCallerInfoExtra_001, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfoExtra_001 begin" << std::endl;
    std::string jsonStr = "test";
    DSchedContinueDataCmd cmd;
    auto ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON *bundleNames = cJSON_CreateArray();
    if (bundleNames == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    cJSON *bundleName = cJSON_CreateNumber(0);
    if (bundleName == nullptr) {
        cJSON_Delete(rootValue);
        cJSON_Delete(bundleNames);
        ASSERT_TRUE(false);
    }

    cJSON_AddItemToArray(bundleNames, bundleName);
    cJSON_AddItemToObject(rootValue, "BundleNames", bundleNames);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfoExtra_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalCallerInfoExtra_002
 * @tc.desc: DSchedContinueDataCmd UnmarshalCallerInfoExtra_002
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalCallerInfoExtra_002, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfoExtra_002 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON *bundleNames = cJSON_CreateArray();
    if (bundleNames == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    cJSON *bundleName = cJSON_CreateString("test");
    if (bundleName == nullptr) {
        cJSON_Delete(rootValue);
        cJSON_Delete(bundleNames);
        ASSERT_TRUE(false);
    }

    cJSON_AddItemToArray(bundleNames, bundleName);
    cJSON_AddItemToObject(rootValue, "BundleNames", bundleNames);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    auto jsonStr = std::string(data);
    auto ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfoExtra_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalCallerInfoExtra_003
 * @tc.desc: DSchedContinueDataCmd UnmarshalCallerInfoExtra_003
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalCallerInfoExtra_003, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfoExtra_003 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    cJSON_AddNumberToObject(rootValue, "ExtraInfo", 0);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    auto jsonStr = std::string(data);
    auto ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "ExtraInfo");
    cJSON_AddStringToObject(rootValue, "ExtraInfo", "test");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfoExtra_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalCallerInfoExtra_004
 * @tc.desc: DSchedContinueDataCmd UnmarshalCallerInfoExtra_004
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalCallerInfoExtra_004, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfoExtra_004 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    nlohmann::json extraInfoJson;
    extraInfoJson["test"] = "test";
    std::string testStr = extraInfoJson.dump();
    cJSON_AddStringToObject(rootValue, "ExtraInfo", testStr.c_str());
    auto data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    auto jsonStr = std::string(data);
    auto ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);

    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = "test";
    testStr = extraInfoJson.dump();
    cJSON_DeleteItemFromObject(rootValue, "ExtraInfo");
    cJSON_AddStringToObject(rootValue, "ExtraInfo", testStr.c_str());
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfoExtra_004 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalCallerInfoExtra_005
 * @tc.desc: DSchedContinueDataCmd UnmarshalCallerInfoExtra_005
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalCallerInfoExtra_005, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfoExtra_005 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    nlohmann::json extraInfoJson;
    extraInfoJson[EXTRO_INFO_JSON_KEY_ACCESS_TOKEN] = 1;
    std::string testStr = extraInfoJson.dump();
    cJSON_AddStringToObject(rootValue, "ExtraInfo", testStr.c_str());
    auto data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    auto jsonStr = std::string(data);
    auto ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);

    extraInfoJson[DMS_VERSION_ID] = 1;
    testStr = extraInfoJson.dump();
    cJSON_DeleteItemFromObject(rootValue, "ExtraInfo");
    cJSON_AddStringToObject(rootValue, "ExtraInfo", testStr.c_str());
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);

    extraInfoJson[DMS_VERSION_ID] = "test";
    testStr = extraInfoJson.dump();
    cJSON_DeleteItemFromObject(rootValue, "ExtraInfo");
    cJSON_AddStringToObject(rootValue, "ExtraInfo", testStr.c_str());
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalCallerInfoExtra_005 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalAccountInfo_001
 * @tc.desc: DSchedContinueDataCmd UnmarshalAccountInfo_001
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalAccountInfo_001, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalAccountInfo_001 begin" << std::endl;
    std::string jsonStr = "test";
    DSchedContinueDataCmd cmd;
    auto ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "AccountType", "AccountType");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_DeleteItemFromObject(rootValue, "AccountType");
    cJSON_AddNumberToObject(rootValue, "AccountType", 0);
    cJSON_AddNumberToObject(rootValue, "groupIdList", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalAccountInfo_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalAccountInfo_002
 * @tc.desc: DSchedContinueDataCmd UnmarshalAccountInfo_002
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalAccountInfo_002, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalAccountInfo_002 begin" << std::endl;
    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "AccountType", 0);
    cJSON *groupIdList = cJSON_CreateArray();
    if (groupIdList == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    cJSON *groupId = cJSON_CreateNumber(0);
    if (groupId == nullptr) {
        cJSON_Delete(rootValue);
        cJSON_Delete(groupIdList);
        ASSERT_TRUE(false);
    }

    cJSON_AddItemToArray(groupIdList, groupId);
    cJSON_AddItemToObject(rootValue, "groupIdList", groupIdList);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    auto jsonStr = std::string(data);
    DSchedContinueDataCmd cmd;
    auto ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalAccountInfo_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalAccountInfo_003
 * @tc.desc: DSchedContinueDataCmd UnmarshalAccountInfo_003
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalAccountInfo_003, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalAccountInfo_003 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "AccountType", 0);
    cJSON *groupIdList = cJSON_CreateArray();
    if (groupIdList == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    cJSON *groupId = cJSON_CreateString("test");
    if (groupId == nullptr) {
        cJSON_Delete(rootValue);
        cJSON_Delete(groupIdList);
        ASSERT_TRUE(false);
    }

    cJSON_AddItemToArray(groupIdList, groupId);
    cJSON_AddItemToObject(rootValue, "groupIdList", groupIdList);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    auto jsonStr = std::string(data);
    auto ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalAccountInfo_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalAccountInfo_004
 * @tc.desc: DSchedContinueDataCmd UnmarshalAccountInfo_004
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalAccountInfo_004, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalAccountInfo_004 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "AccountType", 0);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    auto jsonStr = std::string(data);
    auto ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID, 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID);
    cJSON_AddStringToObject(rootValue, Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID, "test");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalAccountInfo_004 end ret:" << ret << std::endl;
}

/**
 * @tc.name: UnmarshalAccountInfo_005
 * @tc.desc: DSchedContinueDataCmd UnmarshalAccountInfo_005
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, UnmarshalAccountInfo_005, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest UnmarshalAccountInfo_005 begin" << std::endl;
    DSchedContinueDataCmd cmd;
    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "AccountType", 0);
    cJSON_AddStringToObject(rootValue, Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID, "test");
    cJSON_AddStringToObject(rootValue, Constants::EXTRO_INFO_JSON_KEY_USERID_ID, "test");
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    auto jsonStr = std::string(data);
    auto ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, Constants::EXTRO_INFO_JSON_KEY_USERID_ID);
    cJSON_AddNumberToObject(rootValue, Constants::EXTRO_INFO_JSON_KEY_USERID_ID, 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest UnmarshalAccountInfo_005 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueReplyCmd_Unmarshal_001
 * @tc.desc: DSchedContinueReplyCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueReplyCmd_Unmarshal_001, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueReplyCmd_Unmarshal_001 begin" << std::endl;
    std::string jsonStr = "test";
    DSchedContinueReplyCmd cmd;
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "BaseCmd", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_DeleteItemFromObject(rootValue, "BaseCmd");
    cJSON_AddStringToObject(rootValue, "BaseCmd", "test");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueReplyCmd_Unmarshal_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueReplyCmd_Unmarshal_002
 * @tc.desc: DSchedContinueReplyCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueReplyCmd_Unmarshal_002, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueReplyCmd_Unmarshal_002 begin" << std::endl;
    DSchedContinueReplyCmd cmd;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    std::string baseJsonStr;
    DSchedContinueCmdBase baseCmd;
    if (baseCmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    auto jsonStr = std::string(data);
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "ReplyCmd", "test");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueReplyCmd_Unmarshal_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueReplyCmd_Unmarshal_003
 * @tc.desc: DSchedContinueReplyCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueReplyCmd_Unmarshal_003, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueReplyCmd_Unmarshal_003 begin" << std::endl;
    DSchedContinueReplyCmd cmd;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    std::string baseJsonStr;
    DSchedContinueCmdBase baseCmd;
    if (baseCmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    auto jsonStr = std::string(data);
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "ReplyCmd", 0);
    cJSON_AddNumberToObject(rootValue, "AppVersion", 0);
    cJSON_AddNumberToObject(rootValue, "Result", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "Reason", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueReplyCmd_Unmarshal_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueEndCmd_Unmarshal_001
 * @tc.desc: DSchedContinueEndCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueEndCmd_Unmarshal_001, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEndCmd_Unmarshal_001 begin" << std::endl;
    std::string jsonStr = "test";
    DSchedContinueEndCmd cmd;
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "BaseCmd", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_DeleteItemFromObject(rootValue, "BaseCmd");
    cJSON_AddStringToObject(rootValue, "BaseCmd", "test");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEndCmd_Unmarshal_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueEndCmd_Unmarshal_002
 * @tc.desc: DSchedContinueEndCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueEndCmd_Unmarshal_002, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEndCmd_Unmarshal_002 begin" << std::endl;
    DSchedContinueEndCmd cmd;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    std::string baseJsonStr;
    DSchedContinueCmdBase baseCmd;
    if (baseCmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    auto jsonStr = std::string(data);
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "Result", "Result");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEndCmd_Unmarshal_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueStartCmd_Unmarshal_001
 * @tc.desc: DSchedContinueStartCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueStartCmd_Unmarshal_001, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueStartCmd_Unmarshal_001 begin" << std::endl;
    std::string jsonStr = "test";
    DSchedContinueStartCmd cmd;
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    auto rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "BaseCmd", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_DeleteItemFromObject(rootValue, "BaseCmd");
    cJSON_AddStringToObject(rootValue, "BaseCmd", "test");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueStartCmd_Unmarshal_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueStartCmd_Unmarshal_002
 * @tc.desc: DSchedContinueStartCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueStartCmd_Unmarshal_002, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueStartCmd_Unmarshal_002 begin" << std::endl;
    DSchedContinueStartCmd cmd;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    std::string baseJsonStr;
    DSchedContinueCmdBase baseCmd;
    if (baseCmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    auto jsonStr = std::string(data);
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "Direction", "Direction");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueStartCmd_Unmarshal_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueStartCmd_Unmarshal_003
 * @tc.desc: DSchedContinueStartCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueStartCmd_Unmarshal_003, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueStartCmd_Unmarshal_003 begin" << std::endl;
    DSchedContinueStartCmd cmd;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    std::string baseJsonStr;
    DSchedContinueCmdBase baseCmd;
    if (baseCmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());
    cJSON_AddNumberToObject(rootValue, "Direction", 0);

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    auto jsonStr = std::string(data);
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "AppVersion", "AppVersion");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueStartCmd_Unmarshal_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueStartCmd_Unmarshal_004
 * @tc.desc: DSchedContinueStartCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueStartCmd_Unmarshal_004, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueStartCmd_Unmarshal_004 begin" << std::endl;
    DSchedContinueStartCmd cmd;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    std::string baseJsonStr;
    DSchedContinueCmdBase baseCmd;
    if (baseCmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());
    cJSON_AddNumberToObject(rootValue, "Direction", 0);
    cJSON_AddNumberToObject(rootValue, "AppVersion", 0);

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    auto jsonStr = std::string(data);
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "WantParams", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueStartCmd_Unmarshal_004 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueStartCmd_Unmarshal_005
 * @tc.desc: DSchedContinueStartCmd Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueStartCmd_Unmarshal_005, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueStartCmd_Unmarshal_005 begin" << std::endl;
    DSchedContinueStartCmd cmd;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    std::string baseJsonStr;
    DSchedContinueCmdBase baseCmd;
    if (baseCmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());
    cJSON_AddNumberToObject(rootValue, "Direction", 0);
    cJSON_AddNumberToObject(rootValue, "AppVersion", 0);
    cJSON_AddStringToObject(rootValue, "WantParams", "test");

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    auto jsonStr = std::string(data);
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "WantParams");
    Parcel parcel;
    std::string wantParamsStr = ParcelToBase64Str(parcel);
    cJSON_AddStringToObject(rootValue, "WantParams", wantParamsStr.c_str());
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueStartCmd_Unmarshal_005 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueCmdBase_Unmarshal_001
 * @tc.desc: DSchedContinueCmdBase Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueCmdBase_Unmarshal_001, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueCmdBase_Unmarshal_001 begin" << std::endl;
    std::string jsonStr = "test";
    DSchedContinueCmdBase cmd;
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "Version", "Version");
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueCmdBase_Unmarshal_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueCmdBase_Unmarshal_002
 * @tc.desc: DSchedContinueCmdBase Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueCmdBase_Unmarshal_002, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueCmdBase_Unmarshal_002 begin" << std::endl;
    DSchedContinueCmdBase cmd;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "Version", 0);
    cJSON_AddNumberToObject(rootValue, "ServiceType", 0);
    cJSON_AddNumberToObject(rootValue, "SubServiceType", 0);
    cJSON_AddNumberToObject(rootValue, "ContinueByType", 0);
    cJSON_AddNumberToObject(rootValue, "SourceMissionId", 0);
    cJSON_AddNumberToObject(rootValue, "DmsVersion", 0);

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    auto jsonStr = std::string(data);
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "SrcDeviceId", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueCmdBase_Unmarshal_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: DSchedContinueCmdBase_Unmarshal_003
 * @tc.desc: DSchedContinueCmdBase Unmarshal
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueCmdBase_Unmarshal_003, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueCmdBase_Unmarshal_003 begin" << std::endl;
    DSchedContinueCmdBase cmd;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "Version", 0);
    cJSON_AddNumberToObject(rootValue, "ServiceType", 0);
    cJSON_AddNumberToObject(rootValue, "SubServiceType", 0);
    cJSON_AddNumberToObject(rootValue, "ContinueByType", 0);
    cJSON_AddNumberToObject(rootValue, "SourceMissionId", 0);
    cJSON_AddNumberToObject(rootValue, "DmsVersion", 0);
    cJSON_AddStringToObject(rootValue, "SrcDeviceId", "SrcDeviceId");
    cJSON_AddStringToObject(rootValue, "SrcBundleName", "SrcBundleName");
    cJSON_AddStringToObject(rootValue, "DstDeviceId", "DstDeviceId");
    cJSON_AddStringToObject(rootValue, "DstBundleName", "DstBundleName");
    cJSON_AddStringToObject(rootValue, "ContinueType", "ContinueType");

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    auto jsonStr = std::string(data);
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "SrcDeveloperId", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueCmdBase_Unmarshal_003 end ret:" << ret << std::endl;
}
}
}
