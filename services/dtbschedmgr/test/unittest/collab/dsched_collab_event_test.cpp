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

#include "dsched_collab_event_test.h"

#include "distributed_sched_utils.h"
#include "dms_constant.h"
#include "dsched_collab_state.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
void CollabEventTest::SetUpTestCase()
{
    DTEST_LOG << "CollabEventTest::SetUpTestCase" << std::endl;
}

void CollabEventTest::TearDownTestCase()
{
    DTEST_LOG << "CollabEventTest::TearDownTestCase" << std::endl;
}

void CollabEventTest::TearDown()
{
    DTEST_LOG << "CollabEventTest::TearDown" << std::endl;
}

void CollabEventTest::SetUp()
{
    DTEST_LOG << "CollabEventTest::SetUp" << std::endl;
}

/**
 * @tc.name: BaseCmd_Test_001
 * @tc.desc: call BaseCmd
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, BaseCmd_Test_001, TestSize.Level3)
{
    DTEST_LOG << "BaseCmd BaseCmd_Test_001 begin" << std::endl;
    BaseCmd cmd;
    cmd.collabVersion_ = 0;
    cmd.dmsVersion_ = 0;
    cmd.command_ = 0;
    cmd.srcCollabSessionId_ = 0;
    cmd.appVersion_ = 0;
    cmd.collabToken_ = "collabToken_";
    cmd.srcDeviceId_ = "srcDeviceId_";
    cmd.srcBundleName_ = "srcBundleName_";
    cmd.srcAbilityName_ = "srcAbilityName_";
    cmd.srcModuleName_ = "srcModuleName_";
    cmd.srcServerId_ = "srcServerId_";
    cmd.sinkDeviceId_ = "sinkDeviceId_";
    cmd.sinkBundleName_ = "sinkBundleName_";
    cmd.sinkAbilityName_ = "sinkAbilityName_";
    cmd.sinkModuleName_ = "sinkModuleName_";
    cmd.sinkServerId_ = "sinkServerId_";

    std::string jsonStr;
    auto ret = cmd.Marshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);

    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "BaseCmd BaseCmd_Test_001 end" << std::endl;
}

/**
 * @tc.name: BaseCmd_Unmarshal_Test_001
 * @tc.desc: call Unmarshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, BaseCmd_Unmarshal_Test_001, TestSize.Level3)
{
    DTEST_LOG << "BaseCmd BaseCmd_Unmarshal_Test_001 begin" << std::endl;
    std::string jsonStr = "test";
    BaseCmd cmd;
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "Command", 0);
    cJSON_AddNumberToObject(rootValue, "CollabVersion", 0);
    cJSON_AddNumberToObject(rootValue, "DmsVersion", 0);
    
    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "CollabSessionId", "");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_ReplaceItemInObject(rootValue, "CollabSessionId", cJSON_CreateString("test"));
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "BaseCmd BaseCmd_Unmarshal_Test_001 end" << std::endl;
}

/**
 * @tc.name: BaseCmd_Unmarshal_Test_002
 * @tc.desc: call Unmarshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, BaseCmd_Unmarshal_Test_002, TestSize.Level3)
{
    DTEST_LOG << "BaseCmd BaseCmd_Unmarshal_Test_002 begin" << std::endl;
    std::string jsonStr;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "Command", 0);
    cJSON_AddNumberToObject(rootValue, "CollabVersion", 0);
    cJSON_AddNumberToObject(rootValue, "DmsVersion", 0);
    cJSON_AddNumberToObject(rootValue, "CollabSessionId", 0);

    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    BaseCmd cmd;
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "CollabToken", 0);
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "BaseCmd BaseCmd_Unmarshal_Test_002 end" << std::endl;
}

/**
 * @tc.name: BaseCmd_Unmarshal_Test_003
 * @tc.desc: call Unmarshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, BaseCmd_Unmarshal_Test_003, TestSize.Level3)
{
    DTEST_LOG << "BaseCmd BaseCmd_Unmarshal_Test_003 begin" << std::endl;
    std::string jsonStr;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "Command", 0);
    cJSON_AddNumberToObject(rootValue, "CollabVersion", 0);
    cJSON_AddNumberToObject(rootValue, "DmsVersion", 0);
    cJSON_AddNumberToObject(rootValue, "CollabSessionId", 0);
    cJSON_AddStringToObject(rootValue, "CollabToken", "collabToken");
    cJSON_AddStringToObject(rootValue, "SrcDeviceId", "srcDeviceId");
    cJSON_AddStringToObject(rootValue, "SrcBundleName", "srcBundleName");
    cJSON_AddStringToObject(rootValue, "SrcAbilityName", "srcAbilityName");
    cJSON_AddStringToObject(rootValue, "SrcModuleName", "srcModuleName");
    cJSON_AddStringToObject(rootValue, "SrcServiceId", "srcServerId");
    cJSON_AddStringToObject(rootValue, "SinkDeviceId", "sinkDeviceId");
    cJSON_AddStringToObject(rootValue, "SinkBundleName", "sinkBundleName");
    cJSON_AddStringToObject(rootValue, "SinkAbilityName", "sinkAbilityName");
    cJSON_AddStringToObject(rootValue, "SinkModuleName", "sinkModuleName");
    cJSON_AddStringToObject(rootValue, "SinkServiceId", "sinkServerId");

    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    BaseCmd cmd;
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "NeedSendBigData", "test");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "BaseCmd BaseCmd_Unmarshal_Test_003 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_Test_001
 * @tc.desc: call SinkStartCmd
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_Test_001, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd SinkStartCmd_Test_001 begin" << std::endl;
    SinkStartCmd cmd;
    cmd.collabVersion_ = 0;
    cmd.dmsVersion_ = 0;
    cmd.command_ = 0;
    cmd.srcCollabSessionId_ = 0;
    cmd.appVersion_ = 0;
    cmd.collabToken_ = "collabToken_";
    cmd.srcDeviceId_ = "srcDeviceId_";
    cmd.srcBundleName_ = "srcBundleName_";
    cmd.srcAbilityName_ = "srcAbilityName_";
    cmd.srcModuleName_ = "srcModuleName_";
    cmd.srcServerId_ = "srcServerId_";
    cmd.sinkDeviceId_ = "sinkDeviceId_";
    cmd.sinkBundleName_ = "sinkBundleName_";
    cmd.sinkAbilityName_ = "sinkAbilityName_";
    cmd.sinkModuleName_ = "sinkModuleName_";
    cmd.sinkServerId_ = "sinkServerId_";

    CallerInfo callerInfo;
    cmd.callerInfo_ = callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    cmd.accountInfo_ = accountInfo;
    AAFwk::WantParams params;
    cmd.startParams_ = params;
    cmd.messageParams_ = params;

    std::string jsonStr;
    auto ret = cmd.Marshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);

    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "SinkStartCmd SinkStartCmd_Test_001 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_Unmarshal_Test_001
 * @tc.desc: call Unmarshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_Unmarshal_Test_001, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_Unmarshal_Test_001 begin" << std::endl;
    std::string jsonStr = "test";
    SinkStartCmd cmd;
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "AppVersion", 0);
    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "BaseCmd", 0);
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "BaseCmd");
    cJSON_AddStringToObject(rootValue, "BaseCmd", "test");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "SinkStartCmd_Unmarshal_Test_001 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_Unmarshal_Test_002
 * @tc.desc: call Unmarshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_Unmarshal_Test_002, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_Unmarshal_Test_002 begin" << std::endl;
    std::string jsonStr;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    std::string baseJsonStr;
    BaseCmd cmd;
    if (cmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());

    jsonStr = std::string(cJSON_Print(rootValue));
    SinkStartCmd sinkCmd;
    auto ret = sinkCmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_AddStringToObject(rootValue, "AppVersion", "test");
    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = sinkCmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "SinkStartCmd_Unmarshal_Test_002 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalOptParams_Test_001
 * @tc.desc: call UnmarshalOptParams
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalOptParams_Test_001, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_Unmarshal_Test_002 begin" << std::endl;
    std::string jsonStr;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    SinkStartCmd sinkCmd;
    auto ret = sinkCmd.UnmarshalOptParams(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_AddNumberToObject(rootValue, "StartParams", 0);
    ret = sinkCmd.UnmarshalOptParams(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_DeleteItemFromObject(rootValue, "StartParams");
    cJSON_AddStringToObject(rootValue, "StartParams", "test");
    ret = sinkCmd.UnmarshalOptParams(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "SinkStartCmd_Unmarshal_Test_002 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalOptParams_Test_002
 * @tc.desc: call UnmarshalOptParams
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalOptParams_Test_002, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_Unmarshal_Test_002 begin" << std::endl;
    std::string jsonStr;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    SinkStartCmd sinkCmd;
    Parcel parcel;
    if (!sinkCmd.startParams_.Marshalling(parcel)) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    std::string startParamsStr = ParcelToBase64Str(parcel);
    cJSON_AddStringToObject(rootValue, "StartParams", startParamsStr.c_str());
    if (!sinkCmd.messageParams_.Marshalling(parcel)) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    auto ret = sinkCmd.UnmarshalOptParams(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_AddNumberToObject(rootValue, "WantParams", 0);
    ret = sinkCmd.UnmarshalOptParams(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_DeleteItemFromObject(rootValue, "WantParams");
    cJSON_AddStringToObject(rootValue, "WantParams", "test");
    ret = sinkCmd.UnmarshalOptParams(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "SinkStartCmd_Unmarshal_Test_002 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalPartParcel_Test_002
 * @tc.desc: call UnmarshalPartParcel
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalPartParcel_Test_001, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalPartParcel_Test_001 begin" << std::endl;
    std::string jsonStr;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    SinkStartCmd sinkCmd;
    auto ret = sinkCmd.UnmarshalPartParcel(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    Parcel parcel;
    if (!sinkCmd.startParams_.Marshalling(parcel)) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    std::string startParamsStr = ParcelToBase64Str(parcel);
    cJSON_AddStringToObject(rootValue, "StartParams", startParamsStr.c_str());
    if (!sinkCmd.messageParams_.Marshalling(parcel)) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    std::string wantParamsStr = ParcelToBase64Str(parcel);
    cJSON_AddStringToObject(rootValue, "WantParams", wantParamsStr.c_str());
    std::string callerInfoStr;
    if (sinkCmd.MarshalCallerInfo(callerInfoStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    ret = sinkCmd.UnmarshalPartParcel(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_AddNumberToObject(rootValue, "CallerInfo", 0);
    ret = sinkCmd.UnmarshalPartParcel(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_DeleteItemFromObject(rootValue, "CallerInfo");
    cJSON_AddStringToObject(rootValue, "CallerInfo", "test");
    ret = sinkCmd.UnmarshalPartParcel(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "SinkStartCmd_UnmarshalPartParcel_Test_001 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalPartParcel_Test_002
 * @tc.desc: call UnmarshalPartParcel
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalPartParcel_Test_002, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalPartParcel_Test_002 begin" << std::endl;
    std::string jsonStr;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    SinkStartCmd sinkCmd;
    Parcel parcel;
    if (!sinkCmd.startParams_.Marshalling(parcel)) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    std::string startParamsStr = ParcelToBase64Str(parcel);
    cJSON_AddStringToObject(rootValue, "StartParams", startParamsStr.c_str());
    if (!sinkCmd.messageParams_.Marshalling(parcel)) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    std::string wantParamsStr = ParcelToBase64Str(parcel);
    cJSON_AddStringToObject(rootValue, "WantParams", wantParamsStr.c_str());
    std::string callerInfoStr;
    if (sinkCmd.MarshalCallerInfo(callerInfoStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    cJSON_AddStringToObject(rootValue, "CallerInfo", callerInfoStr.c_str());
    auto ret = sinkCmd.UnmarshalPartParcel(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_AddNumberToObject(rootValue, "AccountInfo", 0);
    ret = sinkCmd.UnmarshalPartParcel(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_DeleteItemFromObject(rootValue, "AccountInfo");
    cJSON_AddStringToObject(rootValue, "AccountInfo", "test");
    ret = sinkCmd.UnmarshalPartParcel(rootValue);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "SinkStartCmd_UnmarshalPartParcel_Test_002 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalCallerInfo_Test_001
 * @tc.desc: call UnmarshalCallerInfo
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalCallerInfo_Test_001, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfo_Test_001 begin" << std::endl;
    std::string jsonStr = "test";
    SinkStartCmd cmd;
    auto ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "Uid", 0);
    cJSON_AddNumberToObject(rootValue, "Pid", 0);

    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "SourceDeviceId", 0);
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "SourceDeviceId");
    cJSON_AddStringToObject(rootValue, "SourceDeviceId", "");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfo_Test_001 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalCallerInfo_Test_002
 * @tc.desc: call UnmarshalCallerInfo
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalCallerInfo_Test_002, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfo_Test_002 begin" << std::endl;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddStringToObject(rootValue, "SourceDeviceId", "SourceDeviceId");
    cJSON_AddNumberToObject(rootValue, "Duid", 0);
    cJSON_AddStringToObject(rootValue, "CallerAppId", "CallerAppId");

    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    std::string jsonStr = std::string(data);
    SinkStartCmd cmd;
    auto ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "Uid", "test");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "Uid");
    cJSON_AddNumberToObject(rootValue, "Uid", 0);
    cJSON_AddNumberToObject(rootValue, "Pid", 0);
    cJSON_AddNumberToObject(rootValue, "CallerType", 0);
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfo_Test_002 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalCallerInfo_Test_003
 * @tc.desc: call UnmarshalCallerInfo
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalCallerInfo_Test_003, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfo_Test_003 begin" << std::endl;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddStringToObject(rootValue, "SourceDeviceId", "SourceDeviceId");
    cJSON_AddNumberToObject(rootValue, "Duid", 0);
    cJSON_AddStringToObject(rootValue, "CallerAppId", "CallerAppId");

    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    std::string jsonStr = std::string(data);
    SinkStartCmd cmd;
    auto ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "Uid", "test");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "Uid");
    cJSON_AddNumberToObject(rootValue, "Uid", 0);
    cJSON_AddNumberToObject(rootValue, "Pid", 0);
    cJSON_AddNumberToObject(rootValue, "CallerType", 0);
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfo_Test_003 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalAccountInfo_Test_001
 * @tc.desc: call UnmarshalAccountInfo
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalAccountInfo_Test_001, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalAccountInfo_Test_001 begin" << std::endl;
    std::string jsonStr = "test";
    SinkStartCmd cmd;
    auto ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "AccountType", "test");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "SinkStartCmd_UnmarshalAccountInfo_Test_001 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalAccountInfo_Test_002
 * @tc.desc: call UnmarshalAccountInfo
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalAccountInfo_Test_002, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalAccountInfo_Test_002 begin" << std::endl;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "AccountType", 0);
    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    auto jsonStr = std::string(data);
    SinkStartCmd cmd;
    auto ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID.c_str(), 0);
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "SinkStartCmd_UnmarshalAccountInfo_Test_002 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalAccountInfo_Test_003
 * @tc.desc: call UnmarshalAccountInfo
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalAccountInfo_Test_003, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalAccountInfo_Test_003 begin" << std::endl;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    cJSON_AddNumberToObject(rootValue, "AccountType", 0);
    cJSON_AddStringToObject(rootValue, Constants::EXTRO_INFO_JSON_KEY_ACCOUNT_ID.c_str(),
        "test");
    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    auto jsonStr = std::string(data);
    SinkStartCmd cmd;
    auto ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, Constants::EXTRO_INFO_JSON_KEY_USERID_ID.c_str(),
        "test");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "SinkStartCmd_UnmarshalAccountInfo_Test_003 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalAccountInfo_Test_004
 * @tc.desc: call UnmarshalAccountInfo
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalAccountInfo_Test_004, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalAccountInfo_Test_004 begin" << std::endl;
    cJSON *rootValue = cJSON_CreateObject();
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
    ASSERT_NE(data, nullptr);
    auto jsonStr = std::string(data);
    SinkStartCmd cmd;
    auto ret = cmd.UnmarshalAccountInfo(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "SinkStartCmd_UnmarshalAccountInfo_Test_004 end" << std::endl;
}

void CreateNumberAry(cJSON **rootValue, int32_t size)
{
    if (rootValue == nullptr || *rootValue == nullptr) {
        return;
    }

    cJSON *bundleNames = cJSON_CreateArray();
    if (bundleNames == nullptr) {
        return;
    }
    for (auto i = 0; i < size; i++) {
        cJSON *bundleName = cJSON_CreateNumber(i);
        if (bundleName == nullptr) {
            cJSON_Delete(bundleNames);
            return;
        }
        cJSON_AddItemToArray(bundleNames, bundleName);
    }
    cJSON_AddItemToObject(*rootValue, "BundleNames", bundleNames);
}

void CreateStringAry(cJSON **rootValue, int32_t size)
{
    if (rootValue == nullptr || *rootValue == nullptr) {
        return;
    }

    cJSON *bundleNames = cJSON_CreateArray();
    if (bundleNames == nullptr) {
        return;
    }
    for (auto i = 0; i < size; i++) {
        std::string test = "test" + std::to_string(i);
        cJSON *bundleName = cJSON_CreateString(test.c_str());
        if (bundleName == nullptr) {
            cJSON_Delete(bundleNames);
            return;
        }
        cJSON_AddItemToArray(bundleNames, bundleName);
    }
    cJSON_AddItemToObject(*rootValue, "BundleNames", bundleNames);
}

/**
 * @tc.name: SinkStartCmd_UnmarshalCallerInfoExtra_Test_001
 * @tc.desc: call UnmarshalCallerInfoExtra
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalCallerInfoExtra_Test_001, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfoExtra_Test_001 begin" << std::endl;
    std::string jsonStr = "test";
    SinkStartCmd cmd;
    auto ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    char *data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    int32_t size = 2;
    CreateNumberAry(&rootValue, size);
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
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfoExtra_Test_001 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalCallerInfoExtra_Test_002
 * @tc.desc: call UnmarshalCallerInfoExtra
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalCallerInfoExtra_Test_002, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfoExtra_Test_002 begin" << std::endl;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    int32_t size = 2;
    CreateStringAry(&rootValue, size);
    auto data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    SinkStartCmd cmd;
    auto jsonStr = std::string(data);
    auto ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "ExtraInfo", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
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
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfoExtra_Test_002 end" << std::endl;
}

/**
 * @tc.name: SinkStartCmd_UnmarshalCallerInfoExtra_Test_003
 * @tc.desc: call UnmarshalCallerInfoExtra
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, SinkStartCmd_UnmarshalCallerInfoExtra_Test_003, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfoExtra_Test_003 begin" << std::endl;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    int32_t size = 2;
    CreateStringAry(&rootValue, size);
    auto data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    
    auto jsonStr = std::string(data);
    cJSON_AddStringToObject(rootValue, "ExtraInfo", jsonStr.c_str());
    cJSON_free(data);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    jsonStr = std::string(data);
    SinkStartCmd cmd;
    auto ret = cmd.UnmarshalCallerInfoExtra(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "SinkStartCmd_UnmarshalCallerInfoExtra_Test_003 end" << std::endl;
}

/**
 * @tc.name: NotifyResultCmd_Test_001
 * @tc.desc: call NotifyResultCmd
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, NotifyResultCmd_Test_001, TestSize.Level3)
{
    DTEST_LOG << "SinkStartCmd NotifyResultCmd_Test_001 begin" << std::endl;
    NotifyResultCmd cmd;
    cmd.collabVersion_ = 0;
    cmd.dmsVersion_ = 0;
    cmd.command_ = 0;
    cmd.srcCollabSessionId_ = 0;
    cmd.appVersion_ = 0;
    cmd.collabToken_ = "collabToken_";
    cmd.srcDeviceId_ = "srcDeviceId_";
    cmd.srcBundleName_ = "srcBundleName_";
    cmd.srcAbilityName_ = "srcAbilityName_";
    cmd.srcModuleName_ = "srcModuleName_";
    cmd.srcServerId_ = "srcServerId_";
    cmd.sinkDeviceId_ = "sinkDeviceId_";
    cmd.sinkBundleName_ = "sinkBundleName_";
    cmd.sinkAbilityName_ = "sinkAbilityName_";
    cmd.sinkModuleName_ = "sinkModuleName_";
    cmd.sinkServerId_ = "sinkServerId_";

    cmd.sinkSocketName_ = "sinkSocketName";
    cmd.abilityRejectReason_ = "abilityRejectReason";

    std::string jsonStr;
    auto ret = cmd.Marshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);

    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "SinkStartCmd NotifyResultCmd_Test_001 end" << std::endl;
}

/**
 * @tc.name: NotifyResultCmd_Unmarshal_Test_001
 * @tc.desc: call Unmarshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, NotifyResultCmd_Unmarshal_Test_001, TestSize.Level3)
{
    DTEST_LOG << "NotifyResultCmd_Unmarshal_Test_001 begin" << std::endl;
    std::string jsonStr = "test";
    NotifyResultCmd cmd;
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "BaseCmd", 0);
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "BaseCmd");
    cJSON_AddStringToObject(rootValue, "BaseCmd", "test");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "NotifyResultCmd_Unmarshal_Test_001 end" << std::endl;
}

/**
 * @tc.name: NotifyResultCmd_Unmarshal_Test_002
 * @tc.desc: call Unmarshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, NotifyResultCmd_Unmarshal_Test_002, TestSize.Level3)
{
    DTEST_LOG << "NotifyResultCmd_Unmarshal_Test_002 begin" << std::endl;
    std::string jsonStr;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    std::string baseJsonStr;
    BaseCmd cmd;
    if (cmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());

    jsonStr = std::string(cJSON_Print(rootValue));
    NotifyResultCmd notifyCmd;
    auto ret = notifyCmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_AddStringToObject(rootValue, "SinkCollabSessionId", "test");
    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = notifyCmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "SinkCollabSessionId");
    cJSON_AddNumberToObject(rootValue, "SinkCollabSessionId", 0);
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = notifyCmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "Result", "test");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = notifyCmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);
    cJSON_Delete(rootValue);
    DTEST_LOG << "NotifyResultCmd_Unmarshal_Test_002 end" << std::endl;
}

/**
 * @tc.name: NotifyResultCmd_Unmarshal_Test_003
 * @tc.desc: call Unmarshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, NotifyResultCmd_Unmarshal_Test_003, TestSize.Level3)
{
    DTEST_LOG << "NotifyResultCmd_Unmarshal_Test_003 begin" << std::endl;
    std::string jsonStr;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);

    std::string baseJsonStr;
    BaseCmd cmd;
    if (cmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }

    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());
    cJSON_AddNumberToObject(rootValue, "SinkCollabSessionId", 0);
    cJSON_AddNumberToObject(rootValue, "Result", 0);

    jsonStr = std::string(cJSON_Print(rootValue));
    NotifyResultCmd notifyCmd;
    auto ret = notifyCmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);

    cJSON_AddNumberToObject(rootValue, "SinkSocketName", 0);
    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = notifyCmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "SinkSocketName");
    cJSON_AddStringToObject(rootValue, "SinkSocketName", "SinkSocketName");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = notifyCmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "AbilityRejectReason", 0);
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = notifyCmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "NotifyResultCmd_Unmarshal_Test_003 end" << std::endl;
}

/**
 * @tc.name: DisconnectCmd_Test_001
 * @tc.desc: call DisconnectCmd
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, DisconnectCmd_Test_001, TestSize.Level3)
{
    DTEST_LOG << "DisconnectCmdTest DisconnectCmd_Test_001 begin" << std::endl;
    DisconnectCmd cmd;
    cmd.collabVersion_ = 0;
    cmd.dmsVersion_ = 0;
    cmd.command_ = 0;
    cmd.srcCollabSessionId_ = 0;
    cmd.appVersion_ = 0;
    cmd.collabToken_ = "collabToken_";
    cmd.srcDeviceId_ = "srcDeviceId_";
    cmd.srcBundleName_ = "srcBundleName_";
    cmd.srcAbilityName_ = "srcAbilityName_";
    cmd.srcModuleName_ = "srcModuleName_";
    cmd.srcServerId_ = "srcServerId_";
    cmd.sinkDeviceId_ = "sinkDeviceId_";
    cmd.sinkBundleName_ = "sinkBundleName_";
    cmd.sinkAbilityName_ = "sinkAbilityName_";
    cmd.sinkModuleName_ = "sinkModuleName_";
    cmd.sinkServerId_ = "sinkServerId_";

    std::string jsonStr;
    auto ret = cmd.Marshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);

    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "DisconnectCmdTest DisconnectCmd_Test_001 end" << std::endl;
}

/**
 * @tc.name: DisconnectCmd_Unmarshal_Test_001
 * @tc.desc: call Unmarshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, DisconnectCmd_Unmarshal_Test_001, TestSize.Level3)
{
    DTEST_LOG << "DisconnectCmd_Unmarshal_Test_001 begin" << std::endl;
    std::string jsonStr = "test";
    DisconnectCmd cmd;
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    char *data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddNumberToObject(rootValue, "BaseCmd", 0);
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_DeleteItemFromObject(rootValue, "BaseCmd");
    cJSON_AddStringToObject(rootValue, "BaseCmd", "test");
    data = cJSON_Print(rootValue);
    ASSERT_NE(data, nullptr);
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "DisconnectCmd_Unmarshal_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetSinkCollabVersionCmd_Marshal_Test_001
 * @tc.desc: call Marshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, GetSinkCollabVersionCmd_Marshal_Test_001, TestSize.Level3)
{
    DTEST_LOG << "GetSinkCollabVersionCmd_Marshal_Test_001 begin" << std::endl;
    std::string jsonStr;
    GetSinkCollabVersionCmd cmd;
    auto ret = cmd.Marshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);

    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "GetSinkCollabVersionCmd_Marshal_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetSinkCollabVersionCmd_Unmarshal_Test_001
 * @tc.desc: call Unmarshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, GetSinkCollabVersionCmd_Unmarshal_Test_001, TestSize.Level3)
{
    DTEST_LOG << "GetSinkCollabVersionCmd_Unmarshal_Test_001 begin" << std::endl;
    std::string jsonStr = "test";
    GetSinkCollabVersionCmd cmd;
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

    cJSON_AddNumberToObject(rootValue, "BaseCmd", 0);
    data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    jsonStr = std::string(data);
    ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

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
    cJSON_Delete(rootValue);
    cJSON_free(data);
    DTEST_LOG << "GetSinkCollabVersionCmd_Unmarshal_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetSinkCollabVersionCmd_Unmarshal_Test_002
 * @tc.desc: call Unmarshal
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(CollabEventTest, GetSinkCollabVersionCmd_Unmarshal_Test_002, TestSize.Level3)
{
    DTEST_LOG << "GetSinkCollabVersionCmd_Unmarshal_Test_002 begin" << std::endl;
    cJSON *rootValue = cJSON_CreateObject();
    ASSERT_NE(rootValue, nullptr);
    std::string baseJsonStr;
    BaseCmd baseCmd;
    if (baseCmd.Marshal(baseJsonStr) != ERR_OK) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    cJSON_AddStringToObject(rootValue, "BaseCmd", baseJsonStr.c_str());
    auto data = cJSON_Print(rootValue);
    if (data == nullptr) {
        cJSON_Delete(rootValue);
        ASSERT_TRUE(false);
    }
    auto jsonStr = std::string(data);
    GetSinkCollabVersionCmd cmd;
    auto ret = cmd.Unmarshal(jsonStr);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    cJSON_free(data);

    cJSON_AddStringToObject(rootValue, "SrcPid", "SrcPid");
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
    DTEST_LOG << "GetSinkCollabVersionCmd_Unmarshal_Test_002 end" << std::endl;
}
}
}
