/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "distributed_sched_permission_test.h"

#include "distributed_sched_interface.h"
#define private public
#include "distributed_sched_permission.h"
#undef private
#include "distributed_sched_util.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr uint32_t ACCESS_TOKEN = 100000000;
constexpr uint32_t INVALID_ACCESS_TOKEN = 0;
const string BUNDLE_NAME = "com.ohos.test";
const string INVALID_BUNDLE_NAME = "";
const string ABILITY_NAME = "com.ohos.test.MainAbility";
const string INVALID_ABILITY_NAME = "";
const string GROUP_ID = "TEST_GROUP_ID";
const string INVALID_GROUP_ID = "";
const string DEVICE_ID = "255.255.255.255";
const string INVALID_DEVICE_ID = "";
const string PERMISSION_NAME = "ohos.permission.DISTRIBUTED_DATASYNC";
const string INVALID_PERMISSION_NAME = "ohos.permission.TEST";

const string MOCK_FIELD_GROUP_NAME = "MockName";
const string MOCK_FIELD_GROUP_ID = "MockId";
const string MOCK_FIELD_GROUP_OWNER = "MockOwner";
const int32_t MOCK_FIELD_GROUP_TYPE = 0;
const int32_t MOCK_FIELD_GROUP_VISIBILITY = 0;
const string FIELD_GROUP_NAME = "groupName";
const string FIELD_GROUP_ID = "groupId";
const string FIELD_GROUP_OWNER = "groupOwner";
const string FIELD_GROUP_TYPE = "groupType";
const string FIELD_GROUP_VISIBILITY = "groupVisibility";
const char* FOUNDATION_PROCESS_NAME = "foundation";
}

void DistributedSchedPermissionTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedSchedPermissionTest::SetUpTestCase" << std::endl;
}

void DistributedSchedPermissionTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedSchedPermissionTest::TearDownTestCase" << std::endl;
}

void DistributedSchedPermissionTest::TearDown()
{
    DTEST_LOG << "DistributedSchedPermissionTest::TearDown" << std::endl;
}

void DistributedSchedPermissionTest::SetUp()
{
    DTEST_LOG << "DistributedSchedPermissionTest::SetUp" << std::endl;
}

/**
 * @tc.name: CheckDPermission_001
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDPermission_001, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_001 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string localDeviceId = DEVICE_ID;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckDPermission(want,
        callerInfo, accountInfo, localDeviceId);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_001 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckDPermission_002
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDPermission_002, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_002 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    bool needQueryExtension = true;
    std::string localDeviceId = DEVICE_ID;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckDPermission(want,
        callerInfo, accountInfo, localDeviceId, needQueryExtension);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_002 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckDPermission_003
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDPermission_003, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_003 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string localDeviceId = INVALID_DEVICE_ID;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckDPermission(want,
        callerInfo, accountInfo, localDeviceId);
    EXPECT_TRUE(ret == INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_003 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckDPermission_004
 * @tc.desc: input invalid params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDPermission_004, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_004 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    bool needQueryExtension = true;
    std::string localDeviceId = INVALID_DEVICE_ID;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckDPermission(want,
        callerInfo, accountInfo, localDeviceId, needQueryExtension);
    EXPECT_TRUE(ret == INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_004 end ret:" << ret << std::endl;
}

/**
 * @tc.name: CheckDPermission_005
 * @tc.desc: call CheckDPermission with illegal parameter
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDPermission_005, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_005 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    std::string localDeviceId = DEVICE_ID;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckDPermission(want,
        callerInfo, accountInfo, localDeviceId);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_005 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckDPermission_006
 * @tc.desc: call CheckDPermission with different account type
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDPermission_006, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_006 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    string localDeviceId = DEVICE_ID;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckDPermission(want,
        callerInfo, accountInfo, localDeviceId);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_006 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckDPermission_007
 * @tc.desc: call CheckDPermission with illegal ability info
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDPermission_007, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_007 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    string localDeviceId = DEVICE_ID;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckDPermission(want,
        callerInfo, accountInfo, localDeviceId);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_007 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckDPermission_008
 * @tc.desc: call CheckDPermission with same account type
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDPermission_008, TestSize.Level0)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_008 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    string localDeviceId = DEVICE_ID;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckDPermission(want,
        callerInfo, accountInfo, localDeviceId);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_008 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckDPermission_009
 * @tc.desc: call CheckDPermission with illegal account info
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDPermission_009, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_009 begin" << std::endl;
    AAFwk::Want want;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string localDeviceId = DEVICE_ID;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckDPermission(want,
        callerInfo, accountInfo, localDeviceId);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_009 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckDPermission_010
 * @tc.desc: call CheckDPermission with illegal account info
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckDPermission_010, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_010 begin" << std::endl;
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string localDeviceId = DEVICE_ID;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckDPermission(want,
        callerInfo, accountInfo, localDeviceId);
    EXPECT_TRUE(ret != ERR_OK);
    DTEST_LOG << "DistributedSchedPermissionTest CheckDPermission_010 end result:" << ret << std::endl;
}

/**
 * @tc.name: GetAccountInfo_001
 * @tc.desc: call GetAccountInfo with empty networkId
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, GetAccountInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetAccountInfo_001 begin" << std::endl;
    std::string remoteNetworkId;
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t ret = DistributedSchedPermission::GetInstance().GetAccountInfo(
        remoteNetworkId, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedPermissionTest GetAccountInfo_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: GetAccountInfo_002
 * @tc.desc: call GetAccountInfo with invalid networkId
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, GetAccountInfo_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetAccountInfo_002 begin" << std::endl;
    std::string remoteNetworkId = "0";
    CallerInfo callerInfo;
    IDistributedSched::AccountInfo accountInfo;
    int32_t ret = DistributedSchedPermission::GetInstance().GetAccountInfo(
        remoteNetworkId, callerInfo, accountInfo);
    EXPECT_EQ(ret, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedSchedPermissionTest GetAccountInfo_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: GetRelatedGroups_001
 * @tc.desc: call GetRelatedGroups with empty bundleNames
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, GetRelatedGroups_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_001 begin" << std::endl;
    std::string udid;
    std::vector<std::string> bundleNames;
    IDistributedSched::AccountInfo accountInfo;
    bool ret = DistributedSchedPermission::GetInstance().GetRelatedGroups(
        udid, bundleNames, accountInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: GetRelatedGroups_002
 * @tc.desc: call GetRelatedGroups with invalid bundleNames
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, GetRelatedGroups_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_002 begin" << std::endl;
    std::string udid = "0";
    std::vector<std::string> bundleNames = {"mock.bundle1", "mock.bundle2"};
    IDistributedSched::AccountInfo accountInfo;
    bool ret = DistributedSchedPermission::GetInstance().GetRelatedGroups(
        udid, bundleNames, accountInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: ParseGroupInfos_001
 * @tc.desc: call ParseGroupInfos with empty returnGroupStr
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, ParseGroupInfos_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest ParseGroupInfos_001 begin" << std::endl;
    std::string returnGroupStr;
    std::vector<GroupInfo> groupInfos;
    bool ret = DistributedSchedPermission::GetInstance().ParseGroupInfos(
        returnGroupStr, groupInfos);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: ParseGroupInfos_002
 * @tc.desc: call ParseGroupInfos with invalid returnGroupStr
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, ParseGroupInfos_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest ParseGroupInfos_002 begin" << std::endl;
    std::string returnGroupStr = "mockInvalidGroup";
    std::vector<GroupInfo> groupInfos;
    bool ret = DistributedSchedPermission::GetInstance().ParseGroupInfos(
        returnGroupStr, groupInfos);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: ParseGroupInfos_003
 * @tc.desc: call ParseGroupInfos
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, ParseGroupInfos_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest ParseGroupInfos_003 begin" << std::endl;
    std::string returnGroupStr = "[{\"groupName\":\"mockGroupName\",\"groupId\":\"mockGroupId\",";
    returnGroupStr += "\"groupOwner\":\"mockGroupOwner\",\"groupType\":0,\"groupVisibility\":0}]";
    std::vector<GroupInfo> groupInfos;
    bool ret = DistributedSchedPermission::GetInstance().ParseGroupInfos(
        returnGroupStr, groupInfos);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest GetRelatedGroups_003 end result:" << ret << std::endl;
}

/**
 * @tc.name: IsFoundationCall_001
 * @tc.desc: call IsFoundationCall not from foundation
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, IsFoundationCall_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest IsFoundationCall_001 begin" << std::endl;
    bool ret = DistributedSchedPermission::GetInstance().IsFoundationCall();
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest IsFoundationCall_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: IsFoundationCall_002
 * @tc.desc: call IsFoundationCall from foundation
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DistributedSchedPermissionTest, IsFoundationCall_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest IsFoundationCall_002 begin" << std::endl;
    DistributedSchedUtil::MockProcess(FOUNDATION_PROCESS_NAME);
    bool ret = DistributedSchedPermission::GetInstance().IsFoundationCall();
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest IsFoundationCall_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckAccountAccessPermission_001
 * @tc.desc: call CheckAccountAccessPermission in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckAccountAccessPermission_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_001 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = BUNDLE_NAME;
    bool ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckAccountAccessPermission_002
 * @tc.desc: call CheckAccountAccessPermission with invalid accessToken in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckAccountAccessPermission_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_002 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = BUNDLE_NAME;
    bool ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckAccountAccessPermission_003
 * @tc.desc: call CheckAccountAccessPermission with invalid groupId in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckAccountAccessPermission_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_003 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = INVALID_GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = BUNDLE_NAME;
    bool ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_003 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckAccountAccessPermission_004
 * @tc.desc: call CheckAccountAccessPermission with invalid bundleName in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckAccountAccessPermission_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_004 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = INVALID_BUNDLE_NAME;
    bool ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_004 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckAccountAccessPermission_005
 * @tc.desc: call CheckAccountAccessPermission in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckAccountAccessPermission_005, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_005 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = BUNDLE_NAME;
    bool ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_005 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckAccountAccessPermission_006
 * @tc.desc: call CheckAccountAccessPermission with invalid accessToken in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckAccountAccessPermission_006, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_006 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = BUNDLE_NAME;
    bool ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_006 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckAccountAccessPermission_007
 * @tc.desc: call CheckAccountAccessPermission with invalid groupId in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckAccountAccessPermission_007, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_007 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = INVALID_GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = BUNDLE_NAME;
    bool ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_007 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckAccountAccessPermission_008
 * @tc.desc: call CheckAccountAccessPermission with invalid bundleName in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckAccountAccessPermission_008, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_008 begin" << std::endl;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    string targetBundle = INVALID_BUNDLE_NAME;
    bool ret = DistributedSchedPermission::GetInstance().CheckAccountAccessPermission(
        callerInfo, accountInfo, targetBundle);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckAccountAccessPermission_008 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_001
 * @tc.desc: call CheckComponentAccessPermission in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_001 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_002
 * @tc.desc: call CheckComponentAccessPermission with invalid accessToken in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_002 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_003
 * @tc.desc: call CheckComponentAccessPermission with invalid groupId in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_003 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = INVALID_GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_003 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_004
 * @tc.desc: call CheckComponentAccessPermission with invalid bundleName in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_004 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", INVALID_BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_004 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_005
 * @tc.desc: call CheckComponentAccessPermission with invalid abilityName in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_005, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_005 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_005 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_006
 * @tc.desc: call CheckComponentAccessPermission with visible: true in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_006, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_006 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_006 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_007
 * @tc.desc: call CheckComponentAccessPermission with visible: false in same account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_007, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_007 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = false;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::SAME_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_007 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_008
 * @tc.desc: call CheckComponentAccessPermission in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_008, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_008 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_008 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_009
 * @tc.desc: call CheckComponentAccessPermission with invalid accessToken in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_009, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_009 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_009 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_010
 * @tc.desc: call CheckComponentAccessPermission with invalid groupId in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_010, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_010 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = INVALID_GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_010 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_011
 * @tc.desc: call CheckComponentAccessPermission with invalid bundleName in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_011, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_011 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", INVALID_BUNDLE_NAME, ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_011 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_012
 * @tc.desc: call CheckComponentAccessPermission with invalid abilityName in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_012, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_012 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_012 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_013
 * @tc.desc: call CheckComponentAccessPermission with visible: true in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_013, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_013 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = true;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_013 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckComponentAccessPermission_014
 * @tc.desc: call CheckComponentAccessPermission with visible: false in diff account
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckComponentAccessPermission_014, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_014 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.visible = false;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    IDistributedSched::AccountInfo accountInfo;
    accountInfo.accountType = IDistributedSched::DIFF_ACCOUNT_TYPE;
    std::string groupId = GROUP_ID;
    accountInfo.groupIdList.push_back(groupId);
    AAFwk::Want want;
    AppExecFwk::ElementName element("", BUNDLE_NAME, INVALID_ABILITY_NAME);
    want.SetElement(element);
    bool ret = DistributedSchedPermission::GetInstance().CheckComponentAccessPermission(targetAbility,
        callerInfo, accountInfo, want);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckComponentAccessPermission_014 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_001
 * @tc.desc: call CheckCustomPermission with no permissions
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_001 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(targetAbility, callerInfo);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_002
 * @tc.desc: call CheckCustomPermission with no permissions and invalid accessToken
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_002 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(targetAbility, callerInfo);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_003
 * @tc.desc: call CheckCustomPermission with invalid permissions
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_003 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.emplace_back(INVALID_PERMISSION_NAME);
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(targetAbility, callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_003 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_004
 * @tc.desc: call CheckCustomPermission with invalid permissions and invalid accessToken
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_004, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_004 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.emplace_back(INVALID_PERMISSION_NAME);
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(targetAbility, callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_004 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_005
 * @tc.desc: call CheckCustomPermission with correct permissions
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_005, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_005 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.emplace_back(PERMISSION_NAME);
    CallerInfo callerInfo;
    callerInfo.accessToken = ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(targetAbility, callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_005 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckCustomPermission_006
 * @tc.desc: call CheckCustomPermission with correct permissions and invalid accessToken
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckCustomPermission_006, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_006 begin" << std::endl;
    AppExecFwk::AbilityInfo targetAbility;
    targetAbility.permissions.emplace_back(PERMISSION_NAME);
    CallerInfo callerInfo;
    callerInfo.accessToken = INVALID_ACCESS_TOKEN;
    bool ret = DistributedSchedPermission::GetInstance().CheckCustomPermission(targetAbility, callerInfo);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DistributedSchedPermissionTest CheckCustomPermission_006 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckPermission_001
 * @tc.desc: call CheckPermission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckPermission_001, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_001 begin" << std::endl;
    uint32_t accessToken = ACCESS_TOKEN;
    string permissionName = PERMISSION_NAME;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckPermission(accessToken, permissionName);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_001 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckPermission_002
 * @tc.desc: call CheckPermission with invalid accessToken
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckPermission_002, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_002 begin" << std::endl;
    uint32_t accessToken = INVALID_ACCESS_TOKEN;
    string permissionName = PERMISSION_NAME;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckPermission(accessToken, permissionName);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_002 end result:" << ret << std::endl;
}

/**
 * @tc.name: CheckPermission_003
 * @tc.desc: call CheckPermission with invalid permission
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, CheckPermission_003, TestSize.Level1)
{
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_003 begin" << std::endl;
    uint32_t accessToken = INVALID_ACCESS_TOKEN;
    string permissionName = PERMISSION_NAME;
    int32_t ret = DistributedSchedPermission::GetInstance().CheckPermission(accessToken, permissionName);
    EXPECT_EQ(ret, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedPermissionTest CheckPermission_003 end result:" << ret << std::endl;
}

/**
 * @tc.name: from_json_001
 * @tc.desc: parse groupInfo from json
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, FromJson_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest FromJson_001 begin" << std::endl;
    GroupInfo groupInfo;
    nlohmann::json jsonObject = nlohmann::json{ 
        {FIELD_GROUP_NAME, MOCK_FIELD_GROUP_NAME},
        {FIELD_GROUP_ID, MOCK_FIELD_GROUP_ID},
        {FIELD_GROUP_OWNER, MOCK_FIELD_GROUP_OWNER},
        {FIELD_GROUP_TYPE, MOCK_FIELD_GROUP_TYPE},
        {FIELD_GROUP_VISIBILITY, MOCK_FIELD_GROUP_VISIBILITY}
    };
    if (jsonObject.is_discarded()) {
        return;
    }
    from_json(jsonObject, groupInfo);
    EXPECT_EQ(groupInfo.groupName, MOCK_FIELD_GROUP_NAME);
    DTEST_LOG << "DistributedSchedPermissionTest FromJson_001 end" <<  std::endl;
}

/**
 * @tc.name: from_json_002
 * @tc.desc: parse groupInfo from json with invalid params
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedPermissionTest, FromJson_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedPermissionTest FromJson_002 begin" << std::endl;
    GroupInfo groupInfo;
    nlohmann::json jsonObject;
    if (jsonObject.is_discarded()) {
        return;
    }
    from_json(jsonObject, groupInfo);
    EXPECT_EQ(groupInfo.groupName, "");
    DTEST_LOG << "DistributedSchedPermissionTest FromJson_002 end " <<  std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS