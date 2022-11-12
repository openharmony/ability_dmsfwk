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

#include "dms_version_manager_test.h"

#define private public
#include "dms_version_manager.h"
#undef private

#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
void DmsVersionManagerTest::SetUpTestCase()
{
    DTEST_LOG << "DmsVersionManagerTest::SetUpTestCase" << std::endl;
}

void DmsVersionManagerTest::TearDownTestCase()
{
    DTEST_LOG << "DmsVersionManagerTest::TearDownTestCase" << std::endl;
}

void DmsVersionManagerTest::TearDown()
{
    DTEST_LOG << "DmsVersionManagerTest::TearDown" << std::endl;
}

void DmsVersionManagerTest::SetUp()
{
    DTEST_LOG << "DmsVersionManagerTest::SetUp" << std::endl;
}

/**
 * @tc.name: CompareDmsVersionTest_001
 * @tc.desc: test dmsVersion lower than thresholdDmsVersion
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, CompareDmsVersionTest_001, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest CompareDmsVersionTest_001 begin" << std::endl;
    DmsVersion thresholdDmsVersion = {3, 2, 1};
    DmsVersion dmsVersion = {2, 2, 1};
    bool result = DmsVersionManager::CompareDmsVersion(dmsVersion, thresholdDmsVersion);
    EXPECT_EQ(result, true);
    DTEST_LOG << "DmsVersionManagerTest CompareDmsVersionTest_001 end ret:" << result << std::endl;
}

/**
 * @tc.name: CompareDmsVersionTest_002
 * @tc.desc: test dmsVersion lower than thresholdDmsVersion
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, CompareDmsVersionTest_002, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest CompareDmsVersionTest_002 begin" << std::endl;
    DmsVersion thresholdDmsVersion = {3, 2, 1};
    DmsVersion dmsVersion = {3, 1, 1};
    bool result = DmsVersionManager::CompareDmsVersion(dmsVersion, thresholdDmsVersion);
    EXPECT_EQ(result, true);
    DTEST_LOG << "DmsVersionManagerTest CompareDmsVersionTest_002 end ret:" << result << std::endl;
}

/**
 * @tc.name: CompareDmsVersionTest_003
 * @tc.desc: test dmsVersion lower than thresholdDmsVersion
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, CompareDmsVersionTest_003, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest CompareDmsVersionTest_003 begin" << std::endl;
    DmsVersion thresholdDmsVersion = {3, 2, 1};
    DmsVersion dmsVersion = {3, 2, 0};
    bool result = DmsVersionManager::CompareDmsVersion(dmsVersion, thresholdDmsVersion);
    EXPECT_EQ(result, true);
    DTEST_LOG << "DmsVersionManagerTest CompareDmsVersionTest_003 end ret:" << result << std::endl;
}

/**
 * @tc.name: CompareDmsVersionTest_004
 * @tc.desc: test dmsVersion higher than thresholdDmsVersion
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, CompareDmsVersionTest_004, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest CompareDmsVersionTest_004 begin" << std::endl;
    DmsVersion thresholdDmsVersion = {3, 2, 1};
    DmsVersion dmsVersion = {3, 2, 2};
    bool result = DmsVersionManager::CompareDmsVersion(dmsVersion, thresholdDmsVersion);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DmsVersionManagerTest CompareDmsVersionTest_004 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseDmsVersionTest_001
 * @tc.desc: test call ParseDmsVersion with empty dmsVersionData
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseDmsVersionTest_001, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_001 begin" << std::endl;
    std::string dmsVersionData;
    DmsVersion dmsVersion;
    bool result = DmsVersionManager::ParseDmsVersion(dmsVersionData, dmsVersion);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_001 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseDmsVersionTest_002
 * @tc.desc: test call ParseDmsVersion with invalid dmsVersionData
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseDmsVersionTest_002, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_002 begin" << std::endl;
    std::string dmsVersionData = "invalid.2.1";
    DmsVersion dmsVersion;
    bool result = DmsVersionManager::ParseDmsVersion(dmsVersionData, dmsVersion);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_002 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseDmsVersionTest_003
 * @tc.desc: test call ParseDmsVersion with invalid dmsVersionData
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseDmsVersionTest_003, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_003 begin" << std::endl;
    std::string dmsVersionData = "-2.2.1";
    DmsVersion dmsVersion;
    bool result = DmsVersionManager::ParseDmsVersion(dmsVersionData, dmsVersion);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_003 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseDmsVersionTest_004
 * @tc.desc: test call ParseDmsVersion with invalid dmsVersionData
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseDmsVersionTest_004, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_004 begin" << std::endl;
    std::string dmsVersionData = "3.invalid.1";
    DmsVersion dmsVersion;
    bool result = DmsVersionManager::ParseDmsVersion(dmsVersionData, dmsVersion);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_004 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseDmsVersionTest_005
 * @tc.desc: test call ParseDmsVersion with invalid dmsVersionData
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseDmsVersionTest_005, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_005 begin" << std::endl;
    std::string dmsVersionData = "3.-2.1";
    DmsVersion dmsVersion;
    bool result = DmsVersionManager::ParseDmsVersion(dmsVersionData, dmsVersion);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_005 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseDmsVersionTest_006
 * @tc.desc: test call ParseDmsVersion with invalid dmsVersionData
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseDmsVersionTest_006, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_006 begin" << std::endl;
    std::string dmsVersionData = "3.2.invalid";
    DmsVersion dmsVersion;
    bool result = DmsVersionManager::ParseDmsVersion(dmsVersionData, dmsVersion);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_006 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseDmsVersionTest_007
 * @tc.desc: test call ParseDmsVersion with invalid dmsVersionData
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseDmsVersionTest_007, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_007 begin" << std::endl;
    std::string dmsVersionData = "3.2.-1";
    DmsVersion dmsVersion;
    bool result = DmsVersionManager::ParseDmsVersion(dmsVersionData, dmsVersion);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_007 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseDmsVersionTest_008
 * @tc.desc: test call ParseDmsVersion
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseDmsVersionTest_008, TestSize.Level2)
{
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_008 begin" << std::endl;
    std::string dmsVersionData = "3.2.1";
    DmsVersion dmsVersion;
    bool result = DmsVersionManager::ParseDmsVersion(dmsVersionData, dmsVersion);
    EXPECT_EQ(result, true);
    DTEST_LOG << "DmsVersionManagerTest ParseDmsVersionTest_008 end ret:" << result << std::endl;
}

/**
 * @tc.name: GetDmsVersionDataFromAppInfo_001
 * @tc.desc: test call GetDmsVersionDataFromAppInfo with empty data
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, GetDmsVersionDataFromAppInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest GetDmsVersionDataFromAppInfo_001 begin" << std::endl;
    std::string packageNamesData;
    std::string versionsData;
    std::string dmsVersionData;
    int32_t result = DmsVersionManager::GetDmsVersionDataFromAppInfo(packageNamesData,
        versionsData, dmsVersionData);
    EXPECT_EQ(result, DMS_VERSION_EMPTY);
    DTEST_LOG << "DmsVersionManagerTest GetDmsVersionDataFromAppInfo_001 end ret:" << result << std::endl;
}

/**
 * @tc.name: GetDmsVersionDataFromAppInfo_002
 * @tc.desc: test call GetDmsVersionDataFromAppInfo with empty versionsData
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, GetDmsVersionDataFromAppInfo_002, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest GetDmsVersionDataFromAppInfo_002 begin" << std::endl;
    std::string packageNamesData = "mockData";
    std::string versionsData;
    std::string dmsVersionData;
    int32_t result = DmsVersionManager::GetDmsVersionDataFromAppInfo(packageNamesData,
        versionsData, dmsVersionData);
    EXPECT_EQ(result, DMS_VERSION_EMPTY);
    DTEST_LOG << "DmsVersionManagerTest GetDmsVersionDataFromAppInfo_002 end ret:" << result << std::endl;
}

/**
 * @tc.name: GetDmsVersionDataFromAppInfo_003
 * @tc.desc: test call GetDmsVersionDataFromAppInfo with invalid data
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, GetDmsVersionDataFromAppInfo_003, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest GetDmsVersionDataFromAppInfo_003 begin" << std::endl;
    std::string packageNamesData = "a,b,c";
    std::string versionsData = "1.1,2.2";
    std::string dmsVersionData;
    int32_t result = DmsVersionManager::GetDmsVersionDataFromAppInfo(packageNamesData,
        versionsData, dmsVersionData);
    EXPECT_EQ(result, DMS_VERSION_PARSE_EXCEPTION);
    DTEST_LOG << "DmsVersionManagerTest GetDmsVersionDataFromAppInfo_003 end ret:" << result << std::endl;
}

/**
 * @tc.name: GetDmsVersionDataFromAppInfo_004
 * @tc.desc: test call GetDmsVersionDataFromAppInfo with invalid data
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, GetDmsVersionDataFromAppInfo_004, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest GetDmsVersionDataFromAppInfo_004 begin" << std::endl;
    std::string packageNamesData = "a,b,c";
    std::string versionsData = "1.1,2.2,3.3";
    std::string dmsVersionData;
    int32_t result = DmsVersionManager::GetDmsVersionDataFromAppInfo(packageNamesData,
        versionsData, dmsVersionData);
    EXPECT_EQ(result, DMS_VERSION_EMPTY);
    DTEST_LOG << "DmsVersionManagerTest GetDmsVersionDataFromAppInfo_004 end ret:" << result << std::endl;
}

/**
 * @tc.name: GetDmsVersionDataFromAppInfo_005
 * @tc.desc: test call GetDmsVersionDataFromAppInfo
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, GetDmsVersionDataFromAppInfo_005, TestSize.Level2)
{
    DTEST_LOG << "DmsVersionManagerTest GetDmsVersionDataFromAppInfo_005 begin" << std::endl;
    std::string packageNamesData = "a,b,dmsfwk";
    std::string versionsData = "1.1,2.2,3.3";
    std::string dmsVersionData;
    int32_t result = DmsVersionManager::GetDmsVersionDataFromAppInfo(packageNamesData,
        versionsData, dmsVersionData);
    EXPECT_EQ(result, ERR_OK);
    DTEST_LOG << "DmsVersionManagerTest GetDmsVersionDataFromAppInfo_005 end ret:" << result << std::endl;
}

/**
 * @tc.name: GetAppInfoFromDP_001
 * @tc.desc: test call GetAppInfoFromDP with invalid device id
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, GetAppInfoFromDP_001, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest GetAppInfoFromDP_001 begin" << std::endl;
    std::string deviceId = "1";
    std::string appInfoJson;
    int32_t result = DmsVersionManager::GetAppInfoFromDP(deviceId, appInfoJson);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DmsVersionManagerTest GetAppInfoFromDP_001 end ret:" << result << std::endl;
}

/**
 * @tc.name: GetAppInfoFromDP_002
 * @tc.desc: test call GetAppInfoFromDP with local device id
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, GetAppInfoFromDP_002, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest GetAppInfoFromDP_002 begin" << std::endl;
    std::string deviceId;
    std::string appInfoJson;
    int32_t result = DmsVersionManager::GetAppInfoFromDP(deviceId, appInfoJson);
    EXPECT_EQ(result, ERR_OK);
    DTEST_LOG << "DmsVersionManagerTest GetAppInfoFromDP_002 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseAppInfo_001
 * @tc.desc: test call ParseAppInfo with appInfoJsonDatadata is empty
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseAppInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_001 begin" << std::endl;
    std::string appInfoJsonData;
    std::string packageNamesData;
    std::string versionsData;
    int32_t result = DmsVersionManager::ParseAppInfo(appInfoJsonData,
        packageNamesData, versionsData);
    EXPECT_EQ(result, DMS_VERSION_EMPTY);
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_001 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseAppInfo_002
 * @tc.desc: test call ParseAppInfo with packageNamesData is empty
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseAppInfo_002, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_002 begin" << std::endl;
    std::string appInfoJsonData = "{\"versions\":\"3.2.0\"}";
    std::string packageNamesData;
    std::string versionsData;
    int32_t result = DmsVersionManager::ParseAppInfo(appInfoJsonData,
        packageNamesData, versionsData);
    EXPECT_EQ(result, DMS_VERSION_EMPTY);
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_002 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseAppInfo_003
 * @tc.desc: test call ParseAppInfo with invalid packageNamesData
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseAppInfo_003, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_003 begin" << std::endl;
    std::string appInfoJsonData = "{\"packageNames\":1,\"versions\":\"3.2.0\"}";
    std::string packageNamesData;
    std::string versionsData;
    int32_t result = DmsVersionManager::ParseAppInfo(appInfoJsonData,
        packageNamesData, versionsData);
    EXPECT_EQ(result, DMS_VERSION_EMPTY);
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_003 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseAppInfo_004
 * @tc.desc: test call ParseAppInfo with versionsData is empty
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseAppInfo_004, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_004 begin" << std::endl;
    std::string appInfoJsonData = "{\"packageNames\":\"dmsfwk\"}";
    std::string packageNamesData;
    std::string versionsData;
    int32_t result = DmsVersionManager::ParseAppInfo(appInfoJsonData,
        packageNamesData, versionsData);
    EXPECT_EQ(result, DMS_VERSION_EMPTY);
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_004 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseAppInfo_005
 * @tc.desc: test call ParseAppInfo with invalid versionsData
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseAppInfo_005, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_005 begin" << std::endl;
    std::string appInfoJsonData = "{\"packageNames\":\"dmsfwk\",\"versions\":1}";
    std::string packageNamesData;
    std::string versionsData;
    int32_t result = DmsVersionManager::ParseAppInfo(appInfoJsonData,
        packageNamesData, versionsData);
    EXPECT_EQ(result, DMS_VERSION_EMPTY);
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_005 end ret:" << result << std::endl;
}

/**
 * @tc.name: ParseAppInfo_006
 * @tc.desc: test call ParseAppInfo
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, ParseAppInfo_006, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_006 begin" << std::endl;
    std::string appInfoJsonData = "{\"packageNames\":\"dmsfwk\",\"versions\":\"3.2.0\"}";
    std::string packageNamesData;
    std::string versionsData;
    int32_t result = DmsVersionManager::ParseAppInfo(appInfoJsonData,
        packageNamesData, versionsData);
    EXPECT_EQ(result, ERR_OK);
    DTEST_LOG << "DmsVersionManagerTest ParseAppInfo_006 end ret:" << result << std::endl;
}

/**
 * @tc.name: GetRemoteDmsVersion_001
 * @tc.desc: test call GetRemoteDmsVersion with invalid deviceId
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, GetRemoteDmsVersion_001, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest GetRemoteDmsVersion_001 begin" << std::endl;
    std::string deviceId = "0";
    DmsVersion dmsVersion;
    int32_t result = DmsVersionManager::GetRemoteDmsVersion(deviceId, dmsVersion);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DmsVersionManagerTest GetRemoteDmsVersion_001 end ret:" << result << std::endl;
}

/**
 * @tc.name: GetRemoteDmsVersion_002
 * @tc.desc: test call GetRemoteDmsVersion with local deviceId
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, GetRemoteDmsVersion_002, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest GetRemoteDmsVersion_002 begin" << std::endl;
    std::string deviceId;
    DmsVersion dmsVersion;
    int32_t result = DmsVersionManager::GetRemoteDmsVersion(deviceId, dmsVersion);
    EXPECT_EQ(result, ERR_OK);
    DTEST_LOG << "DmsVersionManagerTest GetRemoteDmsVersion_002 end ret:" << result << std::endl;
}

/**
 * @tc.name: IsRemoteDmsVersionLower_001
 * @tc.desc: test call IsRemoteDmsVersionLower with invalid deviceId
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, IsRemoteDmsVersionLower_001, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest IsRemoteDmsVersionLower_001 begin" << std::endl;
    std::string deviceId = "0";
    DmsVersion thresholdDmsVersion = {3, 2, 0};
    bool result = DmsVersionManager::IsRemoteDmsVersionLower(deviceId, thresholdDmsVersion);
    EXPECT_EQ(result, true);
    DTEST_LOG << "DmsVersionManagerTest IsRemoteDmsVersionLower_001 end ret:" << result << std::endl;
}

/**
 * @tc.name: IsRemoteDmsVersionLower_002
 * @tc.desc: test call IsRemoteDmsVersionLower with local deviceId
 * @tc.type: FUNC
 * @tc.require: I5RWKZ
 */
HWTEST_F(DmsVersionManagerTest, IsRemoteDmsVersionLower_002, TestSize.Level3)
{
    DTEST_LOG << "DmsVersionManagerTest IsRemoteDmsVersionLower_002 begin" << std::endl;
    std::string deviceId;
    DmsVersion thresholdDmsVersion = {3, 2, 0};
    bool result = DmsVersionManager::IsRemoteDmsVersionLower(deviceId, thresholdDmsVersion);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DmsVersionManagerTest IsRemoteDmsVersionLower_002 end ret:" << result << std::endl;
}
}
}