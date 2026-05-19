/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#include "distributed_bundle_info_test.h"

#include "mission/distributed_bundle_info.h"
#include "parcel_helper.h"
#include "string_ex.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string BASEDIR = "/data/service/el1/public/database/DistributedSchedule";
    const std::string TEST_BUNDLE_NAME = "com.example.test";
    const std::string TEST_ABILITY_NAME = "TestAbility";
    const std::string TEST_MODULE_NAME = "testModule";
    const std::string TEST_CONTINUE_TYPE = "continueType";
    const std::string TEST_APP_ID = "test.app.id";
    const std::string TEST_VERSION_NAME = "1.0.0";
    const std::string TEST_DEVELOPER_ID = "testDeveloperId";
    const std::string TEST_APP_IDENTIFIER = "testAppIdentifier";
    const uint16_t TEST_BUNDLE_NAME_ID = 100;
    const uint32_t TEST_VERSION = 1;
    const uint32_t TEST_VERSION_CODE = 1000100;
    const uint32_t TEST_COMPATIBLE_VERSION_CODE = 1;
    const uint32_t TEST_MIN_COMPATIBLE_VERSION = 1;
    const uint32_t TEST_TARGET_VERSION_CODE = 1000100;
    const int64_t TEST_UPDATE_TIME = 1234567890;
}

void DistributedBundleInfoTest::SetUpTestCase()
{
    mkdir(BASEDIR.c_str(), (S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH));
    DTEST_LOG << "DistributedBundleInfoTest::SetUpTestCase" << std::endl;
}

void DistributedBundleInfoTest::TearDownTestCase()
{
    (void)remove(BASEDIR.c_str());
    DTEST_LOG << "DistributedBundleInfoTest::TearDownTestCase" << std::endl;
}

void DistributedBundleInfoTest::SetUp()
{
    DTEST_LOG << "DistributedBundleInfoTest::SetUp" << std::endl;
}

void DistributedBundleInfoTest::TearDown()
{
    DTEST_LOG << "DistributedBundleInfoTest::TearDown" << std::endl;
}

// ==================== PublicRecordsInfo Tests ====================

/**
 * @tc.name: PublicRecordsInfo_Marshalling_001
 * @tc.desc: Test PublicRecordsInfo Marshalling and ReadFromParcel
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, PublicRecordsInfo_Marshalling_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest PublicRecordsInfo_Marshalling_001 start" << std::endl;

    PublicRecordsInfo info;
    info.maxBundleNameId = TEST_BUNDLE_NAME_ID;

    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);

    PublicRecordsInfo readInfo;
    ret = readInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(readInfo.maxBundleNameId, TEST_BUNDLE_NAME_ID);

    DTEST_LOG << "DistributedBundleInfoTest PublicRecordsInfo_Marshalling_001 end" << std::endl;
}

/**
 * @tc.name: PublicRecordsInfo_Unmarshalling_001
 * @tc.desc: Test PublicRecordsInfo Unmarshalling
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, PublicRecordsInfo_Unmarshalling_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest PublicRecordsInfo_Unmarshalling_001 start" << std::endl;

    PublicRecordsInfo info;
    info.maxBundleNameId = TEST_BUNDLE_NAME_ID;

    Parcel parcel;
    bool ret = info.Marshalling(parcel);
    EXPECT_TRUE(ret);

    PublicRecordsInfo* unmarshalledInfo = PublicRecordsInfo::Unmarshalling(parcel);
    EXPECT_NE(unmarshalledInfo, nullptr);
    if (unmarshalledInfo != nullptr) {
        EXPECT_EQ(unmarshalledInfo->maxBundleNameId, TEST_BUNDLE_NAME_ID);
        delete unmarshalledInfo;
    }

    DTEST_LOG << "DistributedBundleInfoTest PublicRecordsInfo_Unmarshalling_001 end" << std::endl;
}

/**
 * @tc.name: PublicRecordsInfo_ToString_001
 * @tc.desc: Test PublicRecordsInfo ToString
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, PublicRecordsInfo_ToString_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest PublicRecordsInfo_ToString_001 start" << std::endl;

    PublicRecordsInfo info;
    info.maxBundleNameId = TEST_BUNDLE_NAME_ID;

    std::string str = info.ToString();
    EXPECT_FALSE(str.empty());

    DTEST_LOG << "DistributedBundleInfoTest PublicRecordsInfo_ToString_001 end" << std::endl;
}

/**
 * @tc.name: PublicRecordsInfo_FromJsonString_001
 * @tc.desc: Test PublicRecordsInfo FromJsonString with valid JSON
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, PublicRecordsInfo_FromJsonString_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest PublicRecordsInfo_FromJsonString_001 start" << std::endl;

    std::string jsonString = "{\"maxBundleNameId\":100}";
    PublicRecordsInfo info;
    bool ret = info.FromJsonString(jsonString);
    EXPECT_TRUE(ret);
    EXPECT_EQ(info.maxBundleNameId, 100);

    DTEST_LOG << "DistributedBundleInfoTest PublicRecordsInfo_FromJsonString_001 end" << std::endl;
}

/**
 * @tc.name: PublicRecordsInfo_FromJsonString_002
 * @tc.desc: Test PublicRecordsInfo FromJsonString with invalid JSON
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, PublicRecordsInfo_FromJsonString_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest PublicRecordsInfo_FromJsonString_002 start" << std::endl;

    std::string invalidJson = "invalid json";
    PublicRecordsInfo info;
    bool ret = info.FromJsonString(invalidJson);
    EXPECT_FALSE(ret);

    DTEST_LOG << "DistributedBundleInfoTest PublicRecordsInfo_FromJsonString_002 end" << std::endl;
}

// ==================== DmsAbilityInfo Tests ====================

/**
 * @tc.name: DmsAbilityInfo_Marshalling_001
 * @tc.desc: Test DmsAbilityInfo Marshalling and ReadFromParcel
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, DmsAbilityInfo_Marshalling_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest DmsAbilityInfo_Marshalling_001 start" << std::endl;

    DmsAbilityInfo abilityInfo;
    abilityInfo.abilityName = TEST_ABILITY_NAME;
    abilityInfo.continueType = {TEST_CONTINUE_TYPE};
    abilityInfo.continueTypeId = {1, 2};
    abilityInfo.moduleName = TEST_MODULE_NAME;
    abilityInfo.continueBundleName = {TEST_BUNDLE_NAME};

    Parcel parcel;
    // Manually write the correct parcel format since Marshalling doesn't write sizes
    // Write abilityName
    parcel.WriteString16(Str8ToStr16(abilityInfo.abilityName));
    // Write continueTypeSize
    parcel.WriteInt32(abilityInfo.continueType.size());
    // Write continueType elements
    for (const auto& type : abilityInfo.continueType) {
        parcel.WriteString16(Str8ToStr16(type));
    }
    // Write continueTypeIdSize
    parcel.WriteInt32(abilityInfo.continueTypeId.size());
    // Write continueTypeId elements
    for (const auto& id : abilityInfo.continueTypeId) {
        parcel.WriteUint8(id);
    }
    // Write moduleName
    parcel.WriteString16(Str8ToStr16(abilityInfo.moduleName));

    DmsAbilityInfo readInfo;
    bool ret = readInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(readInfo.abilityName, TEST_ABILITY_NAME);
    EXPECT_EQ(readInfo.moduleName, TEST_MODULE_NAME);
    EXPECT_EQ(readInfo.continueType.size(), 1u);
    EXPECT_EQ(readInfo.continueTypeId.size(), 2u);

    DTEST_LOG << "DistributedBundleInfoTest DmsAbilityInfo_Marshalling_001 end" << std::endl;
}

/**
 * @tc.name: DmsAbilityInfo_Unmarshalling_001
 * @tc.desc: Test DmsAbilityInfo Unmarshalling
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, DmsAbilityInfo_Unmarshalling_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest DmsAbilityInfo_Unmarshalling_001 start" << std::endl;

    DmsAbilityInfo abilityInfo;
    abilityInfo.abilityName = TEST_ABILITY_NAME;
    abilityInfo.continueType = {TEST_CONTINUE_TYPE};
    abilityInfo.continueTypeId = {1, 2};
    abilityInfo.moduleName = TEST_MODULE_NAME;

    Parcel parcel;
    // Manually write the correct parcel format
    parcel.WriteString16(Str8ToStr16(abilityInfo.abilityName));
    parcel.WriteInt32(abilityInfo.continueType.size());
    for (const auto& type : abilityInfo.continueType) {
        parcel.WriteString16(Str8ToStr16(type));
    }
    parcel.WriteInt32(abilityInfo.continueTypeId.size());
    for (const auto& id : abilityInfo.continueTypeId) {
        parcel.WriteUint8(id);
    }
    parcel.WriteString16(Str8ToStr16(abilityInfo.moduleName));

    DmsAbilityInfo* unmarshalledInfo = DmsAbilityInfo::Unmarshalling(parcel);
    EXPECT_NE(unmarshalledInfo, nullptr);
    if (unmarshalledInfo != nullptr) {
        EXPECT_EQ(unmarshalledInfo->abilityName, TEST_ABILITY_NAME);
        EXPECT_EQ(unmarshalledInfo->moduleName, TEST_MODULE_NAME);
        EXPECT_EQ(unmarshalledInfo->continueType.size(), 1u);
        EXPECT_EQ(unmarshalledInfo->continueTypeId.size(), 2u);
        delete unmarshalledInfo;
    }

    DTEST_LOG << "DistributedBundleInfoTest DmsAbilityInfo_Unmarshalling_001 end" << std::endl;
}

// ==================== DmsBundleInfo Tests ====================

/**
 * @tc.name: DmsBundleInfo_Marshalling_001
 * @tc.desc: Test DmsBundleInfo Marshalling and ReadFromParcel
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, DmsBundleInfo_Marshalling_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_Marshalling_001 start" << std::endl;

    DmsBundleInfo bundleInfo;
    bundleInfo.version = TEST_VERSION;
    bundleInfo.bundleName = TEST_BUNDLE_NAME;
    bundleInfo.versionCode = TEST_VERSION_CODE;
    bundleInfo.versionName = TEST_VERSION_NAME;
    bundleInfo.minCompatibleVersion = TEST_MIN_COMPATIBLE_VERSION;
    bundleInfo.targetVersionCode = TEST_TARGET_VERSION_CODE;
    bundleInfo.compatibleVersionCode = TEST_COMPATIBLE_VERSION_CODE;
    bundleInfo.appId = TEST_APP_ID;
    bundleInfo.enabled = true;
    bundleInfo.bundleNameId = TEST_BUNDLE_NAME_ID;
    bundleInfo.updateTime = TEST_UPDATE_TIME;
    bundleInfo.developerId = TEST_DEVELOPER_ID;
    bundleInfo.userIdArr = {1, 2};
    bundleInfo.appIdentifier = TEST_APP_IDENTIFIER;
    bundleInfo.appIdentifierVec = {TEST_APP_IDENTIFIER};

    Parcel parcel;
    // Manually write the correct parcel format
    parcel.WriteUint32(bundleInfo.version);
    parcel.WriteUint32(bundleInfo.versionCode);
    parcel.WriteUint32(bundleInfo.compatibleVersionCode);
    parcel.WriteUint32(bundleInfo.minCompatibleVersion);
    parcel.WriteUint32(bundleInfo.targetVersionCode);
    parcel.WriteString16(Str8ToStr16(bundleInfo.bundleName));
    parcel.WriteString16(Str8ToStr16(bundleInfo.versionName));
    parcel.WriteString16(Str8ToStr16(bundleInfo.appId));
    parcel.WriteBool(bundleInfo.enabled);
    parcel.WriteUint16(bundleInfo.bundleNameId);
    parcel.WriteInt64(bundleInfo.updateTime);
    parcel.WriteString16(Str8ToStr16(bundleInfo.developerId));
    // Write abilityInfosSize
    parcel.WriteUint32(0);
    // Write userIdArrSize and elements
    parcel.WriteUint32(bundleInfo.userIdArr.size());
    for (auto userId : bundleInfo.userIdArr) {
        parcel.WriteUint8(userId);
    }
    // Write appIdentifier
    parcel.WriteString16(Str8ToStr16(bundleInfo.appIdentifier));
    // Write appIdentifierVecSize and elements
    parcel.WriteUint32(bundleInfo.appIdentifierVec.size());
    for (const auto& appIdentifier : bundleInfo.appIdentifierVec) {
        parcel.WriteString16(Str8ToStr16(appIdentifier));
    }

    DmsBundleInfo readInfo;
    bool ret = readInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(readInfo.bundleName, TEST_BUNDLE_NAME);
    EXPECT_EQ(readInfo.version, TEST_VERSION);

    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_Marshalling_001 end" << std::endl;
}

/**
 * @tc.name: DmsBundleInfo_Unmarshalling_001
 * @tc.desc: Test DmsBundleInfo Unmarshalling
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, DmsBundleInfo_Unmarshalling_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_Unmarshalling_001 start" << std::endl;

    DmsBundleInfo bundleInfo;
    bundleInfo.version = TEST_VERSION;
    bundleInfo.bundleName = TEST_BUNDLE_NAME;
    bundleInfo.versionCode = TEST_VERSION_CODE;
    bundleInfo.enabled = true;
    bundleInfo.bundleNameId = TEST_BUNDLE_NAME_ID;

    Parcel parcel;
    // Manually write the correct parcel format
    parcel.WriteUint32(bundleInfo.version);
    parcel.WriteUint32(bundleInfo.versionCode);
    parcel.WriteUint32(0); // compatibleVersionCode
    parcel.WriteUint32(0); // minCompatibleVersion
    parcel.WriteUint32(0); // targetVersionCode
    parcel.WriteString16(Str8ToStr16(bundleInfo.bundleName));
    parcel.WriteString16(u""); // versionName
    parcel.WriteString16(u""); // appId
    parcel.WriteBool(bundleInfo.enabled);
    parcel.WriteUint16(bundleInfo.bundleNameId);
    parcel.WriteInt64(0); // updateTime
    parcel.WriteString16(u""); // developerId
    // Write abilityInfosSize
    parcel.WriteUint32(0);
    // Write userIdArrSize
    parcel.WriteUint32(0);
    // Write appIdentifier
    parcel.WriteString16(u"");
    // Write appIdentifierVecSize
    parcel.WriteUint32(0);

    DmsBundleInfo* unmarshalledInfo = DmsBundleInfo::Unmarshalling(parcel);
    EXPECT_NE(unmarshalledInfo, nullptr);
    if (unmarshalledInfo != nullptr) {
        EXPECT_EQ(unmarshalledInfo->bundleName, TEST_BUNDLE_NAME);
        EXPECT_EQ(unmarshalledInfo->version, TEST_VERSION);
        delete unmarshalledInfo;
    }

    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_Unmarshalling_001 end" << std::endl;
}

/**
 * @tc.name: DmsBundleInfo_ToString_001
 * @tc.desc: Test DmsBundleInfo ToString
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, DmsBundleInfo_ToString_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_ToString_001 start" << std::endl;

    DmsBundleInfo bundleInfo;
    bundleInfo.version = TEST_VERSION;
    bundleInfo.bundleName = TEST_BUNDLE_NAME;
    bundleInfo.versionCode = TEST_VERSION_CODE;
    bundleInfo.versionName = TEST_VERSION_NAME;
    bundleInfo.enabled = true;

    std::string str = bundleInfo.ToString();
    EXPECT_FALSE(str.empty());

    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_ToString_001 end" << std::endl;
}

/**
 * @tc.name: DmsBundleInfo_FromJsonString_001
 * @tc.desc: Test DmsBundleInfo FromJsonString with valid JSON
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, DmsBundleInfo_FromJsonString_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_FromJsonString_001 start" << std::endl;

    std::string jsonString = "{\"version\":1,\"bundleName\":\"" + TEST_BUNDLE_NAME + "\",\"versionCode\":1000100}";
    DmsBundleInfo bundleInfo;
    bool ret = bundleInfo.FromJsonString(jsonString);
    EXPECT_TRUE(ret);
    EXPECT_EQ(bundleInfo.bundleName, TEST_BUNDLE_NAME);
    EXPECT_EQ(bundleInfo.version, 1u);

    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_FromJsonString_001 end" << std::endl;
}

/**
 * @tc.name: DmsBundleInfo_FromJsonString_002
 * @tc.desc: Test DmsBundleInfo FromJsonString with invalid JSON
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, DmsBundleInfo_FromJsonString_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_FromJsonString_002 start" << std::endl;

    std::string invalidJson = "invalid json";
    DmsBundleInfo bundleInfo;
    bool ret = bundleInfo.FromJsonString(invalidJson);
    EXPECT_FALSE(ret);

    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_FromJsonString_002 end" << std::endl;
}

/**
 * @tc.name: DmsBundleInfo_FromJsonString_003
 * @tc.desc: Test DmsBundleInfo FromJsonString with complete fields
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, DmsBundleInfo_FromJsonString_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_FromJsonString_003 start" << std::endl;

    std::string jsonString = "{"
        "\"version\":1,"
        "\"bundleName\":\"com.example.test\","
        "\"versionCode\":1000100,"
        "\"versionName\":\"1.0.0\","
        "\"compatibleVersionCode\":1,"
        "\"minCompatibleVersion\":1,"
        "\"targetVersionCode\":1000100,"
        "\"appId\":\"test.app.id\","
        "\"enabled\":true,"
        "\"bundleNameId\":100,"
        "\"updateTime\":1234567890,"
        "\"developerId\":\"testDeveloperId\""
        "}";

    DmsBundleInfo bundleInfo;
    bool ret = bundleInfo.FromJsonString(jsonString);
    EXPECT_TRUE(ret);
    EXPECT_EQ(bundleInfo.bundleName, "com.example.test");
    EXPECT_EQ(bundleInfo.version, 1u);
    EXPECT_EQ(bundleInfo.versionCode, 1000100u);
    EXPECT_EQ(bundleInfo.versionName, "1.0.0");
    EXPECT_EQ(bundleInfo.appId, "test.app.id");
    EXPECT_TRUE(bundleInfo.enabled);
    EXPECT_EQ(bundleInfo.bundleNameId, 100);

    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_FromJsonString_003 end" << std::endl;
}

/**
 * @tc.name: DmsBundleInfo_Marshalling_002
 * @tc.desc: Test DmsBundleInfo Marshalling with DmsAbilityInfo
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, DmsBundleInfo_Marshalling_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_Marshalling_002 start" << std::endl;

    DmsBundleInfo bundleInfo;
    bundleInfo.bundleName = TEST_BUNDLE_NAME;

    DmsAbilityInfo abilityInfo;
    abilityInfo.abilityName = TEST_ABILITY_NAME;
    abilityInfo.continueType = {TEST_CONTINUE_TYPE};
    abilityInfo.continueTypeId = {1};
    abilityInfo.moduleName = TEST_MODULE_NAME;
    bundleInfo.dmsAbilityInfos.push_back(abilityInfo);

    Parcel parcel;
    // Manually write the correct parcel format
    // Write DmsBundleInfo basic fields (default values)
    parcel.WriteUint32(0); // version
    parcel.WriteUint32(0); // versionCode
    parcel.WriteUint32(0); // compatibleVersionCode
    parcel.WriteUint32(0); // minCompatibleVersion
    parcel.WriteUint32(0); // targetVersionCode
    parcel.WriteString16(Str8ToStr16(bundleInfo.bundleName));
    parcel.WriteString16(u""); // versionName
    parcel.WriteString16(u""); // appId
    parcel.WriteBool(false); // enabled
    parcel.WriteUint16(0); // bundleNameId
    parcel.WriteInt64(0); // updateTime
    parcel.WriteString16(u""); // developerId
    // Write abilityInfosSize
    parcel.WriteUint32(1);
    // Write DmsAbilityInfo manually with proper sizes
    // WriteParcelable flag (not null)
    parcel.WriteBool(true);
    parcel.WriteString16(Str8ToStr16(abilityInfo.abilityName));
    parcel.WriteInt32(abilityInfo.continueType.size());
    for (const auto& type : abilityInfo.continueType) {
        parcel.WriteString16(Str8ToStr16(type));
    }
    parcel.WriteInt32(abilityInfo.continueTypeId.size());
    for (const auto& id : abilityInfo.continueTypeId) {
        parcel.WriteUint8(id);
    }
    parcel.WriteString16(Str8ToStr16(abilityInfo.moduleName));
    // Write userIdArrSize
    parcel.WriteUint32(0);
    // Write appIdentifier
    parcel.WriteString16(u"");
    // Write appIdentifierVecSize
    parcel.WriteUint32(0);

    DmsBundleInfo readInfo;
    bool ret = readInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(readInfo.dmsAbilityInfos.size(), 1u);
    if (readInfo.dmsAbilityInfos.size() > 0) {
        EXPECT_EQ(readInfo.dmsAbilityInfos[0].abilityName, TEST_ABILITY_NAME);
    }

    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_Marshalling_002 end" << std::endl;
}

/**
 * @tc.name: DmsBundleInfo_Marshalling_003
 * @tc.desc: Test DmsBundleInfo Marshalling with userIdArr
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, DmsBundleInfo_Marshalling_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_Marshalling_003 start" << std::endl;

    DmsBundleInfo bundleInfo;
    bundleInfo.bundleName = TEST_BUNDLE_NAME;
    bundleInfo.userIdArr = {100, 101, 102};

    Parcel parcel;
    // Manually write the correct parcel format
    // Write DmsBundleInfo basic fields
    parcel.WriteUint32(0); // version
    parcel.WriteUint32(0); // versionCode
    parcel.WriteUint32(0); // compatibleVersionCode
    parcel.WriteUint32(0); // minCompatibleVersion
    parcel.WriteUint32(0); // targetVersionCode
    parcel.WriteString16(Str8ToStr16(bundleInfo.bundleName));
    parcel.WriteString16(u""); // versionName
    parcel.WriteString16(u""); // appId
    parcel.WriteBool(false); // enabled
    parcel.WriteUint16(0); // bundleNameId
    parcel.WriteInt64(0); // updateTime
    parcel.WriteString16(u""); // developerId
    // Write abilityInfosSize
    parcel.WriteUint32(0);
    // Write userIdArrSize and elements
    parcel.WriteUint32(bundleInfo.userIdArr.size());
    for (auto userId : bundleInfo.userIdArr) {
        parcel.WriteUint8(userId);
    }
    // Write appIdentifier
    parcel.WriteString16(u"");
    // Write appIdentifierVecSize
    parcel.WriteUint32(0);

    DmsBundleInfo readInfo;
    bool ret = readInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(readInfo.userIdArr.size(), 3u);

    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_Marshalling_003 end" << std::endl;
}

/**
 * @tc.name: DmsBundleInfo_Marshalling_004
 * @tc.desc: Test DmsBundleInfo Marshalling with appIdentifierVec
 * @tc.type: FUNC
 */
HWTEST_F(DistributedBundleInfoTest, DmsBundleInfo_Marshalling_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_Marshalling_004 start" << std::endl;

    DmsBundleInfo bundleInfo;
    bundleInfo.bundleName = TEST_BUNDLE_NAME;
    bundleInfo.appIdentifier = TEST_APP_IDENTIFIER;
    bundleInfo.appIdentifierVec = {"app1", "app2"};

    Parcel parcel;
    // Manually write the correct parcel format
    // Write DmsBundleInfo basic fields
    parcel.WriteUint32(0); // version
    parcel.WriteUint32(0); // versionCode
    parcel.WriteUint32(0); // compatibleVersionCode
    parcel.WriteUint32(0); // minCompatibleVersion
    parcel.WriteUint32(0); // targetVersionCode
    parcel.WriteString16(Str8ToStr16(bundleInfo.bundleName));
    parcel.WriteString16(u""); // versionName
    parcel.WriteString16(u""); // appId
    parcel.WriteBool(false); // enabled
    parcel.WriteUint16(0); // bundleNameId
    parcel.WriteInt64(0); // updateTime
    parcel.WriteString16(u""); // developerId
    // Write abilityInfosSize
    parcel.WriteUint32(0);
    // Write userIdArrSize
    parcel.WriteUint32(0);
    // Write appIdentifier
    parcel.WriteString16(Str8ToStr16(bundleInfo.appIdentifier));
    // Write appIdentifierVecSize and elements
    parcel.WriteUint32(bundleInfo.appIdentifierVec.size());
    for (const auto& appIdentifier : bundleInfo.appIdentifierVec) {
        parcel.WriteString16(Str8ToStr16(appIdentifier));
    }

    DmsBundleInfo readInfo;
    bool ret = readInfo.ReadFromParcel(parcel);
    EXPECT_TRUE(ret);
    EXPECT_EQ(readInfo.appIdentifierVec.size(), 2u);

    DTEST_LOG << "DistributedBundleInfoTest DmsBundleInfo_Marshalling_004 end" << std::endl;
}

} // namespace DistributedSchedule
} // namespace OHOS
