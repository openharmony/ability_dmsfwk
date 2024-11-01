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

#include "distributedWant/distributed_want.h"
#include "distributed_sched_utils.h"
#include "dsched_continue_event.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

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
 * @tc.desc: Test UnmarshalWantStr
 * @tc.type: FUNC
 */
HWTEST_F(DSchedContinueEventTest, DSchedContinueEventTest_006_1, TestSize.Level0)
{
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_006_1 begin" << std::endl;
    DistributedWant dtbWant;
    Parcel wantParcel;
    ASSERT_EQ(dtbWant.Marshalling(wantParcel), true);
    std::string wantStr = ParcelToBase64Str(wantParcel);

    DSchedContinueDataCmd cmd;
    int32_t ret = cmd.UnmarshalWantStr(wantStr);
    EXPECT_EQ(ret, ERR_OK);

    ret = cmd.UnmarshalWantStr("");
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedContinueEventTest DSchedContinueEventTest_006_1 end ret:" << ret << std::endl;
}
}
}
