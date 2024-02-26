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

#include "dms_continue_time_dumper_test.h"

#include "datetime_ex.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

namespace {
    const std::string BUNDLE_NAME = "com.ohos.permissionmanager";
    const std::string ABILITY_NAME = "com.ohos.permissionmanager.MainAbility";
    const std::string NETWORK_ID = "NetworkId";
    constexpr int32_t DMSDURATION_TOTALTIME = 2;
}

void DmsDurationTest::SetUpTestCase()
{
    DTEST_LOG << "DmsDurationTest::SetUpTestCase" << std::endl;
}

void DmsDurationTest::TearDownTestCase()
{
    DTEST_LOG << "DmsDurationTest::TearDownTestCase" << std::endl;
}

void DmsDurationTest::TearDown()
{
    DTEST_LOG << "DmsDurationTest::TearDown" << std::endl;
}

void DmsDurationTest::SetUp()
{
    DTEST_LOG << "DmsDurationTest::SetUp" << std::endl;
}

void DmsContinueTimeTest::SetUpTestCase()
{
    DTEST_LOG << "DmsContinueTimeTest::SetUpTestCase" << std::endl;
}

void DmsContinueTimeTest::TearDownTestCase()
{
    DTEST_LOG << "DmsContinueTimeTest::TearDownTestCase" << std::endl;
}

void DmsContinueTimeTest::TearDown()
{
    DTEST_LOG << "DmsContinueTimeTest::TearDown" << std::endl;
}

void DmsContinueTimeTest::SetUp()
{
    DTEST_LOG << "DmsContinueTimeTest::SetUp" << std::endl;
    DmsContinueTime::GetInstance().Init();
}

/**
 * @tc.name: SetBeginTime_001
 * @tc.desc: test SetBeginTime func
 * @tc.type: FUNC
 */
HWTEST_F(DmsDurationTest, SetBeginTime_001, TestSize.Level3)
{
    DTEST_LOG << "DmsDurationTest SetBeginTime_001 begin" << std::endl;
    int64_t time = GetTickCount();
    dmsDuration.SetBeginTime(time);
    int64_t ret = dmsDuration.GetBeginTime();
    EXPECT_EQ(ret, time);
    DTEST_LOG << "DmsDurationTest SetBeginTime_001 end" << std::endl;
}

/**
 * @tc.name: SetEndTime_001
 * @tc.desc: test SetEndTime func
 * @tc.type: FUNC
 */
HWTEST_F(DmsDurationTest, SetEndTime_001, TestSize.Level3)
{
    DTEST_LOG << "DmsDurationTest SetEndTime_001 begin" << std::endl;
    int64_t time = GetTickCount();
    dmsDuration.SetEndTime(time);
    int64_t ret = dmsDuration.GetEndTime();
    EXPECT_EQ(ret, time);
    DTEST_LOG << "DmsDurationTest SetEndTime_001 end" << std::endl;
}

/**
 * @tc.name: SetDurationTime_001
 * @tc.desc: test SetDurationTime func
 * @tc.type: FUNC
 */
HWTEST_F(DmsDurationTest, SetDurationTime_001, TestSize.Level3)
{
    DTEST_LOG << "DmsDurationTest SetDurationTime_001 begin" << std::endl;
    int64_t time = GetTickCount();
    dmsDuration.SetDurationTime(time);
    int64_t ret = dmsDuration.GetDurationTime();
    EXPECT_EQ(ret, time);
    DTEST_LOG << "DmsDurationTest SetDurationTime_001 end" << std::endl;
}

/**
 * @tc.name: SetStrTime_001
 * @tc.desc: test SetStrTime func
 * @tc.type: FUNC
 */
HWTEST_F(DmsDurationTest, SetStrTime_001, TestSize.Level3)
{
    DTEST_LOG << "DmsDurationTest SetStrTime_001 begin" << std::endl;
    dmsDuration.SetStrTime(BUNDLE_NAME);
    std::string info = dmsDuration.GetStrTime();
    EXPECT_EQ(info.empty(), false);
    DTEST_LOG << "DmsDurationTest SetStrTime_001 end" << std::endl;
}

/**
 * @tc.name: SetDurationName_001
 * @tc.desc: test SetDurationName func
 * @tc.type: FUNC
 */
HWTEST_F(DmsDurationTest, SetDurationName_001, TestSize.Level3)
{
    DTEST_LOG << "DmsDurationTest SetDurationName_001 begin" << std::endl;
    dmsDuration.SetDurationName(BUNDLE_NAME);
    std::string info = dmsDuration.GetDurationName();
    EXPECT_EQ(info.empty(), false);
    DTEST_LOG << "DmsDurationTest SetDurationName_001 end" << std::endl;
}

/**
 * @tc.name: Init_001
 * @tc.desc: test Init func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, Init_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest Init_001 begin" << std::endl;
    DmsContinueTime::GetInstance().Init();
    bool ret = DmsContinueTime::GetInstance().GetDstInfo().bundleName.empty();
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DmsContinueTimeTest Init_001 end" << std::endl;
}

/**
 * @tc.name: SetPull_001
 * @tc.desc: test SetPull func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, SetPull_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest SetPull_001 begin" << std::endl;
    DmsContinueTime::GetInstance().SetPull(false);
    bool ret = DmsContinueTime::GetInstance().GetPull();
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DmsContinueTimeTest SetPull_001 end" << std::endl;
}

/**
 * @tc.name: SetSrcBundleName_001
 * @tc.desc: test SetSrcBundleName func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, SetSrcBundleName_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest SetSrcBundleName_001 begin" << std::endl;
    DmsContinueTime::GetInstance().SetSrcBundleName(BUNDLE_NAME);
    DmsContinueTime::GetInstance().SetSrcAbilityName(ABILITY_NAME);
    DmsContinueTime::GetInstance().SetDstBundleName(BUNDLE_NAME);
    DmsContinueTime::GetInstance().SetDstAbilityName(ABILITY_NAME);
    DmsContinueTime::GetInstance().SetNetWorkId(NETWORK_ID, NETWORK_ID);
    bool ret = DmsContinueTime::GetInstance().GetDstInfo().bundleName.empty();
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DmsContinueTimeTest SetSrcBundleName_001 end" << std::endl;
}

/**
 * @tc.name: SetSaveDataDurationBegin_001
 * @tc.desc: test SetSaveDataDurationBegin func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, SetSaveDataDurationBegin_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest SetSaveDataDurationBegin_001 begin" << std::endl;
    DmsContinueTime::GetInstance().SetDeviceNamePush();
    DmsContinueTime::GetInstance().SetDeviceNamePull();

    int64_t begin = GetTickCount();
    DmsContinueTime::GetInstance().SetDurationBegin(DMSDURATION_TOTALTIME, begin);
    DmsContinueTime::GetInstance().SetDurationEnd(DMSDURATION_TOTALTIME, begin);
    DmsContinueTime::GetInstance().SetDurationStrTime(DMSDURATION_TOTALTIME, BUNDLE_NAME);
    DmsContinueTime::GetInstance().SetSaveDataDurationBegin(begin);
    int64_t ret = DmsContinueTime::GetInstance().GetSaveDataDuration().GetBeginTime();
    EXPECT_NE(ret, 0);
    DTEST_LOG << "DmsContinueTimeTest SetSaveDataDurationBegin_001 end" << std::endl;
}

/**
 * @tc.name: SetSaveDataDurationEnd_001
 * @tc.desc: test SetSaveDataDurationEnd func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, SetSaveDataDurationEnd_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest SetSaveDataDurationEnd_001 begin" << std::endl;
    int64_t end = GetTickCount();
    DmsContinueTime::GetInstance().SetSaveDataDurationEnd(end);
    int64_t ret = DmsContinueTime::GetInstance().GetSaveDataDuration().GetEndTime();
    EXPECT_NE(ret, 0);
    DTEST_LOG << "DmsContinueTimeTest SetSaveDataDurationEnd_001 end" << std::endl;
}

/**
 * @tc.name: WriteDurationInfo_001
 * @tc.desc: test WriteDurationInfo func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, WriteDurationInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest WriteDurationInfo_001 begin" << std::endl;
    int64_t begin = GetTickCount();
    DmsContinueTime::GetInstance().SetSaveDataDurationBegin(begin);
    int64_t end = GetTickCount();
    DmsContinueTime::GetInstance().SetSaveDataDurationEnd(end);
    std::string info = DmsContinueTime::GetInstance().WriteDurationInfo(
        DmsContinueTime::GetInstance().GetSaveDataDuration());
    EXPECT_EQ(info.empty(), false);
    DTEST_LOG << "DmsContinueTimeTest WriteDurationInfo_001 end" << std::endl;
}

/**
 * @tc.name: ReadDurationInfo_001
 * @tc.desc: test ReadDurationInfo func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, ReadDurationInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest ReadDurationInfo_001 begin" << std::endl;
    int64_t begin = GetTickCount();
    DmsContinueTime::GetInstance().SetSaveDataDurationBegin(begin);
    int64_t end = GetTickCount();
    DmsContinueTime::GetInstance().SetSaveDataDurationEnd(end);
    std::string info = DmsContinueTime::GetInstance().WriteDurationInfo(
        DmsContinueTime::GetInstance().GetSaveDataDuration());
    DmsContinueTime::GetInstance().ReadDurationInfo(info.c_str());
    int64_t ret = DmsContinueTime::GetInstance().GetSaveDataDuration().GetBeginTime();
    EXPECT_NE(ret, 0);
    DTEST_LOG << "DmsContinueTimeTest ReadDurationInfo_001 end" << std::endl;
}

/**
 * @tc.name: WriteDstInfo_001
 * @tc.desc: test WriteDstInfo func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, WriteDstInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest WriteDstInfo_001 begin" << std::endl;
    std::string info = DmsContinueTime::GetInstance().WriteDstInfo(BUNDLE_NAME, ABILITY_NAME);
    EXPECT_EQ(info.empty(), false);
    DTEST_LOG << "DmsContinueTimeTest WriteDstInfo_001 end" << std::endl;
}

/**
 * @tc.name: ReadDstInfo_001
 * @tc.desc: test ReadDstInfo func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, ReadDstInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest ReadDstInfo_001 begin" << std::endl;
    std::string info = DmsContinueTime::GetInstance().WriteDstInfo(BUNDLE_NAME, ABILITY_NAME);
    DmsContinueTime::GetInstance().ReadDstInfo(info.c_str());
    bool ret = DmsContinueTime::GetInstance().GetDstInfo().bundleName.empty();
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DmsContinueTimeTest ReadDstInfo_001 end" << std::endl;
}

/**
 * @tc.name: GetCurrentTime_001
 * @tc.desc: test GetCurrentTime func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, GetCurrentTime_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest GetCurrentTime_001 begin" << std::endl;
    std::string strTime = DmsContinueTime::GetInstance().GetCurrentTime();
    EXPECT_EQ(strTime.empty(), false);
    DTEST_LOG << "DmsContinueTimeTest GetCurrentTime_001 end" << std::endl;
}

/**
 * @tc.name: DealDurationPull_001
 * @tc.desc: test DealDurationPull func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, DealDurationPull_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest DealDurationPull_001 begin" << std::endl;
    int64_t begin = GetTickCount();
    DmsContinueTime::GetInstance().SetSaveDataDurationBegin(begin);
    int64_t end = GetTickCount();
    DmsContinueTime::GetInstance().SetSaveDataDurationEnd(end);
    DmsContinueTime::GetInstance().DealDurationPull();
    int64_t ret = DmsContinueTime::GetInstance().GetSaveDataDuration().GetBeginTime();
    EXPECT_NE(ret, 0);
    DTEST_LOG << "DmsContinueTimeTest DealDurationPull_001 end" << std::endl;
}

/**
 * @tc.name: DealDurationPush_001
 * @tc.desc: test DealDurationPush func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, DealDurationPush_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest DealDurationPush_001 begin" << std::endl;
    int64_t begin = GetTickCount();
    DmsContinueTime::GetInstance().SetSaveDataDurationBegin(begin);
    int64_t end = GetTickCount();
    DmsContinueTime::GetInstance().SetSaveDataDurationEnd(end);
    DmsContinueTime::GetInstance().DealDurationPush();
    int64_t ret = DmsContinueTime::GetInstance().GetSaveDataDuration().GetBeginTime();
    EXPECT_NE(ret, 0);
    DTEST_LOG << "DmsContinueTimeTest DealDurationPush_001 end" << std::endl;
}

/**
 * @tc.name: AppendInfo_001
 * @tc.desc: test AppendInfo func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, AppendInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest AppendInfo_001 begin" << std::endl;
    std::string result;
    DmsContinueTime::GetInstance().SetSrcBundleName(BUNDLE_NAME);
    DmsContinueTime::GetInstance().SetDstBundleName(BUNDLE_NAME);
    DmsContinueTime::GetInstance().SetPull(true);
    DmsContinueTime::GetInstance().AppendInfo();
    DmsContinueTime::GetInstance().ShowInfo(result);
    EXPECT_EQ(result.empty(), false);
    DTEST_LOG << "DmsContinueTimeTest AppendInfo_001 end" << std::endl;
}

/**
 * @tc.name: AppendInfo_002
 * @tc.desc: test AppendInfo func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, AppendInfo_002, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest AppendInfo_002 begin" << std::endl;
    std::string result;
    DmsContinueTime::GetInstance().SetSrcBundleName(BUNDLE_NAME);
    DmsContinueTime::GetInstance().SetDstBundleName(BUNDLE_NAME);
    DmsContinueTime::GetInstance().SetPull(false);
    DmsContinueTime::GetInstance().AppendInfo();
    DmsContinueTime::GetInstance().ShowInfo(result);
    EXPECT_EQ(result.empty(), false);
    DTEST_LOG << "DmsContinueTimeTest AppendInfo_002 end" << std::endl;
}

/**
 * @tc.name: ShowInfo_001
 * @tc.desc: test ShowInfo func
 * @tc.type: FUNC
 */
HWTEST_F(DmsContinueTimeTest, ShowInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsContinueTimeTest ShowInfo_001 begin" << std::endl;
    std::string result;
    DmsContinueTime::GetInstance().ShowInfo(result);
    EXPECT_EQ(result.empty(), false);
    DTEST_LOG << "DmsContinueTimeTest ShowInfo_001 end" << std::endl;
}
}
}