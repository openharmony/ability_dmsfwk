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

#include "distributed_radar_test.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

namespace {
    const std::string DEVICE_ID = "DeviceId";
    const std::string BUNDLE_NAME = "BundleName";
}

void DistributedRadarTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedRadarTest::SetUpTestCase" << std::endl;
}

void DistributedRadarTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedRadarTest::TearDownTestCase" << std::endl;
}

void DistributedRadarTest::TearDown()
{
    DTEST_LOG << "DistributedRadarTest::TearDown" << std::endl;
}

void DistributedRadarTest::SetUp()
{
    DTEST_LOG << "DistributedRadarTest::SetUp" << std::endl;
}

/**
 * @tc.name: RegisterSoftbusCallbackRes_001
 * @tc.desc: check RegisterSoftbusCallbackRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, RegisterSoftbusCallbackRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest RegisterSoftbusCallbackRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().RegisterSoftbusCallbackRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest RegisterSoftbusCallbackRes_001 end" << std::endl;
}

/**
 * @tc.name: RegisterSoftbusCallbackRes_002
 * @tc.desc: check RegisterSoftbusCallbackRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, RegisterSoftbusCallbackRes_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest RegisterSoftbusCallbackRes_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().RegisterSoftbusCallbackRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest RegisterSoftbusCallbackRes_002 end" << std::endl;
}

/**
 * @tc.name: RegisterFocusedRes_001
 * @tc.desc: check RegisterFocusedRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, RegisterFocusedRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest RegisterFocusedRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().RegisterFocusedRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest RegisterFocusedRes_001 end" << std::endl;
}

/**
 * @tc.name: RegisterFocusedRes_002
 * @tc.desc: check RegisterFocusedRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, RegisterFocusedRes_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest RegisterFocusedRes_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().RegisterFocusedRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest RegisterFocusedRes_002 end" << std::endl;
}

/**
 * @tc.name: DmsFocused_001
 * @tc.desc: check DmsFocused
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, DmsFocused_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest DmsFocused_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().DmsFocused(FUNC, NORMAL);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest DmsFocused_001 end" << std::endl;
}

/**
 * @tc.name: NormalFocusedSendEventRes_001
 * @tc.desc: check NormalFocusedSendEventRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, NormalFocusedSendEventRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest NormalFocusedSendEventRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().NormalFocusedSendEventRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest NormalFocusedSendEventRes_001 end" << std::endl;
}

/**
 * @tc.name: NormalFocusedSendEventRes_002
 * @tc.desc: check NormalFocusedSendEventRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, NormalFocusedSendEventRes_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest NormalFocusedSendEventRes_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().NormalFocusedSendEventRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest NormalFocusedSendEventRes_002 end" << std::endl;
}

/**
 * @tc.name: SetFocusedState_001
 * @tc.desc: check SetFocusedState
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, SetFocusedState_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest SetFocusedState_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().SetFocusedState(FUNC);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest SetFocusedState_001 end" << std::endl;
}

/**
 * @tc.name: ChangeStateFocusedGetAccessTokenIdRes_001
 * @tc.desc: check ChangeStateFocusedGetAccessTokenIdRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ChangeStateFocusedGetAccessTokenIdRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ChangeStateFocusedGetAccessTokenIdRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ChangeStateFocusedGetAccessTokenIdRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ChangeStateFocusedGetAccessTokenIdRes_001 end" << std::endl;
}

/**
 * @tc.name: ChangeStateFocusedGetAccessTokenIdRes_002
 * @tc.desc: check ChangeStateFocusedGetAccessTokenIdRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ChangeStateFocusedGetAccessTokenIdRes_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ChangeStateFocusedGetAccessTokenIdRes_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ChangeStateFocusedGetAccessTokenIdRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ChangeStateFocusedGetAccessTokenIdRes_002 end" << std::endl;
}

/**
 * @tc.name: ChangeStateFocusedSendEventRes_001
 * @tc.desc: check ChangeStateFocusedSendEventRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ChangeStateFocusedSendEventRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ChangeStateFocusedSendEventRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ChangeStateFocusedSendEventRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ChangeStateFocusedSendEventRes_001 end" << std::endl;
}

/**
 * @tc.name: ChangeStateFocusedSendEventRes_002
 * @tc.desc: check ChangeStateFocusedSendEventRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ChangeStateFocusedSendEventRes_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ChangeStateFocusedSendEventRes_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ChangeStateFocusedSendEventRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ChangeStateFocusedSendEventRes_002 end" << std::endl;
}

/**
 * @tc.name: DmsUnfocused_001
 * @tc.desc: check DmsUnfocused
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, DmsUnfocused_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest DmsUnfocused_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().DmsUnfocused(FUNC);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest DmsUnfocused_001 end" << std::endl;
}

/**
 * @tc.name: NormalUnfocusedGetAccessTokenIdRes_001
 * @tc.desc: check NormalUnfocusedGetAccessTokenIdRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, NormalUnfocusedGetAccessTokenIdRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest NormalUnfocusedGetAccessTokenIdRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().NormalUnfocusedGetAccessTokenIdRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest NormalUnfocusedGetAccessTokenIdRes_001 end" << std::endl;
}

/**
 * @tc.name: NormalUnfocusedGetAccessTokenIdRes_002
 * @tc.desc: check NormalUnfocusedGetAccessTokenIdRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, NormalUnfocusedGetAccessTokenIdRes_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest NormalUnfocusedGetAccessTokenIdRes_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().NormalUnfocusedGetAccessTokenIdRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest NormalUnfocusedGetAccessTokenIdRes_002 end" << std::endl;
}

/**
 * @tc.name: NormalUnfocusedSendEventRes_001
 * @tc.desc: check NormalUnfocusedSendEventRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, NormalUnfocusedSendEventRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest NormalUnfocusedSendEventRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().NormalUnfocusedSendEventRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest NormalUnfocusedSendEventRes_001 end" << std::endl;
}

/**
 * @tc.name: NormalUnfocusedSendEventRes_002
 * @tc.desc: check NormalUnfocusedSendEventRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, NormalUnfocusedSendEventRes_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest NormalUnfocusedSendEventRes_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().NormalUnfocusedSendEventRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest NormalUnfocusedSendEventRes_002 end" << std::endl;
}

/**
 * @tc.name: RecordTime_001
 * @tc.desc: check RecordTime
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, RecordTime_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest RecordTime_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().RecordTime(FUNC);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest RecordTime_001 end" << std::endl;
}

/**
 * @tc.name: MultimodeUnfocusedGetAccessTokenIdRes_001
 * @tc.desc: check MultimodeUnfocusedGetAccessTokenIdRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, MultimodeUnfocusedGetAccessTokenIdRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest MultimodeUnfocusedGetAccessTokenIdRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().MultimodeUnfocusedGetAccessTokenIdRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest MultimodeUnfocusedGetAccessTokenIdRes_001 end" << std::endl;
}

/**
 * @tc.name: MultimodeUnfocusedGetAccessTokenIdRes_002
 * @tc.desc: check MultimodeUnfocusedGetAccessTokenIdRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, MultimodeUnfocusedGetAccessTokenIdRes_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest MultimodeUnfocusedGetAccessTokenIdRes_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().MultimodeUnfocusedGetAccessTokenIdRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest MultimodeUnfocusedGetAccessTokenIdRes_002 end" << std::endl;
}

/**
 * @tc.name: MultimodeUnfocusedSendEventRes_001
 * @tc.desc: check MultimodeUnfocusedSendEventRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, MultimodeUnfocusedSendEventRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest MultimodeUnfocusedSendEventRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().MultimodeUnfocusedSendEventRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest MultimodeUnfocusedSendEventRes_001 end" << std::endl;
}

/**
 * @tc.name: MultimodeUnfocusedSendEventRes_002
 * @tc.desc: check MultimodeUnfocusedSendEventRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, MultimodeUnfocusedSendEventRes_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest MultimodeUnfocusedSendEventRes_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().MultimodeUnfocusedSendEventRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest MultimodeUnfocusedSendEventRes_002 end" << std::endl;
}

/**
 * @tc.name: SetUnfocusedState_001
 * @tc.desc: check SetUnfocusedState
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, SetUnfocusedState_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest SetUnfocusedState_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().SetUnfocusedState(FUNC);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest SetUnfocusedState_001 end" << std::endl;
}

/**
 * @tc.name: ChangeStateUnfocusedGetAccessTokenIdRes_001
 * @tc.desc: check ChangeStateUnfocusedGetAccessTokenIdRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ChangeStateUnfocusedGetAccessTokenIdRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ChangeStateUnfocusedGetAccessTokenIdRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ChangeStateUnfocusedGetAccessTokenIdRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ChangeStateUnfocusedGetAccessTokenIdRes_001 end" << std::endl;
}

/**
 * @tc.name: ChangeStateUnfocusedGetAccessTokenIdRes_002
 * @tc.desc: check ChangeStateUnfocusedGetAccessTokenIdRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ChangeStateUnfocusedGetAccessTokenIdRes_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ChangeStateUnfocusedGetAccessTokenIdRes_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ChangeStateUnfocusedGetAccessTokenIdRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ChangeStateUnfocusedGetAccessTokenIdRes_002 end" << std::endl;
}

/**
 * @tc.name: ChangeStateUnfocusedSendEventRes_001
 * @tc.desc: check ChangeStateUnfocusedSendEventRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ChangeStateUnfocusedSendEventRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ChangeStateUnfocusedSendEventRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ChangeStateUnfocusedSendEventRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ChangeStateUnfocusedSendEventRes_001 end" << std::endl;
}

/**
 * @tc.name: ChangeStateUnfocusedSendEventRes_002
 * @tc.desc: check ChangeStateUnfocusedSendEventRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ChangeStateUnfocusedSendEventRes_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ChangeStateUnfocusedSendEventRes_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ChangeStateUnfocusedSendEventRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ChangeStateUnfocusedSendEventRes_002 end" << std::endl;
}

/**
 * @tc.name: RecvFocused_001
 * @tc.desc: check RecvFocused
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, RecvFocused_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest RecvFocused_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().RecvFocused(FUNC);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest RecvFocused_001 end" << std::endl;
}

/**
 * @tc.name: FocusedGetBundleName_001
 * @tc.desc: check FocusedGetBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, FocusedGetBundleName_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest FocusedGetBundleName_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().FocusedGetBundleName(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest FocusedGetBundleName_001 end" << std::endl;
}

/**
 * @tc.name: FocusedGetBundleName_002
 * @tc.desc: check FocusedGetBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, FocusedGetBundleName_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest FocusedGetBundleName_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().FocusedGetBundleName(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest FocusedGetBundleName_002 end" << std::endl;
}

/**
 * @tc.name: NotifyDockFocused_001
 * @tc.desc: check NotifyDockFocused
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, NotifyDockFocused_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest NotifyDockFocused_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().NotifyDockFocused(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest NotifyDockFocused_001 end" << std::endl;
}

/**
 * @tc.name: NotifyDockFocused_002
 * @tc.desc: check NotifyDockFocused
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, NotifyDockFocused_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest NotifyDockFocused_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().NotifyDockFocused(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest NotifyDockFocused_002 end" << std::endl;
}

/**
 * @tc.name: RecvUnfocused_001
 * @tc.desc: check RecvUnfocused
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, RecvUnfocused_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest RecvUnfocused_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().RecvUnfocused(FUNC);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest RecvUnfocused_001 end" << std::endl;
}

/**
 * @tc.name: UnfocusedGetBundleName_001
 * @tc.desc: check UnfocusedGetBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, UnfocusedGetBundleName_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest UnfocusedGetBundleName_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().UnfocusedGetBundleName(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest UnfocusedGetBundleName_001 end" << std::endl;
}

/**
 * @tc.name: UnfocusedGetBundleName_002
 * @tc.desc: check UnfocusedGetBundleName
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, UnfocusedGetBundleName_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest UnfocusedGetBundleName_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().UnfocusedGetBundleName(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest UnfocusedGetBundleName_002 end" << std::endl;
}

/**
 * @tc.name: NotifyDockUnfocused_001
 * @tc.desc: check NotifyDockUnfocused
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, NotifyDockUnfocused_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest NotifyDockUnfocused_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().NotifyDockUnfocused(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest NotifyDockUnfocused_001 end" << std::endl;
}

/**
 * @tc.name: NotifyDockUnfocused_002
 * @tc.desc: check NotifyDockUnfocused
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, NotifyDockUnfocused_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest NotifyDockUnfocused_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().NotifyDockUnfocused(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest NotifyDockUnfocused_002 end" << std::endl;
}

/**
 * @tc.name: ClickIconDmsContinue_001
 * @tc.desc: check ClickIconDmsContinue
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ClickIconDmsContinue_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ClickIconDmsContinue_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ClickIconDmsContinue(FUNC, ERR_OK, DEVICE_ID, BUNDLE_NAME, BUNDLE_NAME);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ClickIconDmsContinue_001 end" << std::endl;
}

/**
 * @tc.name: ClickIconDmsContinue_002
 * @tc.desc: check ClickIconDmsContinue
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ClickIconDmsContinue_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ClickIconDmsContinue_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ClickIconDmsContinue(FUNC, ERR_NO, DEVICE_ID, BUNDLE_NAME, BUNDLE_NAME);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ClickIconDmsContinue_002 end" << std::endl;
}

/**
 * @tc.name: ClickIconDmsStartAbility_001
 * @tc.desc: check ClickIconDmsStartAbility
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ClickIconDmsStartAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ClickIconDmsStartAbility_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ClickIconDmsStartAbility(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ClickIconDmsStartAbility_001 end" << std::endl;
}

/**
 * @tc.name: ClickIconDmsStartAbility_002
 * @tc.desc: check ClickIconDmsStartAbility
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ClickIconDmsStartAbility_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ClickIconDmsStartAbility_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ClickIconDmsStartAbility(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ClickIconDmsStartAbility_002 end" << std::endl;
}

/**
 * @tc.name: ClickIconDmsRecvOver_001
 * @tc.desc: check ClickIconDmsRecvOver
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ClickIconDmsRecvOver_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ClickIconDmsRecvOver_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ClickIconDmsRecvOver(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ClickIconDmsRecvOver_001 end" << std::endl;
}

/**
 * @tc.name: ClickIconDmsRecvOver_002
 * @tc.desc: check ClickIconDmsRecvOver
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, ClickIconDmsRecvOver_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest ClickIconDmsRecvOver_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().ClickIconDmsRecvOver(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest ClickIconDmsRecvOver_002 end" << std::endl;
}

/**
 * @tc.name: SaveDataDmsContinue_001
 * @tc.desc: check SaveDataDmsContinue
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, SaveDataDmsContinue_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest SaveDataDmsContinue_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().SaveDataDmsContinue(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest SaveDataDmsContinue_001 end" << std::endl;
}

/**
 * @tc.name: SaveDataDmsContinue_002
 * @tc.desc: check SaveDataDmsContinue
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, SaveDataDmsContinue_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest SaveDataDmsContinue_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().SaveDataDmsContinue(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest SaveDataDmsContinue_002 end" << std::endl;
}

/**
 * @tc.name: SaveDataDmsRemoteWant_001
 * @tc.desc: check SaveDataDmsRemoteWant
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, SaveDataDmsRemoteWant_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest SaveDataDmsRemoteWant_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().SaveDataDmsRemoteWant(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest SaveDataDmsRemoteWant_001 end" << std::endl;
}

/**
 * @tc.name: SaveDataDmsRemoteWant_002
 * @tc.desc: check SaveDataDmsRemoteWant
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, SaveDataDmsRemoteWant_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest SaveDataDmsRemoteWant_002 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().SaveDataDmsRemoteWant(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest SaveDataDmsRemoteWant_002 end" << std::endl;
}

/**
 * @tc.name: NormalFocusedGetAccessTokenIdRes_001
 * @tc.desc: check NormalFocusedGetAccessTokenIdRes
 * @tc.type: FUNC
 */
HWTEST_F(DistributedRadarTest, NormalFocusedGetAccessTokenIdRes_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedRadarTest NormalFocusedGetAccessTokenIdRes_001 begin" << std::endl;
    bool ret = DmsRadar::GetInstance().NormalFocusedGetAccessTokenIdRes(FUNC, ERR_NO);
    EXPECT_EQ(ret, true);
    
    ret = DmsRadar::GetInstance().NormalFocusedGetAccessTokenIdRes(FUNC, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DistributedRadarTest NormalFocusedGetAccessTokenIdRes_001 end" << std::endl;
}
}
}