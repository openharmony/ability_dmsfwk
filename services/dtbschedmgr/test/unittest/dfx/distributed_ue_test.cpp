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

#include "distributed_ue_test.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string NO_FAILED_EXTRAINFO = "NULL";
constexpr int32_t ONE = 1;

}

void DmsUETest::SetUpTestCase()
{
    DTEST_LOG << "DmsUETest::SetUpTestCase" << std::endl;
    netAdapterMock_ = std::make_shared<DnetworkAdapterMock>();
    IDnetworkAdapter::netAdapter = netAdapterMock_;
}

void DmsUETest::TearDownTestCase()
{
    DTEST_LOG << "DmsUETest::TearDownTestCase" << std::endl;
    IDnetworkAdapter::netAdapter = nullptr;
    netAdapterMock_ = nullptr;
}

void DmsUETest::TearDown()
{
    DTEST_LOG << "DmsUETest::TearDown" << std::endl;
}

void DmsUETest::SetUp()
{
    DTEST_LOG << "DmsUETest::SetUp" << std::endl;
}

/**
 * @tc.name: TriggerDmsContinue_001
 * @tc.desc: check TriggerDmsContinue
 * @tc.type: FUNC
 */
HWTEST_F(DmsUETest, TriggerDmsContinue_001, TestSize.Level3)
{
    DTEST_LOG << "DmsUETest TriggerDmsContinue_001 begin" << std::endl;
    std::string bundleName;
    std::string abilityName;
    std::string networkId;
    bool ret = DmsUE::GetInstance().TriggerDmsContinue(bundleName, abilityName, networkId, ONE);
    ret = DmsUE::GetInstance().DmsContinueComplete(bundleName, abilityName, networkId, ONE);
    ret = DmsUE::GetInstance().OriginalSwitchState(true, ONE);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DmsUETest TriggerDmsContinue_001 end" << std::endl;
}

/**
 * @tc.name: ChangedSwitchState_001
 * @tc.desc: check ChangedSwitchState
 * @tc.type: FUNC
 */
HWTEST_F(DmsUETest, ChangedSwitchState_001, TestSize.Level3)
{
    DTEST_LOG << "DmsUETest ChangedSwitchState_001 begin" << std::endl;
    bool ret = DmsUE::GetInstance().ChangedSwitchState(true, ONE);
    ret = DmsUE::GetInstance().ChangedSwitchState(true, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DmsUETest ChangedSwitchState_001 end" << std::endl;
}

/**
 * @tc.name: ConvertErrCodeToStr_001
 * @tc.desc: check ConvertErrCodeToStr
 * @tc.type: FUNC
 */
HWTEST_F(DmsUETest, ConvertErrCodeToStr_001, TestSize.Level3)
{
    DTEST_LOG << "DmsUETest ConvertErrCodeToStr_001 begin" << std::endl;
    std::string ret = DmsUE::GetInstance().ConvertErrCodeToStr(ERR_OK);
    EXPECT_EQ(ret, NO_FAILED_EXTRAINFO);

    ret = DmsUE::GetInstance().ConvertErrCodeToStr(INVALID_PARAMETERS_ERR);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(INVALID_REMOTE_PARAMETERS_ERR);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(DMS_START_CONTROL_PERMISSION_DENIED);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(NO_MISSION_INFO_FOR_MISSION_ID);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(OPERATION_DEVICE_NOT_INITIATOR_OR_TARGET);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(CONTINUE_ALREADY_IN_PROGRESS);
    EXPECT_NE(ret, "");
    DTEST_LOG << "DmsUETest ConvertErrCodeToStr_001 end" << std::endl;
}

/**
 * @tc.name: ConvertErrCodeToStr_002
 * @tc.desc: check ConvertErrCodeToStr
 * @tc.type: FUNC
 */
HWTEST_F(DmsUETest, ConvertErrCodeToStr_002, TestSize.Level3)
{
    DTEST_LOG << "DmsUETest ConvertErrCodeToStr_002 begin" << std::endl;
    std::string ret = DmsUE::GetInstance().ConvertErrCodeToStr(MISSION_FOR_CONTINUING_IS_NOT_ALIVE);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(CONTINUE_SEND_EVENT_FAILED);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(CONTINUE_STATE_MACHINE_INVALID_STATE);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(CONTINUE_SESSION_SHUTDOWN);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(CONTINUE_CALL_CONTINUE_ABILITY_FAILED);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(CONTINUE_CALL_START_ABILITY_FAILED);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(CONTINUE_SINK_ABILITY_TERMINATED);
    EXPECT_NE(ret, "");
    ret = DmsUE::GetInstance().ConvertErrCodeToStr(DMS_CONNECT_APPLY_REJECT_FAILED);
    EXPECT_NE(ret, "");
    DTEST_LOG << "DmsUETest ConvertErrCodeToStr_002 end" << std::endl;
}

/**
 * @tc.name: GetLocalDeviceType_001
 * @tc.desc: test GetLocalDeviceType when GetLocalBasicInfo fails
 * @tc.type: FUNC
 */
HWTEST_F(DmsUETest, GetLocalDeviceType_001, TestSize.Level3)
{
    DTEST_LOG << "DmsUETest GetLocalDeviceType_001 begin" << std::endl;
    EXPECT_CALL(*netAdapterMock_, GetLocalBasicInfo(_)).WillOnce(Return(false));
    int32_t ret = DmsUE::GetInstance().GetLocalDeviceType();
    EXPECT_EQ(ret, 0);
    DTEST_LOG << "DmsUETest GetLocalDeviceType_001 end" << std::endl;
}

/**
 * @tc.name: GetLocalDeviceType_002
 * @tc.desc: test GetLocalDeviceType when GetLocalBasicInfo succeeds
 * @tc.type: FUNC
 */
HWTEST_F(DmsUETest, GetLocalDeviceType_002, TestSize.Level3)
{
    DTEST_LOG << "DmsUETest GetLocalDeviceType_002 begin" << std::endl;
    constexpr int32_t EXPECTED_DEVICE_TYPE = 1;
    EXPECT_CALL(*netAdapterMock_, GetLocalBasicInfo(_))
        .WillOnce([](DistributedHardware::DmDeviceInfo& info) {
            info.deviceTypeId = static_cast<decltype(info.deviceTypeId)>(EXPECTED_DEVICE_TYPE);
            return true;
        });
    int32_t ret = DmsUE::GetInstance().GetLocalDeviceType();
    EXPECT_EQ(ret, EXPECTED_DEVICE_TYPE);
    DTEST_LOG << "DmsUETest GetLocalDeviceType_002 end" << std::endl;
}

/**
 * @tc.name: ContinuationMessage_001
 * @tc.desc: test ContinuationMessage when errCode is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(DmsUETest, ContinuationMessage_001, TestSize.Level3)
{
    DTEST_LOG << "DmsUETest ContinuationMessage_001 begin" << std::endl;
    std::string bundleName = "com.test.bundle";
    std::string sinkNetworkId = "sinkNetworkId";
    bool ret = DmsUE::GetInstance().ContinuationMessage(bundleName, sinkNetworkId, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DmsUETest ContinuationMessage_001 end" << std::endl;
}

/**
 * @tc.name: ContinuationMessage_002
 * @tc.desc: test ContinuationMessage when errCode is not ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(DmsUETest, ContinuationMessage_002, TestSize.Level3)
{
    DTEST_LOG << "DmsUETest ContinuationMessage_002 begin" << std::endl;
    std::string bundleName = "com.test.bundle";
    std::string sinkNetworkId = "sinkNetworkId";
    bool ret = DmsUE::GetInstance().ContinuationMessage(bundleName, sinkNetworkId, INVALID_PARAMETERS_ERR);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DmsUETest ContinuationMessage_002 end" << std::endl;
}

/**
 * @tc.name: AccidentalContinuation_001
 * @tc.desc: test AccidentalContinuation when errCode is ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(DmsUETest, AccidentalContinuation_001, TestSize.Level3)
{
    DTEST_LOG << "DmsUETest AccidentalContinuation_001 begin" << std::endl;
    std::string bundleName = "com.test.bundle";
    std::string sourceNetworkId = "sourceNetworkId";
    bool ret = DmsUE::GetInstance().AccidentalContinuation(1000, bundleName, sourceNetworkId, ERR_OK);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DmsUETest AccidentalContinuation_001 end" << std::endl;
}

/**
 * @tc.name: AccidentalContinuation_002
 * @tc.desc: test AccidentalContinuation when errCode is not ERR_OK
 * @tc.type: FUNC
 */
HWTEST_F(DmsUETest, AccidentalContinuation_002, TestSize.Level3)
{
    DTEST_LOG << "DmsUETest AccidentalContinuation_002 begin" << std::endl;
    std::string bundleName = "com.test.bundle";
    std::string sourceNetworkId = "sourceNetworkId";
    bool ret = DmsUE::GetInstance().AccidentalContinuation(1000, bundleName, sourceNetworkId,
        INVALID_PARAMETERS_ERR);
    EXPECT_EQ(ret, true);
    DTEST_LOG << "DmsUETest AccidentalContinuation_002 end" << std::endl;
}
}
}