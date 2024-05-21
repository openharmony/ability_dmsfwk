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

#include "dms_token_callback_test.h"

#include "distributed_sched_test_util.h"
#include "dms_token_callback.h"
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const char* DISTSCHED_PROCESS_NAME = "distributedsched";
const char* FOUNDATION_PROCESS_NAME = "foundation";
const char* INVALID_PROCESS_NAME = "invalid_process";
}

void DmsTokenCallbackTest::SetUpTestCase()
{
    DTEST_LOG << "DmsTokenCallbackTest::SetUpTestCase" << std::endl;
}

void DmsTokenCallbackTest::TearDownTestCase()
{
    DTEST_LOG << "DmsTokenCallbackTest::TearDownTestCase" << std::endl;
}

void DmsTokenCallbackTest::TearDown()
{
    DTEST_LOG << "DmsTokenCallbackTest::TearDown" << std::endl;
}

void DmsTokenCallbackTest::SetUp()
{
    DTEST_LOG << "DmsTokenCallbackTest::SetUp" << std::endl;
    dmsTokenCallback_ = new DmsTokenCallback();
    DistributedSchedUtil::MockProcess(FOUNDATION_PROCESS_NAME);
}

/**
 * @tc.name: SendResultTest_001
 * @tc.desc: call SendResult from distributedsched
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DmsTokenCallbackTest, SendResultTest_001, TestSize.Level3)
{
    DTEST_LOG << "DmsTokenCallbackTest SendResultTest_001 begin" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t requestCode = 0;
    uint32_t accessToken = 0;
    int32_t resultCode = 0;
    DistributedSchedUtil::MockProcess(DISTSCHED_PROCESS_NAME);
    int32_t result = dmsTokenCallback_->SendResult(want, callerUid, requestCode, accessToken, resultCode);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsTokenCallbackTest SendResultTest_001 end" << std::endl;
}

/**
 * @tc.name: SendResultTest_002
 * @tc.desc: call SendResult from foundation
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DmsTokenCallbackTest, SendResultTest_002, TestSize.Level3)
{
    DTEST_LOG << "DmsTokenCallbackTest SendResultTest_002 begin" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t requestCode = 0;
    uint32_t accessToken = 0;
    int32_t resultCode = 0;
    int32_t result = dmsTokenCallback_->SendResult(want, callerUid, requestCode, accessToken, resultCode);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsTokenCallbackTest SendResultTest_002 end" << std::endl;
}

/**
 * @tc.name: SendResultTest_003
 * @tc.desc: call SendResult with local device id
 * @tc.type: FUNC
 * @tc.require: I5WKCK
 */
HWTEST_F(DmsTokenCallbackTest, SendResultTest_003, TestSize.Level3)
{
    DTEST_LOG << "DmsTokenCallbackTest SendResultTest_003 begin" << std::endl;
    AAFwk::Want want;
    string localDeviceId;
    dmsTokenCallback_->GetLocalDeviceId(localDeviceId);
    want.SetParam("dmsSrcNetworkId", localDeviceId);
    int32_t callerUid = 0;
    int32_t requestCode = 0;
    uint32_t accessToken = 0;
    int32_t resultCode = 0;
    int32_t result = dmsTokenCallback_->SendResult(want, callerUid, requestCode, accessToken, resultCode);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsTokenCallbackTest SendResultTest_003 end" << std::endl;
}

/**
 * @tc.name: SendResultTest_004
 * @tc.desc: call SendResult from invalid process
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DmsTokenCallbackTest, SendResultTest_004, TestSize.Level3)
{
    DTEST_LOG << "DmsTokenCallbackTest SendResultTest_004 begin" << std::endl;
    AAFwk::Want want;
    int32_t callerUid = 0;
    int32_t requestCode = 0;
    uint32_t accessToken = 0;
    int32_t resultCode = 0;
    DistributedSchedUtil::MockProcess(INVALID_PROCESS_NAME);
    int32_t result = dmsTokenCallback_->SendResult(want, callerUid, requestCode, accessToken, resultCode);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsTokenCallbackTest SendResultTest_004 end" << std::endl;
}

/**
 * @tc.name: SendResultTest_005
 * @tc.desc: call SendResult with remote device id
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DmsTokenCallbackTest, SendResultTest_005, TestSize.Level3)
{
    DTEST_LOG << "DmsTokenCallbackTest SendResultTest_005 begin" << std::endl;
    AAFwk::Want want;
    string remoteDeviceId = "remoteDeviceId";
    want.SetParam("dmsSrcNetworkId", remoteDeviceId);
    int32_t callerUid = 0;
    int32_t requestCode = 0;
    uint32_t accessToken = 0;
    int32_t resultCode = 0;
    int32_t result = dmsTokenCallback_->SendResult(want, callerUid, requestCode, accessToken, resultCode);
    EXPECT_EQ(result, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DmsTokenCallbackTest SendResultTest_005 end" << std::endl;
}

/**
 * @tc.name: CheckDeviceIdTest_001
 * @tc.desc: call CheckDeviceId with empty deviceId
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DmsTokenCallbackTest, CheckDeviceIdTest_001, TestSize.Level3)
{
    DTEST_LOG << "DmsTokenCallbackTest CheckDeviceIdTest_001 begin" << std::endl;
    std::string localDeviceId;
    std::string remoteDeviceId;
    bool result = dmsTokenCallback_->CheckDeviceId(localDeviceId, remoteDeviceId);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DmsTokenCallbackTest CheckDeviceIdTest_001 end" << std::endl;
}

/**
 * @tc.name: CheckDeviceIdTest_002
 * @tc.desc: call CheckDeviceId with same deviceId
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DmsTokenCallbackTest, CheckDeviceIdTest_002, TestSize.Level3)
{
    DTEST_LOG << "DmsTokenCallbackTest CheckDeviceIdTest_002 begin" << std::endl;
    std::string localDeviceId = "1";
    std::string remoteDeviceId = "1";
    bool result = dmsTokenCallback_->CheckDeviceId(localDeviceId, remoteDeviceId);
    EXPECT_EQ(result, false);
    DTEST_LOG << "DmsTokenCallbackTest CheckDeviceIdTest_002 end" << std::endl;
}

/**
 * @tc.name: CheckDeviceIdTest_003
 * @tc.desc: call CheckDeviceId with different deviceId
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DmsTokenCallbackTest, CheckDeviceIdTest_003, TestSize.Level3)
{
    DTEST_LOG << "DmsTokenCallbackTest CheckDeviceIdTest_003 begin" << std::endl;
    std::string localDeviceId = "1";
    std::string remoteDeviceId = "2";
    bool result = dmsTokenCallback_->CheckDeviceId(localDeviceId, remoteDeviceId);
    EXPECT_EQ(result, true);
    DTEST_LOG << "DmsTokenCallbackTest CheckDeviceIdTest_003 end" << std::endl;
}

/**
 * @tc.name: GetRemoteDmsTest_001
 * @tc.desc: call GetRemoteDms with empty deviceId
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DmsTokenCallbackTest, GetRemoteDmsTest_001, TestSize.Level3)
{
    DTEST_LOG << "DmsTokenCallbackTest GetRemoteDmsTest_001 begin" << std::endl;
    std::string remoteDeviceId;
    sptr<IDistributedSched> result = dmsTokenCallback_->GetRemoteDms(remoteDeviceId);
    EXPECT_EQ(result, nullptr);
    DTEST_LOG << "DmsTokenCallbackTest GetRemoteDmsTest_001 end" << std::endl;
}

/**
 * @tc.name: GetRemoteDmsTest_002
 * @tc.desc: call GetRemoteDms with invalid deviceId
 * @tc.type: FUNC
 * @tc.require: I5RWIV
 */
HWTEST_F(DmsTokenCallbackTest, GetRemoteDmsTest_002, TestSize.Level3)
{
    DTEST_LOG << "DmsTokenCallbackTest GetRemoteDmsTest_002 begin" << std::endl;
    std::string remoteDeviceId = "1";
    sptr<IDistributedSched> result = dmsTokenCallback_->GetRemoteDms(remoteDeviceId);
    EXPECT_EQ(result, nullptr);
    DTEST_LOG << "DmsTokenCallbackTest GetRemoteDmsTest_002 end" << std::endl;
}
}
}