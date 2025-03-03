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

#include "distributed_client.h"

#include "gtest/gtest.h"

#include "dtbcollabmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedCollab {
class DistributedClientTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void DistributedClientTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedClientTest::SetUpTestCase" << std::endl;
}

void DistributedClientTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedClientTest::TearDownTestCase" << std::endl;
}

void DistributedClientTest::TearDown()
{
    DTEST_LOG << "DistributedClientTest::TearDown" << std::endl;
}

void DistributedClientTest::SetUp()
{
    DTEST_LOG << "DistributedClientTest::SetUp" << std::endl;
}

/**
 * @tc.name: CollabMission_Test_001
 * @tc.desc: call CollabMission
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(DistributedClientTest, CollabMission_Test_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedClientTest CollabMission_Test_001 begin" << std::endl;
    DistributedClient dmsClient;
    int32_t sessionId = 3;
    std::string serverSocketName = "serverSocketName";
    AbilityConnectionSessionInfo sessionInfo;
    ConnectOption options;
    std::string token = "token";
    auto result = dmsClient.CollabMission(sessionId, serverSocketName, sessionInfo, options, token);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DistributedClientTest CollabMission_Test_001 end" << std::endl;
}
/**
 * @tc.name: NotifyPrepareResult_Test_001
 * @tc.desc: call NotifyPrepareResult
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(DistributedClientTest, NotifyPrepareResult_Test_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedClientTest NotifyPrepareResult_Test_001 begin" << std::endl;
    DistributedClient dmsClient;
    int32_t sessionId = 3;
    int32_t result = INVALID_PARAMETERS_ERR;
    std::string serverSocketName = "serverSocketName";
    std::string token = "token";
    auto out = dmsClient.NotifyPrepareResult(token, result, sessionId, serverSocketName);
    EXPECT_NE(out, ERR_OK);
    DTEST_LOG << "DistributedClientTest NotifyPrepareResult_Test_001 end" << std::endl;
}

/**
 * @tc.name: NotifyCloseCollabSession_Test_001
 * @tc.desc: call NotifyCloseCollabSession
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(DistributedClientTest, NotifyCloseCollabSession_Test_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedClientTest NotifyCloseCollabSession_Test_001 begin" << std::endl;
    DistributedClient dmsClient;
    std::string token = "token";
    auto result = dmsClient.NotifyCloseCollabSession(token);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DistributedClientTest NotifyCloseCollabSession_Test_001 end" << std::endl;
}

/**
 * @tc.name: GetPeerVersion_Test_001
 * @tc.desc: call GetPeerVersion
 * @tc.type: FUNC
 * @tc.require: IBP3MC
 */
HWTEST_F(DistributedClientTest, GetPeerVersion_Test_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedClientTest GetPeerVersion_Test_001 begin" << std::endl;
    DistributedClient dmsClient;
    int32_t sessionId = 3;
    std::string serverSocketName = "serverSocketName";
    std::string peerDeviceId = "peerDeviceId";
    auto result = dmsClient.GetPeerVersion(sessionId, serverSocketName, peerDeviceId);
    EXPECT_NE(result, ERR_OK);
    DTEST_LOG << "DistributedClientTest GetPeerVersion_Test_001 end" << std::endl;
}
}
}
