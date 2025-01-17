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

#include "dsched_collab_state.h"
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
}
}
