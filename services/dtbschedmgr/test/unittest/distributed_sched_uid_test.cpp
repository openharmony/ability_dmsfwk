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

#define private public
#include "distributed_sched_service.h"
#undef private
#include "distributed_sched_uid_test.h"
#include "distributed_sched_test_util.h"
#define private public
#include "mission/distributed_sched_mission_manager.h"
#undef private
#include "test_log.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::u16string DMS_STUB_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
const std::u16string MOCK_INVALID_DESCRIPTOR = u"invalid descriptor";
constexpr const char* FOUNDATION_PROCESS_NAME = "foundation";
constexpr int32_t UID = 10001;
const char *PERMS[] = {
    "ohos.permission.DISTRIBUTED_DATASYNC"
};
}

void DistributedSchedUidTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedSchedUidTest::SetUpTestCase" << std::endl;
    setuid(UID);
}

void DistributedSchedUidTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedSchedUidTest::TearDownTestCase" << std::endl;
}

void DistributedSchedUidTest::TearDown()
{
    DTEST_LOG << "DistributedSchedUidTest::TearDown" << std::endl;
    distributedSchedStub_ = nullptr;
}

void DistributedSchedUidTest::SetUp()
{
    DTEST_LOG << "DistributedSchedUidTest::SetUp" << std::endl;
    DistributedSchedUtil::MockProcessAndPermission(FOUNDATION_PROCESS_NAME, PERMS, 1);
    distributedSchedStub_ = new DistributedSchedService();
}

/**
 * @tc.name: GetDistributedComponentListInner_001
 * @tc.desc: check GetDistributedComponentListInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, GetDistributedComponentListInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest GetDistributedComponentListInner_001 begin" << std::endl;
    ASSERT_NE(distributedSchedStub_, nullptr);
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->GetDistributedComponentListInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest GetDistributedComponentListInner_001 end" << std::endl;
}
}
}