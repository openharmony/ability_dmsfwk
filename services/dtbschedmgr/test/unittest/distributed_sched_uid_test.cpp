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
constexpr int32_t CAllING_UID = 10001;
const char *PERMS[] = {
    "ohos.permission.DISTRIBUTED_DATASYNC"
};
}

void DistributedSchedUidTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedSchedUidTest::SetUpTestCase" << std::endl;
    setuid(CAllING_UID);
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
    distributedSchedStub_ = new DistributedSchedService();
    DistributedSchedUtil::MockProcessAndPermission(FOUNDATION_PROCESS_NAME, PERMS, 1);
}

/**
 * @tc.name: StartAbilityFromRemoteInner_001
 * @tc.desc: check StartAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, StartAbilityFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest StartAbilityFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->StartAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest StartAbilityFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: SendResultFromRemoteInner_001
 * @tc.desc: check SendResultFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, SendResultFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest SendResultFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->SendResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest SendResultFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyContinuationResultFromRemoteInner_001
 * @tc.desc: check NotifyContinuationResultFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, NotifyContinuationResultFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest NotifyContinuationResultFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->NotifyContinuationResultFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest NotifyContinuationResultFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: ConnectAbilityFromRemoteInner_001
 * @tc.desc: check ConnectAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, ConnectAbilityFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest ConnectAbilityFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->ConnectAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest ConnectAbilityFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: DisconnectAbilityFromRemoteInner_001
 * @tc.desc: check DisconnectAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, DisconnectAbilityFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest DisconnectAbilityFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->DisconnectAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest DisconnectAbilityFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyProcessDiedFromRemoteInner_001
 * @tc.desc: check NotifyProcessDiedFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, NotifyProcessDiedFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest NotifyProcessDiedFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->NotifyProcessDiedFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest NotifyProcessDiedFromRemoteInner_001 end" << std::endl;
}

#ifdef SUPPORT_DISTRIBUTED_MISSION_MANAGER
/**
 * @tc.name: StartSyncMissionsFromRemoteInner_001
 * @tc.desc: check StartSyncMissionsFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, StartSyncMissionsFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest StartSyncMissionsFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->StartSyncMissionsFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest StartSyncMissionsFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: StopSyncMissionsFromRemoteInner_001
 * @tc.desc: check StopSyncMissionsFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, StopSyncMissionsFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest StopSyncMissionsFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->StopSyncMissionsFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest StopSyncMissionsFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyMissionsChangedFromRemoteInner_001
 * @tc.desc: check NotifyMissionsChangedFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, NotifyMissionsChangedFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest NotifyMissionsChangedFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->NotifyMissionsChangedFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest NotifyMissionsChangedFromRemoteInner_001 end" << std::endl;
}
#endif

/**
 * @tc.name: StartAbilityByCallFromRemoteInner_001
 * @tc.desc: check StartAbilityByCallFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, StartAbilityByCallFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest StartAbilityByCallFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->StartAbilityByCallFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest StartAbilityByCallFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: ReleaseAbilityFromRemoteInner_001
 * @tc.desc: check ReleaseAbilityFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, ReleaseAbilityFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest ReleaseAbilityFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->ReleaseAbilityFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest ReleaseAbilityFromRemoteInner_001 end" << std::endl;
}

#ifdef SUPPORT_DISTRIBUTED_FORM_SHARE
/**
 * @tc.name: StartShareFormFromRemoteInner_001
 * @tc.desc: check StartShareFormFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, StartShareFormFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest StartShareFormFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->StartShareFormFromRemoteInner(data, reply);
    EXPECT_EQ(result, ERR_NONE);
    DTEST_LOG << "DistributedSchedUidTest StartShareFormFromRemoteInner_001 end" << std::endl;
}
#endif

/**
 * @tc.name: GetDistributedComponentListInner_001
 * @tc.desc: check GetDistributedComponentListInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, GetDistributedComponentListInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest GetDistributedComponentListInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->GetDistributedComponentListInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest GetDistributedComponentListInner_001 end" << std::endl;
}

/**
 * @tc.name: StartFreeInstallFromRemoteInner_001
 * @tc.desc: check StartFreeInstallFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, StartFreeInstallFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest StartFreeInstallFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->StartFreeInstallFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest StartFreeInstallFromRemoteInner_001 end" << std::endl;
}

/**
 * @tc.name: NotifyCompleteFreeInstallFromRemoteInner_001
 * @tc.desc: check NotifyCompleteFreeInstallFromRemoteInner
 * @tc.type: FUNC
 */
HWTEST_F(DistributedSchedUidTest, NotifyCompleteFreeInstallFromRemoteInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedSchedUidTest NotifyCompleteFreeInstallFromRemoteInner_001 begin" << std::endl;
    MessageParcel data;
    MessageParcel reply;

    int32_t result = distributedSchedStub_->NotifyCompleteFreeInstallFromRemoteInner(data, reply);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedSchedUidTest NotifyCompleteFreeInstallFromRemoteInner_001 end" << std::endl;
}
}
}