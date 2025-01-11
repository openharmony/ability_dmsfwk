/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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
#include "dms_sa_cilent_test.h"

#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string DEVICE_ID = "123456789ABCD";
}

void DmsSaClientTest::SetUpTestCase()
{
    DTEST_LOG << "DmsSaClientTest::SetUpTestCase" << std::endl;
}

void DmsSaClientTest::TearDownTestCase()
{
    DTEST_LOG << "DmsSaClientTest::TearDownTestCase" << std::endl;
}

void DmsSaClientTest::SetUp()
{
    dmssaClient_ = std::make_shared<DmsSaClient>();
    dmsSaStatusChange_ = std::make_shared<DmsSystemAbilityStatusChange>();
    DTEST_LOG << "DmsSaClientTest::SetUp" << std::endl;
}

void DmsSaClientTest::TearDown()
{
    DTEST_LOG << "DmsSaClientTest::TearDown" << std::endl;
}

void IDSchedEventListenerTest::DSchedEventNotify(EventNotify &notify)
{
}
sptr<IRemoteObject> IDSchedEventListenerTest::AsObject()
{
    return nullptr;
}

/**
 * @tc.name: AddDSchedEventListener_001
 * @tc.desc: AddDSchedEventListener
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DmsSaClientTest, AddDSchedEventListener_001, TestSize.Level3)
{
    DTEST_LOG << "DmsSaClientTest AddDSchedEventListener_001 start" << std::endl;
    ASSERT_NE(nullptr, dmssaClient_);

    DTEST_LOG << "DmsSaClientTest OnAddSystemAbility_002 start" << std::endl;
    int32_t systemAbilityId = 1;
    dmssaClient_->OnAddSystemAbility(systemAbilityId, DEVICE_ID);

    systemAbilityId = DISTRIBUTED_SCHED_SA_ID;
    dmssaClient_->OnAddSystemAbility(systemAbilityId, DEVICE_ID);
    DTEST_LOG << "DmsSaClientTest OnAddSystemAbility_002 end" << std::endl;

    sptr<IDSchedEventListenerTest> listener(new IDSchedEventListenerTest());
    dmssaClient_->hasSubscribeDmsSA_ = true;
    int32_t result = dmssaClient_->AddDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result, NO_ERROR);
    DTEST_LOG << "DmsSaClientTest AddDSchedEventListener_001 end" << std::endl;
}

/**
 * @tc.name: AddDSchedEventListener_002
 * @tc.desc: AddDSchedEventListener
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DmsSaClientTest, AddDSchedEventListener_002, TestSize.Level3)
{
    DTEST_LOG << "DmsSaClientTest AddDSchedEventListener_002 start" << std::endl;
    ASSERT_NE(nullptr, dmssaClient_);

    DTEST_LOG << "DmsSaClientTest OnRemoveSystemAbility_001 start" << std::endl;
    int32_t systemAbilityId = 1;
    dmssaClient_->OnAddSystemAbility(systemAbilityId, DEVICE_ID);

    systemAbilityId = DISTRIBUTED_SCHED_SA_ID;
    dmssaClient_->OnRemoveSystemAbility(systemAbilityId, DEVICE_ID);
    DTEST_LOG << "DmsSaClientTest OnRemoveSystemAbility_001 end" << std::endl;

    sptr<IDSchedEventListenerTest> listener(new IDSchedEventListenerTest());
    int32_t result = dmssaClient_->AddDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result, NO_ERROR);
    DTEST_LOG << "DmsSaClientTest AddDSchedEventListener_002 end" << std::endl;
}

/**
 * @tc.name: DelDSchedEventListener_001
 * @tc.desc: DelDSchedEventListener
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DmsSaClientTest, DelDSchedEventListener_001, TestSize.Level3)
{
    DTEST_LOG << "DmsSaClientTest OnAddSystemAbility_001 start" << std::endl;
    ASSERT_NE(nullptr, dmssaClient_);
    //systemAbilityId not is DISTRIBUTED_SCHED_SA_ID
    dmssaClient_->OnAddSystemAbility(-1, DEVICE_ID);
    //systemAbilityId is DISTRIBUTED_SCHED_SA_ID
    dmssaClient_->OnAddSystemAbility(DISTRIBUTED_SCHED_SA_ID, DEVICE_ID);
    DTEST_LOG << "DmsSaClientTest OnAddSystemAbility_001 end" << std::endl;

    DTEST_LOG << "DmsSaClientTest DelDSchedEventListener_001 start" << std::endl;
    sptr<IDSchedEventListenerTest> listener(new IDSchedEventListenerTest());
    int32_t result1 = dmssaClient_->AddDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result1, NO_ERROR);
    int32_t result2 = dmssaClient_->DelDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result2, NO_ERROR);
    DTEST_LOG << "DmsSaClientTest DelDSchedEventListener_001 end" << std::endl;
}

/**
 * @tc.name: GetContinueInfo_001
 * @tc.desc: GetContinueInfo
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DmsSaClientTest, GetContinueInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsSaClientTest GetContinueInfo_001 start" << std::endl;
    ASSERT_NE(nullptr, dmssaClient_);
    //systemAbilityId not is DISTRIBUTED_SCHED_SA_ID
    dmssaClient_->OnAddSystemAbility(-1, DEVICE_ID);
    //systemAbilityId is DISTRIBUTED_SCHED_SA_ID
    dmssaClient_->OnAddSystemAbility(DISTRIBUTED_SCHED_SA_ID, DEVICE_ID);
    DTEST_LOG << "DmsSaClientTest OnAddSystemAbility_001 end" << std::endl;

    DTEST_LOG << "DmsSaClientTest GetContinueInfo_001 start" << std::endl;
    ContinueInfo continueInfo;
    int32_t result1 = dmssaClient_->GetContinueInfo(continueInfo);
    EXPECT_EQ(result1, NO_ERROR);
    DTEST_LOG << "DmsSaClientTest GetContinueInfo_001 end" << std::endl;
}

/**
 * @tc.name: GetDSchedEventInfo_001
 * @tc.desc: GetDSchedEventInfo
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DmsSaClientTest, GetDSchedEventInfo_001, TestSize.Level3)
{
    DTEST_LOG << "DmsSaClientTest GetDSchedEventInfo_001 start" << std::endl;
    ASSERT_NE(nullptr, dmssaClient_);
    //systemAbilityId not is DISTRIBUTED_SCHED_SA_ID
    dmssaClient_->OnAddSystemAbility(-1, DEVICE_ID);
    //systemAbilityId is DISTRIBUTED_SCHED_SA_ID
    dmssaClient_->OnAddSystemAbility(DISTRIBUTED_SCHED_SA_ID, DEVICE_ID);
    DTEST_LOG << "DmsSaClientTest OnAddSystemAbility_001 end" << std::endl;

    DTEST_LOG << "DmsSaClientTest GetDSchedEventInfo_001 start" << std::endl;
    std::vector<EventNotify> events;
    int32_t result1 = dmssaClient_->GetDSchedEventInfo(DMS_UNKNOW, events);
    EXPECT_NE(result1, NO_ERROR);
    DTEST_LOG << "DmsSaClientTest GetDSchedEventInfo_001 end" << std::endl;
}

/**
 * @tc.name: OnAddSystemAbility_001
 * @tc.desc: OnAddSystemAbility
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DmsSaClientTest, OnAddSystemAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DmsSaClientTest OnAddSystemAbility_001 start" << std::endl;
    ASSERT_NE(nullptr, dmsSaStatusChange_);
    //systemAbilityId not is DISTRIBUTED_SCHED_SA_ID
    dmsSaStatusChange_->OnAddSystemAbility(-1, DEVICE_ID);
    //systemAbilityId is DISTRIBUTED_SCHED_SA_ID
    dmsSaStatusChange_->OnAddSystemAbility(DISTRIBUTED_SCHED_SA_ID, DEVICE_ID);
    DTEST_LOG << "DmsSaClientTest OnAddSystemAbility_001 end" << std::endl;

    DTEST_LOG << "DmsSaClientTest DelDSchedEventListener_001 start" << std::endl;
    sptr<IDSchedEventListenerTest> listener(new IDSchedEventListenerTest());
    int32_t result = dmssaClient_->AddDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result, NO_ERROR);
    DTEST_LOG << "DmsSaClientTest OnAddSystemAbility_001 end" << std::endl;
}

/**
 * @tc.name: OnRemoveSystemAbility_001
 * @tc.desc: OnRemoveSystemAbility
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DmsSaClientTest, OnRemoveSystemAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DmsSaClientTest OnRemoveSystemAbilityy_001 start" << std::endl;
    ASSERT_NE(nullptr, dmsSaStatusChange_);
    //systemAbilityId not is DISTRIBUTED_SCHED_SA_ID
    dmsSaStatusChange_->OnRemoveSystemAbility(-1, DEVICE_ID);
    //systemAbilityId is DISTRIBUTED_SCHED_SA_ID
    dmsSaStatusChange_->OnRemoveSystemAbility(DISTRIBUTED_SCHED_SA_ID, DEVICE_ID);
    DTEST_LOG << "DmsSaClientTest OnRemoveSystemAbility_001 end" << std::endl;

    DTEST_LOG << "DmsSaClientTest AddDSchedEventListener_001 start" << std::endl;
    sptr<IDSchedEventListenerTest> listener(new IDSchedEventListenerTest());
    int32_t result = dmssaClient_->AddDSchedEventListener(DMS_CONTINUE, listener);;
    EXPECT_EQ(result, NO_ERROR);
    DTEST_LOG << "DmsSaClientTest OnRemoveSystemAbility_001 end" << std::endl;
}

/**
 * @tc.name: DmsSAStatusChangeOnAddSystemAbility_001
 * @tc.desc: DmsSAStatusChangeOnAddSystemAbility
 * @tc.type: FUNC
 * @tc.require: I9K4JN
 */
HWTEST_F(DmsSaClientTest, DmsSAStatusChangeOnAddSystemAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DmsSaClientTest DmsSAStatusChangeOnAddSystemAbility_001 start" << std::endl;
    DmsSystemAbilityStatusChange dmsSystemAbilityStatusChange;
    //systemAbilityId not is DISTRIBUTED_SCHED_SA_ID
    dmsSystemAbilityStatusChange.OnAddSystemAbility(-1, DEVICE_ID);
    //systemAbilityId is DISTRIBUTED_SCHED_SA_ID
    EXPECT_NO_FATAL_FAILURE(dmsSystemAbilityStatusChange.OnAddSystemAbility(DISTRIBUTED_SCHED_SA_ID, DEVICE_ID));
    DTEST_LOG << "DmsSaClientTest DmsSAStatusChangeOnAddSystemAbility_001 end" << std::endl;
}

/**
 * @tc.name: DmsSAStatusChangeOnRemoveSystemAbility_001
 * @tc.desc: DmsSAStatusChangeOnRemoveSystemAbility_001
 * @tc.type: FUNC
 * @tc.require: I9K4JN
 */
HWTEST_F(DmsSaClientTest, DmsSAStatusChangeOnRemoveSystemAbility_001, TestSize.Level3)
{
    DTEST_LOG << "DmsSaClientTest DmsSAStatusChangeOnRemoveSystemAbility_001 start" << std::endl;
    DmsSystemAbilityStatusChange dmsSystemAbilityStatusChange;
    //systemAbilityId not is DISTRIBUTED_SCHED_SA_ID
    dmsSystemAbilityStatusChange.OnRemoveSystemAbility(-1, DEVICE_ID);
    //systemAbilityId is DISTRIBUTED_SCHED_SA_ID
    EXPECT_NO_FATAL_FAILURE(dmsSystemAbilityStatusChange.OnRemoveSystemAbility(DISTRIBUTED_SCHED_SA_ID, DEVICE_ID));
    DTEST_LOG << "DmsSaClientTest DmsSAStatusChangeOnRemoveSystemAbility_001 end" << std::endl;
}
}
}