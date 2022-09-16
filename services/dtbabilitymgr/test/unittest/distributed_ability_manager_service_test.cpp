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
#include "distributed_ability_manager_service_test.h"

#define private public
#include "distributed_ability_manager_service.h"
#undef private
#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    constexpr int32_t DISTRIBUTED_SCHED_SA_ID = 1401;
    constexpr int32_t GET_DISTRIBUTED_COMPONENT_LIST_REQUEST_CODE = 161;
    constexpr int32_t UPDATE_CONNECT_STATUS = 504;
    constexpr int32_t INVALID_CODE = -1;
    const std::u16string DMS_STUB_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
}

void DistributedAbilityManagerServiceTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest::SetUpTestCase" << std::endl;
}

void DistributedAbilityManagerServiceTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest::TearDownTestCase" << std::endl;
}

void DistributedAbilityManagerServiceTest::SetUp()
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest::SetUp" << std::endl;
}

void DistributedAbilityManagerServiceTest::TearDown()
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest::TearDown" << std::endl;
}

/**
 * @tc.name: IsDistributedSchedLoaded_001
 * @tc.desc: test IsDistributedSchedLoaded
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, IsDistributedSchedLoaded_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest IsDistributedSchedLoaded_001 start" << std::endl;
    sptr<DistributedAbilityManagerService>  dtbabilitymgrService =
        new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    int32_t result = dtbabilitymgrService->IsDistributedSchedLoaded();
    EXPECT_EQ(false, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest IsDistributedSchedLoaded_001 end" << std::endl;
}
/**
 * @tc.name: GetDistributedComponentListInner_001
 * @tc.desc: test GetDistributedComponentListInner when dms not start
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, GetDistributedComponentListInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_001 start" << std::endl;
    sptr<DistributedAbilityManagerService>  dtbabilitymgrService =
        new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = dtbabilitymgrService->GetDistributedComponentListInner(data, reply, option);
    EXPECT_EQ(ERR_NONE, result);
    result = reply.ReadInt32();
    EXPECT_EQ(ERR_NONE, result);
    std::vector<std::string> distributedComponents;
    reply.ReadStringVector(&distributedComponents);
    EXPECT_EQ(true, distributedComponents.empty());
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_001 end" << std::endl;
}

/**
 * @tc.name: GetDistributedComponentListInner_002
 * @tc.desc: test GetDistributedComponentListInner when isLoaded_ true
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, GetDistributedComponentListInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_002 start" << std::endl;
    sptr<DistributedAbilityManagerService>  dtbabilitymgrService =
        new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    bool result1 = dtbabilitymgrService->InitDmsImplFunc();
    EXPECT_EQ(true, result1);
    int32_t result2 = dtbabilitymgrService->GetDistributedComponentListInner(data, reply, option);
    EXPECT_EQ(ERR_NONE, result2);
    result2 = reply.ReadInt32();
    EXPECT_EQ(ERR_NONE, result2);
    std::vector<std::string> distributedComponents;
    reply.ReadStringVector(&distributedComponents);
    EXPECT_EQ(true, distributedComponents.empty());
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_002 end" << std::endl;
}

/**
 * @tc.name: GetDistributedComponentListInner_003
 * @tc.desc: test GetDistributedComponentListInner with invalid token
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, GetDistributedComponentListInner_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_003 start" << std::endl;
    sptr<DistributedAbilityManagerService>  dtbabilitymgrService =
        new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t result = dtbabilitymgrService->GetDistributedComponentListInner(data, reply, option);
    EXPECT_EQ(DMS_PERMISSION_DENIED, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest GetDistributedComponentListInner_003 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: test OnRemoteRequest to start GetDistributedComponentListInner
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, OnRemoteRequest_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_001 start" << std::endl;
    sptr<DistributedAbilityManagerService>  dtbabilitymgrService =
        new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = dtbabilitymgrService->OnRemoteRequest(
        GET_DISTRIBUTED_COMPONENT_LIST_REQUEST_CODE, data, reply, option);
    EXPECT_EQ(ERR_NONE, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_001 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: test OnRemoteRequest to start funcsMap_
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, OnRemoteRequest_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_002 start" << std::endl;
    sptr<DistributedAbilityManagerService>  dtbabilitymgrService =
        new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = dtbabilitymgrService->OnRemoteRequest(UPDATE_CONNECT_STATUS, data, reply, option);
    EXPECT_NE(ERR_NONE, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_002 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_003
 * @tc.desc: test OnRemoteRequest to start funcsMap_ with invalid token
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, OnRemoteRequest_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_003 start" << std::endl;
    sptr<DistributedAbilityManagerService>  dtbabilitymgrService =
        new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t result = dtbabilitymgrService->OnRemoteRequest(UPDATE_CONNECT_STATUS, data, reply, option);
    EXPECT_EQ(DMS_PERMISSION_DENIED, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_003 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_004
 * @tc.desc: test OnRemoteRequest with invalid code
 * @tc.type: FUNC
 * @tc.require: I5NOA1
 */
HWTEST_F(DistributedAbilityManagerServiceTest, OnRemoteRequest_004, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_004 start" << std::endl;
    sptr<DistributedAbilityManagerService>  dtbabilitymgrService =
        new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    data.WriteInterfaceToken(DMS_STUB_INTERFACE_TOKEN);
    int32_t result = dtbabilitymgrService->OnRemoteRequest(INVALID_CODE, data, reply, option);
    EXPECT_NE(ERR_NONE, result);
    DTEST_LOG << "DistributedAbilityManagerServiceTest OnRemoteRequest_004 end" << std::endl;
}
}
}