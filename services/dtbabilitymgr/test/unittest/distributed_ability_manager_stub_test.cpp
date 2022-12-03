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
#include "distributed_ability_manager_stub_test.h"

#include "dtbschedmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
constexpr int32_t DISTRIBUTED_SCHED_SA_ID = 1401;
constexpr int32_t INVALID_CODE = 123456;
const std::u16string DMS_PROXY_INTERFACE_TOKEN = u"ohos.distributedschedule.accessToken";
}

void DistributedAbilityManagerStubTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedAbilityManagerStubTest::SetUpTestCase" << std::endl;
}

void DistributedAbilityManagerStubTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedAbilityManagerStubTest::TearDownTestCase" << std::endl;
}

void DistributedAbilityManagerStubTest::SetUp()
{
    dtbabilitymgrStub_ = new DistributedAbilityManagerService(DISTRIBUTED_SCHED_SA_ID, true);
    DTEST_LOG << "DistributedAbilityManagerStubTest::SetUp" << std::endl;
}

void DistributedAbilityManagerStubTest::TearDown()
{
    DTEST_LOG << "DistributedAbilityManagerStubTest::TearDown" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: test OnRemoteRequest with func is nullptr
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedAbilityManagerStubTest, OnRemoteRequest_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerStubTest OnRemoteRequest_001 start" << std::endl;
    uint32_t code = INVALID_CODE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    dtbabilitymgrStub_->funcsMap_[INVALID_CODE] = nullptr;
    data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN);
    int32_t result = dtbabilitymgrStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedAbilityManagerStubTest OnRemoteRequest_001 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: test OnRemoteRequest with distributedFunc is nullptr
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedAbilityManagerStubTest, OnRemoteRequest_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerStubTest OnRemoteRequest_002 start" << std::endl;
    uint32_t code = INVALID_CODE;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    dtbabilitymgrStub_->distributedFuncMap_[INVALID_CODE] = nullptr;
    data.WriteInterfaceToken(DMS_PROXY_INTERFACE_TOKEN);
    int32_t result = dtbabilitymgrStub_->OnRemoteRequest(code, data, reply, option);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedAbilityManagerStubTest OnRemoteRequest_002 end" << std::endl;
}

/**
 * @tc.name: RegisterInner_001
 * @tc.desc: test RegisterInner with continuationExtraParams is nullptr
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedAbilityManagerStubTest, RegisterInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerStubTest RegisterInner_001 start" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    data.WriteInt32(VALUE_OBJECT);
    int32_t result = dtbabilitymgrStub_->RegisterInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedAbilityManagerStubTest RegisterInner_001 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackInner_001
 * @tc.desc: test RegisterDeviceSelectionCallbackInner with cbType is empty
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedAbilityManagerStubTest, RegisterDeviceSelectionCallbackInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerStubTest RegisterDeviceSelectionCallbackInner_001 start" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t token = 0;
    data.WriteInt32(token);
    std::string cbType = "";
    data.WriteString(cbType);
    int32_t result = dtbabilitymgrStub_->RegisterDeviceSelectionCallbackInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedAbilityManagerStubTest RegisterDeviceSelectionCallbackInner_001 end" << std::endl;
}

/**
 * @tc.name: RegisterDeviceSelectionCallbackInner_002
 * @tc.desc: test RegisterDeviceSelectionCallbackInner with notifier is nullptr
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedAbilityManagerStubTest, RegisterDeviceSelectionCallbackInner_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerStubTest RegisterDeviceSelectionCallbackInner_002 start" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t token = 0;
    data.WriteInt32(token);
    std::string cbType = "mockType";
    data.WriteString(cbType);
    int32_t result = dtbabilitymgrStub_->RegisterDeviceSelectionCallbackInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedAbilityManagerStubTest RegisterDeviceSelectionCallbackInner_002 end" << std::endl;
}

/**
 * @tc.name: UnregisterDeviceSelectionCallbackInner_001
 * @tc.desc: test UnregisterDeviceSelectionCallbackInner with cbType is empty
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedAbilityManagerStubTest, UnregisterDeviceSelectionCallbackInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerStubTest UnregisterDeviceSelectionCallbackInner_001 start" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t token = 0;
    data.WriteInt32(token);
    std::string cbType = "";
    data.WriteString(cbType);
    int32_t result = dtbabilitymgrStub_->UnregisterDeviceSelectionCallbackInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedAbilityManagerStubTest UnregisterDeviceSelectionCallbackInner_001 end" << std::endl;
}

/**
 * @tc.name: StartDeviceManagerInner_001
 * @tc.desc: test StartDeviceManagerInner with continuationExtraParams is nullptr
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedAbilityManagerStubTest, StartDeviceManagerInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerStubTest StartDeviceManagerInner_001 start" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    int32_t token = 0;
    data.WriteInt32(token);
    int32_t flag = VALUE_OBJECT;
    data.WriteInt32(flag);
    int32_t result = dtbabilitymgrStub_->StartDeviceManagerInner(data, reply);
    EXPECT_EQ(result, ERR_NULL_OBJECT);
    DTEST_LOG << "DistributedAbilityManagerStubTest StartDeviceManagerInner_001 end" << std::endl;
}

/**
 * @tc.name: GetDistributedComponentListInner_001
 * @tc.desc: test GetDistributedComponentListInner with interfaceToken is empty
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DistributedAbilityManagerStubTest, GetDistributedComponentListInner_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedAbilityManagerStubTest GetDistributedComponentListInner_001 start" << std::endl;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;
    int32_t result = dtbabilitymgrStub_->GetDistributedComponentListInner(data, reply, option);
    EXPECT_EQ(result, DMS_PERMISSION_DENIED);
    DTEST_LOG << "DistributedAbilityManagerStubTest GetDistributedComponentListInner_001 end" << std::endl;
}
}
}