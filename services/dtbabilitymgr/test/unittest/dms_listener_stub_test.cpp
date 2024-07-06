/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#include "dms_listener_stub_test.h"

#include <cstring>
#include <memory>
#include <string>

#include "ipc_object_stub.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "message_option.h"
#include "message_parcel.h"
#include "securec.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string DEVICE_ID = "123456789ABCD";
}

void DSchedEventListenerStubTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedEventListenerStubTest::SetUpTestCase" << std::endl;
}

void DSchedEventListenerStubTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedEventListenerStubTest::TearDownTestCase" << std::endl;
}

void DSchedEventListenerStubTest::SetUp()
{
    dschedeventlistenerStub_ = new DSchedEventListenerStubPub();
    DTEST_LOG << "DSchedEventListenerStubTest::SetUp" << std::endl;
}

void DSchedEventListenerStubTest::TearDown()
{
    DTEST_LOG << "DSchedEventListenerStubTest::TearDown" << std::endl;
}

void DSchedEventListenerStubPub::DSchedEventNotify(EventNotify &notify)
{
}

/**
 * @tc.name: OnRemoteRequest_001
 * @tc.desc: OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DSchedEventListenerStubTest, OnRemoteRequest_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedEventListenerStubTest OnRemoteRequest_001 start" << std::endl;
    ASSERT_NE(nullptr, dschedeventlistenerStub_);
    int32_t code = -1;
    MessageParcel data;
    MessageParcel reply;
    MessageOption option;

    data.WriteInterfaceToken(IDSchedEventListener::GetDescriptor());
    int32_t result = dschedeventlistenerStub_->OnRemoteRequest(-1, data, reply, option);
    EXPECT_TRUE(ERR_OK != result);
    DTEST_LOG << "DSchedEventListenerStubTest OnRemoteRequest_001 end" << std::endl;
}

/**
 * @tc.name: OnRemoteRequest_002
 * @tc.desc: OnRemoteRequest
 * @tc.type: FUNC
 * @tc.require: I64FU7
 */
HWTEST_F(DSchedEventListenerStubTest, OnRemoteRequest_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedEventListenerStubTest DSchedEventNotifyInner_001 start" << std::endl;
    ASSERT_NE(nullptr, dschedeventlistenerStub_);
    MessageParcel data1;
    MessageParcel reply1;
    dschedeventlistenerStub_->DSchedEventNotifyInner(data1, reply1);
    DTEST_LOG << "DSchedEventListenerStubTest DSchedEventNotifyInner_001 end" << std::endl;

    DTEST_LOG << "DSchedEventListenerStubTest OnRemoteRequest_002 start" << std::endl;
    int32_t code = -1;
    MessageParcel data2;
    MessageParcel reply2;
    MessageOption option;
    int32_t result = dschedeventlistenerStub_->OnRemoteRequest(-1, data2, reply2, option);
    EXPECT_TRUE(ERR_OK != result);
    DTEST_LOG << "DSchedEventListenerStubTest OnRemoteRequest_002 end" << std::endl;
}
}
}