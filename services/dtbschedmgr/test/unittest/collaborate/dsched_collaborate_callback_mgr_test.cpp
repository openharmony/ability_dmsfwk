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

#include "dsched_collaborate_callback_mgr_test.h"

#include "mock_distributed_sched.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

void DSchedCollaborationCallbackMgrTest::SetUpTestCase()
{
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest::SetUpTestCase" << std::endl;
}

void DSchedCollaborationCallbackMgrTest::TearDownTestCase()
{
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest::TearDownTestCase" << std::endl;
}

void DSchedCollaborationCallbackMgrTest::TearDown()
{
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest::TearDown" << std::endl;
}

void DSchedCollaborationCallbackMgrTest::SetUp()
{
    dschedcollaborationcallbackmgr_ = std::make_shared<DSchedCollaborationCallbackMgr>();
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest::SetUp" << std::endl;
}

sptr<IRemoteObject> DSchedCollaborationCallbackMgrTest::GetDSchedService() const
{
    sptr<IRemoteObject> dsched(new MockDistributedSched());
    return dsched;
}

/**
 * @tc.name: PushCallback_001
 * @tc.desc: call PushCallback
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollaborationCallbackMgrTest, PushCallback_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest PushCallback_001 begin" << std::endl;
    ASSERT_NE(dschedcollaborationcallbackmgr_, nullptr);
    sptr<IRemoteObject> callback = nullptr;
    //diedListener_ is null
    bool ret = dschedcollaborationcallbackmgr_->PushCallback(callback);
    EXPECT_EQ(ret, false);

    //diedListener_ is not null and callback is null
    dschedcollaborationcallbackmgr_->Init();
    ret = dschedcollaborationcallbackmgr_->PushCallback(callback);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest PushCallback_001 end" << std::endl;
}

/**
 * @tc.name: PushCallback_002
 * @tc.desc: call PushCallback
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollaborationCallbackMgrTest, PushCallback_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest PushCallback_002 begin" << std::endl;
    ASSERT_NE(dschedcollaborationcallbackmgr_, nullptr);
    dschedcollaborationcallbackmgr_->Init();
    //callback already exists!
    sptr<IRemoteObject> callback = GetDSchedService();
    dschedcollaborationcallbackmgr_->collaborateCbArr_.clear();
    bool ret = dschedcollaborationcallbackmgr_->PushCallback(callback);
    EXPECT_EQ(ret, true);

    dschedcollaborationcallbackmgr_->collaborateCbArr_.clear();
    dschedcollaborationcallbackmgr_->collaborateCbArr_.push_back(callback);
    ret = dschedcollaborationcallbackmgr_->PushCallback(callback);
    EXPECT_EQ(ret, false);
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest PushCallback_002 end" << std::endl;
}

/**
 * @tc.name: CleanupCallback_001
 * @tc.desc: call CleanupCallback
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollaborationCallbackMgrTest, CleanupCallback_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest CleanupCallback_001 begin" << std::endl;
    ASSERT_NE(dschedcollaborationcallbackmgr_, nullptr);
    dschedcollaborationcallbackmgr_->Init();
    sptr<IRemoteObject> callback = nullptr;
    dschedcollaborationcallbackmgr_->collaborateCbArr_.clear();
    bool ret = dschedcollaborationcallbackmgr_->CleanupCallback(callback);
    EXPECT_EQ(ret, false);

    callback = GetDSchedService();
    dschedcollaborationcallbackmgr_->collaborateCbArr_.push_back(callback);
    ret = dschedcollaborationcallbackmgr_->CleanupCallback(callback);
    EXPECT_EQ(ret, true);

    DTEST_LOG << "DSchedCollaborationCallbackMgrTest CleanupCallback_001 end" << std::endl;
}

/**
 * @tc.name: NotifyDSchedEventForOneCB_001
 * @tc.desc: call NotifyDSchedEventForOneCB
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollaborationCallbackMgrTest, NotifyDSchedEventForOneCB_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest NotifyDSchedEventForOneCB_001 begin" << std::endl;
    ASSERT_NE(dschedcollaborationcallbackmgr_, nullptr);
    dschedcollaborationcallbackmgr_->Init();
    sptr<IRemoteObject> cb = nullptr;
    EventNotify event;
    int32_t ret = dschedcollaborationcallbackmgr_->NotifyDSchedEventForOneCB(cb, event);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest NotifyDSchedEventForOneCB_001 end" << std::endl;
}

/**
 * @tc.name: NotifyDSchedEventResult_001
 * @tc.desc: call NotifyDSchedEventResult
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollaborationCallbackMgrTest, NotifyDSchedEventResult_001, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest NotifyDSchedEventResult_001 begin" << std::endl;
    ASSERT_NE(dschedcollaborationcallbackmgr_, nullptr);
    dschedcollaborationcallbackmgr_->Init();
    int32_t resultCode = 0;
    EventNotify event;
    dschedcollaborationcallbackmgr_->collaborateCbArr_.clear();
    int32_t ret = dschedcollaborationcallbackmgr_->NotifyDSchedEventResult(resultCode, event);
    EXPECT_EQ(ret, INVALID_PARAMETERS_ERR);
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest NotifyDSchedEventResult_001 end" << std::endl;
}

/**
 * @tc.name: NotifyDSchedEventResult_002
 * @tc.desc: call NotifyDSchedEventResult
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(DSchedCollaborationCallbackMgrTest, NotifyDSchedEventResult_002, TestSize.Level3)
{
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest NotifyDSchedEventResult_002 begin" << std::endl;
    ASSERT_NE(dschedcollaborationcallbackmgr_, nullptr);
    dschedcollaborationcallbackmgr_->Init();
    int32_t resultCode = 0;
    EventNotify event;
    sptr<IRemoteObject> callback = GetDSchedService();
    dschedcollaborationcallbackmgr_->collaborateCbArr_.clear();
    dschedcollaborationcallbackmgr_->collaborateCbArr_.push_back(callback);
    int32_t ret = dschedcollaborationcallbackmgr_->NotifyDSchedEventResult(resultCode, event);
    EXPECT_EQ(ret, SEND_REQUEST_DEF_FAIL);
    DTEST_LOG << "DSchedCollaborationCallbackMgrTest NotifyDSchedEventResult_002 end" << std::endl;
}
}
}