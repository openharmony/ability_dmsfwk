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

#include "mmi_adapter_test.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

void MMIAdapterTest::SetUpTestCase()
{
    DTEST_LOG << "MMIAdapterTest::SetUpTestCase" << std::endl;
}

void MMIAdapterTest::TearDownTestCase()
{
    DTEST_LOG << "MMIAdapterTest::TearDownTestCase" << std::endl;
}

void MMIAdapterTest::TearDown()
{
    DTEST_LOG << "MMIAdapterTest::TearDown" << std::endl;
    MMIAdapter::GetInstance().UnInit();
}

void MMIAdapterTest::SetUp()
{
    DTEST_LOG << "MMIAdapterTest::SetUp" << std::endl;
    MMIAdapter::GetInstance().Init();
}

/**
 * @tc.name: AddMMIListener_001
 * @tc.desc: test AddMMIListener func
 * @tc.type: FUNC
 */
HWTEST_F(MMIAdapterTest, AddMMIListener_001, TestSize.Level3)
{
    DTEST_LOG << "MMIAdapterTest AddMMIListener_001 begin" << std::endl;
    int32_t ret = MMIAdapter::GetInstance().AddMMIListener();
    EXPECT_GT(ret, 0);
    DTEST_LOG << "MMIAdapterTest AddMMIListener_001 end" << std::endl;
}

/**
 * @tc.name: RemoveMMIListener_001
 * @tc.desc: test RemoveMMIListener func
 * @tc.type: FUNC
 */
HWTEST_F(MMIAdapterTest, RemoveMMIListener_001, TestSize.Level3)
{
    DTEST_LOG << "MMIAdapterTest RemoveMMIListener_001 begin" << std::endl;
    int32_t mmiId = -1;
    MMIAdapter::GetInstance().RemoveMMIListener(mmiId);
    EXPECT_NE(MMIAdapter::GetInstance().eventHandler_, nullptr);
    DTEST_LOG << "MMIAdapterTest RemoveMMIListener_001 end" << std::endl;
}

/**
 * @tc.name: PostRawMMIEvent_001
 * @tc.desc: test PostRawMMIEvent func
 * @tc.type: FUNC
 */
HWTEST_F(MMIAdapterTest, PostRawMMIEvent_001, TestSize.Level3)
{
    DTEST_LOG << "MMIAdapterTest PostRawMMIEvent_001 begin" << std::endl;
    MMIAdapter::GetInstance().PostRawMMIEvent();
    EXPECT_NE(MMIAdapter::GetInstance().eventHandler_, nullptr);
    DTEST_LOG << "MMIAdapterTest PostRawMMIEvent_001 end" << std::endl;
}

/**
 * @tc.name: PostUnfreezeMMIEvent_001
 * @tc.desc: test PostUnfreezeMMIEvent func
 * @tc.type: FUNC
 */
HWTEST_F(MMIAdapterTest, PostUnfreezeMMIEvent_001, TestSize.Level3)
{
    DTEST_LOG << "MMIAdapterTest PostUnfreezeMMIEvent_001 begin" << std::endl;
    MMIAdapter::GetInstance().PostUnfreezeMMIEvent();
    EXPECT_NE(MMIAdapter::GetInstance().eventHandler_, nullptr);
    DTEST_LOG << "MMIAdapterTest PostUnfreezeMMIEvent_001 end" << std::endl;
}

/**
 * @tc.name: HandleRawMMIEvent_001
 * @tc.desc: test HandleRawMMIEvent func
 * @tc.type: FUNC
 */
HWTEST_F(MMIAdapterTest, HandleRawMMIEvent_001, TestSize.Level3)
{
    DTEST_LOG << "MMIAdapterTest HandleRawMMIEvent_001 begin" << std::endl;
    MMIAdapter::GetInstance().isMMIFreezed_ = true;
    MMIAdapter::GetInstance().HandleRawMMIEvent();
    EXPECT_EQ(MMIAdapter::GetInstance().isMMIFreezed_, true);
    DTEST_LOG << "MMIAdapterTest HandleRawMMIEvent_001 end" << std::endl;
}

/**
 * @tc.name: HandleRawMMIEvent_002
 * @tc.desc: test HandleRawMMIEvent func
 * @tc.type: FUNC
 */
HWTEST_F(MMIAdapterTest, HandleRawMMIEvent_002, TestSize.Level3)
{
    DTEST_LOG << "MMIAdapterTest HandleRawMMIEvent_002 begin" << std::endl;
    MMIAdapter::GetInstance().isMMIFreezed_ = false;
    MMIAdapter::GetInstance().HandleRawMMIEvent();
    EXPECT_EQ(MMIAdapter::GetInstance().isMMIFreezed_, true);
    DTEST_LOG << "MMIAdapterTest HandleRawMMIEvent_002 end" << std::endl;
}

/**
 * @tc.name: HandleUnfreezeMMIEvent_001
 * @tc.desc: test HandleUnfreezeMMIEvent func
 * @tc.type: FUNC
 */
HWTEST_F(MMIAdapterTest, HandleUnfreezeMMIEvent_001, TestSize.Level3)
{
    DTEST_LOG << "MMIAdapterTest HandleUnfreezeMMIEvent_001 begin" << std::endl;
    MMIAdapter::GetInstance().isMMIFreezed_ = true;
    MMIAdapter::GetInstance().HandleUnfreezeMMIEvent();
    EXPECT_EQ(MMIAdapter::GetInstance().isMMIFreezed_, false);
    DTEST_LOG << "MMIAdapterTest HandleUnfreezeMMIEvent_001 end" << std::endl;
}
}
}
