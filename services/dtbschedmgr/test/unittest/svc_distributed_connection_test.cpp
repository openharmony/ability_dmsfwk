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

#include "svc_distributed_connection_test.h"

#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
void SvcDistributedConnectionTest::SetUpTestCase()
{
    disconnectedCon_ = sptr(new SvcDistributedConnection("com.example.dms_extension"));
    DTEST_LOG << "SvcDistributedConnectionTest::SetUpTestCase" << std::endl;
}

void SvcDistributedConnectionTest::TearDownTestCase()
{
    disconnectedCon_ = nullptr;
    DTEST_LOG << "SvcDistributedConnectionTest::TearDownTestCase" << std::endl;
}

void SvcDistributedConnectionTest::TearDown()
{
    DTEST_LOG << "SvcDistributedConnectionTest::TearDown" << std::endl;
}

void SvcDistributedConnectionTest::SetUp()
{
    DTEST_LOG << "SvcDistributedConnectionTest::SetUp" << std::endl;
}

/**
 * @tc.name: OnAbilityConnectDone_001
 * @tc.desc: OnAbilityConnectDone
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, OnAbilityConnectDone_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest OnAbilityConnectDone_001 begin" << std::endl;
    int resultCode = 0;
    AppExecFwk::ElementName element;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    disconnectedCon_->OnAbilityConnectDone(element, nullptr, resultCode);
    EXPECT_TRUE(true);

    sptr<IRemoteObject> remoteObject;
    disconnectedCon_->OnAbilityConnectDone(element, remoteObject, resultCode);
    EXPECT_TRUE(true);
    DTEST_LOG << "SvcDistributedConnectionTest OnAbilityConnectDone_001 end" << std::endl;
}

/**
 * @tc.name: OnAbilityDisconnectDone_001
 * @tc.desc: OnAbilityDisconnectDone
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, OnAbilityDisconnectDone_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest OnAbilityDisconnectDone_001 begin" << std::endl;

    AppExecFwk::ElementName element;
    string bundleName = "";
    element.SetBundleName(bundleName);
    int resultCode = 1;

    EXPECT_TRUE(disconnectedCon_ != nullptr);
    disconnectedCon_->isConnectCalled_ = false;
    disconnectedCon_->OnAbilityDisconnectDone(element, resultCode);
    bool ret = disconnectedCon_->IsExtAbilityConnected();
    EXPECT_FALSE(ret);

    disconnectedCon_->isConnectCalled_ = true;
    disconnectedCon_->OnAbilityDisconnectDone(element, resultCode);
    ret = disconnectedCon_->IsExtAbilityConnected();
    EXPECT_FALSE(ret);

    DTEST_LOG << "SvcDistributedConnectionTest OnAbilityDisconnectDone_001 end" << std::endl;
}

/**
 * @tc.name: GetDistributedExtProxy_001
 * @tc.desc: GetDistributedExtProxy
 * @tc.type: FUNC
 */
HWTEST_F(SvcDistributedConnectionTest, GetDistributedExtProxy_001, TestSize.Level3)
{
    DTEST_LOG << "SvcDistributedConnectionTest GetDistributedExtProxy_001 begin" << std::endl;
    EXPECT_TRUE(disconnectedCon_ != nullptr);
    auto proxy = disconnectedCon_->GetDistributedExtProxy();
    EXPECT_EQ(proxy, nullptr);
    DTEST_LOG << "SvcDistributedConnectionTest GetDistributedExtProxy_001 end" << std::endl;
}
}
}