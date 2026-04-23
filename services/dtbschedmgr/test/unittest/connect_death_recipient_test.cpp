/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "connect_death_recipient_test.h"

#include "connect_death_recipient.h"
#include "mock_remote_stub.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

ConnectDeathRecipientTest::ConnectDeathRecipientTest()
{}

ConnectDeathRecipientTest::~ConnectDeathRecipientTest()
{}

void ConnectDeathRecipientTest::SetUpTestCase()
{}

void ConnectDeathRecipientTest::TearDownTestCase()
{}

void ConnectDeathRecipientTest::SetUp()
{}

void ConnectDeathRecipientTest::TearDown()
{}

/**
 * @tc.name: testDestructor_001
 * @tc.desc: test destructor
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(ConnectDeathRecipientTest, testDestructor_001, TestSize.Level3)
{
    DTEST_LOG << "ConnectDeathRecipientTest testDestructor_001 begin" << std::endl;
    auto* recipient = new ConnectDeathRecipient();
    ASSERT_NE(recipient, nullptr);
    delete recipient;
    // Test that destructor works correctly
    DTEST_LOG << "ConnectDeathRecipientTest testDestructor_001 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDied_001
 * @tc.desc: test OnRemoteDied with null remote
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(ConnectDeathRecipientTest, testOnRemoteDied_001, TestSize.Level3)
{
    DTEST_LOG << "ConnectDeathRecipientTest testOnRemoteDied_001 begin" << std::endl;
    ConnectDeathRecipient recipient;
    wptr<IRemoteObject> nullRemote;

    // Test with null remote - should not crash
    EXPECT_NO_FATAL_FAILURE(recipient.OnRemoteDied(nullRemote));
    DTEST_LOG << "ConnectDeathRecipientTest testOnRemoteDied_001 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDied_002
 * @tc.desc: test OnRemoteDied with valid remote
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(ConnectDeathRecipientTest, testOnRemoteDied_002, TestSize.Level3)
{
    DTEST_LOG << "ConnectDeathRecipientTest testOnRemoteDied_002 begin" << std::endl;
    ConnectDeathRecipient recipient;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remote = new MockRemoteStub();
    wptr<IRemoteObject> weakRemote = remote;

    // Test with null remote - should not crash
    EXPECT_NO_FATAL_FAILURE(recipient.OnRemoteDied(weakRemote));
    DTEST_LOG << "ConnectDeathRecipientTest testOnRemoteDied_002 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDied_003
 * @tc.desc: test OnRemoteDied with expired weak pointer
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(ConnectDeathRecipientTest, testOnRemoteDied_003, TestSize.Level3)
{
    DTEST_LOG << "ConnectDeathRecipientTest testOnRemoteDied_003 begin" << std::endl;
    ConnectDeathRecipient recipient;

    // Create an expired weak pointer
    wptr<IRemoteObject> expiredWeak;
    {
        sptr<IRemoteObject> temp = new MockRemoteStub();
        expiredWeak = temp;
    }
    // temp is destroyed here, expiredWeak should be expired

    // Test with expired weak pointer - should not crash
    EXPECT_NO_FATAL_FAILURE(recipient.OnRemoteDied(expiredWeak));
    DTEST_LOG << "ConnectDeathRecipientTest testOnRemoteDied_003 end" << std::endl;
}

/**
 * @tc.name: testMultipleOnRemoteDiedCalls_001
 * @tc.desc: test multiple OnRemoteDied calls
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(ConnectDeathRecipientTest, testMultipleOnRemoteDiedCalls_001, TestSize.Level3)
{
    DTEST_LOG << "ConnectDeathRecipientTest testMultipleOnRemoteDiedCalls_001 begin" << std::endl;
    ConnectDeathRecipient recipient;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remote = new MockRemoteStub();
    wptr<IRemoteObject> weakRemote = remote;

    // Test multiple calls - should not crash
    for (int i = 0; i < 10; i++) {
        EXPECT_NO_FATAL_FAILURE(recipient.OnRemoteDied(weakRemote));
    }
    DTEST_LOG << "ConnectDeathRecipientTest testMultipleOnRemoteDiedCalls_001 end" << std::endl;
}

/**
 * @tc.name: testOnRemoteDiedWithDifferentRemotes_001
 * @tc.desc: test OnRemoteDied with different remote objects
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(ConnectDeathRecipientTest, testOnRemoteDiedWithDifferentRemotes_001, TestSize.Level3)
{
    DTEST_LOG << "ConnectDeathRecipientTest testOnRemoteDiedWithDifferentRemotes_001 begin" << std::endl;
    ConnectDeathRecipient recipient;

    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remote1 = new MockRemoteStub();
    sptr<IRemoteObject> remote2 = new MockRemoteStub();
    sptr<IRemoteObject> remote3 = new MockRemoteStub();

    wptr<IRemoteObject> weakRemote1 = remote1;
    wptr<IRemoteObject> weakRemote2 = remote2;
    wptr<IRemoteObject> weakRemote3 = remote3;

    // Test with different remotes - should not crash
    EXPECT_NO_FATAL_FAILURE(recipient.OnRemoteDied(weakRemote1));
    EXPECT_NO_FATAL_FAILURE(recipient.OnRemoteDied(weakRemote2));
    EXPECT_NO_FATAL_FAILURE(recipient.OnRemoteDied(weakRemote3));
    DTEST_LOG << "ConnectDeathRecipientTest testOnRemoteDiedWithDifferentRemotes_001 end" << std::endl;
}

/**
 * @tc.name: testSharedPtrBehavior_001
 * @tc.desc: test shared_ptr reference counting behavior
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(ConnectDeathRecipientTest, testSharedPtrBehavior_001, TestSize.Level3)
{
    DTEST_LOG << "ConnectDeathRecipientTest testSharedPtrBehavior_001 begin" << std::endl;

    // Create recipient using shared_ptr
    auto recipient = std::make_shared<ConnectDeathRecipient>();
    ASSERT_NE(recipient, nullptr);

    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remote = new MockRemoteStub();
    wptr<IRemoteObject> weakRemote = remote;

    // Test OnRemoteDied with shared_ptr recipient
    EXPECT_NO_FATAL_FAILURE(recipient->OnRemoteDied(weakRemote));
    DTEST_LOG << "ConnectDeathRecipientTest testSharedPtrBehavior_001 end" << std::endl;
}

/**
 * @tc.name: testNullptrPromote_001
 * @tc.desc: test OnRemoteDied when promote returns nullptr
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(ConnectDeathRecipientTest, testNullptrPromote_001, TestSize.Level3)
{
    DTEST_LOG << "ConnectDeathRecipientTest testNullptrPromote_001 begin" << std::endl;
    ConnectDeathRecipient recipient;

    // Create empty weak pointer
    sptr<IRemoteObject> nullRemote;
    wptr<IRemoteObject> weakNull = nullRemote;

    // promote() on empty weak pointer returns nullptr
    // ProcessConnectDied should handle nullptr gracefully
    EXPECT_NO_FATAL_FAILURE(recipient.OnRemoteDied(weakNull));
    DTEST_LOG << "ConnectDeathRecipientTest testNullptrPromote_001 end" << std::endl;
}

/**
 * @tc.name: testConcurrentOnRemoteDied_001
 * @tc.desc: test concurrent OnRemoteDied calls
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(ConnectDeathRecipientTest, testConcurrentOnRemoteDied_001, TestSize.Level3)
{
    DTEST_LOG << "ConnectDeathRecipientTest testConcurrentOnRemoteDied_001 begin" << std::endl;
    auto recipient = std::make_shared<ConnectDeathRecipient>();

    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remote = new MockRemoteStub();
    wptr<IRemoteObject> weakRemote = remote;

    // Simulate concurrent calls (though not truly concurrent in single thread)
    for (int i = 0; i < 5; i++) {
        EXPECT_NO_FATAL_FAILURE(recipient->OnRemoteDied(weakRemote));
    }
    DTEST_LOG << "ConnectDeathRecipientTest testConcurrentOnRemoteDied_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
