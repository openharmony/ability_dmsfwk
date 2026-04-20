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

#include "ability_connection_wrapper_stub_test.h"

#include "ability_connection_wrapper_stub.h"
#include "ability_connect_callback_interface.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "mock_remote_stub.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AAFwk;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string BUNDLE_NAME = "com.test.bundle";
    const std::string ABILITY_NAME = "TestAbility";
    const std::string DEVICE_ID = "test_device_id";
    const std::string LOCAL_DEVICE_ID = "local_device_id";
    const int32_t RESULT_CODE_SUCCESS = 0;
    const int32_t RESULT_CODE_FAILED = -1;
}

AbilityConnectionWrapperStubTest::AbilityConnectionWrapperStubTest()
{}

AbilityConnectionWrapperStubTest::~AbilityConnectionWrapperStubTest()
{}

void AbilityConnectionWrapperStubTest::SetUpTestCase()
{}

void AbilityConnectionWrapperStubTest::TearDownTestCase()
{}

void AbilityConnectionWrapperStubTest::SetUp()
{}

void AbilityConnectionWrapperStubTest::TearDown()
{}

/**
 * @tc.name: testOnAbilityConnectDone_001
 * @tc.desc: test OnAbilityConnectDone with null distributedConnection
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperStubTest, testOnAbilityConnectDone_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityConnectDone_001 begin" << std::endl;
    AbilityConnectionWrapperStub stub;
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remoteObject = new MockRemoteStub();

    // Test with null distributedConnection_ - should return early without crash
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityConnectDone(element, remoteObject, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityConnectDone_001 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityConnectDone_002
 * @tc.desc: test OnAbilityConnectDone with valid connection
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperStubTest, testOnAbilityConnectDone_002, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityConnectDone_002 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> connection = new MockRemoteStub();

    AbilityConnectionWrapperStub stub(connection);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remoteObject = new MockRemoteStub();

    // Test with valid connection - should not crash
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityConnectDone(element, remoteObject, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityConnectDone_002 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityConnectDone_003
 * @tc.desc: test OnAbilityConnectDone with isCall_ mode
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperStubTest, testOnAbilityConnectDone_003, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityConnectDone_003 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> connection = new MockRemoteStub();

    AbilityConnectionWrapperStub stub(connection, LOCAL_DEVICE_ID);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remoteObject = new MockRemoteStub();

    // Test with isCall_ mode - should not crash
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityConnectDone(element, remoteObject, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityConnectDone_003 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityConnectDone_004
 * @tc.desc: test OnAbilityConnectDone with null remoteObject
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperStubTest, testOnAbilityConnectDone_004, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityConnectDone_004 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> connection = new MockRemoteStub();

    AbilityConnectionWrapperStub stub(connection);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    sptr<IRemoteObject> nullRemoteObject = nullptr;

    // Test with null remoteObject - should not crash
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityConnectDone(element, nullRemoteObject, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityConnectDone_004 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityDisconnectDone_001
 * @tc.desc: test OnAbilityDisconnectDone with null distributedConnection
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperStubTest, testOnAbilityDisconnectDone_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityDisconnectDone_001 begin" << std::endl;
    AbilityConnectionWrapperStub stub;
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);

    // Test with null distributedConnection_ - should return early without crash
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityDisconnectDone(element, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityDisconnectDone_001 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityDisconnectDone_002
 * @tc.desc: test OnAbilityDisconnectDone with valid connection
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperStubTest, testOnAbilityDisconnectDone_002, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityDisconnectDone_002 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> connection = new MockRemoteStub();

    AbilityConnectionWrapperStub stub(connection);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);

    // Test with valid connection - should not crash
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityDisconnectDone(element, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityDisconnectDone_002 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityDisconnectDone_003
 * @tc.desc: test OnAbilityDisconnectDone with isCall_ mode
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperStubTest, testOnAbilityDisconnectDone_003, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityDisconnectDone_003 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> connection = new MockRemoteStub();

    AbilityConnectionWrapperStub stub(connection, LOCAL_DEVICE_ID);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);

    // Test with isCall_ mode - should not crash
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityDisconnectDone(element, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityDisconnectDone_003 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityDisconnectDone_004
 * @tc.desc: test OnAbilityDisconnectDone with failed result code
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperStubTest, testOnAbilityDisconnectDone_004, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityDisconnectDone_004 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> connection = new MockRemoteStub();

    AbilityConnectionWrapperStub stub(connection);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);

    // Test with failed result code - should not crash
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityDisconnectDone(element, RESULT_CODE_FAILED));
    DTEST_LOG << "AbilityConnectionWrapperStubTest testOnAbilityDisconnectDone_004 end" << std::endl;
}

/**
 * @tc.name: testMultipleOperations_001
 * @tc.desc: test multiple connect/disconnect operations
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperStubTest, testMultipleOperations_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperStubTest testMultipleOperations_001 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> connection = new MockRemoteStub();

    AbilityConnectionWrapperStub stub(connection);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remoteObject = new MockRemoteStub();

    // Test multiple operations - should not crash
    for (int i = 0; i < 5; i++) {
        EXPECT_NO_FATAL_FAILURE(stub.OnAbilityConnectDone(element, remoteObject, RESULT_CODE_SUCCESS));
        EXPECT_NO_FATAL_FAILURE(stub.OnAbilityDisconnectDone(element, RESULT_CODE_SUCCESS));
    }
    DTEST_LOG << "AbilityConnectionWrapperStubTest testMultipleOperations_001 end" << std::endl;
}

/**
 * @tc.name: testEmptyElementName_001
 * @tc.desc: test with empty element name
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperStubTest, testEmptyElementName_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperStubTest testEmptyElementName_001 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> connection = new MockRemoteStub();

    AbilityConnectionWrapperStub stub(connection);
    ElementName element;  // Empty element
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remoteObject = new MockRemoteStub();

    // Test with empty element - should not crash
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityConnectDone(element, remoteObject, RESULT_CODE_SUCCESS));
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityDisconnectDone(element, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperStubTest testEmptyElementName_001 end" << std::endl;
}

/**
 * @tc.name: testSpecialCharactersInElementName_001
 * @tc.desc: test with special characters in element name
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperStubTest, testSpecialCharactersInElementName_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperStubTest testSpecialCharactersInElementName_001 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> connection = new MockRemoteStub();

    AbilityConnectionWrapperStub stub(connection, LOCAL_DEVICE_ID);
    ElementName element(DEVICE_ID, "com.test@#$%.bundle", "Test@#$%Ability");
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remoteObject = new MockRemoteStub();

    // Test with special characters - should not crash
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityConnectDone(element, remoteObject, RESULT_CODE_SUCCESS));
    EXPECT_NO_FATAL_FAILURE(stub.OnAbilityDisconnectDone(element, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperStubTest testSpecialCharactersInElementName_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
