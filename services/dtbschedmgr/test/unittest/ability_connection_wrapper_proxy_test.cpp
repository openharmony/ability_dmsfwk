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

#include "ability_connection_wrapper_proxy_test.h"

#include "ability_connection_wrapper_proxy.h"
#include "ability_connect_callback_interface.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "mock_remote_stub.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;
using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
namespace {
    const std::string BUNDLE_NAME = "com.test.bundle";
    const std::string ABILITY_NAME = "TestAbility";
    const std::string DEVICE_ID = "test_device_id";
    const int32_t RESULT_CODE_SUCCESS = 0;
    const int32_t RESULT_CODE_FAILED = -1;
}

AbilityConnectionWrapperProxyTest::AbilityConnectionWrapperProxyTest()
{}

AbilityConnectionWrapperProxyTest::~AbilityConnectionWrapperProxyTest()
{}

void AbilityConnectionWrapperProxyTest::SetUpTestCase()
{}

void AbilityConnectionWrapperProxyTest::TearDownTestCase()
{}

void AbilityConnectionWrapperProxyTest::SetUp()
{}

void AbilityConnectionWrapperProxyTest::TearDown()
{}

/**
 * @tc.name: testOnAbilityConnectDone_001
 * @tc.desc: test OnAbilityConnectDone with valid parameters
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperProxyTest, testOnAbilityConnectDone_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityConnectDone_001 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remoteObj = new MockRemoteStub();

    AbilityConnectionWrapperProxy proxy(remoteObj);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);

    // Test with valid parameters - should not crash
    EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityConnectDone(element, remoteObj, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityConnectDone_001 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityConnectDone_002
 * @tc.desc: test OnAbilityConnectDone with null element
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperProxyTest, testOnAbilityConnectDone_002, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityConnectDone_002 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remoteObj = new MockRemoteStub();

    AbilityConnectionWrapperProxy proxy(remoteObj);
    ElementName element;

    // Test with empty element - should not crash
    EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityConnectDone(element, remoteObj, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityConnectDone_002 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityConnectDone_003
 * @tc.desc: test OnAbilityConnectDone with null remote object
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperProxyTest, testOnAbilityConnectDone_003, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityConnectDone_003 begin" << std::endl;
    sptr<IRemoteObject> impl = new MockRemoteStub();

    AbilityConnectionWrapperProxy proxy(impl);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    sptr<IRemoteObject> nullRemoteObj = nullptr;

    // Test with null remote object - should not crash
    EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityConnectDone(element, nullRemoteObj, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityConnectDone_003 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityConnectDone_004
 * @tc.desc: test OnAbilityConnectDone with failed result code
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperProxyTest, testOnAbilityConnectDone_004, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityConnectDone_004 begin" << std::endl;
    // Use MockRemoteStub instead of abstract IRemoteObject
    sptr<IRemoteObject> remoteObj = new MockRemoteStub();

    AbilityConnectionWrapperProxy proxy(remoteObj);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);

    // Test with failed result code - should not crash
    EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityConnectDone(element, remoteObj, RESULT_CODE_FAILED));
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityConnectDone_004 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityDisconnectDone_001
 * @tc.desc: test OnAbilityDisconnectDone with valid parameters
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperProxyTest, testOnAbilityDisconnectDone_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityDisconnectDone_001 begin" << std::endl;
    sptr<IRemoteObject> impl = new MockRemoteStub();

    AbilityConnectionWrapperProxy proxy(impl);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);

    // Test with valid parameters - should not crash
    EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityDisconnectDone(element, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityDisconnectDone_001 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityDisconnectDone_002
 * @tc.desc: test OnAbilityDisconnectDone with empty element
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperProxyTest, testOnAbilityDisconnectDone_002, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityDisconnectDone_002 begin" << std::endl;
    sptr<IRemoteObject> impl = new MockRemoteStub();

    AbilityConnectionWrapperProxy proxy(impl);
    ElementName element;

    // Test with empty element - should not crash
    EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityDisconnectDone(element, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityDisconnectDone_002 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityDisconnectDone_003
 * @tc.desc: test OnAbilityDisconnectDone with failed result code
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperProxyTest, testOnAbilityDisconnectDone_003, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityDisconnectDone_003 begin" << std::endl;
    sptr<IRemoteObject> impl = new MockRemoteStub();

    AbilityConnectionWrapperProxy proxy(impl);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);

    // Test with failed result code - should not crash
    EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityDisconnectDone(element, RESULT_CODE_FAILED));
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityDisconnectDone_003 end" << std::endl;
}

/**
 * @tc.name: testOnAbilityDisconnectDone_004
 * @tc.desc: test OnAbilityDisconnectDone with special characters in element name
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperProxyTest, testOnAbilityDisconnectDone_004, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityDisconnectDone_004 begin" << std::endl;
    sptr<IRemoteObject> impl = new MockRemoteStub();

    AbilityConnectionWrapperProxy proxy(impl);
    ElementName element(DEVICE_ID, "com.test.bundle@#$%", "Test@#$%Ability");

    // Test with special characters - should not crash
    EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityDisconnectDone(element, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testOnAbilityDisconnectDone_004 end" << std::endl;
}

/**
 * @tc.name: testProxyConstructor_001
 * @tc.desc: test proxy constructor with null remote object
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperProxyTest, testProxyConstructor_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testProxyConstructor_001 begin" << std::endl;
    sptr<IRemoteObject> nullObj = nullptr;

    // Test with null remote object - should create proxy but methods may not work
    AbilityConnectionWrapperProxy proxy(nullObj);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    sptr<IRemoteObject> remoteObj = nullptr;

    // These should handle null gracefully
    EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityConnectDone(element, remoteObj, RESULT_CODE_SUCCESS));
    EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityDisconnectDone(element, RESULT_CODE_SUCCESS));
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testProxyConstructor_001 end" << std::endl;
}

/**
 * @tc.name: testMultipleConnectDisconnect_001
 * @tc.desc: test multiple connect and disconnect calls
 * @tc.type: FUNC
 * @tc.require: I7XVTZ
 */
HWTEST_F(AbilityConnectionWrapperProxyTest, testMultipleConnectDisconnect_001, TestSize.Level3)
{
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testMultipleConnectDisconnect_001 begin" << std::endl;
    sptr<IRemoteObject> impl = new MockRemoteStub();

    AbilityConnectionWrapperProxy proxy(impl);
    ElementName element(DEVICE_ID, BUNDLE_NAME, ABILITY_NAME);
    sptr<IRemoteObject> remoteObj = nullptr;

    // Test multiple calls - should not crash
    for (int i = 0; i < 10; i++) {
        EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityConnectDone(element, remoteObj, RESULT_CODE_SUCCESS));
        EXPECT_NO_FATAL_FAILURE(proxy.OnAbilityDisconnectDone(element, RESULT_CODE_SUCCESS));
    }
    DTEST_LOG << "AbilityConnectionWrapperProxyTest testMultipleConnectDisconnect_001 end" << std::endl;
}
} // namespace DistributedSchedule
} // namespace OHOS
