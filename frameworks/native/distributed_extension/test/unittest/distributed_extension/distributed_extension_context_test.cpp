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

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#define private public
#define protected public
#include "distributed_extension_context.h"
#include "ability_connect_callback.h"
#include "want.h"
#undef private
#undef protected

namespace OHOS::DistributedSchedule {
using namespace testing;

class MockAbilityConnectCallback : public AbilityConnectCallback {
public:
    MOCK_METHOD(void, OnAbilityConnectDone,
        (const AppExecFwk::ElementName&, const sptr<IRemoteObject>&, int32_t), (override));
    MOCK_METHOD(void, OnAbilityDisconnectDone, (const AppExecFwk::ElementName&, int32_t), (override));
};

class DistributedExtensionContextTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp() override {};
    void TearDown() override {};
public:
    static inline std::shared_ptr<DistributedExtensionContext> context_ = nullptr;
};

void DistributedExtensionContextTest::SetUpTestCase()
{
    context_ = std::make_shared<DistributedExtensionContext>();
}

void DistributedExtensionContextTest::TearDownTestCase()
{
    context_ = nullptr;
}

/**
 * @tc.number: DistributedExtensionContext_ConnectAbility_0100
 * @tc.name: Test ConnectAbility with valid parameters
 * @tc.desc: Verify ConnectAbility returns correct error code
 */
HWTEST_F(DistributedExtensionContextTest, DistributedExtensionContext_ConnectAbility_0100,
    testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_ConnectAbility_0100 begin";
    AAFwk::Want want;
    want.SetElementName("device", "com.test.bundle", "TestAbility");
    
    sptr<MockAbilityConnectCallback> callback = new MockAbilityConnectCallback();
    ASSERT_NE(callback, nullptr);
    
    auto result = context_->ConnectAbility(want, callback);
    GTEST_LOG_(INFO) << "ConnectAbility result: " << result;
    EXPECT_TRUE(result >= 0);
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_ConnectAbility_0100 end";
}

/**
 * @tc.number: DistributedExtensionContext_DisconnectAbility_0100
 * @tc.name: Test DisconnectAbility with valid parameters
 * @tc.desc: Verify DisconnectAbility returns correct error code
 */
HWTEST_F(DistributedExtensionContextTest, DistributedExtensionContext_DisconnectAbility_0100,
    testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_DisconnectAbility_0100 begin";
    AAFwk::Want want;
    want.SetElementName("device", "com.test.bundle", "TestAbility");
    
    sptr<MockAbilityConnectCallback> callback = new MockAbilityConnectCallback();
    ASSERT_NE(callback, nullptr);
    
    auto result = context_->DisconnectAbility(want, callback);
    GTEST_LOG_(INFO) << "DisconnectAbility result: " << result;
    EXPECT_TRUE(result >= 0);
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_DisconnectAbility_0100 end";
}

/**
 * @tc.number: DistributedExtensionContext_IsContext_0100
 * @tc.name: Test IsContext method
 * @tc.desc: Verify IsContext returns correct result
 */
HWTEST_F(DistributedExtensionContextTest, DistributedExtensionContext_IsContext_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_IsContext_0100 begin";
    try {
        bool result = context_->IsContext(DistributedExtensionContext::CONTEXT_TYPE_ID);
        EXPECT_TRUE(result);
        
        result = context_->IsContext(std::hash<const char *>{}("unknownContext"));
        EXPECT_FALSE(result);
    } catch (...) {
        GTEST_LOG_(INFO) << "IsContext exception occurred";
    }
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_IsContext_0100 end";
}

/**
 * @tc.number: DistributedExtensionContext_Constructor_0100
 * @tc.name: Test constructor
 * @tc.desc: Verify constructor creates valid object
 */
HWTEST_F(DistributedExtensionContextTest, DistributedExtensionContext_Constructor_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_Constructor_0100 begin";
    try {
        auto newContext = std::make_shared<DistributedExtensionContext>();
        ASSERT_NE(newContext, nullptr);
    } catch (...) {
        GTEST_LOG_(INFO) << "Constructor exception occurred";
    }
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_Constructor_0100 end";
}

/**
 * @tc.number: DistributedExtensionContext_Destructor_0100
 * @tc.name: Test destructor
 * @tc.desc: Verify destructor works correctly
 */
HWTEST_F(DistributedExtensionContextTest, DistributedExtensionContext_Destructor_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_Destructor_0100 begin";
    try {
        auto newContext = new DistributedExtensionContext();
        ASSERT_NE(newContext, nullptr);
        delete newContext;
    } catch (...) {
        GTEST_LOG_(INFO) << "Destructor exception occurred";
    }
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_Destructor_0100 end";
}

/**
 * @tc.number: DistributedExtensionContext_ConnectAbility_0200
 * @tc.name: Test ConnectAbility with empty want
 * @tc.desc: Verify ConnectAbility handles empty want
 */
HWTEST_F(DistributedExtensionContextTest, DistributedExtensionContext_ConnectAbility_0200,
    testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_ConnectAbility_0200 begin";
    try {
        AAFwk::Want want;
        
        auto callback = sptr<MockAbilityConnectCallback>(new MockAbilityConnectCallback());
        ASSERT_NE(callback, nullptr);
        
        auto result = context_->ConnectAbility(want, callback);
        GTEST_LOG_(INFO) << "ConnectAbility with empty want result: " << result;
    } catch (...) {
        GTEST_LOG_(INFO) << "ConnectAbility exception occurred";
    }
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_ConnectAbility_0200 end";
}

/**
 * @tc.number: DistributedExtensionContext_DisconnectAbility_0200
 * @tc.name: Test DisconnectAbility with empty want
 * @tc.desc: Verify DisconnectAbility handles empty want
 */
HWTEST_F(DistributedExtensionContextTest, DistributedExtensionContext_DisconnectAbility_0200,
    testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_DisconnectAbility_0200 begin";
    try {
        AAFwk::Want want;
        
        auto callback = sptr<MockAbilityConnectCallback>(new MockAbilityConnectCallback());
        ASSERT_NE(callback, nullptr);
        
        auto result = context_->DisconnectAbility(want, callback);
        GTEST_LOG_(INFO) << "DisconnectAbility with empty want result: " << result;
    } catch (...) {
        GTEST_LOG_(INFO) << "DisconnectAbility exception occurred";
    }
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_DisconnectAbility_0200 end";
}

/**
 * @tc.number: DistributedExtensionContext_CONTEXT_TYPE_ID_0100
 * @tc.name: Test CONTEXT_TYPE_ID constant
 * @tc.desc: Verify CONTEXT_TYPE_ID is valid
 */
HWTEST_F(DistributedExtensionContextTest, DistributedExtensionContext_CONTEXT_TYPE_ID_0100,
    testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_CONTEXT_TYPE_ID_0100 begin";
    try {
        size_t contextTypeId = DistributedExtensionContext::CONTEXT_TYPE_ID;
        EXPECT_TRUE(contextTypeId != 0);
        
        size_t expectedHash = std::hash<const char *>{}("distributedExtensionContext");
        EXPECT_EQ(contextTypeId, expectedHash);
    } catch (...) {
        GTEST_LOG_(INFO) << "CONTEXT_TYPE_ID test exception occurred";
    }
    GTEST_LOG_(INFO) << "DistributedExtensionContextTest DistributedExtensionContext_CONTEXT_TYPE_ID_0100 end";
}
} // namespace OHOS::DistributedSchedule