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

#include "distributed_extension_mock.h"
#include "distributed_extension.h"
#include "ohos_application.h"
#include "ability_handler.h"
#include "distributed_extension_js.cpp"

namespace OHOS::DistributedSchedule {
using namespace std;
using namespace testing;

napi_value CreateDistributedExtensionContextJS(napi_env env, std::shared_ptr<DistributedExtensionContext> context)
{
    return TDExtension::tDExtension->CreateDistributedExtensionContextJS(env, context);
}

class DExtensionTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp() override {};
    void TearDown() override {};
public:
    static inline shared_ptr<DistributedExtension> dExt = nullptr;
    static inline shared_ptr<DExtensionMock> dExtensionMock = nullptr;
};

void DExtensionTest::SetUpTestCase()
{
    dExt = make_shared<DistributedExtension>();
    dExtensionMock = make_shared<DExtensionMock>();
    DExtensionMock::tDExtension = dExtensionMock;
}
void DExtensionTest::TearDownTestCase()
{
    dExt = nullptr;
    DExtensionMock::tDExtension = nullptr;
    dExtensionMock = nullptr;
}

/**
 * @tc.number: DistributedExtension_Create_0100
 * @tc.name: DistributedExtension_Create_0100
 * @tc.desc: Test the function of invoking the Create interface.
 */
HWTEST_F(DExtensionTest, DistributedExtension_Create_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionTest DistributedExtension_Create_0100 begin";
    try {
        std::unique_ptr<AbilityRuntime::Runtime> runtime;
        auto dExtension = DistributedExtension::Create(runtime);
        EXPECT_TRUE(dExtension != nullptr);

        AbilityRuntime::Runtime::Options options;
        runtime = AbilityRuntime::Runtime::Create(options);
        dExtension = DistributedExtension::Create(runtime);
        EXPECT_TRUE(dExtension != nullptr);
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionTest DistributedExtension_Create_0100 end";
}

/**
 * @tc.number: DistributedExtension_OnConnect_0100
 * @tc.name: DistributedExtension_OnConnect_0100
 * @tc.desc: Test the function of invoking the OnConnect interface.
 */
HWTEST_F(DExtensionTest, DistributedExtension_OnConnect_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionTest DistributedExtension_OnConnect_0100 begin";
    try {
        AbilityRuntime::Runtime::Options options;
        std::unique_ptr<AbilityRuntime::Runtime> runtime = AbilityRuntime::Runtime::Create(options);
        auto dExtension = DistributedExtension::Create(runtime);
        dExtension->abilityInfo_ = std::make_shared<AppExecFwk::AbilityInfo>();

        AAFwk::Want want;
        auto remoteObj = dExtension->OnConnect(want);
        EXPECT_TRUE(remoteObj == nullptr);
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionTest DistributedExtension_OnConnect_0100 end";
}

/**
 * @tc.number: DistributedExtension_OnDisconnect_0100
 * @tc.name: DistributedExtension_OnDisconnect_0100
 * @tc.desc: Test the function of invoking the OnDisconnect interface.
 */
HWTEST_F(DExtensionTest, DistributedExtension_OnDisconnect_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionTest DistributedExtension_OnDisconnect_0100 begin";
    try {
        AbilityRuntime::Runtime::Options options;
        std::unique_ptr<AbilityRuntime::Runtime> runtime = AbilityRuntime::Runtime::Create(options);
        auto dExtension = DistributedExtension::Create(runtime);
        dExtension->abilityInfo_ = std::make_shared<AppExecFwk::AbilityInfo>();

        AAFwk::Want want;
        dExtension->OnDisconnect(want);

        wptr<IRemoteObject> remoteObj = nullptr;
        dExtension->SetDistributedExtensionService(remoteObj);
        dExtension->OnDisconnect(want);

    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionTest DistributedExtension_OnDisconnect_0100 end";
}
} // namespace OHOS::DistributedSchedule
