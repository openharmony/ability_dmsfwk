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

#include "js_extension_context_mock.h"
#include "napi_mock.h"
#include "distributed_extension_context_js.cpp"

namespace OHOS {
namespace AbilityRuntime {
napi_value CreateJsExtensionContext(napi_env env, const std::shared_ptr<AbilityRuntime::ExtensionContext>& context,
    std::shared_ptr<OHOS::AppExecFwk::AbilityInfo> abilityInfo)
{
    return OHOS::DistributedSchedule::TJsExtensionContext::tJsExtContext->CreateJsExtensionContext(env,
        context, abilityInfo);
}
}
}

namespace OHOS::DistributedSchedule {
using namespace std;
using namespace testing;

class DExtensionContextJSTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp() override {};
    void TearDown() override {};
public:
    static inline shared_ptr<JsExtensionContextMock> jsExtensionContextMock_ = nullptr;
    static inline shared_ptr<NapiMock> napiMock = nullptr;
};

void DExtensionContextJSTest::SetUpTestCase()
{
    jsExtensionContextMock_ = make_shared<JsExtensionContextMock>();
    JsExtensionContextMock::tJsExtContext = jsExtensionContextMock_;
    napiMock = make_shared<NapiMock>();
    Napi::napi = napiMock;
}
void DExtensionContextJSTest::TearDownTestCase()
{
    JsExtensionContextMock::tJsExtContext = nullptr;
    jsExtensionContextMock_ = nullptr;
    Napi::napi = nullptr;
    napiMock = nullptr;
}

/**
 * @tc.number: DExtensionContextJS_CreateDistributedExtensionContextJS_0100
 * @tc.name: DExtensionContextJS_CreateDistributedExtensionContextJS_0100
 * @tc.desc: Test the function of invoking the CreateDistributedExtensionContextJS interface.
 */
HWTEST_F(DExtensionContextJSTest, DExtensionContextJS_CreateDistributedExtensionContextJS_0100,
    testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionContextJSTest DExtensionContextJS_CreateDistributedExtensionContextJS_0100 begin";
    try {
        int env = 0;
        auto value = make_shared<DistributedExtensionContext>();
        auto ptr = reinterpret_cast<std::weak_ptr<DistributedExtensionContext> *>(value.get())->lock();
        auto ret = CreateDistributedExtensionContextJS(reinterpret_cast<napi_env>(&env), ptr);
        EXPECT_TRUE(ret == nullptr);

        EXPECT_CALL(*jsExtensionContextMock_, CreateJsExtensionContext(_, _, _)).WillOnce(Return(nullptr));
        int env1 = 0;
        shared_ptr<DistributedExtensionContext> value1 = make_shared<DistributedExtensionContext>();
        ret = CreateDistributedExtensionContextJS(reinterpret_cast<napi_env>(&env1), value1);
        EXPECT_TRUE(ret == nullptr);

        napi_value jhc = 0;
        EXPECT_CALL(*jsExtensionContextMock_, CreateJsExtensionContext(_, _, _))
            .WillOnce(Return(reinterpret_cast<napi_value>(&jhc)));
        int env2 = 0;
        shared_ptr<DistributedExtensionContext> value2 = make_shared<DistributedExtensionContext>();
        ret = CreateDistributedExtensionContextJS(reinterpret_cast<napi_env>(&env2), value2);
        EXPECT_TRUE(ret != nullptr);
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionContextJSTest DExtensionContextJS_CreateDistributedExtensionContextJS_0100 end";
}
} // namespace OHOS::DistributedSchedule
