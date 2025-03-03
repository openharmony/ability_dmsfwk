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
#include "js_runtime_mock.h"
#include "napi_mock.h"
#include "native_reference_mock.h"
#include "distributed_extension_js.cpp"

namespace OHOS::DistributedSchedule {
using namespace testing;

class DExtensionJsTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase();
    void SetUp() override {};
    void TearDown() override {};
public:
    static inline unique_ptr<JsRuntimeMock> jsRuntime = nullptr;
    static inline shared_ptr<DistributedExtensionJs> dExtensionJs = nullptr;
    static inline shared_ptr<DExtensionMock> dExtensionMock = nullptr;
    static inline shared_ptr<NapiMock> napiMock = nullptr;
};

napi_value CreateDistributedExtensionContextJS(napi_env env, std::shared_ptr<DistributedExtensionContext> context)
{
    return TDExtension::tDExtension->CreateDistributedExtensionContextJS(env, context);
}

void DExtensionJsTest::SetUpTestCase()
{
    GTEST_LOG_(INFO) << "SetUpTestCase enter";
    jsRuntime = make_unique<JsRuntimeMock>();
    dExtensionJs = make_shared<DistributedExtensionJs>(*jsRuntime);
    dExtensionMock = make_shared<DExtensionMock>();
    DExtensionMock::tDExtension = dExtensionMock;
    napiMock = make_shared<NapiMock>();
    Napi::napi = napiMock;
}

void DExtensionJsTest::TearDownTestCase()
{
    GTEST_LOG_(INFO) << "TearDownTestCase enter";
    dExtensionJs = nullptr;
    jsRuntime = nullptr;
    DExtensionMock::tDExtension = nullptr;
    dExtensionMock = nullptr;
    Napi::napi = nullptr;
    napiMock = nullptr;
}

/**
 * @tc.number: DistributedExtensionJs_GetSrcPath_0100
 * @tc.name: DistributedExtensionJs_GetSrcPath_0100
 * @tc.desc: Test the function of invoking the GetSrcPath interface.
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_GetSrcPath_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_GetSrcPath_0100 begin";
    try {
        sptr<AppExecFwk::AbilityInfo> info = sptr(new AppExecFwk::AbilityInfo());
        info->srcEntrance = "";
        auto ret = GetSrcPath(*info);
        EXPECT_TRUE(ret.empty());

        info->srcEntrance = "test";
        ret = GetSrcPath(*info);
        EXPECT_FALSE(ret.empty());
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_GetSrcPath_0100 end";
}

/**
 * @tc.number: DistributedExtensionJs_AttachDistributedExtensionContext_0100
 * @tc.name: DistributedExtensionJs_AttachDistributedExtensionContext_0100
 * @tc.desc: Test the function of invoking the AttachBackupExtensionContext interface.
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_AttachDistributedExtensionContext_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_AttachDistributedExtensionContext_0100 begin";
    try {
        auto ret = AttachDistributedExtensionContext(nullptr, nullptr, nullptr);
        EXPECT_TRUE(ret == nullptr);

        int env = 0;
        ret = AttachDistributedExtensionContext(reinterpret_cast<napi_env>(&env), nullptr, nullptr);
        EXPECT_TRUE(ret == nullptr);

        auto value = make_shared<DistributedExtensionContext>();
        ret = AttachDistributedExtensionContext(reinterpret_cast<napi_env>(&env), value.get(), nullptr);
        EXPECT_TRUE(ret == nullptr);

        ret = AttachDistributedExtensionContext(reinterpret_cast<napi_env>(&env), value.get(), nullptr);
        EXPECT_TRUE(ret == nullptr);
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_AttachDistributedExtensionContext_0100 end";
}

/**
 * @tc.number: DistributedExtensionJs_ExportJsContext_0100
 * @tc.name: DistributedExtensionJs_ExportJsContext_0100
 * @tc.desc: Test the function of invoking the ExportJsContext interface.
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_ExportJsContext_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_ExportJsContext_0100 begin";
    try {
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        dExtensionJs->ExportJsContext();
        EXPECT_TRUE(dExtensionJs->jsObj_ == nullptr);

        dExtensionJs->jsObj_ = make_unique<NativeReferenceMock>();
        auto refMock = static_cast<NativeReferenceMock*>(dExtensionJs->jsObj_.get());
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*refMock, GetNapiValue()).WillOnce(Return(nullptr));
        dExtensionJs->ExportJsContext();
        EXPECT_TRUE(dExtensionJs->jsObj_ != nullptr);

        int value = 0;
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*refMock, GetNapiValue()).WillOnce(Return(reinterpret_cast<napi_value>(&value)));
        dExtensionJs->ExportJsContext();
        EXPECT_TRUE(dExtensionJs->jsObj_ != nullptr);
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_ExportJsContext_0100 end";
}

/**
 * @tc.number: DistributedExtensionJs_CallJsMethod_0100
 * @tc.name: DistributedExtensionJs_CallJsMethod_0100
 * @tc.desc: Test the function of invoking the CallJsMethod interface.
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_CallJsMethod_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsMethod_0100 begin";
    try {
        dExtensionJs->jsObj_ = make_unique<NativeReferenceMock>();
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_invalid_arg));
        auto ret = dExtensionJs->CallJsMethod("", *jsRuntime, dExtensionJs->jsObj_.get(), nullptr, nullptr);
        EXPECT_EQ(ret, EINVAL);
    } catch (...) {
        EXPECT_TRUE(false);
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsMethod_0100 end";
}
} // namespace OHOS::DistributedSchedule