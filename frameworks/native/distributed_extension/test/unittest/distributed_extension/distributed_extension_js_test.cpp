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

const int ARG_INDEX_FIRST = 1;

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
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: issuesIAFBOS
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_GetSrcPath_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_GetSrcPath_0100 begin";
    try {
        sptr<AppExecFwk::AbilityInfo> info = sptr(new AppExecFwk::AbilityInfo());
        info->srcEntrance = "";
        auto ret = GetSrcPath(*info);
        EXPECT_TRUE(ret.empty());
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_GetSrcPath_0100 case1 finished";

        info->srcEntrance = "test";
        ret = GetSrcPath(*info);
        EXPECT_FALSE(ret.empty());
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_GetSrcPath_0100 case2 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionJsTest an exception occurred by GetSrcPath.";
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_GetSrcPath_0100 end";
}

/**
 * @tc.number: DistributedExtensionJs_AttachDistributedExtensionContext_0100
 * @tc.name: DistributedExtensionJs_AttachDistributedExtensionContext_0100
 * @tc.desc: Test the function of invoking the AttachBackupExtensionContext interface.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: issuesIAFBOS
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_AttachDistributedExtensionContext_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_AttachDistributedExtensionContext_0100 begin";
    try {
        auto ret = AttachDistributedExtensionContext(nullptr, nullptr, nullptr);
        EXPECT_TRUE(ret == nullptr);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_AttachDistributedExtensionContext_0100 finished";

        int env = 0;
        ret = AttachDistributedExtensionContext(reinterpret_cast<napi_env>(&env), nullptr, nullptr);
        EXPECT_TRUE(ret == nullptr);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_AttachDistributedExtensionContext_0100 finished";

        auto value = make_shared<DistributedExtensionContext>();
        ret = AttachDistributedExtensionContext(reinterpret_cast<napi_env>(&env), value.get(), nullptr);
        EXPECT_TRUE(ret == nullptr);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_AttachDistributedExtensionContext_0100 finished";

        ret = AttachDistributedExtensionContext(reinterpret_cast<napi_env>(&env), value.get(), nullptr);
        EXPECT_TRUE(ret == nullptr);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_AttachDistributedExtensionContext_0100 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionJsTest an exception occurred by AttachBackupExtensionContext.";
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_AttachDistributedExtensionContext_0100 end";
}

/**
 * @tc.number: DistributedExtensionJs_ExportJsContext_0100
 * @tc.name: DistributedExtensionJs_ExportJsContext_0100
 * @tc.desc: Test the function of invoking the ExportJsContext interface.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: issuesIAFBOS
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_ExportJsContext_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_ExportJsContext_0100 begin";
    try {
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        dExtensionJs->ExportJsContext();
        EXPECT_TRUE(dExtensionJs->jsObj_ == nullptr);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_ExportJsContext_0100 case1 finished";

        dExtensionJs->jsObj_ = make_unique<NativeReferenceMock>();
        auto refMock = static_cast<NativeReferenceMock*>(dExtensionJs->jsObj_.get());
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*refMock, GetNapiValue()).WillOnce(Return(nullptr));
        dExtensionJs->ExportJsContext();
        EXPECT_TRUE(dExtensionJs->jsObj_ != nullptr);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_ExportJsContext_0100 case2 finished";

        int value = 0;
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*refMock, GetNapiValue()).WillOnce(Return(reinterpret_cast<napi_value>(&value)));
        dExtensionJs->ExportJsContext();
        EXPECT_TRUE(dExtensionJs->jsObj_ != nullptr);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_ExportJsContext_0100 case3 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionJsTest an exception occurred by ExportJsContext.";
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_ExportJsContext_0100 end";
}

/**
 * @tc.number: DistributedExtensionJs_CallJsMethod_0100
 * @tc.name: DistributedExtensionJs_CallJsMethod_0100
 * @tc.desc: Test the function of invoking the CallJsMethod interface.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: issuesIAFBOS
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
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsMethod_0100 case1 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionJsTest an exception occurred by CallJsMethod.";
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsMethod_0100 end";
}

/**
 * @tc.number: DistributedExtensionJs_DoCallJsMethod_0100
 * @tc.name: DistributedExtensionJs_DoCallJsMethod_0100
 * @tc.desc: Test the function of invoking the DoCallJsMethod interface.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: issuesIAFBOS
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_DoCallJsMethod_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0100 begin";
    try {
        string funcName = "";
        InputArgsParser argParserIn = {};
        ResultValueParser retParserIn = {};
        auto param = make_shared<CallJsParam>(funcName, nullptr, nullptr, argParserIn, retParserIn);
        auto ret = DoCallJsMethod(param.get());
        EXPECT_EQ(ret, EINVAL);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0100 case1 finished";

        param->jsRuntime = jsRuntime.get();
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_open_handle_scope(_, _)).WillOnce(Return(napi_ok));
        ret = DoCallJsMethod(param.get());
        EXPECT_EQ(ret, EINVAL);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0100 case2 finished";

        int scope = 0;
        param->argParser = [](napi_env, std::vector<napi_value> &){ return false; };
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_open_handle_scope(_, _)).WillOnce(
            DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_handle_scope>(&scope)), Return(napi_ok)));
        EXPECT_CALL(*napiMock, napi_close_handle_scope(_, _)).WillOnce(Return(napi_ok));
        ret = DoCallJsMethod(param.get());
        EXPECT_EQ(ret, EINVAL);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0100 case3 finished";

        auto ref = make_shared<NativeReferenceMock>();
        param->argParser = [](napi_env, std::vector<napi_value> &){ return true; };
        param->jsObj = ref.get();
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_open_handle_scope(_, _)).WillOnce(
            DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_handle_scope>(&scope)), Return(napi_ok)));
        EXPECT_CALL(*ref, GetNapiValue()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_close_handle_scope(_, _)).WillOnce(Return(napi_ok));
        ret = DoCallJsMethod(param.get());
        EXPECT_EQ(ret, EINVAL);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0100 case4 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionJsTest an exception occurred by DoCallJsMethod.";
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0100 end";
}

/**
 * @tc.number: DistributedExtensionJs_DoCallJsMethod_0200
 * @tc.name: DistributedExtensionJs_DoCallJsMethod_0200
 * @tc.desc: Test the function of invoking the DoCallJsMethod interface.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: issuesIAFBOS
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_DoCallJsMethod_0200, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0200 begin";
    try {
        string funcName = "";
        InputArgsParser argParserIn = {};
        ResultValueParser retParserIn = {};
        auto param = make_shared<CallJsParam>(funcName, nullptr, nullptr, argParserIn, retParserIn);
        auto ref = make_shared<NativeReferenceMock>();
        param->argParser = nullptr;
        param->retParser = nullptr;
        param->jsObj = ref.get();

        int scope = 0;
        napi_value value = nullptr;
        param->jsRuntime = jsRuntime.get();
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_open_handle_scope(_, _)).WillOnce(
            DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_handle_scope>(&scope)), Return(napi_ok)));
        EXPECT_CALL(*ref, GetNapiValue()).WillOnce(Return(reinterpret_cast<napi_value>(&value)));
        EXPECT_CALL(*napiMock, napi_get_named_property(_, _, _, _)).WillOnce(Return(napi_invalid_arg));
        EXPECT_CALL(*napiMock, napi_close_handle_scope(_, _)).WillOnce(Return(napi_ok));
        auto ret = DoCallJsMethod(param.get());
        EXPECT_EQ(ret, EINVAL);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0200 case1 finished";

        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_open_handle_scope(_, _)).WillOnce(
            DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_handle_scope>(&scope)), Return(napi_ok)));
        EXPECT_CALL(*ref, GetNapiValue()).WillOnce(Return(reinterpret_cast<napi_value>(&value)));
        EXPECT_CALL(*napiMock, napi_get_named_property(_, _, _, _)).WillOnce(Return(napi_ok));
        EXPECT_CALL(*napiMock, napi_close_handle_scope(_, _)).WillOnce(Return(napi_ok));
        ret = DoCallJsMethod(param.get());
        EXPECT_EQ(ret, ERR_OK);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0200 case2 finished";

        param->retParser = [](napi_env, napi_value){ return false; };
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_open_handle_scope(_, _)).WillOnce(
            DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_handle_scope>(&scope)), Return(napi_ok)));
        EXPECT_CALL(*ref, GetNapiValue()).WillOnce(Return(reinterpret_cast<napi_value>(&value)));
        EXPECT_CALL(*napiMock, napi_get_named_property(_, _, _, _)).WillOnce(Return(napi_ok));
        EXPECT_CALL(*napiMock, napi_call_function(_, _, _, _, _, _)).WillOnce(Return(napi_ok));
        EXPECT_CALL(*napiMock, napi_escape_handle(_, _, _, _)).WillOnce(Return(napi_ok));
        EXPECT_CALL(*napiMock, napi_close_handle_scope(_, _)).WillOnce(Return(napi_ok));
        ret = DoCallJsMethod(param.get());
        EXPECT_EQ(ret, EINVAL);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0200 case3 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionJsTest an exception occurred by DoCallJsMethod.";
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0200 end";
}

/**
 * @tc.number: DistributedExtensionJs_DoCallJsMethod_0300
 * @tc.name: DistributedExtensionJs_DoCallJsMethod_0300
 * @tc.desc: Test the function of invoking the DoCallJsMethod interface.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: issuesIAFBOS
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_DoCallJsMethod_0300, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0300 begin";
    try {
        string funcName = "";
        InputArgsParser argParserIn = {};
        ResultValueParser retParserIn = {};
        auto param = make_shared<CallJsParam>(funcName, nullptr, nullptr, argParserIn, retParserIn);
        auto ref = make_shared<NativeReferenceMock>();
        param->argParser = nullptr;
        param->retParser = nullptr;
        param->jsObj = ref.get();

        int scope = 0;
        napi_value value = nullptr;
        param->jsRuntime = jsRuntime.get();
        param->retParser = [](napi_env, napi_value){ return true; };
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_open_handle_scope(_, _)).WillOnce(
            DoAll(SetArgPointee<ARG_INDEX_FIRST>(reinterpret_cast<napi_handle_scope>(&scope)), Return(napi_ok)));
        EXPECT_CALL(*ref, GetNapiValue()).WillOnce(Return(reinterpret_cast<napi_value>(&value)));
        EXPECT_CALL(*napiMock, napi_get_named_property(_, _, _, _)).WillOnce(Return(napi_ok));
        EXPECT_CALL(*napiMock, napi_call_function(_, _, _, _, _, _)).WillOnce(Return(napi_ok));
        EXPECT_CALL(*napiMock, napi_escape_handle(_, _, _, _)).WillOnce(Return(napi_ok));
        EXPECT_CALL(*napiMock, napi_close_handle_scope(_, _)).WillOnce(Return(napi_ok));
        auto ret = DoCallJsMethod(param.get());
        EXPECT_EQ(ret, ERR_OK);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0300 case1 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionJsTest an exception occurred by DoCallJsMethod.";
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_DoCallJsMethod_0300 end";
}

/**
 * @tc.number: DistributedExtensionJs_CallJsOnCreate_0100
 * @tc.name: DistributedExtensionJs_CallJsOnCreate_0100
 * @tc.desc: Test the function of invoking the CallJsOnCreate interface.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: issuesIAFBOS
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_CallJsOnCreate_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsOnCreate_0100 begin";
    try {
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_invalid_arg));
        auto ret = dExtensionJs->CallJsOnCreate();
        EXPECT_EQ(ret, EINVAL);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsOnCreate_0100 case1 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionJsTest an exception occurred by CallJsOnCreate.";
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsOnCreate_0100 end";
}

/**
 * @tc.number: DistributedExtensionJs_CallJsOnDestroy_0100
 * @tc.name: DistributedExtensionJs_CallJsOnDestroy_0100
 * @tc.desc: Test the function of invoking the CallJsOnDestroy interface.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: issuesIAFBOS
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_CallJsOnDestroy_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsOnDestroy_0100 begin";
    try {
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_invalid_arg));
        auto ret = dExtensionJs->CallJsOnDestroy();
        EXPECT_EQ(ret, EINVAL);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsOnDestroy_0100 case1 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionJsTest an exception occurred by CallJsOnDestroy.";
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsOnDestroy_0100 end";
}

/**
 * @tc.number: DistributedExtensionJs_CallJsOnCollaborate_0100
 * @tc.name: DistributedExtensionJs_CallJsOnCollaborate_0100
 * @tc.desc: Test the function of invoking the CallJsOnCollaborate interface.
 * @tc.size: MEDIUM
 * @tc.type: FUNC
 * @tc.level Level 1
 * @tc.require: issuesIAFBOS
 */
HWTEST_F(DExtensionJsTest, DistributedExtensionJs_CallJsOnCollaborate_0100, testing::ext::TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsOnCollaborate_0100 begin";
    try {
        EXPECT_CALL(*dExtensionMock, GetNapiEnv()).WillOnce(Return(nullptr));
        EXPECT_CALL(*napiMock, napi_get_uv_event_loop(_, _)).WillOnce(Return(napi_invalid_arg));
        auto ret = dExtensionJs->CallJsOnCollaborate();
        EXPECT_EQ(ret, EINVAL);
        GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsOnCollaborate_0100 case1 finished";
    } catch (...) {
        EXPECT_TRUE(false);
        GTEST_LOG_(INFO) << "DExtensionJsTest an exception occurred by CallJsOnCollaborate.";
    }
    GTEST_LOG_(INFO) << "DExtensionJsTest DistributedExtensionJs_CallJsOnCollaborate_0100 end";
}
} // namespace OHOS::DistributedSchedule
