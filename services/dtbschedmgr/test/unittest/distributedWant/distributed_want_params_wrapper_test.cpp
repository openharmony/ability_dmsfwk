/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#define private public
#include "distributed_want_params_wrapper.h"
#undef protected
#include "string_wrapper.h"

using namespace testing::ext;
using namespace OHOS;
using namespace AAFwk;
using namespace DistributedSchedule;

namespace {
const std::string STRING_WANT_PARAMS_KEY_01 = "key01";
const std::string STRING_WANT_PARAMS_VALUE_01 = "value01";
const std::string STRING_WANT_PARAMS_STRING_01 = "{\"key01\":{\"9\":\"value01\"}}";

const std::string STRING_WANT_PARAMS_KEY_02 = "key02";
const std::string STRING_WANT_PARAMS_VALUE_02 = "value02";
const std::string STRING_WANT_PARAMS_STRING_0201 =
    "{\"key01\":{\"101\":{\"key02\":{\"9\":\"value02\"}}},\"key02\":{\"9\":\"value02\"}}";
}  // namespace

class DistributedWantParamWrapperBaseTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override;
    void TearDown() override;

    DistributedWantParams wantParams_;
    std::shared_ptr<DistributedWantParamWrapper> wantParamWrapperPtr_;
};

void DistributedWantParamWrapperBaseTest::SetUpTestCase()
{}

void DistributedWantParamWrapperBaseTest::TearDownTestCase(void)
{}

void DistributedWantParamWrapperBaseTest::SetUp(void)
{
    wantParams_ = {};
    wantParams_.SetParam(STRING_WANT_PARAMS_KEY_01, String::Box(STRING_WANT_PARAMS_VALUE_01));
    wantParamWrapperPtr_ = std::make_shared<DistributedWantParamWrapper>(wantParams_);
}

void DistributedWantParamWrapperBaseTest::TearDown(void)
{}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_0100
 * @tc.name: GetValue
 * @tc.desc: Verify the "GetValue" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_0100, Function | MediumTest | Level3)
{
    DistributedWantParams wantParams;
    ErrCode result = wantParamWrapperPtr_->GetValue(wantParams);

    EXPECT_EQ(result, ERR_OK);

    EXPECT_EQ(wantParams_ == wantParams, true);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_0200
 * @tc.name: GetValue
 * @tc.desc: Verify the "GetValue" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_0200, Function | MediumTest | Level3)
{
    DistributedWantParams wantParams;
    ErrCode result = wantParamWrapperPtr_->GetValue(wantParams);

    EXPECT_EQ(result, ERR_OK);

    // make another empty WantParams
    DistributedWantParams wantParamsEmpty = {};

    EXPECT_EQ(wantParams_ == wantParamsEmpty, false);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_0300
 * @tc.name: Equals
 * @tc.desc: Verify the "Equals" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_0300, Function | MediumTest | Level3)
{
    DistributedWantParams wantParams;
    wantParams.SetParam(STRING_WANT_PARAMS_KEY_01, String::Box(STRING_WANT_PARAMS_VALUE_01));
    DistributedWantParamWrapper wantParamWrapper(wantParams);

    bool result = wantParamWrapperPtr_->Equals(wantParamWrapper);

    EXPECT_EQ(result, true);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_0400
 * @tc.name: Equals
 * @tc.desc: Verify the "Equals" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_0400, Function | MediumTest | Level3)
{
    DistributedWantParams wantParams;
    DistributedWantParamWrapper wantParamWrapper(wantParams);

    bool result = wantParamWrapperPtr_->Equals(wantParamWrapper);

    EXPECT_EQ(result, false);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_0500
 * @tc.name: Box
 * @tc.desc: Verify the "Box" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_0500, Function | MediumTest | Level3)
{
    auto wantParamsPtr = DistributedWantParamWrapper::Box(wantParams_);

    DistributedWantParams wantParams;
    ErrCode result = wantParamsPtr->GetValue(wantParams);

    EXPECT_EQ(result, ERR_OK);

    EXPECT_EQ(wantParams_ == wantParams, true);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_0600
 * @tc.name: Box
 * @tc.desc: Verify the "Box" function with am empty object.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_0600, Function | MediumTest | Level3)
{
    auto wantParamsPtr = DistributedWantParamWrapper::Box({});

    EXPECT_NE(wantParamsPtr, nullptr);

    DistributedWantParams wantParams;
    ErrCode result = wantParamsPtr->GetValue(wantParams);

    EXPECT_EQ(result, ERR_OK);

    // make another empty WantParams
    DistributedWantParams wantParamsEmpty = {};

    EXPECT_EQ(wantParams == wantParamsEmpty, true);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_0700
 * @tc.name: Unbox
 * @tc.desc: Verify the "Unbox" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_0700, Function | MediumTest | Level3)
{
    auto wantParamsPtr = DistributedWantParamWrapper::Box(wantParams_);

    auto wantParams = DistributedWantParamWrapper::Unbox(wantParamsPtr);

    EXPECT_EQ(wantParams_ == wantParams, true);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_0800
 * @tc.name: Unbox
 * @tc.desc: Verify the "Unbox" function with a nullptr
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_0800, Function | MediumTest | Level3)
{
    auto wantParams = DistributedWantParamWrapper::Unbox(nullptr);

    // make another empty WantParams
    DistributedWantParams wantParamsEmpty = {};

    EXPECT_EQ(wantParams == wantParamsEmpty, true);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_0900
 * @tc.name: ValidateStr
 * @tc.desc: Verify the "ValidateStr" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_0900, Function | MediumTest | Level3)
{
    bool result = DistributedWantParamWrapper::ValidateStr("{");

    EXPECT_EQ(result, false);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_1000
 * @tc.name: ValidateStr
 * @tc.desc: Verify the "ValidateStr" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_1000, Function | MediumTest | Level3)
{
    bool result = DistributedWantParamWrapper::ValidateStr("}");

    EXPECT_EQ(result, false);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_1100
 * @tc.name: ValidateStr
 * @tc.desc: Verify the "ValidateStr" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_1100, Function | MediumTest | Level3)
{
    bool result = DistributedWantParamWrapper::ValidateStr("}{");

    EXPECT_EQ(result, false);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_1200
 * @tc.name: ValidateStr
 * @tc.desc: Verify the "ValidateStr" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_1200, Function | MediumTest | Level3)
{
    bool result = DistributedWantParamWrapper::ValidateStr("{\"\"}");

    EXPECT_EQ(result, false);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_1300
 * @tc.name: Parse
 * @tc.desc: Verify the "Parse" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_1300, Function | MediumTest | Level3)
{
    auto wantParamsPtr = DistributedWantParamWrapper::Parse("");

    auto wantParams = DistributedWantParamWrapper::Unbox(wantParamsPtr);

    // make another empty WantParams
    DistributedWantParams wantParamsEmpty = {};

    EXPECT_EQ(wantParams == wantParamsEmpty, true);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_1400
 * @tc.name: Parse
 * @tc.desc: Verify the "Parse" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_1400, Function | MediumTest | Level3)
{
    auto wantParamsPtr = DistributedWantParamWrapper::Parse("{}");

    auto wantParams = DistributedWantParamWrapper::Unbox(wantParamsPtr);

    // make another empty WantParams
    DistributedWantParams wantParamsEmpty = {};

    EXPECT_EQ(wantParams == wantParamsEmpty, true);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_1500
 * @tc.name: ToString
 * @tc.desc: Verify the "ToString" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_1500, Function | MediumTest | Level3)
{
    auto wantParamsString = wantParamWrapperPtr_->ToString();

    EXPECT_EQ(wantParamsString, STRING_WANT_PARAMS_STRING_01);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_1600
 * @tc.name: ToString
 * @tc.desc: Verify the "ToString" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_1600, Function | MediumTest | Level3)
{
    DistributedWantParams wantParams = {};
    DistributedWantParamWrapper wantParamWrapper(wantParams);

    auto wantParamsString = wantParamWrapper.ToString();

    EXPECT_EQ(wantParamsString, "{}");
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_1700
 * @tc.name: ToString
 * @tc.desc: Verify the "ToString" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_1700, Function | MediumTest | Level3)
{
    DistributedWantParams wantParams = {};
    wantParams.SetParam(STRING_WANT_PARAMS_KEY_02, String::Box(STRING_WANT_PARAMS_VALUE_02));
    wantParams.SetParam(STRING_WANT_PARAMS_KEY_01, DistributedWantParamWrapper::Box(wantParams));
    DistributedWantParamWrapper wantParamWrapper(wantParams);

    auto wantParamsString = wantParamWrapper.ToString();

    EXPECT_EQ(wantParamsString, STRING_WANT_PARAMS_STRING_0201);
}

/**
 * @tc.number: Distributed_Want_Param_Wrapper_1800
 * @tc.name: from ToString to Parse
 * @tc.desc: Verify the "from ToString to Parse" function.
 */
HWTEST_F(DistributedWantParamWrapperBaseTest, Distributed_Want_Param_Wrapper_1800, Function | MediumTest | Level3)
{
    auto wantParamsString = wantParamWrapperPtr_->ToString();

    EXPECT_EQ(wantParamsString, STRING_WANT_PARAMS_STRING_01);

    auto wantParamsPtr = DistributedWantParamWrapper::Parse(wantParamsString);

    auto wantParams = DistributedWantParamWrapper::Unbox(wantParamsPtr);

    EXPECT_EQ(wantParams_ == wantParams, true);
}
