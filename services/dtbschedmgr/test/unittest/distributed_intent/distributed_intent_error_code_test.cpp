/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
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

#include "distributed_intent_error_code.h"
#include "ability_manager_errors.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {

class DistributedIntentErrorCodeTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};

void DistributedIntentErrorCodeTest::SetUpTestCase() {}

void DistributedIntentErrorCodeTest::TearDownTestCase() {}

void DistributedIntentErrorCodeTest::SetUp() {}

void DistributedIntentErrorCodeTest::TearDown() {}

/**
 * @tc.name: ConvertDiErrCode_PermissionDenied_001
 * @tc.desc: test ConvertDiErrCode with ERR_DI_PERMISSION_DENIED
 * @tc.type: FUNC
 */
HWTEST_F(DistributedIntentErrorCodeTest, ConvertDiErrCode_PermissionDenied_001, TestSize.Level3)
{
    int32_t result = ConvertDiErrCode(ERR_DI_PERMISSION_DENIED);
    EXPECT_EQ(result, AAFwk::CHECK_PERMISSION_FAILED);
}

/**
 * @tc.name: ConvertDiErrCode_AbilityVisibleFalseDenyRequest_001
 * @tc.desc: test ConvertDiErrCode with ERR_DI_ABILITY_VISIBLE_FALSE_DENY_REQUEST
 * @tc.type: FUNC
 */
HWTEST_F(DistributedIntentErrorCodeTest, ConvertDiErrCode_AbilityVisibleFalseDenyRequest_001, TestSize.Level3)
{
    int32_t result = ConvertDiErrCode(ERR_DI_ABILITY_VISIBLE_FALSE_DENY_REQUEST);
    EXPECT_EQ(result, AAFwk::ABILITY_VISIBLE_FALSE_DENY_REQUEST);
}

/**
 * @tc.name: ConvertDiErrCode_StaticCfgPermission_001
 * @tc.desc: test ConvertDiErrCode with ERR_DI_STATIC_CFG_PERMISSION
 * @tc.type: FUNC
 */
HWTEST_F(DistributedIntentErrorCodeTest, ConvertDiErrCode_StaticCfgPermission_001, TestSize.Level3)
{
    int32_t result = ConvertDiErrCode(ERR_DI_STATIC_CFG_PERMISSION);
    EXPECT_EQ(result, AAFwk::ERR_STATIC_CFG_PERMISSION);
}

/**
 * @tc.name: ConvertDiErrCode_CapabilityNotSupport_001
 * @tc.desc: test ConvertDiErrCode with ERR_DI_CAPABILITY_NOT_SUPPORT
 * @tc.type: FUNC
 */
HWTEST_F(DistributedIntentErrorCodeTest, ConvertDiErrCode_CapabilityNotSupport_001, TestSize.Level3)
{
    int32_t result = ConvertDiErrCode(ERR_DI_CAPABILITY_NOT_SUPPORT);
    EXPECT_EQ(result, AAFwk::ERR_CAPABILITY_NOT_SUPPORT);
}

/**
 * @tc.name: ConvertDiErrCode_DefaultCase_001
 * @tc.desc: test ConvertDiErrCode with unknown error code returns original value
 * @tc.type: FUNC
 */
HWTEST_F(DistributedIntentErrorCodeTest, ConvertDiErrCode_DefaultCase_001, TestSize.Level3)
{
    int32_t unknownCode = 999999;
    int32_t result = ConvertDiErrCode(unknownCode);
    EXPECT_EQ(result, unknownCode);
}

/**
 * @tc.name: ConvertDiErrCode_DefaultCase_002
 * @tc.desc: test ConvertDiErrCode with ERR_DI_OK returns original value
 * @tc.type: FUNC
 */
HWTEST_F(DistributedIntentErrorCodeTest, ConvertDiErrCode_DefaultCase_002, TestSize.Level3)
{
    int32_t result = ConvertDiErrCode(ERR_DI_OK);
    EXPECT_EQ(result, ERR_DI_OK);
}

/**
 * @tc.name: ConvertDiErrCode_DefaultCase_003
 * @tc.desc: test ConvertDiErrCode with ERR_DI_INVALID_PARAMETER returns original value
 * @tc.type: FUNC
 */
HWTEST_F(DistributedIntentErrorCodeTest, ConvertDiErrCode_DefaultCase_003, TestSize.Level3)
{
    int32_t result = ConvertDiErrCode(ERR_DI_INVALID_PARAMETER);
    EXPECT_EQ(result, ERR_DI_INVALID_PARAMETER);
}

/**
 * @tc.name: ConvertDiErrCode_DefaultCase_004
 * @tc.desc: test ConvertDiErrCode with ERR_DI_SYSTEM_WORK_ABNORMALLY returns original value
 * @tc.type: FUNC
 */
HWTEST_F(DistributedIntentErrorCodeTest, ConvertDiErrCode_DefaultCase_004, TestSize.Level3)
{
    int32_t result = ConvertDiErrCode(ERR_DI_SYSTEM_WORK_ABNORMALLY);
    EXPECT_EQ(result, ERR_DI_SYSTEM_WORK_ABNORMALLY);
}

/**
 * @tc.name: ConvertDiErrCode_DefaultCase_005
 * @tc.desc: test ConvertDiErrCode with negative error code returns original value
 * @tc.type: FUNC
 */
HWTEST_F(DistributedIntentErrorCodeTest, ConvertDiErrCode_DefaultCase_005, TestSize.Level3)
{
    int32_t negativeCode = -1;
    int32_t result = ConvertDiErrCode(negativeCode);
    EXPECT_EQ(result, negativeCode);
}

} // namespace DistributedSchedule
} // namespace OHOS
