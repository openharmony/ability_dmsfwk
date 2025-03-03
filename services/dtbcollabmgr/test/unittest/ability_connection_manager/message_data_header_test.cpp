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

#include "message_data_header_test.h"

#include "dtbcollabmgr_log.h"
#include "test_log.h"

#include "message_data_header.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedCollab {
void MessageDataHeaderTest::SetUpTestCase()
{
    DTEST_LOG << "MessageDataHeaderTest::SetUpTestCase" << std::endl;
}

void MessageDataHeaderTest::TearDownTestCase()
{
    DTEST_LOG << "MessageDataHeaderTest::TearDownTestCase" << std::endl;
}

void MessageDataHeaderTest::TearDown()
{
    DTEST_LOG << "MessageDataHeaderTest::TearDown" << std::endl;
}

void MessageDataHeaderTest::SetUp()
{
    DTEST_LOG << "MessageDataHeaderTest::SetUp" << std::endl;
}

/**
 * @tc.name: MessageDataHeader_Test_001
 * @tc.desc: call IsVaildChannel
 * @tc.type: FUNC
 * @tc.require: I6SJQ6
 */
HWTEST_F(MessageDataHeaderTest, MessageDataHeader_Test_001, TestSize.Level3)
{
    DTEST_LOG << "MessageDataHeaderTest MessageDataHeader_Test_001 begin" << std::endl;
    MessageDataHeader data;

    uint8_t *buffer = nullptr;
    EXPECT_EQ(data.Deserialize(buffer, 0), std::nullopt);

    auto avData = data.Serialize();
    buffer = avData->Data();
    ASSERT_NE(buffer, nullptr);
    EXPECT_EQ(data.Deserialize(buffer, 0), std::nullopt);
    EXPECT_NE(data.Deserialize(buffer, avData->Size()), std::nullopt);

    buffer = new (std::nothrow) uint8_t[MessageDataHeader::HEADER_LEN];
    EXPECT_EQ(data.Deserialize(buffer, MessageDataHeader::HEADER_LEN), std::nullopt);
    DTEST_LOG << "MessageDataHeaderTest MessageDataHeader_Test_001 end" << std::endl;
}
}
}
