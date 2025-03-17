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

#include "softbus_file_adapter_test.h"

#include <fcntl.h>
#include <unistd.h>
#include "securec.h"

#include "dtbcollabmgr_log.h"
#include "test_log.h"

using namespace testing;
using namespace testing::ext;
namespace OHOS {
namespace DistributedCollab {
void SoftbusFileAdpaterTest::SetUpTestCase()
{
    DTEST_LOG << "SoftbusFileAdpaterTest::SetUpTestCase" << std::endl;
}

void SoftbusFileAdpaterTest::TearDownTestCase()
{
    DTEST_LOG << "SoftbusFileAdpaterTest::TearDownTestCase" << std::endl;
}

void SoftbusFileAdpaterTest::SetUp()
{
    DTEST_LOG << "SoftbusFileAdpaterTest::SetUp" << std::endl;
}

void SoftbusFileAdpaterTest::TearDown()
{
    DTEST_LOG << "SoftbusFileAdpaterTest::TearDown" << std::endl;
}

/**
 * @tc.name: Open_Test_001
 * @tc.desc: Test Open
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SoftbusFileAdpaterTest, Open_Test_001, TestSize.Level1)
{
    char *filename = nullptr;
    int32_t flag = O_RDWR | O_CREAT;
    int32_t mode = S_IRUSR | S_IWUSR;
    auto ret = SoftbusFileAdpater::GetInstance().Open(filename, flag, mode);
    EXPECT_EQ(ret, ERR_OK);

    string testName = "/data/test/../bak";
    ret = SoftbusFileAdpater::GetInstance().Open(testName.c_str(), flag, mode);
    EXPECT_EQ(ret, ERR_OK);

    testName = "/data/test/bak/1.txt";
    ret = SoftbusFileAdpater::GetInstance().Open(testName.c_str(), flag, mode);
    EXPECT_EQ(ret, ERR_OK);

    ret = SoftbusFileAdpater::GetInstance().Close(ret);

    ret = SoftbusFileAdpater::GetInstance().Open(testName.c_str(), flag, mode);
    EXPECT_EQ(ret, ERR_OK);
    ret = SoftbusFileAdpater::GetInstance().Close(ret);
    ret = SoftbusFileAdpater::GetInstance().Remove(testName.c_str());
    EXPECT_EQ(ret, ERR_OK);

    ret = SoftbusFileAdpater::GetInstance().Remove(testName.c_str());
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: Close_Failed_001
 * @tc.desc: Test close
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SoftbusFileAdpaterTest, Close_Failed_001, TestSize.Level1)
{
    int32_t fd = -1;
    auto ret = SoftbusFileAdpater::GetInstance().Close(fd);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: Remove_Failed_001
 * @tc.desc: Test Remove
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SoftbusFileAdpaterTest, Remove_Failed_001, TestSize.Level1)
{
    char *filename = nullptr;
    auto ret = SoftbusFileAdpater::GetInstance().Remove(filename);
    EXPECT_EQ(ret, ERR_OK);
}

/**
 * @tc.name: SetFileSchema_001
 * @tc.desc: Test SetFileSchema
 * @tc.type: FUNC
 * @tc.level: TestSize.Level1
 */
HWTEST_F(SoftbusFileAdpaterTest, SetFileSchema_001, TestSize.Level1)
{
    int32_t socketId = -1;
    auto ret = SoftbusFileAdpater::GetInstance().SetFileSchema(socketId);
    EXPECT_EQ(ret, ERR_OK);
}
} // namespace DistributedCollab
} // namespace OHOS
