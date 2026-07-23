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
#include <thread>

#define private public
#define protected public
#include "distributed_extension_service_test.h"
#include "test_log.h"
#include "distributed_extension_service.cpp"
#include "distributed_extension.h"
#undef private
#undef protected

using namespace std;
using namespace testing;
using namespace testing::ext;
using namespace OHOS;

namespace OHOS {
namespace DistributedSchedule {
void DistributedExtensionServiceTest::SetUpTestCase()
{
    DTEST_LOG << "DistributedExtensionServiceTest::SetUpTestCase" << std::endl;
}

void DistributedExtensionServiceTest::TearDownTestCase()
{
    DTEST_LOG << "DistributedExtensionServiceTest::TearDownTestCase" << std::endl;
}

void DistributedExtensionServiceTest::SetUp()
{
    std::shared_ptr<DistributedExtension> dExtension;
    std::string bundleName = "bundleName";
    DistributedExtensionService_ = new DistributedExtensionService(dExtension, bundleName);
    DTEST_LOG << "DistributedExtensionServiceTest::SetUp" << std::endl;
}

void DistributedExtensionServiceTest::TearDown()
{
    DTEST_LOG << "DistributedExtensionServiceTest::TearDown" << std::endl;
}

/**
 * @tc.name:TriggerOnCreate_001
 * @tc.desc: TriggerOnCreate
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, TriggerOnCreate_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCreate_001 start" << std::endl;
    ASSERT_NE(nullptr, DistributedExtensionService_);
    AAFwk::Want want;

    DistributedExtensionService_->distributedExtension_ = std::make_shared<DistributedExtension>();
    int32_t result = DistributedExtensionService_->TriggerOnCreate(want);
    EXPECT_EQ(result, ERR_OK);
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCreate_001 end" << std::endl;
}

/**
 * @tc.name:TriggerOnCreate_002
 * @tc.desc: TriggerOnCreate
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, TriggerOnCreate_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCreate_002 start" << std::endl;
    ASSERT_NE(nullptr, DistributedExtensionService_);
    AAFwk::Want want;

    int32_t result = DistributedExtensionService_->TriggerOnCreate(want);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCreate_002 end" << std::endl;
}

/**
 * @tc.name:TriggerOnDestroy_001
 * @tc.desc: TriggerOnDestroy
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, TriggerOnDestroy_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnDestroy_001 start" << std::endl;
    ASSERT_NE(nullptr, DistributedExtensionService_);

    DistributedExtensionService_->distributedExtension_ = std::make_shared<DistributedExtension>();
    int32_t result = DistributedExtensionService_->TriggerOnDestroy();
    EXPECT_EQ(result, ERR_OK);
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnDestroy_001 end" << std::endl;
}

/**
 * @tc.name:TriggerOnDestroy_002
 * @tc.desc: TriggerOnDestroy
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, TriggerOnDestroy_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnDestroy_002 start" << std::endl;
    ASSERT_NE(nullptr, DistributedExtensionService_);

    int32_t result = DistributedExtensionService_->TriggerOnDestroy();
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnDestroy_002 end" << std::endl;
}


/**
 * @tc.name:TriggerOnCollaborate_001
 * @tc.desc: TriggerOnCollaborate
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, TriggerOnCollaborate_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCollaborate_001 start" << std::endl;
    ASSERT_NE(nullptr, DistributedExtensionService_);
    AAFwk::WantParams wantParam;

    DistributedExtensionService_->distributedExtension_ = std::make_shared<DistributedExtension>();
    int32_t result = DistributedExtensionService_->TriggerOnCollaborate(wantParam);
    EXPECT_EQ(result, ERR_OK);
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCollaborate_001 end" << std::endl;
}

/**
 * @tc.name:TriggerOnCollaborate_002
 * @tc.desc: TriggerOnCollaborate
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, TriggerOnCollaborate_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCollaborate_002 start" << std::endl;
    ASSERT_NE(nullptr, DistributedExtensionService_);
    AAFwk::WantParams wantParam;

    int32_t result = DistributedExtensionService_->TriggerOnCollaborate(wantParam);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCollaborate_002 end" << std::endl;
}

/**
 * @tc.name:Clear_001
 * @tc.desc: Clear function test
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, Clear_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest Clear_001 start" << std::endl;
    ASSERT_NE(nullptr, DistributedExtensionService_);
    EXPECT_NO_FATAL_FAILURE(DistributedExtensionService_->Clear());
    DTEST_LOG << "DistributedExtensionServiceTest Clear_001 end" << std::endl;
}

/**
 * @tc.name:TriggerOnCreate_003
 * @tc.desc: TriggerOnCreate with empty want
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, TriggerOnCreate_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCreate_003 start" << std::endl;
    ASSERT_NE(nullptr, DistributedExtensionService_);
    
    DistributedExtensionService_->distributedExtension_ = std::make_shared<DistributedExtension>();
    AAFwk::Want want;
    want.SetElementName("device", "bundle", "ability");
    
    int32_t result = DistributedExtensionService_->TriggerOnCreate(want);
    EXPECT_EQ(result, ERR_OK);
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCreate_003 end" << std::endl;
}
/**
 * @tc.name:TriggerOnDestroy_003
 * @tc.desc: TriggerOnDestroy multiple times
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, TriggerOnDestroy_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnDestroy_003 start" << std::endl;
    ASSERT_NE(nullptr, DistributedExtensionService_);
    
    DistributedExtensionService_->distributedExtension_ = std::make_shared<DistributedExtension>();
    int32_t result1 = DistributedExtensionService_->TriggerOnDestroy();
    EXPECT_EQ(result1, ERR_OK);
    
    int32_t result2 = DistributedExtensionService_->TriggerOnDestroy();
    EXPECT_EQ(result2, ERR_OK);
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnDestroy_003 end" << std::endl;
}

/**
 * @tc.name:TriggerOnCollaborate_003
 * @tc.desc: TriggerOnCollaborate with valid wantParams
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, TriggerOnCollaborate_003, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCollaborate_003 start" << std::endl;
    ASSERT_NE(nullptr, DistributedExtensionService_);
    
    DistributedExtensionService_->distributedExtension_ = std::make_shared<DistributedExtension>();
    AAFwk::WantParams wantParam;
    
    int32_t result = DistributedExtensionService_->TriggerOnCollaborate(wantParam);
    EXPECT_EQ(result, ERR_OK);
    DTEST_LOG << "DistributedExtensionServiceTest TriggerOnCollaborate_003 end" << std::endl;
}

/**
 * @tc.name:Constructor_001
 * @tc.desc: Constructor with nullptr extension
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, Constructor_001, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest Constructor_001 start" << std::endl;
    std::string bundleName = "testBundle";
    auto service = std::make_shared<DistributedExtensionService>(nullptr, bundleName);
    ASSERT_NE(nullptr, service);
    
    AAFwk::Want want;
    int32_t result = service->TriggerOnCreate(want);
    EXPECT_EQ(result, ERR_INVALID_VALUE);
    DTEST_LOG << "DistributedExtensionServiceTest Constructor_001 end" << std::endl;
}

/**
 * @tc.name:Constructor_002
 * @tc.desc: Constructor with empty bundle name
 * @tc.type: FUNC
 */
HWTEST_F(DistributedExtensionServiceTest, Constructor_002, TestSize.Level3)
{
    DTEST_LOG << "DistributedExtensionServiceTest Constructor_002 start" << std::endl;
    std::shared_ptr<DistributedExtension> dExtension = std::make_shared<DistributedExtension>();
    auto service = std::make_shared<DistributedExtensionService>(dExtension, "");
    ASSERT_NE(nullptr, service);
    
    int32_t result = service->TriggerOnDestroy();
    EXPECT_EQ(result, ERR_OK);
    DTEST_LOG << "DistributedExtensionServiceTest Constructor_002 end" << std::endl;
}
}
}
