/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "datashare_manager_test.h"

#include "test_log.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace DistributedSchedule {
void DataShareManagerTest::SetUpTestCase()
{
    DTEST_LOG << "DataShareManagerTest::SetUpTestCase" << std::endl;
}

void DataShareManagerTest::TearDownTestCase()
{
    DTEST_LOG << "DataShareManagerTest::TearDownTestCase" << std::endl;
}

void DataShareManagerTest::TearDown()
{
    DTEST_LOG << "DataShareManagerTest::TearDown" << std::endl;
}

void DataShareManagerTest::SetUp()
{
    DTEST_LOG << "DataShareManagerTest::SetUp" << std::endl;
}
}
}