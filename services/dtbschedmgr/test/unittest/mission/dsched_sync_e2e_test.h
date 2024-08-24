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

#ifndef DSCHED_SYNC_E2E_TEST_H
#define DSCHED_SYNC_E2E_TEST_H

#include "gtest/gtest.h"

#include "device_manager.h"
#include "mission/dsched_sync_e2e.h"

namespace OHOS {
namespace DistributedSchedule {
class DmsKvSyncE2ETest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
    std::shared_ptr<DmsKvSyncE2E> GetDmsKvSyncE2E();
protected:
    std::shared_ptr<DmsKvSyncE2E> dmsKvSyncE2E_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif /* DSCHED_SYNC_E2E_TEST_H */
