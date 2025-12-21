/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_SCHED_ADAPTER_TEST_H
#define DISTRIBUTED_SCHED_ADAPTER_TEST_H

#include "gtest/gtest.h"

#define private public
#include "distributed_sched_adapter.h"
#undef private
#include "mock/ability_manager_client_mock.h"
#include "mock/accesstoken_kit_mock.h"

namespace OHOS {
namespace DistributedSchedule {
class DistributedSchedAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DistributedSchedAdapter> distributedSchedAdapter_;
    static inline std::shared_ptr<AAFwk::AbilityManagerClientMock> clientMock_ = nullptr;
    static inline std::shared_ptr<AccesstokenMock> tokenMock_ = nullptr;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DISTRIBUTED_SCHED_ADAPTER_TEST_H