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

#ifndef DISTRIBUTED_RADAR_TEST_H
#define DISTRIBUTED_RADAR_TEST_H

#include "gtest/gtest.h"
#include "test_log.h"

#include "dfx/distributed_radar.h"

namespace OHOS {
namespace DistributedSchedule {
constexpr int32_t ERR_NO = 1;

class DistributedRadarTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DISTRIBUTED_RADAR_TEST_H