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

#ifndef SURFACE_ENCODER_FILTER_TEST_H
#define SURFACE_ENCODER_FILTER_TEST_H

#include <gtest/gtest.h>
#include "surface_encoder_filter.h"

namespace OHOS {
namespace DistributedCollab {
class SurfaceEncoderFilterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;
};
}  // namespace DistributedCollab
}  // namespace OHOS
#endif // SURFACE_ENCODER_FILTER_TEST_H
