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

#ifndef OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_DECODER_FILTER_SUP_TEST_H
#define OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_DECODER_FILTER_SUP_TEST_H

#include <gtest/gtest.h>
#include "surface_decoder_filter.h"
#include "surface_decoder_adapter_mock.h"

namespace OHOS {
namespace DistributedCollab {
class SurfaceDecoderFilterSupTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp() override;
    void TearDown() override;

    static inline std::shared_ptr<SurfaceDecoderFilter> decodeFilter_ = nullptr;
    static inline std::shared_ptr<SurfaceDecoderAptMock> surfaceDecoderAptMock_ = nullptr;
};
}  // namespace DistributedCollab
}  // namespace OHOS
#endif
