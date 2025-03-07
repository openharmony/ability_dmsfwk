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
#include "surface_decoder_filter_test.h"

#include "dtbcollabmgr_log.h"
#include "media_description.h"
#include "test_log.h"

namespace OHOS {
namespace DistributedCollab {

namespace {
    static const std::string TAG = "SurfaceDecoderFilterTest";
    using Status = Media::Status;
    using FilterType = Media::Pipeline::FilterType;
    using FilterLinkCallback = Media::Pipeline::FilterLinkCallback;
    using AVBufferQueueProducer = Media::AVBufferQueueProducer;
    using StreamType = Media::Pipeline::StreamType;
    using Meta = Media::Meta;
    using Tag = Media::Tag;
    using Filter = Media::Pipeline::Filter;
    using namespace testing;
    using namespace testing::ext;
}

void SurfaceDecoderFilterTest::SetUpTestCase()
{
    HILOGI("SurfaceDecoderFilterTest::SetUpTestCase");
    decodeFilter_ = std::make_shared<SurfaceDecoderFilter>(
        "builtin.dtbcollab.sender", FilterType::FILTERTYPE_SOURCE);
    decodeFilter_->codecAdpater_ = std::make_shared<SurfaceDecoderAdapter>();
}

void SurfaceDecoderFilterTest::TearDownTestCase()
{
    HILOGI("SurfaceDecoderFilterTest::TearDownTestCase");
}

void SurfaceDecoderFilterTest::SetUp()
{
    HILOGI("SurfaceDecoderFilterTest::SetUp");
}

void SurfaceDecoderFilterTest::TearDown()
{
    HILOGI("SurfaceDecoderFilterTest::TearDown");
}

/**
 * @tc.name: Configurer_Test
 * @tc.desc: Test Configure
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterTest, Configure_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterTest Configure_Test begin" << std::endl;
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    auto ret = decodeFilter_->Configure(parameter);
    EXPECT_EQ(ret, Status::ERROR_NULL_POINTER);
    DTEST_LOG << "SurfaceDecoderFilterTest Configure_Test end" << std::endl;
}

/**
 * @tc.name: DoStart_Test
 * @tc.desc: Test DoStart
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterTest, DoStart_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterTest DoStart_Test begin" << std::endl;
    auto ret = decodeFilter_->DoStart();
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceDecoderFilterTest DoStart_Test end" << std::endl;
}

/**
 * @tc.name: DoPause_Test
 * @tc.desc: Test DoPause
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterTest, DoPause_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterTest DoPause_Test begin" << std::endl;
    auto ret = decodeFilter_->DoPause();
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceDecoderFilterTest DoPause_Test end" << std::endl;
}

/**
 * @tc.name: DoResume_Test
 * @tc.desc: Test DoResume
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterTest, DoResume_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterTest DoResume_Test begin" << std::endl;
    auto ret = decodeFilter_->DoResume();
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceDecoderFilterTest DoResume_Test end" << std::endl;
}

/**
 * @tc.name: DoStop_Test
 * @tc.desc: Test DoStop
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterTest, DoStop_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterTest DoStop_Test begin" << std::endl;
    auto ret = decodeFilter_->DoStop();
    EXPECT_EQ(ret, Status::OK);
    DTEST_LOG << "SurfaceDecoderFilterTest DoStop_Test end" << std::endl;
}

/**
 * @tc.name: SetParameter_Test
 * @tc.desc: Test SetParameter
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterTest, SetParameter_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterTest SetParameter_Test begin" << std::endl;
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    EXPECT_NO_FATAL_FAILURE(decodeFilter_->SetParameter(parameter));
    DTEST_LOG << "SurfaceDecoderFilterTest SetParameter_Test end" << std::endl;
}

/**
 * @tc.name: OnLinkedResult_Test
 * @tc.desc: Test OnLinkedResult
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterTest, OnLinkedResult_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterTest OnLinkedResult_Test begin" << std::endl;
    decodeFilter_->onLinkedResultCallback_ = nullptr;
    sptr<AVBufferQueueProducer> outputBufferQueue = nullptr;
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    EXPECT_NO_FATAL_FAILURE(decodeFilter_->OnLinkedResult(nullptr, parameter));
    DTEST_LOG << "SurfaceDecoderFilterTest OnLinkedResult_Test end" << std::endl;
}
}  // namespace DistributedCollab
}  // namespace OHOS
