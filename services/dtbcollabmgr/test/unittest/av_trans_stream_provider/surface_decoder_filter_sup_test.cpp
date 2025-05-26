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
#include "surface_decoder_filter_sup_test.h"

#include "dtbcollabmgr_log.h"
#include "media_description.h"
#include "test_log.h"

namespace OHOS {
namespace DistributedCollab {

namespace {
    static const std::string TAG = "SurfaceDecoderFilterSupTest";
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

void SurfaceDecoderFilterSupTest::SetUpTestCase()
{
    HILOGI("SurfaceDecoderFilterSupTest::SetUpTestCase");
    decodeFilter_ = std::make_shared<SurfaceDecoderFilter>(
        "builtin.dtbcollab.sender", FilterType::FILTERTYPE_SOURCE);

    if (decodeFilter_ == nullptr) {
        return;
    }
    decodeFilter_->codecAdpater_ = std::make_shared<SurfaceDecoderAdapter>();
    surfaceDecoderAptMock_ = std::make_shared<SurfaceDecoderAptMock>();
    SurfaceDecoderAptMock::surfaceDecoderAptMock = surfaceDecoderAptMock_;
}

void SurfaceDecoderFilterSupTest::TearDownTestCase()
{
    HILOGI("SurfaceDecoderFilterSupTest::TearDownTestCase");
    decodeFilter_->codecAdpater_ = nullptr;
    decodeFilter_ = nullptr;
    SurfaceDecoderAptMock::surfaceDecoderAptMock = nullptr;
    surfaceDecoderAptMock_ = nullptr;
}

void SurfaceDecoderFilterSupTest::SetUp()
{
    HILOGI("SurfaceDecoderFilterSupTest::SetUp");
}

void SurfaceDecoderFilterSupTest::TearDown()
{
    HILOGI("SurfaceDecoderFilterSupTest::TearDown");
}

/**
 * @tc.name: Configurer_Test
 * @tc.desc: Test Configure
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterSupTest, Configure_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterSupTest Configure_Test begin" << std::endl;
    ASSERT_NE(decodeFilter_, nullptr);
    ASSERT_NE(decodeFilter_->codecAdpater_, nullptr);
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();

    EXPECT_CALL(*surfaceDecoderAptMock_, Configure(_)).WillOnce(Return(Status::ERROR_UNKNOWN));
    auto ret = decodeFilter_->Configure(parameter);
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);

    EXPECT_CALL(*surfaceDecoderAptMock_, Configure(_)).WillOnce(Return(Status::OK));
    parameter->SetData(Tag::VIDEO_IS_HDR_VIVID, true);
    ret = decodeFilter_->Configure(parameter);
    EXPECT_EQ(ret, Status::OK);
    DTEST_LOG << "SurfaceDecoderFilterSupTest Configure_Test end" << std::endl;
}

/**
 * @tc.name: DoStart_Test
 * @tc.desc: Test DoStart
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterSupTest, DoStart_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterSupTest DoStart_Test begin" << std::endl;
    ASSERT_NE(decodeFilter_, nullptr);
    ASSERT_NE(decodeFilter_->codecAdpater_, nullptr);
    EXPECT_CALL(*surfaceDecoderAptMock_, Start()).WillOnce(Return(Status::ERROR_UNKNOWN));
    auto ret = decodeFilter_->DoStart();
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);

    EXPECT_CALL(*surfaceDecoderAptMock_, Start()).WillOnce(Return(Status::OK));
    ret = decodeFilter_->DoStart();
    EXPECT_EQ(ret, Status::OK);
    DTEST_LOG << "SurfaceDecoderFilterSupTest DoStart_Test end" << std::endl;
}

/**
 * @tc.name: DoPause_Test
 * @tc.desc: Test DoPause
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterSupTest, DoPause_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterSupTest DoPause_Test begin" << std::endl;
    ASSERT_NE(decodeFilter_, nullptr);
    ASSERT_NE(decodeFilter_->codecAdpater_, nullptr);
    EXPECT_CALL(*surfaceDecoderAptMock_, Pause()).WillOnce(Return(Status::ERROR_UNKNOWN));
    auto ret = decodeFilter_->DoPause();
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);

    EXPECT_CALL(*surfaceDecoderAptMock_, Pause()).WillOnce(Return(Status::OK));
    ret = decodeFilter_->DoPause();
    EXPECT_EQ(ret, Status::OK);
    DTEST_LOG << "SurfaceDecoderFilterSupTest DoPause_Test end" << std::endl;
}

/**
 * @tc.name: DoResume_Test
 * @tc.desc: Test DoResume
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterSupTest, DoResume_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterSupTest DoResume_Test begin" << std::endl;
    ASSERT_NE(decodeFilter_, nullptr);
    ASSERT_NE(decodeFilter_->codecAdpater_, nullptr);
    EXPECT_CALL(*surfaceDecoderAptMock_, Resume()).WillOnce(Return(Status::ERROR_UNKNOWN));
    auto ret = decodeFilter_->DoResume();
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);

    EXPECT_CALL(*surfaceDecoderAptMock_, Resume()).WillOnce(Return(Status::OK));
    ret = decodeFilter_->DoResume();
    EXPECT_EQ(ret, Status::OK);
    DTEST_LOG << "SurfaceDecoderFilterSupTest DoResume_Test end" << std::endl;
}

/**
 * @tc.name: DoStop_Test
 * @tc.desc: Test DoStop
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterSupTest, DoStop_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterSupTest DoStop_Test begin" << std::endl;
    ASSERT_NE(decodeFilter_, nullptr);
    ASSERT_NE(decodeFilter_->codecAdpater_, nullptr);
    EXPECT_CALL(*surfaceDecoderAptMock_, Stop()).WillOnce(Return(Status::ERROR_UNKNOWN));
    auto ret = decodeFilter_->DoStop();
    EXPECT_EQ(ret, Status::ERROR_UNKNOWN);

    EXPECT_CALL(*surfaceDecoderAptMock_, Stop()).WillRepeatedly(Return(Status::OK));
    ret = decodeFilter_->DoStop();
    EXPECT_EQ(ret, Status::OK);
    DTEST_LOG << "SurfaceDecoderFilterSupTest DoStop_Test end" << std::endl;
}

/**
 * @tc.name: SetParameter_Test
 * @tc.desc: Test SetParameter
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterSupTest, SetParameter_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterSupTest SetParameter_Test begin" << std::endl;
    ASSERT_NE(decodeFilter_, nullptr);
    ASSERT_NE(decodeFilter_->codecAdpater_, nullptr);
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    EXPECT_CALL(*surfaceDecoderAptMock_, SetParameter(_)).WillOnce(Return(Status::ERROR_UNKNOWN));
    EXPECT_NO_FATAL_FAILURE(decodeFilter_->SetParameter(parameter));

    EXPECT_CALL(*surfaceDecoderAptMock_, SetParameter(_)).WillOnce(Return(Status::OK));
    EXPECT_NO_FATAL_FAILURE(decodeFilter_->SetParameter(parameter));
    DTEST_LOG << "SurfaceDecoderFilterSupTest SetParameter_Test end" << std::endl;
}

/**
 * @tc.name: OnLinkedResult_Test
 * @tc.desc: Test OnLinkedResult
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterSupTest, OnLinkedResult_Test, TestSize.Level1)
{
    DTEST_LOG << "SurfaceDecoderFilterSupTest OnLinkedResult_Test begin" << std::endl;
    ASSERT_NE(decodeFilter_, nullptr);
    ASSERT_NE(decodeFilter_->codecAdpater_, nullptr);
    decodeFilter_->onLinkedResultCallback_ = nullptr;
    sptr<AVBufferQueueProducer> outputBufferQueue = nullptr;
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    EXPECT_NO_FATAL_FAILURE(decodeFilter_->OnLinkedResult(nullptr, parameter));
    DTEST_LOG << "SurfaceDecoderFilterSupTest OnLinkedResult_Test end" << std::endl;
}

/**
 * @tc.name: SetOutputSurface_001
 * @tc.desc: SurfaceDecoderFilter SetOutputSurface
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterSupTest, SetOutputSurface_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceDecoderFilterSupTest SetOutputSurface_001 begin" << std::endl;
    ASSERT_NE(decodeFilter_, nullptr);
    ASSERT_NE(decodeFilter_->codecAdpater_, nullptr);
    sptr<Surface> surface = nullptr;
    EXPECT_CALL(*surfaceDecoderAptMock_, SetOutputSurface(_)).WillOnce(Return(Status::ERROR_UNKNOWN));
    EXPECT_EQ(decodeFilter_->SetOutputSurface(surface), Status::ERROR_UNKNOWN);

    EXPECT_CALL(*surfaceDecoderAptMock_, SetOutputSurface(_)).WillOnce(Return(Status::OK));
    EXPECT_EQ(decodeFilter_->SetOutputSurface(surface), Status::OK);
    DTEST_LOG << "SurfaceDecoderFilterSupTest SetOutputSurface_001 end" << std::endl;
}

/**
 * @tc.name: LinkNext_001
 * @tc.desc: SurfaceDecoderFilter LinkNext
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceDecoderFilterSupTest, LinkNext_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceDecoderFilterSupTest LinkNext_001 begin" << std::endl;
    ASSERT_NE(decodeFilter_, nullptr);
    ASSERT_NE(decodeFilter_->codecAdpater_, nullptr);
    decodeFilter_->nextFiltersMap_.clear();
    decodeFilter_->configureParameter_ = std::make_shared<Meta>();
    auto filter = std::make_shared<SurfaceDecoderFilter>("", FilterType::FILTERTYPE_VDEC);
    StreamType outType = StreamType::STREAMTYPE_ENCODED_VIDEO;
    EXPECT_EQ(decodeFilter_->LinkNext(filter, outType), Status::OK);
    decodeFilter_->nextFiltersMap_.clear();

    decodeFilter_->configureParameter_->SetData(Tag::MIME_TYPE, Media::Plugins::MimeType::VIDEO_AVC);
    EXPECT_CALL(*surfaceDecoderAptMock_, Init(_)).WillOnce(Return(Status::ERROR_UNKNOWN));
    EXPECT_CALL(*surfaceDecoderAptMock_, Configure(_)).WillOnce(Return(Status::ERROR_UNKNOWN));
    EXPECT_CALL(*surfaceDecoderAptMock_, GetInputBufferQueue()).WillOnce(nullptr);
    EXPECT_EQ(decodeFilter_->LinkNext(filter, outType), Status::OK);
    decodeFilter_->nextFiltersMap_.clear();

    EXPECT_CALL(*surfaceDecoderAptMock_, Init(_)).WillOnce(Return(Status::OK));
    EXPECT_CALL(*surfaceDecoderAptMock_, SetDecoderAdapterCallback(_)).WillOnce(Return(Status::OK));
    EXPECT_CALL(*surfaceDecoderAptMock_, Configure(_)).WillOnce(Return(Status::OK));
    EXPECT_CALL(*surfaceDecoderAptMock_, GetInputBufferQueue()).WillOnce(nullptr);
    EXPECT_EQ(decodeFilter_->LinkNext(filter, outType), Status::OK);
    decodeFilter_->nextFiltersMap_.clear();
    DTEST_LOG << "SurfaceDecoderFilterSupTest LinkNext_001 end" << std::endl;
}
}  // namespace DistributedCollab
}  // namespace OHOS
