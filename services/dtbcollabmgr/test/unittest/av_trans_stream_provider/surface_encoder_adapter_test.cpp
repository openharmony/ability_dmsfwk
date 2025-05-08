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
#include "surface_encoder_adapter_test.h"

#include "dtbcollabmgr_log.h"
#include "media_description.h"
#include "test_log.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
    using Status = Media::Status;
    using Meta = Media::Meta;
    using Tag = Media::Tag;
    using namespace testing;
    using namespace testing::ext;
    constexpr uint32_t NS_PER_US = 1000;
}

void SurfaceEncoderAdapterTest::SetUpTestCase()
{
    DTEST_LOG << "SurfaceEncoderAdapterTest::SetUpTestCase" << std::endl;
    encodeAdapter_ = std::make_shared<SurfaceEncoderAdapter>();
}

void SurfaceEncoderAdapterTest::TearDownTestCase()
{
    DTEST_LOG << "SurfaceEncoderAdapterTest::TearDownTestCase" << std::endl;
}

void SurfaceEncoderAdapterTest::SetUp()
{
    DTEST_LOG << "SurfaceEncoderAdapterTest::SetUp" << std::endl;
}

void SurfaceEncoderAdapterTest::TearDown()
{
    DTEST_LOG << "SurfaceEncoderAdapterTest::TearDown" << std::endl;
}

/**
 * @tc.name: Init_001
 * @tc.desc: SurfaceEncoderAdapter ConfigureGeneralFormat
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, Init_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest Init_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    std::string mine = "test";
    bool isEncode = false;
    EXPECT_EQ(encodeAdapter_->Init(mine, isEncode), Status::ERROR_UNKNOWN);
    EXPECT_EQ(encodeAdapter_->codecServer_, nullptr);
    DTEST_LOG << "SurfaceEncoderAdapterTest Init_001 end" << std::endl;
}

/**
 * @tc.name: Configure_001
 * @tc.desc: SurfaceEncoderAdapter Configure
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, Configure_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest Configure_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    EXPECT_EQ(encodeAdapter_->Configure(parameter), Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceEncoderAdapterTest Configure_001 end" << std::endl;
}

/**
 * @tc.name: SetInputSurface_001
 * @tc.desc: SurfaceEncoderAdapter Configure
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, SetInputSurface_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest SetInputSurface_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    sptr<Surface> surface = nullptr;
    EXPECT_EQ(encodeAdapter_->SetInputSurface(surface), Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceEncoderAdapterTest SetInputSurface_001 end" << std::endl;
}

/**
 * @tc.name: Start_001
 * @tc.desc: Start
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, Start_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest Start_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    EXPECT_EQ(encodeAdapter_->Start(), Status::ERROR_NULL_POINTER);
    DTEST_LOG << "SurfaceEncoderAdapterTest Start_001 end" << std::endl;
}

/**
 * @tc.name: Stop_001
 * @tc.desc: Stop
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, Stop_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest Start_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    encodeAdapter_->isStart_ = false;
    EXPECT_EQ(encodeAdapter_->Stop(), Status::OK);

    encodeAdapter_->isStart_ = true;
    encodeAdapter_->isTransCoderMode = true;
    EXPECT_EQ(encodeAdapter_->Stop(), Status::OK);

    encodeAdapter_->isTransCoderMode = false;
    EXPECT_EQ(encodeAdapter_->Stop(), Status::OK);
    DTEST_LOG << "SurfaceEncoderAdapterTest Start_001 end" << std::endl;
}

/**
 * @tc.name: Flush_001
 * @tc.desc: Flush
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, Flush_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest Start_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    EXPECT_EQ(encodeAdapter_->Flush(), Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceEncoderAdapterTest Start_001 end" << std::endl;
}

/**
 * @tc.name: Reset_001
 * @tc.desc: Reset
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, Reset_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest Reset_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    EXPECT_EQ(encodeAdapter_->Reset(), Status::OK);
    DTEST_LOG << "SurfaceEncoderAdapterTest Reset_001 end" << std::endl;
}

/**
 * @tc.name: Release_001
 * @tc.desc: Release
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, Release_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest Release_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    EXPECT_EQ(encodeAdapter_->Release(), Status::OK);
    DTEST_LOG << "SurfaceEncoderAdapterTest Release_001 end" << std::endl;
}

/**
 * @tc.name: NotifyEos_001
 * @tc.desc: NotifyEos
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, NotifyEos_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest NotifyEos_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    int64_t pts = 0;
    EXPECT_EQ(encodeAdapter_->NotifyEos(pts), Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceEncoderAdapterTest NotifyEos_001 end" << std::endl;
}

/**
 * @tc.name: SetParameter_001
 * @tc.desc: SetParameter
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, SetParameter_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest SetParameter_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    EXPECT_EQ(encodeAdapter_->SetParameter(parameter), Status::ERROR_UNKNOWN);
    DTEST_LOG << "SurfaceEncoderAdapterTest SetParameter_001 end" << std::endl;
}

/**
 * @tc.name: ConfigureGeneralFormat_001
 * @tc.desc: SurfaceEncoderAdapter ConfigureGeneralFormat
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, ConfigureGeneralFormat_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest ConfigureGeneralFormat_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    MediaAVCodec::Format format;
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    EXPECT_NO_FATAL_FAILURE(encodeAdapter_->ConfigureGeneralFormat(format, parameter));

    parameter->SetData(Tag::VIDEO_WIDTH, 10);
    parameter->SetData(Tag::VIDEO_HEIGHT, 10);
    parameter->SetData(Tag::VIDEO_CAPTURE_RATE, 10.00);
    parameter->SetData(Tag::MEDIA_BITRATE, 10);
    parameter->SetData(Tag::VIDEO_FRAME_RATE, 10.00);
    parameter->SetData(Tag::MIME_TYPE, Media::Plugins::MimeType::VIDEO_AVC);
    parameter->SetData(Tag::VIDEO_H265_PROFILE, Media::Plugins::HEVCProfile::HEVC_PROFILE_MAIN_10);
    EXPECT_NO_FATAL_FAILURE(encodeAdapter_->ConfigureGeneralFormat(format, parameter));
    DTEST_LOG << "SurfaceEncoderAdapterTest ConfigureGeneralFormat_001 end" << std::endl;
}

/**
 * @tc.name: ConfigureAboutRGBA_001
 * @tc.desc: SurfaceEncoderAdapter ConfigureAboutRGBA
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, ConfigureAboutRGBA_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest ConfigureAboutRGBA_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    MediaAVCodec::Format format;
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    EXPECT_NO_FATAL_FAILURE(encodeAdapter_->ConfigureAboutRGBA(format, parameter));

    parameter->SetData(Tag::VIDEO_PIXEL_FORMAT, Media::Plugins::VideoPixelFormat::NV12);
    parameter->SetData(Tag::VIDEO_ENCODE_BITRATE_MODE, Media::Plugins::VideoEncodeBitrateMode::VBR);
    EXPECT_NO_FATAL_FAILURE(encodeAdapter_->ConfigureAboutRGBA(format, parameter));
    DTEST_LOG << "SurfaceEncoderAdapterTest ConfigureAboutRGBA_001 end" << std::endl;
}

/**
 * @tc.name: ConfigureAboutEnableTemporalScale_001
 * @tc.desc: SurfaceEncoderAdapter ConfigureAboutEnableTemporalScale
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, ConfigureAboutEnableTemporalScale_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest ConfigureAboutEnableTemporalScale_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    MediaAVCodec::Format format;
    std::shared_ptr<Meta> parameter = std::make_shared<Meta>();
    EXPECT_NO_FATAL_FAILURE(encodeAdapter_->ConfigureAboutEnableTemporalScale(format, parameter));

    bool enableTemporalScale = false;
    parameter->SetData(Tag::VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY, enableTemporalScale);
    EXPECT_NO_FATAL_FAILURE(encodeAdapter_->ConfigureAboutEnableTemporalScale(format, parameter));

    enableTemporalScale = true;
    parameter->SetData(Tag::VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY, enableTemporalScale);
    EXPECT_NO_FATAL_FAILURE(encodeAdapter_->ConfigureAboutEnableTemporalScale(format, parameter));
    DTEST_LOG << "SurfaceEncoderAdapterTest ConfigureAboutEnableTemporalScale_001 end" << std::endl;
}

/**
 * @tc.name: AddStartPts_001
 * @tc.desc: SurfaceEncoderAdapter AddStartPts
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, AddStartPts_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest AddStartPts_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    encodeAdapter_->isStartKeyFramePts_ = true;
    encodeAdapter_->keyFramePts_ = "test";
    int64_t currentPts = NS_PER_US * 2;
    encodeAdapter_->AddStartPts(currentPts);
    EXPECT_EQ(encodeAdapter_->keyFramePts_, "test2,");
    EXPECT_EQ(encodeAdapter_->isStartKeyFramePts_, false);

    encodeAdapter_->AddStartPts(currentPts);
    EXPECT_EQ(encodeAdapter_->keyFramePts_, "test2,");
    EXPECT_EQ(encodeAdapter_->isStartKeyFramePts_, false);
    DTEST_LOG << "SurfaceEncoderAdapterTest AddStartPts_001 end" << std::endl;
}

/**
 * @tc.name: AddStopPts_001
 * @tc.desc: SurfaceEncoderAdapter AddStopPts
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, AddStopPts_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest AddStopPts_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    encodeAdapter_->isStopKeyFramePts_ = true;
    encodeAdapter_->currentKeyFramePts_ = NS_PER_US * 3;
    encodeAdapter_->stopTime_ = 0;
    encodeAdapter_->keyFramePts_ = "test";
    encodeAdapter_->preKeyFramePts_ = NS_PER_US * 2;
    encodeAdapter_->AddStopPts();

    encodeAdapter_->isStopKeyFramePts_ = true;
    encodeAdapter_->stopTime_ = NS_PER_US * 4;
    encodeAdapter_->AddStopPts();
    EXPECT_EQ(encodeAdapter_->isStopKeyFramePts_, false);

    encodeAdapter_->AddStopPts();
    EXPECT_EQ(encodeAdapter_->isStopKeyFramePts_, false);
    DTEST_LOG << "SurfaceEncoderAdapterTest AddStopPts_001 end" << std::endl;
}

/**
 * @tc.name: AddPauseResumePts_001
 * @tc.desc: SurfaceEncoderAdapter AddPauseResumePts
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, AddPauseResumePts_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest AddPauseResumePts_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    encodeAdapter_->pauseResumePts_.clear();
    int64_t currentPts = 5;
    StateCode state = StateCode::PAUSE;
    EXPECT_FALSE(encodeAdapter_->AddPauseResumePts(currentPts));

    encodeAdapter_->pauseResumePts_.push_back(std::make_pair(currentPts, state));
    int64_t inputPts = 4;

    EXPECT_FALSE(encodeAdapter_->AddPauseResumePts(inputPts));

    inputPts = 6;
    EXPECT_FALSE(encodeAdapter_->AddPauseResumePts(inputPts));

    state = StateCode::RESUME;
    encodeAdapter_->pauseResumePts_.push_back(std::make_pair(currentPts, state));

    inputPts = 4;
    EXPECT_TRUE(encodeAdapter_->AddPauseResumePts(inputPts));

    inputPts = 6;
    EXPECT_FALSE(encodeAdapter_->AddPauseResumePts(inputPts));
    encodeAdapter_->pauseResumePts_.clear();
    DTEST_LOG << "SurfaceEncoderAdapterTest AddPauseResumePts_001 end" << std::endl;
}

/**
 * @tc.name: CheckFrames_001
 * @tc.desc: SurfaceEncoderAdapter CheckFrames
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, CheckFrames_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest CheckFrames_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    encodeAdapter_->pauseResumeQueue_.clear();
    encodeAdapter_->lastBufferTime_ = 0;
    int64_t currentPts = 5;
    int64_t checkFramesPauseTime = 10;
    StateCode state = StateCode::PAUSE;
    EXPECT_FALSE(encodeAdapter_->CheckFrames(currentPts, checkFramesPauseTime));

    encodeAdapter_->pauseResumeQueue_.push_back(std::make_pair(currentPts, state));
    int64_t inputPts = 4;

    EXPECT_FALSE(encodeAdapter_->CheckFrames(inputPts, checkFramesPauseTime));

    inputPts = 6;
    EXPECT_FALSE(encodeAdapter_->CheckFrames(inputPts, checkFramesPauseTime));
    EXPECT_EQ(checkFramesPauseTime, 5);
    
    state = StateCode::RESUME;
    encodeAdapter_->pauseResumeQueue_.push_back(std::make_pair(currentPts, state));

    inputPts = 4;
    EXPECT_TRUE(encodeAdapter_->CheckFrames(inputPts, checkFramesPauseTime));
    EXPECT_EQ(checkFramesPauseTime, 5);

    inputPts = 6;
    EXPECT_FALSE(encodeAdapter_->CheckFrames(inputPts, checkFramesPauseTime));
    encodeAdapter_->pauseResumeQueue_.clear();
    DTEST_LOG << "SurfaceEncoderAdapterTest AddPauseResumePts_001 end" << std::endl;
}

/**
 * @tc.name: Pause_001
 * @tc.desc: SurfaceEncoderAdapter Pause
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, Pause_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest Pause_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    encodeAdapter_->pauseResumeQueue_.clear();
    encodeAdapter_->pauseResumePts_.clear();
    encodeAdapter_->isTransCoderMode = true;
    EXPECT_EQ(encodeAdapter_->Pause(), Status::OK);

    encodeAdapter_->isTransCoderMode = false;
    EXPECT_EQ(encodeAdapter_->Pause(), Status::OK);
    EXPECT_EQ(encodeAdapter_->pauseResumeQueue_.size(), 2);
    EXPECT_EQ(encodeAdapter_->pauseResumePts_.size(), 2);

    StateCode state = StateCode::RESUME;
    int64_t currentPts = 10;
    encodeAdapter_->pauseResumeQueue_.push_back(std::make_pair(currentPts, state));

    EXPECT_EQ(encodeAdapter_->Pause(), Status::OK);
    EXPECT_EQ(encodeAdapter_->pauseResumeQueue_.size(), 5);
    EXPECT_EQ(encodeAdapter_->pauseResumePts_.size(), 4);

    EXPECT_EQ(encodeAdapter_->Pause(), Status::OK);
    EXPECT_EQ(encodeAdapter_->pauseResumeQueue_.size(), 5);
    EXPECT_EQ(encodeAdapter_->pauseResumePts_.size(), 4);
    encodeAdapter_->pauseResumeQueue_.clear();
    encodeAdapter_->pauseResumePts_.clear();
    DTEST_LOG << "SurfaceEncoderAdapterTest Pause_001 end" << std::endl;
}

/**
 * @tc.name: Resume_001
 * @tc.desc: SurfaceEncoderAdapter Resume
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceEncoderAdapterTest, Resume_001, TestSize.Level3)
{
    DTEST_LOG << "SurfaceEncoderAdapterTest Resume_001 begin" << std::endl;
    ASSERT_NE(encodeAdapter_, nullptr);
    encodeAdapter_->pauseResumeQueue_.clear();
    encodeAdapter_->pauseResumePts_.clear();
    encodeAdapter_->isTransCoderMode = true;
    EXPECT_EQ(encodeAdapter_->Resume(), Status::OK);

    encodeAdapter_->isTransCoderMode = false;
    EXPECT_EQ(encodeAdapter_->Resume(), Status::ERROR_UNKNOWN);

    int64_t currentPts = 5;
    StateCode state = StateCode::PAUSE;
    encodeAdapter_->pauseResumeQueue_.push_back(std::make_pair(currentPts, state));
    EXPECT_EQ(encodeAdapter_->Resume(), Status::OK);
    EXPECT_EQ(encodeAdapter_->pauseResumeQueue_.size(), 1);
    EXPECT_EQ(encodeAdapter_->pauseResumePts_.size(), 0);

    state = StateCode::RESUME;
    encodeAdapter_->pauseResumeQueue_.push_back(std::make_pair(currentPts, state));
    encodeAdapter_->pauseResumePts_.push_back(std::make_pair(currentPts, state));
    EXPECT_EQ(encodeAdapter_->Resume(), Status::OK);
    EXPECT_EQ(encodeAdapter_->pauseResumeQueue_.size(), 2);
    EXPECT_EQ(encodeAdapter_->pauseResumePts_.size(), 1);
    encodeAdapter_->pauseResumeQueue_.clear();
    encodeAdapter_->pauseResumePts_.clear();
    DTEST_LOG << "SurfaceEncoderAdapterTest Resume_001 end" << std::endl;
}
}  // namespace DistributedCollab
}  // namespace OHOS
