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
#include "av_stream_param_test.h"
#include "dtbcollabmgr_log.h"
#include "media_description.h"

namespace OHOS {
namespace DistributedCollab {

namespace {
    static const std::string TAG = "AVStreamParamTest";
    using MDKey = MediaAVCodec::MediaDescriptionKey;
    using namespace testing;
    using namespace testing::ext;
    static constexpr int32_t NUM_1920 = 1920;
    static constexpr int32_t NUM_1080 = 1080;
    static constexpr int32_t NUM_1280 = 1280;
    static constexpr int32_t NUM_720 = 720;
    static constexpr int32_t BITRATE = 5000000;
    static constexpr int32_t FRAME_RATE = 30;
    static constexpr int32_t NUM_1 = 1;
    static constexpr int32_t INVALID_ENMU = 99999;
}

void SurfaceParamTest::SetUpTestCase()
{
    HILOGI("SurfaceParamTest::SetUpTestCase");
}

void SurfaceParamTest::TearDownTestCase()
{
    HILOGI("SurfaceParamTest::TearDownTestCase");
}

void SurfaceParamTest::SetUp()
{
    HILOGI("SurfaceParamTest::SetUp");
}

void SurfaceParamTest::TearDown()
{
    HILOGI("SurfaceParamTest::TearDown");
}

/**
 * @tc.name: VidEnc_Configure_Failed
 * @tc.desc: Test VidEnc::Configure failed
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidEnc_Configure_Failed, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidEnc encoder(VideoCodecFormat::VIDEO_DEFAULT);

    ConfigureMode mode = static_cast<ConfigureMode>(INVALID_ENMU);
    encoder.Configure(meta, mode);
    std::string mimeType;
    meta->GetData(Media::Tag::MIME_TYPE, mimeType);
    EXPECT_EQ(mimeType, "");

    encoder.encFmt = static_cast<VideoCodecFormat>(INVALID_ENMU);
    encoder.Configure(meta, ConfigureMode::Encode);
    meta->GetData(Media::Tag::MIME_TYPE, mimeType);
    EXPECT_EQ(mimeType, "");

    encoder.Configure(meta, ConfigureMode::Decode);
    meta->GetData(Media::Tag::MIME_TYPE, mimeType);
    EXPECT_EQ(mimeType, "");
}

/**
 * @tc.name: VidEnc_Configure_Encode_Success
 * @tc.desc: Test VidEnc::Configure with Encode mode, covering all codec formats
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidEnc_Configure_Encode_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidEnc encoder(VideoCodecFormat::VIDEO_DEFAULT);

    // Test for VIDEO_DEFAULT codec format
    encoder.Configure(meta, ConfigureMode::Encode);
    std::string mimeType;
    meta->GetData(Media::Tag::MIME_TYPE, mimeType);
    EXPECT_EQ(mimeType, std::string(Media::Plugins::MimeType::VIDEO_AVC));

    // Test for H264 codec format
    encoder.encFmt = VideoCodecFormat::H264;
    encoder.Configure(meta, ConfigureMode::Encode);
    meta->GetData(Media::Tag::MIME_TYPE, mimeType);
    EXPECT_EQ(mimeType, std::string(Media::Plugins::MimeType::VIDEO_AVC));

    // Test for MPEG4 codec format
    encoder.encFmt = VideoCodecFormat::MPEG4;
    encoder.Configure(meta, ConfigureMode::Encode);
    meta->GetData(Media::Tag::MIME_TYPE, mimeType);
    EXPECT_EQ(mimeType, std::string(Media::Plugins::MimeType::VIDEO_MPEG4));

    // Test for H265 codec format
    encoder.encFmt = VideoCodecFormat::H265;
    encoder.Configure(meta, ConfigureMode::Encode);
    meta->GetData(Media::Tag::MIME_TYPE, mimeType);
    EXPECT_EQ(mimeType, std::string(Media::Plugins::MimeType::VIDEO_HEVC));
}

/**
 * @tc.name: VidEnc_Configure_Decode_Success
 * @tc.desc: Test VidEnc::Configure with Decode mode, covering all codec formats
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidEnc_Configure_Decode_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidEnc encoder(VideoCodecFormat::VIDEO_DEFAULT);

    // Test for VIDEO_DEFAULT codec format
    encoder.Configure(meta, ConfigureMode::Decode);
    std::string mimeType;
    meta->GetData(std::string(MDKey::MD_KEY_CODEC_MIME), mimeType);
    EXPECT_EQ(mimeType, std::string(Media::Plugins::MimeType::VIDEO_AVC));

    // Test for H264 codec format
    encoder.encFmt = VideoCodecFormat::H264;
    encoder.Configure(meta, ConfigureMode::Decode);
    meta->GetData(std::string(MDKey::MD_KEY_CODEC_MIME), mimeType);
    EXPECT_EQ(mimeType, std::string(Media::Plugins::MimeType::VIDEO_AVC));

    // Test for MPEG4 codec format
    encoder.encFmt = VideoCodecFormat::MPEG4;
    encoder.Configure(meta, ConfigureMode::Decode);
    meta->GetData(std::string(MDKey::MD_KEY_CODEC_MIME), mimeType);
    EXPECT_EQ(mimeType, std::string(Media::Plugins::MimeType::VIDEO_MPEG4));

    // Test for H265 codec format
    encoder.encFmt = VideoCodecFormat::H265;
    encoder.Configure(meta, ConfigureMode::Decode);
    meta->GetData(std::string(MDKey::MD_KEY_CODEC_MIME), mimeType);
    EXPECT_EQ(mimeType, std::string(Media::Plugins::MimeType::VIDEO_HEVC));
}

/**
 * @tc.name: VidRectangle_Configure_Failed
 * @tc.desc: Test VidRectangle::Configure failed
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidRectangle_Configure_Failed, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidRectangle rect(NUM_1920, NUM_1080);  // Create VidRectangle with width = 1920 and height = 1080

    ConfigureMode mode = static_cast<ConfigureMode>(INVALID_ENMU);
    // Test Configure for Encode mode
    rect.Configure(meta, mode);

    int32_t width = 0;
    int32_t height = 0;
    meta->GetData(Media::Tag::VIDEO_WIDTH, width);
    meta->GetData(Media::Tag::VIDEO_HEIGHT, height);
  
    EXPECT_EQ(width, 0);
    EXPECT_EQ(height, 0);
}

/**
 * @tc.name: VidRectangle_Configure_Encode_Success
 * @tc.desc: Test VidRectangle::Configure in Encode mode, setting width and height in meta
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidRectangle_Configure_Encode_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidRectangle rect(NUM_1920, NUM_1080);  // Create VidRectangle with width = 1920 and height = 1080

    // Test Configure for Encode mode
    rect.Configure(meta, ConfigureMode::Encode);
  
    // Verify that the width and height are correctly set in the meta
    int32_t width = 0;
    int32_t height = 0;
    meta->GetData(Media::Tag::VIDEO_WIDTH, width);
    meta->GetData(Media::Tag::VIDEO_HEIGHT, height);
  
    EXPECT_EQ(width, NUM_1920);
    EXPECT_EQ(height, NUM_1080);
}

/**
 * @tc.name: VidRectangle_Configure_Decode_Success
 * @tc.desc: Test VidRectangle::Configure in Decode mode, setting width and height in meta
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidRectangle_Configure_Decode_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidRectangle rect(NUM_1280, NUM_720);  // Create VidRectangle with width = 1280 and height = 720

    // Test Configure for Decode mode
    rect.Configure(meta, ConfigureMode::Decode);
  
    // Verify that the width and height are correctly set in the meta
    int32_t width = 0;
    int32_t height = 0;
    meta->GetData(std::string(MDKey::MD_KEY_WIDTH), width);
    meta->GetData(std::string(MDKey::MD_KEY_HEIGHT), height);
  
    EXPECT_EQ(width, NUM_1280);
    EXPECT_EQ(height, NUM_720);
}

/**
 * @tc.name: VidBitRate_Configure_Failed
 * @tc.desc: Test VidBitRate::Configure failed
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidBitRate_Configure_Failed, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidBitRate bitRateParam(BITRATE);  // Create VidBitRate with default bitrate

    ConfigureMode mode = static_cast<ConfigureMode>(INVALID_ENMU);
    // Test Configure for Encode mode
    bitRateParam.Configure(meta, mode);

    int64_t bitrate = 0;
    meta->Get<Media::Tag::MEDIA_BITRATE>(bitrate);
  
    EXPECT_EQ(bitrate, 0);
}

/**
 * @tc.name: VidBitRate_Configure_Encode_Success
 * @tc.desc: Test VidBitRate::Configure in Encode mode, setting bitrate in meta
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidBitRate_Configure_Encode_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidBitRate bitRateParam(BITRATE);  // Create VidBitRate with default bitrate

    // Test Configure for Encode mode
    bitRateParam.Configure(meta, ConfigureMode::Encode);
  
    // Verify that the bitrate is correctly set in the meta
    int64_t bitrate = 0;
    meta->Get<Media::Tag::MEDIA_BITRATE>(bitrate);
  
    EXPECT_EQ(bitrate, BITRATE);
}

/**
 * @tc.name: VidBitRate_Configure_Decode_Success
 * @tc.desc: Test VidBitRate::Configure in Decode mode, setting bitrate in meta
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidBitRate_Configure_Decode_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidBitRate bitRateParam(BITRATE);

    // Test Configure for Decode mode
    bitRateParam.Configure(meta, ConfigureMode::Decode);
  
    // Verify that the bitrate is correctly set in the meta
    int32_t bitrate = 0;
    meta->GetData(std::string(MDKey::MD_KEY_BITRATE), bitrate);
  
    EXPECT_EQ(bitrate, BITRATE);
}

/**
 * @tc.name: VidFrameRate_Configure_Failed
 * @tc.desc: Test VidFrameRate::Configure failed
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidFrameRate_Configure_Failed, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidFrameRate frameRateParam(FRAME_RATE);  // Create VidFrameRate with default frame rate

    ConfigureMode mode = static_cast<ConfigureMode>(INVALID_ENMU);
    // Test Configure for Encode mode
    frameRateParam.Configure(meta, mode);

    // Verify that the frame rate is correctly set in the meta
    double frameRate = 0.0;
    meta->Get<Media::Tag::VIDEO_FRAME_RATE>(frameRate);

    EXPECT_DOUBLE_EQ(frameRate, 0.0);
}

/**
 * @tc.name: VidFrameRate_Configure_Encode_Success
 * @tc.desc: Test VidFrameRate::Configure in Encode mode, setting frame rate in meta
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidFrameRate_Configure_Encode_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidFrameRate frameRateParam(FRAME_RATE);  // Create VidFrameRate with default frame rate

    // Test Configure for Encode mode
    frameRateParam.Configure(meta, ConfigureMode::Encode);

    // Verify that the frame rate is correctly set in the meta
    double frameRate = 0.0;
    meta->Get<Media::Tag::VIDEO_FRAME_RATE>(frameRate);

    EXPECT_DOUBLE_EQ(frameRate, FRAME_RATE);
}

/**
 * @tc.name: VidFrameRate_Configure_Decode_Success
 * @tc.desc: Test VidFrameRate::Configure in Decode mode, setting frame rate in meta
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidFrameRate_Configure_Decode_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidFrameRate frameRateParam(FRAME_RATE);

    // Test Configure for Decode mode
    frameRateParam.Configure(meta, ConfigureMode::Decode);

    // Verify that the frame rate is correctly set in the meta
    int32_t frameRate = 0;
    meta->GetData(std::string(MDKey::MD_KEY_FRAME_RATE), frameRate);

    EXPECT_EQ(frameRate, FRAME_RATE);
}

/**
 * @tc.name: VidIsHdr_Configure_Failed
 * @tc.desc: Test VidIsHdr::Configure failed
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidIsHdr_Configure_Failed, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidIsHdr hdrParam(true);  // Create VidIsHdr with isHdr = true

    ConfigureMode mode = static_cast<ConfigureMode>(INVALID_ENMU);
    // Test Configure for Encode mode
    hdrParam.Configure(meta, mode);

    // Verify that the frame rate is correctly set in the meta
    Media::Plugins::HEVCProfile profile;
    meta->Get<Media::Tag::VIDEO_H265_PROFILE>(profile);

    EXPECT_EQ(profile, 0);
}

/**
 * @tc.name: VidIsHdr_Configure_Encode_Hdr_Success
 * @tc.desc: Test VidIsHdr::Configure in Encode mode when isHdr is true, setting profile in meta
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidIsHdr_Configure_Encode_Hdr_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidIsHdr hdrParam(true);  // Create VidIsHdr with isHdr = true

    // Test Configure for Encode mode when isHdr is true
    hdrParam.Configure(meta, ConfigureMode::Encode);

    // Verify that the profile is set to HEVC_PROFILE_MAIN_10 in the meta
    Media::Plugins::HEVCProfile profile;
    meta->Get<Media::Tag::VIDEO_H265_PROFILE>(profile);

    EXPECT_EQ(profile, Media::Plugins::HEVCProfile::HEVC_PROFILE_MAIN_10);
}

/**
 * @tc.name: VidIsHdr_Configure_Encode_NoHdr_Success
 * @tc.desc: Test VidIsHdr::Configure in Encode mode when isHdr is false, profile should not be set
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidIsHdr_Configure_Encode_NoHdr_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidIsHdr hdrParam(false);  // Create VidIsHdr with isHdr = false

    // Test Configure for Encode mode when isHdr is false
    hdrParam.Configure(meta, ConfigureMode::Encode);

    // Verify that the profile is not set in the meta
    Media::Plugins::HEVCProfile profile;
    EXPECT_FALSE(meta->GetData(Media::Tag::VIDEO_H265_PROFILE, profile));  // Profile should not exist
}

/**
 * @tc.name: VidIsHdr_Configure_Decode_Hdr_Success
 * @tc.desc: Test VidIsHdr::Configure in Decode mode when isHdr is true, setting profile in meta
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidIsHdr_Configure_Decode_Hdr_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidIsHdr hdrParam(true);  // Create VidIsHdr with isHdr = true

    // Test Configure for Decode mode when isHdr is true
    hdrParam.Configure(meta, ConfigureMode::Decode);

    // Verify that the profile is set to HEVC_PROFILE_MAIN_10 in the meta
    Media::Plugins::HEVCProfile profile;
    meta->GetData(std::string(MDKey::MD_KEY_PROFILE), profile);

    EXPECT_EQ(profile, NUM_1);
}

/**
 * @tc.name: VidIsHdr_Configure_Decode_NoHdr_Success
 * @tc.desc: Test VidIsHdr::Configure in Decode mode when isHdr is false, profile should not be set
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidIsHdr_Configure_Decode_NoHdr_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidIsHdr hdrParam(false);  // Create VidIsHdr with isHdr = false

    // Test Configure for Decode mode when isHdr is false
    hdrParam.Configure(meta, ConfigureMode::Decode);

    // Verify that the profile is not set in the meta
    Media::Plugins::HEVCProfile profile;
    EXPECT_FALSE(meta->GetData(std::string(MDKey::MD_KEY_PROFILE), profile));
}

/**
 * @tc.name: VidEnableTemporalScale_Configure_Failed
 * @tc.desc: Test VidEnableTemporalScale::Configure failed
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidEnableTemporalScale_Configure_Failed, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidEnableTemporalScale temporalScaleParam(true);

    ConfigureMode mode = static_cast<ConfigureMode>(INVALID_ENMU);
    // Test Configure for Encode mode
    temporalScaleParam.Configure(meta, mode);

    // Verify that the frame rate is correctly set in the meta
    bool enableTemporalScalability = false;
    meta->GetData(Media::Tag::VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY, enableTemporalScalability);
    EXPECT_FALSE(enableTemporalScalability);  // The tag should be set to true
}

/**
 * @tc.name: VidEnableTemporalScale_Configure_Encode_Enable_Success
 * @tc.desc: Test VidEnableTemporalScale::Configure in Encode mode when enableTemporalScale is true
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidEnableTemporalScale_Configure_Encode_Enable_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidEnableTemporalScale temporalScaleParam(true);

    // Test Configure for Encode mode when enableTemporalScale is true
    temporalScaleParam.Configure(meta, ConfigureMode::Encode);

    // Verify that the encoder enable temporal scalability tag is set in the meta
    bool enableTemporalScalability;
    meta->GetData(Media::Tag::VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY, enableTemporalScalability);

    EXPECT_TRUE(enableTemporalScalability);  // The tag should be set to true
}

/**
 * @tc.name: VidEnableTemporalScale_Configure_Encode_Disable_Success
 * @tc.desc: Test VidEnableTemporalScale::Configure in Encode mode when enableTemporalScale is false
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidEnableTemporalScale_Configure_Encode_Disable_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidEnableTemporalScale temporalScaleParam(false);

    // Test Configure for Encode mode when enableTemporalScale is false
    temporalScaleParam.Configure(meta, ConfigureMode::Encode);

    // Verify that the encoder enable temporal scalability tag is not set in the meta
    bool enableTemporalScalability;
    EXPECT_FALSE(meta->GetData(Media::Tag::VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY, enableTemporalScalability));
}

/**
 * @tc.name: VidEnableTemporalScale_Configure_Decode_Enable_Success
 * @tc.desc: Test VidEnableTemporalScale::Configure in Decode mode when enableTemporalScale is true
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidEnableTemporalScale_Configure_Decode_Enable_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidEnableTemporalScale temporalScaleParam(true);

    // Test Configure for Decode mode when enableTemporalScale is true
    temporalScaleParam.Configure(meta, ConfigureMode::Decode);
   
    // Verify that the decoder enable temporal scalability tag is set to 1 in the meta
    int enableTemporalScalability;
    meta->GetData(std::string(MDKey::OH_MD_KEY_VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY),
        enableTemporalScalability);

    EXPECT_EQ(enableTemporalScalability, NUM_1);  // The tag should be set to 1
}

/**
 * @tc.name: VidEnableTemporalScale_Configure_Decode_Disable_Success
 * @tc.desc: Test VidEnableTemporalScale::Configure in Decode mode when enableTemporalScale is false
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidEnableTemporalScale_Configure_Decode_Disable_Success, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    VidEnableTemporalScale temporalScaleParam(false);

    // Test Configure for Decode mode when enableTemporalScale is false
    temporalScaleParam.Configure(meta, ConfigureMode::Decode);
   
    // Verify that the decoder enable temporal scalability tag is not set in the meta
    int enableTemporalScalability;
    EXPECT_FALSE(meta->GetData(std::string(MDKey::OH_MD_KEY_VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY),
        enableTemporalScalability));
}

/**
 * @tc.name: VidSurfaceParam__Configure_Failed
 * @tc.desc: Test VidSurfaceParam_::Configure failed
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_Failed, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {static_cast<SurfaceRotate>(INVALID_ENMU), static_cast<SurfaceFilp>(INVALID_ENMU)};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    ConfigureMode mode = static_cast<ConfigureMode>(INVALID_ENMU);
    // Test Configure for Encode mode
    vidSurfaceParam.Configure(meta, mode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation = 0;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, 0);

    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, Media::Plugins::VideoOrientationType::ROTATE_NONE);

    surfaceParam.filp = SurfaceFilp::FLIP_NONE;
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, Media::Plugins::VideoOrientationType::ROTATE_NONE);

    surfaceParam.filp = SurfaceFilp::FLIP_H;
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, Media::Plugins::VideoOrientationType::ROTATE_NONE);

    surfaceParam.filp = SurfaceFilp::FLIP_V;
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, Media::Plugins::VideoOrientationType::ROTATE_NONE);
}

/**
 * @tc.name: VidSurfaceParam_Configure_RotateNone_FlipNone_Test
 * @tc.desc: Test VidSurfaceParam::Configure with RotateNone and FlipNone in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_RotateNone_FlipNone_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_NONE, SurfaceFilp::FLIP_NONE};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::ROTATE_NONE));
}

/**
 * @tc.name: VidSurfaceParam_Configure_Rotate90_FlipNone_Test
 * @tc.desc: Test VidSurfaceParam::Configure with Rotate90 and FlipNone in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_Rotate90_FlipNone_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_90, SurfaceFilp::FLIP_NONE};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::ROTATE_90));
}

/**
 * @tc.name: VidSurfaceParam_Configure_Rotate180_FlipNone_Test
 * @tc.desc: Test VidSurfaceParam::Configure with Rotate180 and FlipNone in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_Rotate180_FlipNone_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_180, SurfaceFilp::FLIP_NONE};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::ROTATE_180));
}

/**
 * @tc.name: VidSurfaceParam_Configure_Rotate270_FlipNone_Test
 * @tc.desc: Test VidSurfaceParam::Configure with Rotate270 and FlipNone in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_Rotate270_FlipNone_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_270, SurfaceFilp::FLIP_NONE};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::ROTATE_270));
}

/**
 * @tc.name: VidSurfaceParam_Configure_FlipH_RotateNone_Test
 * @tc.desc: Test VidSurfaceParam::Configure with FlipH and RotateNone in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_FlipH_RotateNone_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_NONE, SurfaceFilp::FLIP_H};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::FLIP_H));
}

/**
 * @tc.name: VidSurfaceParam_Configure_FlipV_RotateNone_Test
 * @tc.desc: Test VidSurfaceParam::Configure with FlipV and RotateNone in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_FlipV_RotateNone_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_NONE, SurfaceFilp::FLIP_V};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::FLIP_V));
}

/**
 * @tc.name: VidSurfaceParam_Configure_FlipH_Rotate90_Test
 * @tc.desc: Test VidSurfaceParam::Configure with FlipH and Rotate90 in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_FlipH_Rotate90_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_90, SurfaceFilp::FLIP_H};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::FLIP_H_ROT90));
}

/**
 * @tc.name: VidSurfaceParam_Configure_FlipV_Rotate90_Test
 * @tc.desc: Test VidSurfaceParam::Configure with FlipV and Rotate90 in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_FlipV_Rotate90_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_90, SurfaceFilp::FLIP_V};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::FLIP_V_ROT90));
}

/**
 * @tc.name: VidSurfaceParam_Configure_FlipH_Rotate180_Test
 * @tc.desc: Test VidSurfaceParam::Configure with FlipH and Rotate180 in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_FlipH_Rotate180_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_180, SurfaceFilp::FLIP_H};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::FLIP_H_ROT180));
}

/**
 * @tc.name: VidSurfaceParam_Configure_FlipV_Rotate180_Test
 * @tc.desc: Test VidSurfaceParam::Configure with FlipV and Rotate180 in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_FlipV_Rotate180_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_180, SurfaceFilp::FLIP_V};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::FLIP_V_ROT180));
}

/**
 * @tc.name: VidSurfaceParam_Configure_FlipH_Rotate270_Test
 * @tc.desc: Test VidSurfaceParam::Configure with FlipH and Rotate270 in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_FlipH_Rotate270_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_270, SurfaceFilp::FLIP_H};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::FLIP_H_ROT270));
}

/**
 * @tc.name: VidSurfaceParam_Configure_FlipV_Rotate270_Test
 * @tc.desc: Test VidSurfaceParam::Configure with FlipV and Rotate270 in Decode mode
 * @tc.type: FUNC
 */
HWTEST_F(SurfaceParamTest, VidSurfaceParam_Configure_FlipV_Rotate270_Test, TestSize.Level1)
{
    std::shared_ptr<Media::Meta> meta = std::make_shared<Media::Meta>();
    SurfaceParam surfaceParam = {SurfaceRotate::ROTATE_270, SurfaceFilp::FLIP_V};
    VidSurfaceParam vidSurfaceParam(surfaceParam);

    // Test Configure for Decode mode
    vidSurfaceParam.Configure(meta, ConfigureMode::Decode);

    // Get the value as int32_t and compare with the expected value
    int32_t orientation;
    GetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, orientation);
    EXPECT_EQ(orientation, static_cast<int32_t>(Media::Plugins::VideoOrientationType::FLIP_V_ROT270));
}
}  // namespace DistributedCollab
}  // namespace OHOS
