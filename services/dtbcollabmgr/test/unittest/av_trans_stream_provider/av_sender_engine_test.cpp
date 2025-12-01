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
#include "av_sender_engine_test.h"

#include "dtbcollabmgr_log.h"
#include "media_description.h"
#include "test_log.h"

namespace OHOS {
namespace DistributedCollab {

namespace {
    static const std::string TAG = "AVStreamParamTest";
    using Status = Media::Status;
    using FilterType = Media::Pipeline::FilterType;
    using Filter = Media::Pipeline::Filter;
    using FilterCallBackCommand = Media::Pipeline::FilterCallBackCommand;
    using StreamType = Media::Pipeline::StreamType;
    using namespace testing;
    using namespace testing::ext;
    const int32_t WAITTIME = 2000;
}

void AVSenderEngineTest::SetUpTestCase()
{
    HILOGI("AVSenderEngineTest::SetUpTestCase");
    int32_t appUid = 0;
    int32_t appPid = 0;
    std::string bundleName = "bundleName";
    uint64_t instanceId = 0;
    senderEngine_ = std::make_shared<AVSenderEngine>(appUid, appPid, bundleName, instanceId);
}

void AVSenderEngineTest::TearDownTestCase()
{
    HILOGI("AVSenderEngineTest::TearDownTestCase");
}

void AVSenderEngineTest::SetUp()
{
    HILOGI("AVSenderEngineTest::SetUp");
}

void AVSenderEngineTest::TearDown()
{
    HILOGI("AVSenderEngineTest::TearDown");
}

/**
 * @tc.name: InitVideoHeaderFilter_Test
 * @tc.desc: Test InitVideoHeaderFilter
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, InitVideoHeaderFilter_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest InitVideoHeaderFilter_Test begin" << std::endl;
    auto ret = senderEngine_->InitVideoHeaderFilter();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::OK));

    ret = senderEngine_->InitVideoHeaderFilter();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::OK));
    DTEST_LOG << "AVSenderEngineTest InitVideoHeaderFilter_Test end" << std::endl;
}

/**
 * @tc.name: SetVideoSource_Test
 * @tc.desc: Test SetVideoSource
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, SetVideoSource_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest SetVideoSource_Test begin" << std::endl;
    EXPECT_NO_FATAL_FAILURE(senderEngine_->SetVideoSource(VideoSourceType::NV12));
    EXPECT_NO_FATAL_FAILURE(senderEngine_->SetVideoSource(VideoSourceType::NV21));

    uint32_t type = 3000;
    EXPECT_NO_FATAL_FAILURE(senderEngine_->SetVideoSource(static_cast<VideoSourceType>(type)));
    DTEST_LOG << "AVSenderEngineTest SetVideoSource_Test end" << std::endl;
}

/**
 * @tc.name: Configure_Test_001
 * @tc.desc: Test Configure
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Configure_Test_001, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest Configure_Test begin" << std::endl;
    VidEnc recParam(VideoCodecFormat::VIDEO_DEFAULT);
    uint32_t type = 3000;
    recParam.type_ = static_cast<StreamParamType>(type);
    EXPECT_EQ(senderEngine_->Configure(recParam), static_cast<int32_t>(Status::OK));

    recParam.type_ = StreamParamType::VID_CAPTURERATE;
    EXPECT_EQ(senderEngine_->Configure(recParam), static_cast<int32_t>(Status::OK));
    DTEST_LOG << "AVSenderEngineTest Configure_Test end" << std::endl;
}

/**
 * @tc.name: Configure_Test_002
 * @tc.desc: Test Configure with VID_ENC_FMT parameter
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Configure_Test_002, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest Configure_Test_002 begin" << std::endl;
    VidEnc encParam(VideoCodecFormat::H264);
    EXPECT_EQ(senderEngine_->Configure(encParam), static_cast<int32_t>(Status::OK));

    VidEnc encParam2(VideoCodecFormat::H265);
    EXPECT_EQ(senderEngine_->Configure(encParam2), static_cast<int32_t>(Status::OK));
    DTEST_LOG << "AVSenderEngineTest Configure_Test_002 end" << std::endl;
}

/**
 * @tc.name: Configure_Test_003
 * @tc.desc: Test Configure with VID_RECTANGLE parameter
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Configure_Test_003, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest Configure_Test_003 begin" << std::endl;
    VidRectangle rectParam(1920, 1080);
    EXPECT_EQ(senderEngine_->Configure(rectParam), static_cast<int32_t>(Status::OK));

    VidRectangle rectParam2(1280, 720);
    EXPECT_EQ(senderEngine_->Configure(rectParam2), static_cast<int32_t>(Status::OK));
    DTEST_LOG << "AVSenderEngineTest Configure_Test_003 end" << std::endl;
}

/**
 * @tc.name: Configure_Test_004
 * @tc.desc: Test Configure with VID_BITRATE parameter
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Configure_Test_004, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest Configure_Test_004 begin" << std::endl;
    VidBitRate bitrateParam(8000000); // 8Mbps
    EXPECT_EQ(senderEngine_->Configure(bitrateParam), static_cast<int32_t>(Status::OK));

    VidBitRate bitrateParam2(4000000); // 4Mbps
    EXPECT_EQ(senderEngine_->Configure(bitrateParam2), static_cast<int32_t>(Status::OK));
    DTEST_LOG << "AVSenderEngineTest Configure_Test_004 end" << std::endl;
}

/**
 * @tc.name: Configure_Test_005
 * @tc.desc: Test Configure with VID_FRAMERATE parameter
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Configure_Test_005, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest Configure_Test_005 begin" << std::endl;
    VidFrameRate framerateParam(30); // 30fps
    EXPECT_EQ(senderEngine_->Configure(framerateParam), static_cast<int32_t>(Status::OK));

    VidFrameRate framerateParam2(60); // 60fps
    EXPECT_EQ(senderEngine_->Configure(framerateParam2), static_cast<int32_t>(Status::OK));
    DTEST_LOG << "AVSenderEngineTest Configure_Test_005 end" << std::endl;
}

/**
 * @tc.name: Configure_Test_006
 * @tc.desc: Test Configure with VID_IS_HDR parameter
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Configure_Test_006, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest Configure_Test_006 begin" << std::endl;
    VidIsHdr hdrParam(true);
    EXPECT_EQ(senderEngine_->Configure(hdrParam), static_cast<int32_t>(Status::OK));

    VidIsHdr hdrParam2(false);
    EXPECT_EQ(senderEngine_->Configure(hdrParam2), static_cast<int32_t>(Status::OK));
    DTEST_LOG << "AVSenderEngineTest Configure_Test_006 end" << std::endl;
}

/**
 * @tc.name: Configure_Test_007
 * @tc.desc: Test Configure with VID_ENABLE_TEMPORAL_SCALE parameter
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Configure_Test_007, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest Configure_Test_008 begin" << std::endl;
    VidEnableTemporalScale temporalScaleParam(true);
    EXPECT_EQ(senderEngine_->Configure(temporalScaleParam), static_cast<int32_t>(Status::OK));

    VidEnableTemporalScale temporalScaleParam2(false);
    EXPECT_EQ(senderEngine_->Configure(temporalScaleParam2), static_cast<int32_t>(Status::OK));
    DTEST_LOG << "AVSenderEngineTest Configure_Test_008 end" << std::endl;
}

/**
 * @tc.name: Configure_Test_008
 * @tc.desc: Test Configure with VID_SURFACE_PARAM parameter
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Configure_Test_008, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest Configure_Test_009 begin" << std::endl;
    SurfaceParam surfaceParam;
    surfaceParam.filp = SurfaceFilp::FLIP_NONE;
    surfaceParam.rotate = SurfaceRotate::ROTATE_NONE;
    VidSurfaceParam surfaceParamObj(surfaceParam);
    EXPECT_EQ(senderEngine_->Configure(surfaceParamObj), static_cast<int32_t>(Status::OK));

    SurfaceParam surfaceParam2;
    surfaceParam2.filp = SurfaceFilp::FLIP_H;
    surfaceParam2.rotate = SurfaceRotate::ROTATE_90;
    VidSurfaceParam surfaceParamObj2(surfaceParam2);
    EXPECT_EQ(senderEngine_->Configure(surfaceParamObj2), static_cast<int32_t>(Status::OK));
    DTEST_LOG << "AVSenderEngineTest Configure_Test_009 end" << std::endl;
}

/**
 * @tc.name: isVideoParam_Test
 * @tc.desc: Test isVideoParam
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, isVideoParam_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest isVideoParam_Test begin" << std::endl;
    VidEnc recParam(VideoCodecFormat::VIDEO_DEFAULT);
    recParam.type_ = StreamParamType::VID_CAPTURERATE;
    EXPECT_TRUE(senderEngine_->isVideoParam(recParam));

    recParam.type_ = StreamParamType::VID_RECTANGLE;
    EXPECT_TRUE(senderEngine_->isVideoParam(recParam));

    recParam.type_ = StreamParamType::VID_BITRATE;
    EXPECT_TRUE(senderEngine_->isVideoParam(recParam));

    recParam.type_ = StreamParamType::VID_FRAMERATE;
    EXPECT_TRUE(senderEngine_->isVideoParam(recParam));

    recParam.type_ = StreamParamType::VID_IS_HDR;
    EXPECT_TRUE(senderEngine_->isVideoParam(recParam));

    recParam.type_ = StreamParamType::VID_ENC_FMT;
    EXPECT_TRUE(senderEngine_->isVideoParam(recParam));

    recParam.type_ = StreamParamType::VID_ENABLE_TEMPORAL_SCALE;
    EXPECT_TRUE(senderEngine_->isVideoParam(recParam));

    uint32_t type = 3000;
    recParam.type_ = static_cast<StreamParamType>(type);
    EXPECT_FALSE(senderEngine_->isVideoParam(recParam));
    DTEST_LOG << "AVSenderEngineTest isVideoParam_Test end" << std::endl;
}

/**
 * @tc.name: SetTransChannel_Test
 * @tc.desc: Test SetTransChannel
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, SetTransChannel_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest SetTransChannel_Test begin" << std::endl;
    int32_t channelId = 30;
    ChannelDataType channelType = ChannelDataType::MESSAGE;
    senderEngine_->senderFilter_ = nullptr;
    EXPECT_NO_FATAL_FAILURE(senderEngine_->SetTransChannel(channelId, channelType));

    std::string name = "test";
    Media::Pipeline::FilterType type;
    senderEngine_->senderFilter_ = std::make_shared<AVSenderFilter>(name, type);
    EXPECT_NO_FATAL_FAILURE(senderEngine_->SetTransChannel(channelId, channelType));
    DTEST_LOG << "AVSenderEngineTest SetTransChannel_Test end" << std::endl;
}

/**
 * @tc.name: GetSurface_Test
 * @tc.desc: Test GetSurface
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, GetSurface_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest GetSurface_Test begin" << std::endl;
    senderEngine_->videoEncoderFilter_ = nullptr;
    EXPECT_EQ(senderEngine_->GetSurface(), 0);

    senderEngine_->videoEncoderFilter_ = std::make_shared<SurfaceEncoderFilter>(
        "builtin.dtbcollab.videoencoder", FilterType::FILTERTYPE_VENC);
    EXPECT_EQ(senderEngine_->GetSurface(), 0);
    DTEST_LOG << "AVSenderEngineTest GetSurface_Test end" << std::endl;
}

/**
 * @tc.name: GetVideoCodecAbility_Test
 * @tc.desc: Test GetVideoCodecAbility
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, GetVideoCodecAbility_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest GetVideoCodecAbility_Test begin" << std::endl;
    EXPECT_NE(senderEngine_->GetVideoCodecAbility(), nullptr);
    DTEST_LOG << "AVSenderEngineTest GetVideoCodecAbility_Test end" << std::endl;
}

/**
 * @tc.name: OnCallback_Test
 * @tc.desc: Test OnCallback
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, OnCallback_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest OnCallback_Test begin" << std::endl;
    std::shared_ptr<Filter> filter = std::make_shared<Filter>(
        "builtin.dtbcollab.videoencoder", FilterType::FILTERTYPE_VENC);
    FilterCallBackCommand cmd = FilterCallBackCommand::NEXT_FILTER_REMOVED;
    StreamType outType = StreamType::STREAMTYPE_PACKED;
    senderEngine_->senderFilter_ = nullptr;
    EXPECT_EQ(senderEngine_->OnCallback(filter, cmd, outType), Status::OK);
    EXPECT_EQ(senderEngine_->senderFilter_, nullptr);

    cmd = FilterCallBackCommand::NEXT_FILTER_NEEDED;
    EXPECT_EQ(senderEngine_->OnCallback(filter, cmd, outType), Status::OK);
    EXPECT_EQ(senderEngine_->senderFilter_, nullptr);

    outType = StreamType::STREAMTYPE_ENCODED_VIDEO;
    EXPECT_EQ(senderEngine_->OnCallback(filter, cmd, outType), Status::OK);
    EXPECT_NE(senderEngine_->senderFilter_, nullptr);
    usleep(WAITTIME);

    EXPECT_EQ(senderEngine_->OnCallback(filter, cmd, outType), Status::OK);
    EXPECT_NE(senderEngine_->senderFilter_, nullptr);
    DTEST_LOG << "AVSenderEngineTest OnCallback_Test end" << std::endl;
}

/**
 * @tc.name: Prepare_Test
 * @tc.desc: Test Prepare
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Prepare_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest Prepare_Test begin" << std::endl;
    senderEngine_->videoEncoderFilter_ = nullptr;
    auto ret = senderEngine_->Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_NULL_POINTER));
    DTEST_LOG << "AVSenderEngineTest Prepare_Test end" << std::endl;
}

/**
 * @tc.name: Start_Test
 * @tc.desc: Test Start
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Start_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest Prepare_Test begin" << std::endl;
    senderEngine_->senderFilter_ = nullptr;
    auto ret = senderEngine_->Start();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_NULL_POINTER));

    senderEngine_->senderFilter_ = std::make_shared<AVSenderFilter>(
        "builtin.dtbcollab.sender", FilterType::FILTERTYPE_SOURCE);
    senderEngine_->curState_ = EngineState::START;
    ret = senderEngine_->Start();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::OK));

    senderEngine_->curState_ = EngineState::SETTING;
    ret = senderEngine_->Start();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::ERROR_WRONG_STATE));

    senderEngine_->curState_ = EngineState::PREPARE;
    ret = senderEngine_->Start();
    EXPECT_NE(ret, static_cast<int32_t>(Status::OK));

    senderEngine_->curState_ = EngineState::STOP;
    ret = senderEngine_->Start();
    EXPECT_NE(ret, static_cast<int32_t>(Status::OK));
    DTEST_LOG << "AVSenderEngineTest Start_Test end" << std::endl;
}

/**
 * @tc.name: Stop_Test
 * @tc.desc: Test Start
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Stop_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest Prepare_Test begin" << std::endl;
    senderEngine_->curState_ = EngineState::INIT;
    auto ret = senderEngine_->Stop();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::OK));

    senderEngine_->curState_ = EngineState::STOP;
    ret = senderEngine_->Stop();
    EXPECT_EQ(ret, static_cast<int32_t>(Status::OK));

    senderEngine_->curState_ = EngineState::SETTING;
    ret = senderEngine_->Stop();
    EXPECT_NE(ret, static_cast<int32_t>(Status::OK));
    DTEST_LOG << "AVSenderEngineTest Start_Test end" << std::endl;
}

/**
 * @tc.name: Stop_Test
 * @tc.desc: Test Start
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, SendPixelMap_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest SendPixelMap_Test begin" << std::endl;
    std::shared_ptr<Media::PixelMap> pixelMap = nullptr;
    int32_t imageQuality = 30;
    senderEngine_->senderFilter_ = nullptr;
    auto ret = senderEngine_->SendPixelMap(pixelMap, imageQuality);
    EXPECT_EQ(ret, NULL_POINTER_ERROR);

    senderEngine_->senderFilter_ = std::make_shared<AVSenderFilter>(
        "builtin.dtbcollab.sender", FilterType::FILTERTYPE_SOURCE);
    ret = senderEngine_->SendPixelMap(pixelMap, imageQuality);
    EXPECT_EQ(ret, NULL_POINTER_ERROR);
    DTEST_LOG << "AVSenderEngineTest SendPixelMap_Test end" << std::endl;
}

/**
 * @tc.name: SetSurfaceParam_Test
 * @tc.desc: Test SetSurfaceParam
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, SetSurfaceParam_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest SetSurfaceParam_Test begin" << std::endl;
    SurfaceParam param;
    senderEngine_->senderFilter_ = nullptr;
    auto ret = senderEngine_->SetSurfaceParam(param);
    EXPECT_EQ(ret, NULL_POINTER_ERROR);

    senderEngine_->senderFilter_ = std::make_shared<AVSenderFilter>(
        "builtin.dtbcollab.sender", FilterType::FILTERTYPE_SOURCE);
    ret = senderEngine_->SetSurfaceParam(param);
    EXPECT_EQ(ret, ERR_OK);
    DTEST_LOG << "AVSenderEngineTest SetSurfaceParam_Test end" << std::endl;
}

/**
 * @tc.name: OnEvent_Test
 * @tc.desc: Test Start
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, OnEvent_Test, TestSize.Level1)
{
    DTEST_LOG << "AVSenderEngineTest OnEvent_Test begin" << std::endl;
    Media::Event event;
    event.type = Media::EventType::EVENT_ERROR;
    senderEngine_->OnEvent(event);
    EXPECT_EQ(senderEngine_->GetState(), EngineState::ERROR);
    
    event.type = Media::EventType::EVENT_READY;
    senderEngine_->OnEvent(event);
    EXPECT_EQ(senderEngine_->GetState(), EngineState::START);

    event.type = Media::EventType::EVENT_COMPLETE;
    senderEngine_->OnEvent(event);
    EXPECT_EQ(senderEngine_->GetState(), EngineState::START);
    DTEST_LOG << "AVSenderEngineTest OnEvent_Test end" << std::endl;
}
}  // namespace DistributedCollab
}  // namespace OHOS
