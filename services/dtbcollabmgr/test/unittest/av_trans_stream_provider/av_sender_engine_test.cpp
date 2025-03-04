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
 * @tc.name: Configure_Test
 * @tc.desc: Test Configure
 * @tc.type: FUNC
 */
HWTEST_F(AVSenderEngineTest, Configure_Test, TestSize.Level1)
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
    senderEngine_->senderFilter_ = nullptr;
    auto ret = senderEngine_->SendPixelMap(pixelMap);
    EXPECT_EQ(ret, NULL_POINTER_ERROR);

    senderEngine_->senderFilter_ = std::make_shared<AVSenderFilter>(
        "builtin.dtbcollab.sender", FilterType::FILTERTYPE_SOURCE);
    ret = senderEngine_->SendPixelMap(pixelMap);
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
