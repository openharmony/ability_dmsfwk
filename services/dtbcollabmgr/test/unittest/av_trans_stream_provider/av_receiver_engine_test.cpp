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
#include "av_receiver_engine_test.h"

#include "dtbcollabmgr_log.h"
#include "av_stream_param.h"

namespace OHOS {
namespace DistributedCollab {

namespace {
    static const std::string TAG = "AVReceiverEngineTest";
    using namespace testing;
    using namespace testing::ext;
    using Filter = Media::Pipeline::Filter;
    using StreamType = Media::Pipeline::StreamType;
    using FilterCallBackCommand = Media::Pipeline::FilterCallBackCommand;
    using FilterType = Media::Pipeline::FilterType;
}

void AVReceiverEngineTest::SetUpTestCase()
{
    HILOGI("AVReceiverEngineTest::SetUpTestCase");
}

void AVReceiverEngineTest::TearDownTestCase()
{
    HILOGI("AVReceiverEngineTest::TearDownTestCase");
}

void AVReceiverEngineTest::SetUp()
{
    HILOGI("AVReceiverEngineTest::SetUp");
}

void AVReceiverEngineTest::TearDown()
{
    HILOGI("AVReceiverEngineTest::TearDown");
}

/**
 * @tc.name: Configure_Test_001
 * @tc.desc: Configure
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverEngineTest, Configure_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverEngineTest::Configure_Test_001 begin");
    AVReceiverEngine engine;
    engine.receiverFilter_ = nullptr;
    engine.SetVideoSource(VideoSourceType::NV12);
    engine.SetVideoSource(VideoSourceType::NV21);
    engine.SetVideoSource(static_cast<VideoSourceType>(-1));

    VidIsHdr recParam(false);
    engine.receiverFilter_ = nullptr;
    auto ret = engine.Configure(recParam);
    EXPECT_EQ(ret, static_cast<int32_t>(Media::Status::ERROR_NULL_POINTER));

    VidIsHdr recParam1(true);
    engine.receiverFilter_ = std::make_shared<AVReceiverFilter>(
        "builtin.dtbcollab.receiver", Media::Pipeline::FilterType::FILTERTYPE_VENC);
    recParam1.type_ = static_cast<StreamParamType>(-1);
    ret = engine.Configure(recParam1);
    EXPECT_EQ(ret, static_cast<int32_t>(Media::Status::OK));
    HILOGI("AVReceiverEngineTest::Configure_Test_001 end");
}

/**
 * @tc.name: SetVideoSurface_Test_001
 * @tc.desc: SetVideoSurface
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverEngineTest, SetVideoSurface_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverEngineTest::SetVideoSurface_Test_001 begin");
    AVReceiverEngine engine;
    auto ret = engine.SetVideoSurface(-1);
    EXPECT_EQ(ret, static_cast<int32_t>(Media::Status::ERROR_NULL_POINTER));

    engine.SetChannelListener(0);

    engine.receiverFilter_ = nullptr;
    engine.SetChannelListener(0);

    auto ret1 = engine.GetVideoCodecAbility();
    EXPECT_NE(ret1, nullptr);
    HILOGI("AVReceiverEngineTest::SetVideoSurface_Test_001 end");
}

/**
 * @tc.name: OnCallback_Test_001
 * @tc.desc: OnCallback
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverEngineTest, OnCallback_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverEngineTest::OnCallback_Test_001 begin");
    AVReceiverEngine engine;
    std::shared_ptr<Filter> filter = std::make_shared<Filter>("", FilterType::FILTERTYPE_VDEC);
    auto ret = engine.OnCallback(filter, FilterCallBackCommand::NEXT_FILTER_REMOVED,
        StreamType::STREAMTYPE_ENCODED_VIDEO);
    EXPECT_EQ(ret, Media::Status::OK);

    ret = engine.OnCallback(filter, FilterCallBackCommand::NEXT_FILTER_NEEDED, StreamType::STREAMTYPE_RAW_AUDIO);
    EXPECT_EQ(ret, Media::Status::OK);

    engine.videoDecoderFilter_ = nullptr;
    engine.surface_ = nullptr;
    ret = engine.OnCallback(filter, FilterCallBackCommand::NEXT_FILTER_NEEDED,
        StreamType::STREAMTYPE_ENCODED_VIDEO);
    EXPECT_EQ(ret, Media::Status::ERROR_NULL_POINTER);

    ret = engine.OnCallback(filter, FilterCallBackCommand::NEXT_FILTER_NEEDED,
        StreamType::STREAMTYPE_ENCODED_VIDEO);
    EXPECT_EQ(ret, Media::Status::OK);
    HILOGI("AVReceiverEngineTest::OnCallback_Test_001 end");
}

/**
 * @tc.name: Prepare_Test_001
 * @tc.desc: Prepare
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverEngineTest, Prepare_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverEngineTest::Prepare_Test_001 begin");
    AVReceiverEngine engine;
    engine.receiverFilter_ = nullptr;
    auto ret = engine.Prepare();
    EXPECT_EQ(ret, static_cast<int32_t>(Media::Status::ERROR_NULL_POINTER));
    HILOGI("AVReceiverEngineTest::Prepare_Test_001 end");
}

/**
 * @tc.name: Start_Test_001
 * @tc.desc: Start
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverEngineTest, Start_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverEngineTest::Start_Test_001 begin");
    AVReceiverEngine engine;
    engine.videoDecoderFilter_ = nullptr;
    auto ret = engine.Start();
    EXPECT_EQ(ret, static_cast<int32_t>(Media::Status::ERROR_NULL_POINTER));

    engine.videoDecoderFilter_ = std::make_shared<SurfaceDecoderFilter>(
        "builtin.dtbcollab.surfacedecoder", FilterType::FILTERTYPE_VDEC);
    engine.curState_ = EngineState::START;
    ret = engine.Start();
    EXPECT_EQ(ret, static_cast<int32_t>(Media::Status::OK));

    engine.curState_ = EngineState::INIT;
    ret = engine.Start();
    EXPECT_EQ(ret, static_cast<int32_t>(Media::Status::ERROR_WRONG_STATE));

    engine.curState_ = EngineState::STOP;
    ret = engine.Start();
    EXPECT_EQ(ret, static_cast<int32_t>(Media::Status::OK));

    engine.curState_ = EngineState::PREPARE;
    ret = engine.Start();
    EXPECT_NE(ret, static_cast<int32_t>(Media::Status::ERROR_NULL_POINTER));
    HILOGI("AVReceiverEngineTest::Start_Test_001 end");
}

/**
 * @tc.name: Stop_Test_001
 * @tc.desc: Stop
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverEngineTest, Stop_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverEngineTest::Stop_Test_001 begin");
    AVReceiverEngine engine;
    engine.curState_ = EngineState::INIT;
    auto ret = engine.Stop();
    EXPECT_EQ(ret, static_cast<int32_t>(Media::Status::OK));

    engine.curState_ = EngineState::STOP;
    ret = engine.Stop();
    EXPECT_EQ(ret, static_cast<int32_t>(Media::Status::OK));

    engine.curState_ = EngineState::PREPARE;
    ret = engine.Stop();
    EXPECT_EQ(ret, static_cast<int32_t>(Media::Status::ERROR_WRONG_STATE));

    engine.curState_ = EngineState::START;
    ret = engine.Stop();
    EXPECT_NE(ret, static_cast<int32_t>(Media::Status::ERROR_WRONG_STATE));
    HILOGI("AVReceiverEngineTest::Stop_Test_001 end");
}

/**
 * @tc.name: ConvertToGraphicTrans_Test_001
 * @tc.desc: ConvertToGraphicTrans
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverEngineTest, ConvertToGraphicTrans_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverEngineTest::ConvertToGraphicTrans_Test_001 begin");
    AVReceiverEngine engine;
    engine.receiverFilter_ = nullptr;
    engine.SetEngineListener(nullptr);
    
    engine.receiverFilter_ = std::make_shared<AVReceiverFilter>(
        "builtin.dtbcollab.receiver", Media::Pipeline::FilterType::FILTERTYPE_VENC);
    engine.SetEngineListener(nullptr);

    SurfaceParam param;
    param.filp = SurfaceFilp::FLIP_NONE;
    param.rotate = SurfaceRotate::ROTATE_NONE;
    auto ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_ROTATE_NONE);

    param.rotate = SurfaceRotate::ROTATE_90;
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_ROTATE_90);

    param.rotate = SurfaceRotate::ROTATE_180;
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_ROTATE_180);

    param.rotate = SurfaceRotate::ROTATE_270;
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_ROTATE_270);

    param.rotate = static_cast<SurfaceRotate>(-1);
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_ROTATE_BUTT);
    HILOGI("AVReceiverEngineTest::ConvertToGraphicTrans_Test_001 end");
}

/**
 * @tc.name: ConvertToGraphicTrans_Test_002
 * @tc.desc: ConvertToGraphicTrans
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverEngineTest, ConvertToGraphicTrans_Test_002, TestSize.Level1)
{
    HILOGI("AVReceiverEngineTest::ConvertToGraphicTrans_Test_002 begin");
    AVReceiverEngine engine;
    SurfaceParam param;
    param.filp = SurfaceFilp::FLIP_H;
    param.rotate = SurfaceRotate::ROTATE_NONE;
    auto ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_FLIP_H);

    param.rotate = SurfaceRotate::ROTATE_90;
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_FLIP_H_ROT90);

    param.rotate = SurfaceRotate::ROTATE_180;
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_FLIP_H_ROT180);

    param.rotate = SurfaceRotate::ROTATE_270;
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_FLIP_H_ROT270);

    param.rotate = static_cast<SurfaceRotate>(-1);
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_ROTATE_BUTT);
    HILOGI("AVReceiverEngineTest::ConvertToGraphicTrans_Test_002 end");
}

/**
 * @tc.name: ConvertToGraphicTrans_Test_003
 * @tc.desc: ConvertToGraphicTrans
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverEngineTest, ConvertToGraphicTrans_Test_003, TestSize.Level1)
{
    HILOGI("AVReceiverEngineTest::ConvertToGraphicTrans_Test_003 begin");
    AVReceiverEngine engine;
    SurfaceParam param;
    param.filp = SurfaceFilp::FLIP_V;
    param.rotate = SurfaceRotate::ROTATE_NONE;
    auto ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_FLIP_V);

    param.rotate = SurfaceRotate::ROTATE_90;
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_FLIP_V_ROT90);

    param.rotate = SurfaceRotate::ROTATE_180;
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_FLIP_V_ROT180);

    param.rotate = SurfaceRotate::ROTATE_270;
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_FLIP_V_ROT270);

    param.rotate = static_cast<SurfaceRotate>(-1);
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_ROTATE_BUTT);

    param.filp = static_cast<SurfaceFilp>(-1);
    ret = engine.ConvertToGraphicTrans(param);
    EXPECT_EQ(ret, GraphicTransformType::GRAPHIC_ROTATE_BUTT);
    HILOGI("AVReceiverEngineTest::ConvertToGraphicTrans_Test_003 end");
}

/**
 * @tc.name: OnEvent_Test_001
 * @tc.desc: OnEvent
 * @tc.type: FUNC
 */
HWTEST_F(AVReceiverEngineTest, OnEvent_Test_001, TestSize.Level1)
{
    HILOGI("AVReceiverEngineTest::OnEvent_Test_001 begin");
    AVReceiverEngine engine;
    SurfaceParam param;
    engine.videoDecoderFilter_ = nullptr;
    engine.OnRecvSurfaceParam(param);

    engine.videoDecoderFilter_ = std::make_shared<SurfaceDecoderFilter>(
        "builtin.dtbcollab.surfacedecoder", FilterType::FILTERTYPE_VDEC);
    engine.OnRecvSurfaceParam(param);

    Media::Event event;
    event.type = Media::EventType::EVENT_ERROR;
    engine.OnEvent(event);

    event.type = Media::EventType::EVENT_READY;
    engine.OnEvent(event);

    event.type = Media::EventType::EVENT_COMPLETE;
    EXPECT_NO_FATAL_FAILURE(engine.OnEvent(event));
    HILOGI("AVReceiverEngineTest::OnEvent_Test_001 end");
}
}
}
