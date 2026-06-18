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

#include "av_colorspace_converter_test.h"
#include "av_surface_buffer_cache.h"
#include "buffer_extra_data.h"
#include "dtbcollabmgr_log.h"
#include "securec.h"
#include "test_log.h"

namespace OHOS {
namespace DistributedCollab {

using namespace testing;
using namespace testing::ext;

namespace {
    static const std::string TAG = "AVColorspaceConverterTest";
}

void AVColorspaceConverterTest::SetUpTestCase()
{
    DTEST_LOG << "AVColorspaceConverterTest::SetUpTestCase" << std::endl;
}

void AVColorspaceConverterTest::TearDownTestCase()
{
    DTEST_LOG << "AVColorspaceConverterTest::TearDownTestCase" << std::endl;
}

void AVColorspaceConverterTest::SetUp()
{
    DTEST_LOG << "AVColorspaceConverterTest::SetUp" << std::endl;
    videoProcessingMock_ = std::make_unique<VideoProcessingMock>();

    ON_CALL(*videoProcessingMock_, InitializeEnvironment())
        .WillByDefault(Return(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));
    ON_CALL(*videoProcessingMock_, Create(_, _))
        .WillByDefault(Invoke([](OH_VideoProcessing** processor, int32_t type) {
            *processor = reinterpret_cast<OH_VideoProcessing*>(new int64_t(1));
            return VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS;
        }));
    ON_CALL(*videoProcessingMock_, CallbackCreate(_))
        .WillByDefault(Invoke([](VideoProcessing_Callback** callback) {
            *callback = reinterpret_cast<VideoProcessing_Callback*>(new int64_t(1));
            return VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS;
        }));
    ON_CALL(*videoProcessingMock_, CallbackBindOnError(_, _))
        .WillByDefault(Return(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));
    ON_CALL(*videoProcessingMock_, CallbackBindOnState(_, _))
        .WillByDefault(Return(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));
    ON_CALL(*videoProcessingMock_, CallbackBindOnNewOutputBuffer(_, _))
        .WillByDefault(Return(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));
    ON_CALL(*videoProcessingMock_, RegisterCallback(_, _, _))
        .WillByDefault(Return(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));
    ON_CALL(*videoProcessingMock_, GetSurface(_, _))
        .WillByDefault(Invoke([](OH_VideoProcessing* processor, OHNativeWindow** window) {
            OHNativeWindow* nativeWindow = new OHNativeWindow();
            nativeWindow->surface = IConsumerSurface::Create();
            *window = nativeWindow;
            return VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS;
        }));
    ON_CALL(*videoProcessingMock_, CreateNativeWindow(_))
        .WillByDefault(Invoke([](void* pSurface) {
            sptr<Surface>* surface = static_cast<sptr<Surface>*>(pSurface);
            OHNativeWindow* nativeWindow = new OHNativeWindow();
            nativeWindow->surface = *surface;
            return nativeWindow;
        }));
    ON_CALL(*videoProcessingMock_, SetSurface(_, _))
        .WillByDefault(Return(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));
    ON_CALL(*videoProcessingMock_, Start(_))
        .WillByDefault(Return(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));
    ON_CALL(*videoProcessingMock_, Stop(_))
        .WillByDefault(Return(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));
    ON_CALL(*videoProcessingMock_, NativeWindowHandleOpt(_, _))
        .WillByDefault(Return(0));
    ON_CALL(*videoProcessingMock_, SetColorSpace(_, _))
        .WillByDefault(Return(0));
    ON_CALL(*videoProcessingMock_, CallbackDestroy(_))
        .WillByDefault(Invoke([](VideoProcessing_Callback* callback) {
            delete reinterpret_cast<int64_t*>(callback);
            return VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS;
        }));
    ON_CALL(*videoProcessingMock_, Destroy(_))
        .WillByDefault(Invoke([](OH_VideoProcessing* processor) {
            delete reinterpret_cast<int64_t*>(processor);
            return VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS;
        }));
    ON_CALL(*videoProcessingMock_, DestroyNativeWindow(_))
        .WillByDefault(Invoke([](OHNativeWindow* window) { delete window; }));
    ON_CALL(*videoProcessingMock_, DeinitializeEnvironment())
        .WillByDefault(Return(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));

    EXPECT_CALL(*videoProcessingMock_, InitializeEnvironment());
    converter_ = std::make_unique<AVColorspaceConverter>();
}

void AVColorspaceConverterTest::TearDown()
{
    DTEST_LOG << "AVColorspaceConverterTest::TearDown" << std::endl;
    converter_.reset();
    videoProcessingMock_.reset();
}

#ifdef DMSFWK_UT_COVER
/**
 * @tc.name: Init_Test
 * @tc.desc: Test successful initialization
 * @tc.type: FUNC
 */
HWTEST_F(AVColorspaceConverterTest, Init_Test, TestSize.Level1)
{
    DTEST_LOG << "AVColorspaceConverterTest Init_Test begin" << std::endl;

    EXPECT_CALL(*videoProcessingMock_, Create(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackCreate(_));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnError(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnState(_, _));
    EXPECT_CALL(*videoProcessingMock_, RegisterCallback(_, _, _));

    int32_t ret = converter_->Init();
    EXPECT_EQ(ret, static_cast<int32_t>(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));

    DTEST_LOG << "AVColorspaceConverterTest Init_Test end" << std::endl;
}

/**
 * @tc.name: Callback_Test
 * @tc.desc: Test successful callback registration
 * @tc.type: FUNC
 */
HWTEST_F(AVColorspaceConverterTest, Callback_Test, TestSize.Level1)
{
    DTEST_LOG << "AVColorspaceConverterTest Callback_Test begin" << std::endl;

    EXPECT_CALL(*videoProcessingMock_, Create(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackCreate(_));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnError(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnState(_, _));
    EXPECT_CALL(*videoProcessingMock_, RegisterCallback(_, _, _));
    EXPECT_CALL(*videoProcessingMock_, GetSurface(_, _));

    int32_t ret = converter_->Init();
    EXPECT_EQ(ret, static_cast<int32_t>(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));
    converter_->OnState(converter_->GetProcesser(),
        VideoProcessing_State::VIDEO_PROCESSING_STATE_RUNNING, nullptr);
    converter_->OnState(converter_->GetProcesser(),
        VideoProcessing_State::VIDEO_PROCESSING_STATE_STOPPED, static_cast<void*>(this));
    converter_->OnNewOutputBuffer(converter_->GetProcesser(), 0, nullptr);
    converter_->OnNewOutputBuffer(converter_->GetProcesser(), 1, static_cast<void*>(this));
    converter_->OnError(converter_->GetProcesser(),
        VideoProcessing_ErrorCode::VIDEO_PROCESSING_ERROR_INVALID_PARAMETER, nullptr);

    sptr<Surface> surface = converter_->GetSurface();
    EXPECT_NE(surface, nullptr);
    DTEST_LOG << "AVColorspaceConverterTest Callback_Test end" << std::endl;
}

/**
 * @tc.name: GetSurface_Test
 * @tc.desc: Test successful surface retrieval using IConsumerSurface
 * @tc.type: FUNC
 */
HWTEST_F(AVColorspaceConverterTest, GetSurface_Test, TestSize.Level1)
{
    DTEST_LOG << "AVColorspaceConverterTest GetSurface_Test begin" << std::endl;

    EXPECT_CALL(*videoProcessingMock_, Create(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackCreate(_));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnError(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnState(_, _));
    EXPECT_CALL(*videoProcessingMock_, RegisterCallback(_, _, _));
    EXPECT_CALL(*videoProcessingMock_, GetSurface(_, _));

    int32_t ret = converter_->Init();
    EXPECT_EQ(ret, static_cast<int32_t>(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));

    sptr<Surface> surface = converter_->GetSurface();
    EXPECT_NE(surface, nullptr);

    DTEST_LOG << "AVColorspaceConverterTest GetSurface_Test end" << std::endl;
}

/**
 * @tc.name: SetSurface_Test
 * @tc.desc: Test successful surface setting
 * @tc.type: FUNC
 */
HWTEST_F(AVColorspaceConverterTest, SetSurface_Test, TestSize.Level1)
{
    DTEST_LOG << "AVColorspaceConverterTest SetSurface_Test begin" << std::endl;

    EXPECT_CALL(*videoProcessingMock_, Create(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackCreate(_));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnError(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnState(_, _));
    EXPECT_CALL(*videoProcessingMock_, RegisterCallback(_, _, _));
    EXPECT_CALL(*videoProcessingMock_, GetSurface(_, _));
    EXPECT_CALL(*videoProcessingMock_, CreateNativeWindow(_));

    int32_t ret = converter_->Init();
    EXPECT_EQ(ret, static_cast<int32_t>(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));

    sptr<Surface> surface = converter_->GetSurface();
    EXPECT_NE(surface, nullptr);

    ret = converter_->SetSurface(surface);
    EXPECT_EQ(ret, ERR_OK);

    DTEST_LOG << "AVColorspaceConverterTest SetSurface_Test end" << std::endl;
}

/**
 * @tc.name: Configure_Test
 * @tc.desc: Test successful configuration
 * @tc.type: FUNC
 */
HWTEST_F(AVColorspaceConverterTest, Configure_Test, TestSize.Level1)
{
    DTEST_LOG << "AVColorspaceConverterTest Configure_Test begin" << std::endl;

    EXPECT_CALL(*videoProcessingMock_, Create(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackCreate(_));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnError(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnState(_, _));
    EXPECT_CALL(*videoProcessingMock_, RegisterCallback(_, _, _));
    EXPECT_CALL(*videoProcessingMock_, GetSurface(_, _));
    EXPECT_CALL(*videoProcessingMock_, CreateNativeWindow(_));
    EXPECT_CALL(*videoProcessingMock_, NativeWindowHandleOpt(_, _));
    EXPECT_CALL(*videoProcessingMock_, SetColorSpace(_, _));
    EXPECT_CALL(*videoProcessingMock_, SetSurface(_, _));

    int32_t ret = converter_->Init();
    EXPECT_EQ(ret, static_cast<int32_t>(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));

    sptr<Surface> surface = converter_->GetSurface();
    EXPECT_NE(surface, nullptr);

    ret = converter_->SetSurface(surface);
    EXPECT_EQ(ret, ERR_OK);

    ret = converter_->Configure(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_LIMIT);

    DTEST_LOG << "AVColorspaceConverterTest Configure_Test end" << std::endl;
}

/**
 * @tc.name: Configure_Invalid_Test
 * @tc.desc: Test configuration with invalid surface
 * @tc.type: FUNC
 */
HWTEST_F(AVColorspaceConverterTest, Configure_Invalid_Test, TestSize.Level1)
{
    DTEST_LOG << "AVColorspaceConverterTest Configure_Invalid_Test begin" << std::endl;

    auto ret = converter_->Configure(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_NONE);
    EXPECT_EQ(ret, INVALID_COLORSPACE);

    ret = converter_->Configure(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_FULL);
    EXPECT_EQ(ret, INVALID_COLORSPACE);

    DTEST_LOG << "AVColorspaceConverterTest Configure_Invalid_Test end" << std::endl;
}

/**
 * @tc.name: Stop_Test
 * @tc.desc: Test stop functionality with various scenarios
 * @tc.type: FUNC
 */
HWTEST_F(AVColorspaceConverterTest, Stop_Test, TestSize.Level1)
{
    DTEST_LOG << "AVColorspaceConverterTest Stop_Test begin" << std::endl;

    auto ret = converter_->Stop();
    EXPECT_EQ(ret, NULL_POINTER_ERROR);

    EXPECT_CALL(*videoProcessingMock_, Create(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackCreate(_));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnError(_, _));
    EXPECT_CALL(*videoProcessingMock_, CallbackBindOnState(_, _));
    EXPECT_CALL(*videoProcessingMock_, RegisterCallback(_, _, _));
    EXPECT_CALL(*videoProcessingMock_, Stop(_))
        .WillOnce(Return(VideoProcessing_ErrorCode::VIDEO_PROCESSING_ERROR_PROCESS_FAILED));

    ret = converter_->Init();
    EXPECT_EQ(ret, static_cast<int32_t>(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));

    ret = converter_->Stop();
    EXPECT_NE(ret, static_cast<int32_t>(VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS));

    DTEST_LOG << "AVColorspaceConverterTest Stop_Test end" << std::endl;
}
#endif

/**
 * @tc.name: Start_Test
 * @tc.desc: Test start functionality with various scenarios
 * @tc.type: FUNC
 */
HWTEST_F(AVColorspaceConverterTest, Start_Test, TestSize.Level1)
{
    DTEST_LOG << "AVColorspaceConverterTest Start_Test_001 begin" << std::endl;

    auto ret = converter_->Start();
    EXPECT_EQ(ret, NULL_POINTER_ERROR);
    
    DTEST_LOG << "AVColorspaceConverterTest Start_Test end" << std::endl;
}
}  // namespace DistributedCollab
}  // namespace OHOS