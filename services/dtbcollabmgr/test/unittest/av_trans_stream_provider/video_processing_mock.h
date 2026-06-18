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
#ifndef OHOS_AV_TRANS_STREAM_VIDEO_PROCESSING_MOCK_TEST_H
#define OHOS_AV_TRANS_STREAM_VIDEO_PROCESSING_MOCK_TEST_H

#include <gmock/gmock.h>
#include <cstdint>
#include "video_processing_types.h"
#include "native_window.h"
#include "surface.h"

namespace OHOS {
namespace DistributedCollab {

class VideoProcessingMock {
public:
    VideoProcessingMock();
    ~VideoProcessingMock();

    static VideoProcessingMock& GetMock();

    MOCK_METHOD(VideoProcessing_ErrorCode, InitializeEnvironment, ());
    MOCK_METHOD(VideoProcessing_ErrorCode, DeinitializeEnvironment, ());
    MOCK_METHOD(VideoProcessing_ErrorCode, Create, (OH_VideoProcessing** videoProcessor, int32_t type));
    MOCK_METHOD(VideoProcessing_ErrorCode, Destroy, (OH_VideoProcessing* videoProcessor));
    MOCK_METHOD(VideoProcessing_ErrorCode, RegisterCallback,
        (OH_VideoProcessing* videoProcessor, const VideoProcessing_Callback* callback, void* userData));
    MOCK_METHOD(VideoProcessing_ErrorCode, SetSurface,
        (OH_VideoProcessing* videoProcessor, const OHNativeWindow* window));
    MOCK_METHOD(VideoProcessing_ErrorCode, GetSurface,
        (OH_VideoProcessing* videoProcessor, OHNativeWindow** window));
    MOCK_METHOD(VideoProcessing_ErrorCode, Start, (OH_VideoProcessing* videoProcessor));
    MOCK_METHOD(VideoProcessing_ErrorCode, Stop, (OH_VideoProcessing* videoProcessor));
    MOCK_METHOD(VideoProcessing_ErrorCode, CallbackCreate, (VideoProcessing_Callback** callback));
    MOCK_METHOD(VideoProcessing_ErrorCode, CallbackDestroy, (VideoProcessing_Callback* callback));
    MOCK_METHOD(VideoProcessing_ErrorCode, CallbackBindOnError,
        (VideoProcessing_Callback* callback,
         void(*onError)(OH_VideoProcessing*, VideoProcessing_ErrorCode, void*)));
    MOCK_METHOD(VideoProcessing_ErrorCode, CallbackBindOnState,
        (VideoProcessing_Callback* callback,
         void(*onState)(OH_VideoProcessing*, VideoProcessing_State, void*)));
    MOCK_METHOD(VideoProcessing_ErrorCode, CallbackBindOnNewOutputBuffer,
        (VideoProcessing_Callback* callback,
         void(*onNewOutputBuffer)(OH_VideoProcessing*, uint32_t, void*)));
    MOCK_METHOD(void, DestroyNativeWindow, (OHNativeWindow* window));
    MOCK_METHOD(OHNativeWindow*, CreateNativeWindow, (void* pSurface));
    MOCK_METHOD(int32_t, NativeWindowHandleOpt, (OHNativeWindow* window, int code));
    MOCK_METHOD(int32_t, SetColorSpace, (OHNativeWindow* window, OH_NativeBuffer_ColorSpace colorSpace));

private:
    static VideoProcessingMock* gMock;
};

extern "C" {
    VideoProcessing_ErrorCode OH_VideoProcessing_InitializeEnvironment(void);
    VideoProcessing_ErrorCode OH_VideoProcessing_DeinitializeEnvironment(void);
    VideoProcessing_ErrorCode OH_VideoProcessing_Create(OH_VideoProcessing** videoProcessor, int32_t type);
    VideoProcessing_ErrorCode OH_VideoProcessing_Destroy(OH_VideoProcessing* videoProcessor);
    VideoProcessing_ErrorCode OH_VideoProcessing_RegisterCallback(
        OH_VideoProcessing* videoProcessor, const VideoProcessing_Callback* callback, void* userData);
    VideoProcessing_ErrorCode OH_VideoProcessing_SetSurface(
        OH_VideoProcessing* videoProcessor, const OHNativeWindow* window);
    VideoProcessing_ErrorCode OH_VideoProcessing_GetSurface(
        OH_VideoProcessing* videoProcessor, OHNativeWindow** window);
    VideoProcessing_ErrorCode OH_VideoProcessing_Start(OH_VideoProcessing* videoProcessor);
    VideoProcessing_ErrorCode OH_VideoProcessing_Stop(OH_VideoProcessing* videoProcessor);
    VideoProcessing_ErrorCode OH_VideoProcessingCallback_Create(VideoProcessing_Callback** callback);
    VideoProcessing_ErrorCode OH_VideoProcessingCallback_Destroy(VideoProcessing_Callback* callback);
    VideoProcessing_ErrorCode OH_VideoProcessingCallback_BindOnError(
        VideoProcessing_Callback* callback,
        void(*onError)(OH_VideoProcessing*, VideoProcessing_ErrorCode, void*));
    VideoProcessing_ErrorCode OH_VideoProcessingCallback_BindOnState(
        VideoProcessing_Callback* callback,
        void(*onState)(OH_VideoProcessing*, VideoProcessing_State, void*));
    VideoProcessing_ErrorCode OH_VideoProcessingCallback_BindOnNewOutputBuffer(
        VideoProcessing_Callback* callback,
        void(*onNewOutputBuffer)(OH_VideoProcessing*, uint32_t, void*));
    void OH_NativeWindow_DestroyNativeWindow(OHNativeWindow* window);
    OHNativeWindow* OH_NativeWindow_CreateNativeWindow(void* pSurface);
    int32_t OH_NativeWindow_NativeWindowHandleOpt(OHNativeWindow* window, int code, ...);
    int32_t OH_NativeWindow_SetColorSpace(OHNativeWindow* window, OH_NativeBuffer_ColorSpace colorSpace);
}
}  // namespace DistributedCollab
}  // namespace OHOS
#endif
