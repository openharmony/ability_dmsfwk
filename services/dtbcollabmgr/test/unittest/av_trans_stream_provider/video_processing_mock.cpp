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
#include "video_processing_mock.h"

namespace OHOS {
namespace DistributedCollab {

VideoProcessingMock* VideoProcessingMock::gMock;

VideoProcessingMock::VideoProcessingMock()
{
    gMock = this;
}

VideoProcessingMock::~VideoProcessingMock()
{
    gMock = nullptr;
}

VideoProcessingMock& VideoProcessingMock::GetMock()
{
    return *gMock;
}

extern "C" {
    VideoProcessing_ErrorCode OH_VideoProcessing_InitializeEnvironment(void)
    {
        return VideoProcessingMock::GetMock().InitializeEnvironment();
    }

    VideoProcessing_ErrorCode OH_VideoProcessing_DeinitializeEnvironment(void)
    {
        return VideoProcessingMock::GetMock().DeinitializeEnvironment();
    }

    VideoProcessing_ErrorCode OH_VideoProcessing_Create(OH_VideoProcessing** videoProcessor, int32_t type)
    {
        return VideoProcessingMock::GetMock().Create(videoProcessor, type);
    }

    VideoProcessing_ErrorCode OH_VideoProcessing_Destroy(OH_VideoProcessing* videoProcessor)
    {
        return VideoProcessingMock::GetMock().Destroy(videoProcessor);
    }

    VideoProcessing_ErrorCode OH_VideoProcessing_RegisterCallback(
        OH_VideoProcessing* videoProcessor, const VideoProcessing_Callback* callback, void* userData)
    {
        return VideoProcessingMock::GetMock().RegisterCallback(videoProcessor, callback, userData);
    }

    VideoProcessing_ErrorCode OH_VideoProcessing_SetSurface(
        OH_VideoProcessing* videoProcessor, const OHNativeWindow* window)
    {
        return VideoProcessingMock::GetMock().SetSurface(videoProcessor, window);
    }

    VideoProcessing_ErrorCode OH_VideoProcessing_GetSurface(
        OH_VideoProcessing* videoProcessor, OHNativeWindow** window)
    {
        return VideoProcessingMock::GetMock().GetSurface(videoProcessor, window);
    }

    VideoProcessing_ErrorCode OH_VideoProcessing_Start(OH_VideoProcessing* videoProcessor)
    {
        return VideoProcessingMock::GetMock().Start(videoProcessor);
    }

    VideoProcessing_ErrorCode OH_VideoProcessing_Stop(OH_VideoProcessing* videoProcessor)
    {
        return VideoProcessingMock::GetMock().Stop(videoProcessor);
    }

    VideoProcessing_ErrorCode OH_VideoProcessingCallback_Create(VideoProcessing_Callback** callback)
    {
        return VideoProcessingMock::GetMock().CallbackCreate(callback);
    }

    VideoProcessing_ErrorCode OH_VideoProcessingCallback_Destroy(VideoProcessing_Callback* callback)
    {
        return VideoProcessingMock::GetMock().CallbackDestroy(callback);
    }

    VideoProcessing_ErrorCode OH_VideoProcessingCallback_BindOnError(
        VideoProcessing_Callback* callback,
        void(*onError)(OH_VideoProcessing*, VideoProcessing_ErrorCode, void*))
    {
        return VideoProcessingMock::GetMock().CallbackBindOnError(callback, onError);
    }

    VideoProcessing_ErrorCode OH_VideoProcessingCallback_BindOnState(
        VideoProcessing_Callback* callback,
        void(*onState)(OH_VideoProcessing*, VideoProcessing_State, void*))
    {
        return VideoProcessingMock::GetMock().CallbackBindOnState(callback, onState);
    }

    VideoProcessing_ErrorCode OH_VideoProcessingCallback_BindOnNewOutputBuffer(
        VideoProcessing_Callback* callback,
        void(*onNewOutputBuffer)(OH_VideoProcessing*, uint32_t, void*))
    {
        return VideoProcessingMock::GetMock().CallbackBindOnNewOutputBuffer(callback, onNewOutputBuffer);
    }

    void OH_NativeWindow_DestroyNativeWindow(OHNativeWindow* window)
    {
        VideoProcessingMock::GetMock().DestroyNativeWindow(window);
    }

    OHNativeWindow* OH_NativeWindow_CreateNativeWindow(void* pSurface)
    {
        return VideoProcessingMock::GetMock().CreateNativeWindow(pSurface);
    }

    int32_t OH_NativeWindow_NativeWindowHandleOpt(OHNativeWindow* window, int code, ...)
    {
        return VideoProcessingMock::GetMock().NativeWindowHandleOpt(window, code);
    }

    int32_t OH_NativeWindow_SetColorSpace(OHNativeWindow* window, OH_NativeBuffer_ColorSpace colorSpace)
    {
        return VideoProcessingMock::GetMock().SetColorSpace(window, colorSpace);
    }
}
}  // namespace DistributedCollab
}  // namespace OHOS
