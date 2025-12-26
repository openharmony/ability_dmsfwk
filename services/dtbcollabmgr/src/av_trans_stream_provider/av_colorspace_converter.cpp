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

#include "av_colorspace_converter.h"
#include <string>
#include "dtbcollabmgr_log.h"
#include "video_processing.h"
#include "native_window.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
    static const std::string TAG = "AVColorSpaceConverter";
}

AVColorspaceConverter::AVColorspaceConverter()
{
    HILOGI("AVColorspaceConverter create");
    OH_VideoProcessing_InitializeEnvironment();
}

AVColorspaceConverter::~AVColorspaceConverter()
{
    HILOGI("AVColorspaceConverter destroy");
    if (GetProcesser() == nullptr) {
        return;
    }
    if (inWindow_ != nullptr) {
        DestoryNativeWindow(inWindow_);
        inWindow_ = nullptr;
    }
    if (outWindow_ != nullptr) {
        DestoryNativeWindow(outWindow_);
        outWindow_ = nullptr;
    }
    (void)OH_VideoProcessingCallback_Destroy(callback_);
    callback_ = nullptr;
    {
        std::lock_guard<std::mutex> lock(processorMutex_);
        (void)OH_VideoProcessing_Destroy(videoProcessor_);
        videoProcessor_ = nullptr;
    }
    OH_VideoProcessing_DeinitializeEnvironment();
}

int32_t AVColorspaceConverter::Init()
{
    HILOGI("init called");
    VideoProcessing_ErrorCode ret = VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS;
    {
        std::lock_guard<std::mutex> lock(processorMutex_);
        ret = OH_VideoProcessing_Create(&videoProcessor_,
            VIDEO_PROCESSING_TYPE_COLOR_SPACE_CONVERSION);
        if (ret != VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS) {
            HILOGE("create color space converter failed");
            return static_cast<int32_t>(ret);
        }
    }
    ret = RegisterCallback();
    return static_cast<int32_t>(ret);
}

VideoProcessing_ErrorCode AVColorspaceConverter::RegisterCallback()
{
    HILOGI("register callback to video processer");
    VideoProcessing_ErrorCode ret = OH_VideoProcessingCallback_Create(&callback_);
    if (ret != VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS) {
        HILOGE("create callback failed, err=%{public}d", static_cast<int32_t>(ret));
        callback_ = nullptr;
        return ret;
    }
    OH_VideoProcessingCallback_BindOnError(callback_, &AVColorspaceConverter::OnError);
    OH_VideoProcessingCallback_BindOnState(callback_, &AVColorspaceConverter::OnState);
    {
        std::lock_guard<std::mutex> lock(processorMutex_);
        ret = OH_VideoProcessing_RegisterCallback(videoProcessor_, callback_, this);
        if (ret != VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS) {
            HILOGE("register callback failed, err=%{public}d", static_cast<int32_t>(ret));
        }
    }
    return ret;
}

OH_VideoProcessing* AVColorspaceConverter::GetProcesser()
{
    std::lock_guard<std::mutex> lock(processorMutex_);
    return videoProcessor_;
}

// static for callback, using this for userData
void AVColorspaceConverter::OnError(OH_VideoProcessing* videoProcessor,
    VideoProcessing_ErrorCode error, void* userData)
{
    AVColorspaceConverter* instance = static_cast<AVColorspaceConverter*>(userData);
    if (instance) {
        instance->HandleError(videoProcessor, error);
    }
}

void AVColorspaceConverter::OnState(OH_VideoProcessing* videoProcessor,
    VideoProcessing_State state, void* userData)
{
    AVColorspaceConverter* instance = static_cast<AVColorspaceConverter*>(userData);
    if (instance) {
        instance->HandleState(videoProcessor, state);
    }
}

void AVColorspaceConverter::OnNewOutputBuffer(OH_VideoProcessing* videoProcessor,
    uint32_t index, void* userData)
{
    AVColorspaceConverter* instance = static_cast<AVColorspaceConverter*>(userData);
    if (instance) {
        instance->HandleNewOutputBuffer(videoProcessor, index);
    }
}

void AVColorspaceConverter::HandleError(OH_VideoProcessing* videoProcessor,
    VideoProcessing_ErrorCode error)
{
    HILOGE("start to handle error, %{public}d", static_cast<int32_t>(error));
    (void)Stop();
}

void AVColorspaceConverter::HandleState(OH_VideoProcessing* videoProcessor, VideoProcessing_State state)
{
    HILOGI("change state %{public}d", static_cast<int32_t>(state));
}

void AVColorspaceConverter::HandleNewOutputBuffer(OH_VideoProcessing* videoProcessor, uint32_t index)
{
    HILOGI("start to process %{public}u buffer", index);
}

sptr<Surface> AVColorspaceConverter::GetSurface()
{
    HILOGI("start get surface");
    {
        std::lock_guard<std::mutex> lock(processorMutex_);
        VideoProcessing_ErrorCode ret = OH_VideoProcessing_GetSurface(videoProcessor_, &inWindow_);
        if (ret != VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS ||
            inWindow_ == nullptr || inWindow_->surface == nullptr) {
            HILOGE("get surface failed");
            return nullptr;
        }
    }
    surface_ = inWindow_->surface;
    return surface_;
}

int32_t AVColorspaceConverter::SetSurface(const sptr<Surface>& surface)
{
    if (surface == nullptr) {
        HILOGE("empty surface");
        return EMPTY_SURFACE;
    }
    surface_ = surface;
    OHNativeWindow* nativeWindow = OH_NativeWindow_CreateNativeWindow(&surface_);
    if (nativeWindow == nullptr) {
        HILOGE("create native window failed");
        return CREATE_NATIVE_WINDOW_FAILED;
    }
    outWindow_ = nativeWindow;
    return ERR_OK;
}

int32_t AVColorspaceConverter::Configure(OH_NativeBuffer_ColorSpace colorSpace)
{
    HILOGI("configure output color space");
    if (colorSpace == OH_NativeBuffer_ColorSpace::OH_COLORSPACE_NONE) {
        HILOGE("invalid color space");
        return INVALID_COLORSPACE;
    }
    if (colorSpace != OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_LIMIT) {
        HILOGE("not support colorspace %{public}d", static_cast<int32_t>(colorSpace));
        return INVALID_COLORSPACE;
    }
    outputColorSpace_ = colorSpace;
    OH_NativeBuffer_Format format = OH_NativeBuffer_Format::NATIVEBUFFER_PIXEL_FMT_YCBCR_420_SP;
    int32_t ret = OH_NativeWindow_NativeWindowHandleOpt(outWindow_, NativeWindowOperation::SET_FORMAT, format);
    if (ret != GSError::GSERROR_OK) {
        HILOGE("set format %{public}d failed, ret=%{public}d",
            static_cast<int32_t>(OH_NativeBuffer_Format::NATIVEBUFFER_PIXEL_FMT_YCBCR_420_SP), ret);
        return ret;
    }
    ret = OH_NativeWindow_SetColorSpace(outWindow_, outputColorSpace_);
    if (ret != GSError::GSERROR_OK) {
        HILOGE("set color %{public}d failed, ret=%{public}d",
            static_cast<int32_t>(OH_NativeBuffer_ColorSpace::OH_COLORSPACE_BT709_LIMIT), ret);
        return ret;
    }
    std::lock_guard<std::mutex> lock(processorMutex_);
    VideoProcessing_ErrorCode setRet = OH_VideoProcessing_SetSurface(videoProcessor_, outWindow_);
    if (setRet != VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS) {
        HILOGE("set surface failed, err=%{public}d", static_cast<int32_t>(setRet));
    }
    return static_cast<int32_t>(setRet);
}

int32_t AVColorspaceConverter::Start()
{
    HILOGI("start convert colorspace");
    std::lock_guard<std::mutex> lock(processorMutex_);
    if (videoProcessor_ == nullptr) {
        HILOGE("videoProcessor is null");
        return NULL_POINTER_ERROR;
    }
    VideoProcessing_ErrorCode ret = OH_VideoProcessing_Start(videoProcessor_);
    if (ret != VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS) {
        HILOGE("start convert failed, err=%{public}d", static_cast<int32_t>(ret));
    }
    return static_cast<int32_t>(ret);
}

int32_t AVColorspaceConverter::Stop()
{
    HILOGI("stop convert colorspace");
    std::lock_guard<std::mutex> lock(processorMutex_);
    if (videoProcessor_ == nullptr) {
        HILOGE("videoProcessor is null");
        return NULL_POINTER_ERROR;
    }
    VideoProcessing_ErrorCode ret = OH_VideoProcessing_Stop(videoProcessor_);
    if (ret != VideoProcessing_ErrorCode::VIDEO_PROCESSING_SUCCESS) {
        HILOGE("stop convert failed, err=%{public}d", static_cast<int32_t>(ret));
    }
    return static_cast<int32_t>(ret);
}
} // namespace DistributedCollab
} // namespace OHOS
