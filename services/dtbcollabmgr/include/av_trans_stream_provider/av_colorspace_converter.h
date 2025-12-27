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
#ifndef OHOS_AV_TRANS_STREAM_AV_COLORSPACE_CONVERTER_H
#define OHOS_AV_TRANS_STREAM_AV_COLORSPACE_CONVERTER_H

#include <atomic>

#include "native_buffer.h"
#include "surface.h"
#include "video_processing_types.h"

namespace OHOS {
namespace DistributedCollab {
class AVColorspaceConverter {
public:
    AVColorspaceConverter();
    ~AVColorspaceConverter();

    int32_t Init();
    OH_VideoProcessing* GetProcesser();
    sptr<Surface> GetSurface();
    int32_t SetSurface(const sptr<Surface>& surface);
    int32_t Configure(OH_NativeBuffer_ColorSpace colorSpace);
    int32_t Start();
    int32_t Stop();

private:
    // static for c callback
    static void OnError(OH_VideoProcessing* videoProcessor, VideoProcessing_ErrorCode error, void* userData);
    static void OnState(OH_VideoProcessing* videoProcessor, VideoProcessing_State state, void* userData);
    static void OnNewOutputBuffer(OH_VideoProcessing* videoProcessor, uint32_t index, void* userData);

    // member func for handle
    void HandleError(OH_VideoProcessing* videoProcessor, VideoProcessing_ErrorCode error);
    void HandleState(OH_VideoProcessing* videoProcessor, VideoProcessing_State state);
    void HandleNewOutputBuffer(OH_VideoProcessing* videoProcessor, uint32_t index);

    VideoProcessing_ErrorCode RegisterCallback();

private:
    OH_VideoProcessing* videoProcessor_ = nullptr;
    VideoProcessing_Callback* callback_ = nullptr;
    OHNativeWindow* inWindow_ = nullptr;
    OHNativeWindow* outWindow_ = nullptr;
    sptr<Surface> surface_ = nullptr;
    std::mutex processorMutex_;
    OH_NativeBuffer_ColorSpace outputColorSpace_ = OH_NativeBuffer_ColorSpace::OH_COLORSPACE_NONE;
};
} // namespace DistributedCollab
} // namespace OHOS
#endif