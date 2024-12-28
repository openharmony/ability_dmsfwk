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

#ifndef OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_DECODER_ADAPTER_H
#define OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_DECODER_ADAPTER_H

#include "avcodec_common.h"
#include "avcodec_video_decoder.h"
#include "buffer/avbuffer.h"
#include "buffer/avbuffer_queue.h"
#include "buffer/avbuffer_queue_consumer.h"
#include "buffer/avbuffer_queue_producer.h"
#include "common/status.h"
#include "meta/meta.h"
#include "osal/task/condition_variable.h"
#include "osal/task/task.h"
#include "surface.h"
#include <cstring>
#include <shared_mutex>

namespace OHOS {
namespace DistributedCollab {
class DecoderAdapterCallback {
public:
    virtual ~DecoderAdapterCallback() = default;
    virtual void OnError(MediaAVCodec::AVCodecErrorType type, int32_t errorCode) = 0;
    virtual void OnOutputFormatChanged(const std::shared_ptr<Media::Meta>& format) = 0;
    virtual void OnBufferEos(int64_t pts, int64_t frameNum) = 0;
};

class SurfaceDecoderAdapter : public std::enable_shared_from_this<SurfaceDecoderAdapter> {
public:
    explicit SurfaceDecoderAdapter();
    ~SurfaceDecoderAdapter();

public:
    Media::Status Init(const std::string& mime);
    Media::Status Configure(const MediaAVCodec::Format& format);
    sptr<Media::AVBufferQueueProducer> GetInputBufferQueue();
    Media::Status SetOutputSurface(const sptr<Surface>& surface);
    Media::Status SetDecoderAdapterCallback(const std::shared_ptr<DecoderAdapterCallback>& decoderAdapterCallback);
    Media::Status Start();
    Media::Status Stop();
    Media::Status Pause();
    Media::Status Resume();
    Media::Status Flush();
    Media::Status Release();
    Media::Status SetParameter(const MediaAVCodec::Format& format);
    void OnInputBufferAvailable(uint32_t index, std::shared_ptr<Media::AVBuffer> buffer);
    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<Media::AVBuffer> buffer);
    void AcquireAvailableInputBuffer();

    std::shared_ptr<DecoderAdapterCallback> decoderAdapterCallback_;
    std::atomic<int64_t> frameNum_ = 0;
    std::atomic<int64_t> lastBufferPts_ = INT64_MIN;

private:
    void ReleaseBuffer();

    std::shared_ptr<MediaAVCodec::AVCodecVideoDecoder> codecServer_;
    std::shared_ptr<Media::AVBufferQueue> inputBufferQueue_;
    sptr<Media::AVBufferQueueProducer> inputBufferQueueProducer_;
    sptr<Media::AVBufferQueueConsumer> inputBufferQueueConsumer_;

    std::shared_ptr<Media::Task> releaseBufferTask_ { nullptr };
    std::mutex releaseBufferMutex_;
    std::condition_variable releaseBufferCondition_;
    std::vector<uint32_t> indexs_;
    std::vector<uint32_t> dropIndexs_;
    std::atomic<bool> isThreadExit_ = true;
};
} // namespace MediaAVCodec
} // namespace OHOS
#endif // FILTERS_SURFACE_ENCODER_ADAPTER_H
