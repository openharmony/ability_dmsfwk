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
#ifndef OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_DECODER_FILTER_H
#define OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_DECODER_FILTER_H

#include <cstring>
#include "filter/filter.h"
#include "surface.h"
#include "meta/meta.h"
#include "meta/format.h"
#include "buffer/avbuffer.h"
#include "buffer/avbuffer_queue.h"
#include "buffer/avbuffer_queue_producer.h"
#include "common/status.h"
#include "surface_decoder_adapter.h"

namespace OHOS {
namespace DistributedCollab {
class SurfaceDecoderFilter : public Media::Pipeline::Filter,
    public std::enable_shared_from_this<SurfaceDecoderFilter> {
public:
    explicit SurfaceDecoderFilter(const std::string& name, Media::Pipeline::FilterType type);
    ~SurfaceDecoderFilter() override;

    void Init(const std::shared_ptr<Media::Pipeline::EventReceiver> &receiver,
        const std::shared_ptr<Media::Pipeline::FilterCallback> &callback) override;
    Media::Status Configure(const std::shared_ptr<Media::Meta> &parameter);
    Media::Status SetOutputSurface(const sptr<Surface>& surface);
    Media::Status DoPrepare() override;
    Media::Status DoStart() override;
    Media::Status DoPause() override;
    Media::Status DoResume() override;
    Media::Status DoStop() override;
    Media::Status DoFlush() override;
    Media::Status DoRelease() override;
    void SetParameter(const std::shared_ptr<Media::Meta>& parameter) override;
    void GetParameter(std::shared_ptr<Media::Meta>& parameter) override;
    Media::Status LinkNext(const std::shared_ptr<Media::Pipeline::Filter> &nextFilter,
        Media::Pipeline::StreamType outType) override;
    Media::Status UpdateNext(const std::shared_ptr<Media::Pipeline::Filter> &nextFilter,
        Media::Pipeline::StreamType outType) override;
    Media::Status UnLinkNext(const std::shared_ptr<Media::Pipeline::Filter> &nextFilter,
        Media::Pipeline::StreamType outType) override;
    Media::Status OnLinked(Media::Pipeline::StreamType inType, const std::shared_ptr<Media::Meta> &meta,
        const std::shared_ptr<Media::Pipeline::FilterLinkCallback> &callback) override;
    Media::Status OnUpdated(Media::Pipeline::StreamType inType, const std::shared_ptr<Media::Meta> &meta,
        const std::shared_ptr<Media::Pipeline::FilterLinkCallback> &callback) override;
    Media::Status OnUnLinked(Media::Pipeline::StreamType inType,
        const std::shared_ptr<Media::Pipeline::FilterLinkCallback>& callback) override;
    void OnLinkedResult(const sptr<Media::AVBufferQueueProducer> &outputBufferQueue,
        std::shared_ptr<Media::Meta> &meta);
    void OnUpdatedResult(std::shared_ptr<Media::Meta> &meta);
    void OnUnlinkedResult(std::shared_ptr<Media::Meta> &meta);

private:
    std::string name_;
    std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver_ { nullptr };
    std::shared_ptr<Media::Pipeline::FilterCallback> filterCallback_ { nullptr };
    std::shared_ptr<SurfaceDecoderAdapter> codecAdpater_ { nullptr };
    std::shared_ptr<Media::Pipeline::FilterLinkCallback> onLinkedResultCallback_ { nullptr };
    std::string codecMimeType_;
    std::shared_ptr<Media::Meta> configureParameter_ { nullptr };
    MediaAVCodec::Format configFormat_{};

    std::shared_ptr<Media::Pipeline::Filter> nextFilter_ { nullptr };

    sptr<Surface> outputSurface_ { nullptr };

    std::shared_ptr<Media::Meta> meta_ { nullptr };
};
} // namespace Media
} // namespace OHOS
#endif // FILTERS_SURFACE_DECODER_FILTER_H
