/*
* Copyright (c) 2023-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_ENCODER_FILTER_H
#define OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_ENCODER_FILTER_H

#include "avcodec_common.h"
#include "buffer/avallocator.h"
#include "buffer/avbuffer.h"
#include "buffer/avbuffer_queue.h"
#include "buffer/avbuffer_queue_consumer.h"
#include "buffer/avbuffer_queue_producer.h"
#include "common/status.h"
#include "filter/filter.h"
#include "meta/meta.h"
#include "surface.h"
#include <cstring>
#include "surface_encoder_adapter.h"

namespace OHOS {
namespace DistributedCollab {
class SurfaceEncoderFilter : public Media::Pipeline::Filter,
    public std::enable_shared_from_this<SurfaceEncoderFilter> {
public:
    explicit SurfaceEncoderFilter(std::string name, Media::Pipeline::FilterType type);
    ~SurfaceEncoderFilter() override;
    Media::Status SetCodecFormat(const std::shared_ptr<Media::Meta>& format);
    void Init(const std::shared_ptr<Media::Pipeline::EventReceiver>& receiver,
        const std::shared_ptr<Media::Pipeline::FilterCallback>& callback) override;
    Media::Status Configure(const std::shared_ptr<Media::Meta>& parameter);
    Media::Status SetInputSurface(sptr<Surface> surface);
    Media::Status SetTransCoderMode();
    sptr<Surface> GetInputSurface();
    Media::Status DoPrepare() override;
    Media::Status DoStart() override;
    Media::Status DoPause() override;
    Media::Status DoResume() override;
    Media::Status Reset();
    Media::Status DoStop() override;
    Media::Status DoFlush() override;
    Media::Status DoRelease() override;
    Media::Status NotifyEos(int64_t pts);
    void SetParameter(const std::shared_ptr<Media::Meta>& parameter) override;
    void GetParameter(std::shared_ptr<Media::Meta>& parameter) override;
    Media::Status LinkNext(const std::shared_ptr<Media::Pipeline::Filter>& nextFilter,
        Media::Pipeline::StreamType outType) override;
    Media::Status UpdateNext(const std::shared_ptr<Media::Pipeline::Filter>& nextFilter,
        Media::Pipeline::StreamType outType) override;
    Media::Status UnLinkNext(const std::shared_ptr<Media::Pipeline::Filter>& nextFilter,
        Media::Pipeline::StreamType outType) override;
    void OnLinkedResult(const sptr<Media::AVBufferQueueProducer>& outputBufferQueue,
        std::shared_ptr<Media::Meta>& meta);
    void OnUpdatedResult(std::shared_ptr<Media::Meta>& meta);
    void OnUnlinkedResult(std::shared_ptr<Media::Meta>& meta);
    void SetCallingInfo(int32_t appUid, int32_t appPid, const std::string& bundleName, uint64_t instanceId);
    void OnError(MediaAVCodec::AVCodecErrorType errorType, int32_t errorCode);
    void OnReportKeyFramePts(std::string KeyFramePts);

protected:
    Media::Status OnLinked(Media::Pipeline::StreamType inType, const std::shared_ptr<Media::Meta>& meta,
        const std::shared_ptr<Media::Pipeline::FilterLinkCallback>& callback) override;
    Media::Status OnUpdated(Media::Pipeline::StreamType inType, const std::shared_ptr<Media::Meta>& meta,
        const std::shared_ptr<Media::Pipeline::FilterLinkCallback>& callback) override;
    Media::Status OnUnLinked(Media::Pipeline::StreamType inType,
        const std::shared_ptr<Media::Pipeline::FilterLinkCallback>& callback) override;

private:
    std::string name_;

    std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver_ = nullptr;
    std::shared_ptr<Media::Pipeline::FilterCallback> filterCallback_ = nullptr;

    std::shared_ptr<Media::Pipeline::FilterLinkCallback> onLinkedResultCallback_;

    std::shared_ptr<SurfaceEncoderAdapter> codecAdapter_ = nullptr;

    std::string codecMimeType_;
    std::shared_ptr<Media::Meta> configureParameter_ = nullptr;

    std::shared_ptr<Media::Pipeline::Filter> nextFilter_ = nullptr;

    std::atomic<bool> isUpdateCodecNeeded_ = false;
    sptr<Surface> surface_ { nullptr };
    std::string bundleName_;
    uint64_t instanceId_ { 0 };
    int32_t appUid_ { 0 };
    int32_t appPid_ { 0 };
};
} // namespace DistributedCollab
} // namespace OHOS
#endif // OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_ENCODER_FILTER_H
