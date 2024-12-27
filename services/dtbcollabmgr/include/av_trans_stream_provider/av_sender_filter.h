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
#ifndef OHOS_AV_TRANS_STREAM_AV_SENDER_FILTER_H
#define OHOS_AV_TRANS_STREAM_AV_SENDER_FILTER_H

#include "buffer/avbuffer_queue.h"
#include "buffer/avbuffer_queue_define.h"
#include "channel_common_definition.h"
#include "common/status.h"
#include "filter/filter.h"
#include "meta/meta.h"
#include "refbase.h"
#include <memory>
#include <string>
#include "pixel_map.h"
#include <queue>
#include "event_handler.h"
#include <atomic>
#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
#include "ichannel_listener.h"
#endif

namespace OHOS {
namespace DistributedCollab {
class AVSenderFilter : public Media::Pipeline::Filter, public std::enable_shared_from_this<AVSenderFilter> {
public:
    explicit AVSenderFilter(std::string name, Media::Pipeline::FilterType type);
    ~AVSenderFilter();
    void Init(const std::shared_ptr<Media::Pipeline::EventReceiver>& receiver,
        const std::shared_ptr<Media::Pipeline::FilterCallback>& callback) override;
    Media::Status DoPrepare() override;
    Media::Status DoStart() override;
    Media::Status DoPause() override;
    Media::Status DoResume() override;
    Media::Status DoStop() override;
    Media::Status DoFlush() override;
    Media::Status DoRelease() override;
    void SetParameter(const std::shared_ptr<Media::Meta>& parameter) override;
    void GetParameter(std::shared_ptr<Media::Meta>& parameter) override;
    Media::Status LinkNext(const std::shared_ptr<Media::Pipeline::Filter>& nextFilter,
        Media::Pipeline::StreamType outType) override;
    Media::Status UpdateNext(const std::shared_ptr<Media::Pipeline::Filter>& nextFilter,
        Media::Pipeline::StreamType outType) override;
    Media::Status UnLinkNext(const std::shared_ptr<Media::Pipeline::Filter>& nextFilter,
        Media::Pipeline::StreamType outType) override;
    Media::Status OnLinked(Media::Pipeline::StreamType inType, const std::shared_ptr<Media::Meta>& meta,
        const std::shared_ptr<Media::Pipeline::FilterLinkCallback>& callback) override;
    Media::Status OnUpdated(Media::Pipeline::StreamType inType, const std::shared_ptr<Media::Meta>& meta,
        const std::shared_ptr<Media::Pipeline::FilterLinkCallback>& callback) override;
    Media::Status OnUnLinked(Media::Pipeline::StreamType inType,
        const std::shared_ptr<Media::Pipeline::FilterLinkCallback>& callback) override;
    void SetTransChannel(int32_t channelId, const ChannelDataType type);
    int32_t SendPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap);
    int32_t SetSurfaceParam(const SurfaceParam& param);
#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
    void SetChannelListener(const std::shared_ptr<IChannelListener>& listener);
    void WriteFile(const std::shared_ptr<AVTransDataBuffer>& data);
    int64_t GetEncoderTimeStamp();
#endif

public:
    static constexpr uint32_t version = 0;
    static constexpr int32_t transType = 0;

private:
    static constexpr uint32_t MAX_BUFFER_COUNT = 10;

private:
    void OnBufferAvailable(const std::shared_ptr<Media::AVBuffer>& buffer);
    std::shared_ptr<AVTransStreamData> PackStreamDataForAVBuffer(const std::shared_ptr<Media::AVBuffer>& buffer,
        const std::shared_ptr<AVTransDataBuffer>& dataBuffer);
    int32_t SendStreamData(const std::shared_ptr<AVTransStreamData>& streamData);
    int32_t SendStreamDataByStream(const std::shared_ptr<AVTransStreamData>& streamData);
    int32_t SendStreamDataByBytes(const std::shared_ptr<AVTransStreamData>& streamData);
    int32_t PackPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap,
        std::shared_ptr<AVTransDataBuffer>& buffer);
    std::shared_ptr<AVTransStreamData> PackStreamDataForPixelMap(const std::shared_ptr<AVTransDataBuffer>& dataBuffer);
    std::shared_ptr<AVTransStreamData> PackStreamDataForSurfaceParam(const SurfaceParam& param);
    void Process();
    int32_t WriteDataToBuffer(std::shared_ptr<AVTransDataBuffer>& buffer,
        cJSON* headerJson, char* headerStr, const std::shared_ptr<AVTransStreamData>& streamData);

private:
    class BqConsumerProxy : public Media::IConsumerListener {
    public:
        BqConsumerProxy(std::shared_ptr<AVSenderFilter> filter)
            : filter_(filter) {};
        virtual ~BqConsumerProxy() = default;
        void OnBufferAvailable() override;
        void ReleaseBuffer(const std::shared_ptr<Media::AVBuffer>& buffer);

    public:
        std::weak_ptr<AVSenderFilter> filter_;
        sptr<Media::AVBufferQueueProducer> producer_ = nullptr;
        sptr<Media::AVBufferQueueConsumer> consumer_ = nullptr;
        std::shared_ptr<Media::AVBufferQueue> bufferQ_ = nullptr;
    };

private:
    std::string name_;
    int32_t channelId_ = -1;
    ChannelDataType channelType_ = ChannelDataType::BYTES;
    std::atomic_int32_t lastIndex_ = 0;
    std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver_ = nullptr;
    std::shared_ptr<Media::Pipeline::FilterCallback> filterCallback_ = nullptr;
#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
    std::weak_ptr<IChannelListener> listener_;
#endif
    sptr<BqConsumerProxy> bufferQProxy_ = nullptr;
    std::shared_ptr<Media::Meta> meta_ = nullptr;

    std::mutex queueMutex_;
    std::queue<std::shared_ptr<AVTransStreamData>> sendDatas_;
    
    std::condition_variable cv_;
    std::atomic<bool> isRunning_ = false;
    std::thread processingThread_;
};

} // namespace DistributedCollab
} // namespace OHOS
#endif