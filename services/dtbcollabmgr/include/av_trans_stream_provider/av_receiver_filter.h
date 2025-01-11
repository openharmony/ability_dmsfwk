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
#ifndef OHOS_AV_TRANS_STREAM_AV_RECEIVER_FILTER_H
#define OHOS_AV_TRANS_STREAM_AV_RECEIVER_FILTER_H

#include "av_trans_stream_data.h"
#include "buffer/avbuffer_queue.h"
#include "buffer/avbuffer_queue_define.h"
#include "event_handler.h"
#include "common/status.h"
#include "filter/filter.h"
#include "ichannel_listener.h"
#include "meta/meta.h"
#include "refbase.h"
#include <memory>
#include <queue>
#include <string>
#include <vector>
#include "iengine_listener.h"
#include "pixel_map.h"

namespace OHOS {
namespace DistributedCollab {
class AVReceiverFilter : public Media::Pipeline::Filter, public std::enable_shared_from_this<AVReceiverFilter> {
public:
    explicit AVReceiverFilter(std::string name, Media::Pipeline::FilterType type);
    ~AVReceiverFilter();
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
    void OnLinkedResult(const sptr<Media::AVBufferQueueProducer>& outputBufferQueue,
        std::shared_ptr<Media::Meta>& meta);
    void OnUpdatedResult(std::shared_ptr<Media::Meta>& meta);
    void OnUnlinkedResult(std::shared_ptr<Media::Meta>& meta);
    void OnStream(const std::shared_ptr<AVTransStreamData>& stream);
    void OnBytes(const std::shared_ptr<AVTransDataBuffer>& buffer);
    void OnError(const int32_t errorCode);
    void SetChannelListener(int32_t channelId);
    void SetEngineListener(const std::shared_ptr<IEngineListener>& listener);
#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
    std::shared_ptr<IChannelListener> GetChannelListener();
#endif

private:
    void Process();
    void OnBufferAvailable();
    void AddStreamData(const std::shared_ptr<AVTransStreamData>& data);
    std::shared_ptr<AVTransStreamData> GetStreamData();
    int32_t RequestAndPushData(const std::shared_ptr<AVTransStreamData>& data);
    std::shared_ptr<AVTransStreamData> ReadStreamDataFromBuffer(uint8_t* dataHeader,
        uint32_t headerLen, size_t totalLen);
    std::shared_ptr<Media::PixelMap> GetPixelMap(const std::shared_ptr<AVTransStreamData>& data);
    void StartEvent();
    void DispatchProcessData(const std::shared_ptr<AVTransStreamData>& data);
    void ProcessPixelMap(const std::shared_ptr<AVTransStreamData>& data);
    void ProcessSurfaceParam(const std::shared_ptr<AVTransStreamData>& data);

private:
    class BqProducerProxy : public Media::IProducerListener {
    public:
        BqProducerProxy(std::shared_ptr<AVReceiverFilter> filter)
            : filter_(filter) {};
        virtual ~BqProducerProxy() = default;
        void OnBufferAvailable() override;
        sptr<IRemoteObject> AsObject() override;
        Media::Status RequestBuffer(std::shared_ptr<Media::AVBuffer>& outBuffer,
            const Media::AVBufferConfig& config);
        Media::Status PushBuffer(const std::shared_ptr<Media::AVBuffer>& inBuffer);
        Media::Status CancelBuffer(const std::shared_ptr<Media::AVBuffer>& inBuffer);

    public:
        std::weak_ptr<AVReceiverFilter> filter_;
        sptr<Media::AVBufferQueueProducer> producer_ = nullptr;
        std::shared_ptr<Media::AVBuffer> buffer_ = nullptr;
    };

private:
    std::string name_;
    int32_t channelId_;
    std::shared_ptr<Media::Pipeline::EventReceiver> eventReceiver_ = nullptr;
    std::shared_ptr<Media::Pipeline::FilterCallback> filterCallback_ = nullptr;
    std::shared_ptr<Media::Pipeline::Filter> nextFilter_ = nullptr;
    sptr<BqProducerProxy> bufferQProxy_ = nullptr;
    std::shared_ptr<Media::Meta> meta_ = nullptr;
    int64_t lastIndex_ = -1;

    struct CompareAVTransStreamData {
        bool operator()(const std::shared_ptr<AVTransStreamData>& a,
            const std::shared_ptr<AVTransStreamData>& b) const
        {
            return a->GetStreamDataExt().index_ > b->GetStreamDataExt().index_;
        }
    };
    std::priority_queue<std::shared_ptr<AVTransStreamData>,
        std::vector<std::shared_ptr<AVTransStreamData>>,
        CompareAVTransStreamData>
        dataQueue_;

    std::mutex channelMutex_;
    std::vector<std::shared_ptr<IChannelListener>> listeners_;

    std::mutex queueMutex_;
    std::condition_variable cv_;
    std::atomic<bool> isRunning_ = false;
    std::atomic<int> availableBuffers_ = 0;
    std::thread processingThread_;

    std::mutex eventMutex_;
    std::thread eventThread_;
    std::shared_ptr<AppExecFwk::EventHandler> eventHandler_;
    std::condition_variable eventCon_;

    std::mutex listenerMutex_;
    std::vector<std::weak_ptr<IEngineListener>> engineListeners_;
};

} // namespace DistributedCollab
} // namespace OHOS
#endif