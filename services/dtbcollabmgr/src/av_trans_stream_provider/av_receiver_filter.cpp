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
#include "av_receiver_filter.h"
#include "av_receiver_filter_listener.h"
#include "av_sender_filter.h"
#include "av_trans_data_buffer.h"
#include "channel_manager.h"
#include "dtbcollabmgr_log.h"
#include "filter/filter_factory.h"
#include "image_source.h"
#include "image_type.h"
#include "securec.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
    using Status = Media::Status;
    using EventReceiver = Media::Pipeline::EventReceiver;
    using FilterCallback = Media::Pipeline::FilterCallback;
    using Filter = Media::Pipeline::Filter;
    using StreamType = Media::Pipeline::StreamType;
    using AVBufferQueueProducer = Media::AVBufferQueueProducer;
    using AVBufferQueueConsumer = Media::AVBufferQueueConsumer;
    using AVBufferQueue = Media::AVBufferQueue;
    using AVBuffer = Media::AVBuffer;
    using FilterLinkCallback = Media::Pipeline::FilterLinkCallback;
    using Meta = Media::Meta;
    using FilterCallBackCommand = Media::Pipeline::FilterCallBackCommand;
    using FilterType = Media::Pipeline::FilterType;
    static const std::string TAG = "AVReceiverFilter";
    static constexpr int32_t decodePixelMapWidth = 256;
    static constexpr int32_t decodePixelMapHeight = 256;
    static constexpr int32_t requestBufferTimeout = 1000;
}

static Media::Pipeline::AutoRegisterFilter<AVReceiverFilter> g_registerAVReceiverFilter("builtin.dtbcollab.receiver",
    FilterType::FILTERTYPE_VENC,
    [](const std::string& name, const FilterType type) {
        return std::make_shared<AVReceiverFilter>(name, FilterType::FILTERTYPE_VENC);
    });

class AVReceiverFilterLinkCallback : public FilterLinkCallback {
public:
    explicit AVReceiverFilterLinkCallback(const std::shared_ptr<AVReceiverFilter>& filter)
        : filter_(filter)
    {
    }

    void OnLinkedResult(const sptr<AVBufferQueueProducer>& queue, std::shared_ptr<Meta>& meta) override
    {
        if (auto ptr = filter_.lock()) {
            ptr->OnLinkedResult(queue, meta);
        }
    }

    void OnUnlinkedResult(std::shared_ptr<Meta>& meta) override
    {
        if (auto ptr = filter_.lock()) {
            ptr->OnUnlinkedResult(meta);
        }
    }

    void OnUpdatedResult(std::shared_ptr<Meta>& meta) override
    {
        if (auto ptr = filter_.lock()) {
            ptr->OnUpdatedResult(meta);
        }
    }

private:
    std::weak_ptr<AVReceiverFilter> filter_;
};

AVReceiverFilter::AVReceiverFilter(std::string name, FilterType type)
    : Filter(name, type)
{
    HILOGI("AVReceiverFilter create");
}

AVReceiverFilter::~AVReceiverFilter()
{
    HILOGI("AVReceiverFilter destroy");
    if (eventHandler_ != nullptr) {
        eventHandler_->GetEventRunner()->Stop();
        eventThread_.join();
        eventHandler_ = nullptr;
    }
}

void AVReceiverFilter::Init(const std::shared_ptr<EventReceiver>& receiver,
    const std::shared_ptr<FilterCallback>& callback)
{
    HILOGI("AVReceiverFilter Init");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
    eventThread_ = std::thread(&AVReceiverFilter::StartEvent, this);
    std::unique_lock<std::mutex> lock(eventMutex_);
    eventCon_.wait(lock, [this] {
        return eventHandler_ != nullptr;
    });
}

void AVReceiverFilter::StartEvent()
{
    HILOGI("StartEvent start");
    auto runner = AppExecFwk::EventRunner::Create(false);
    {
        std::lock_guard<std::mutex> lock(eventMutex_);
        eventHandler_ = std::make_shared<AppExecFwk::EventHandler>(runner);
    }
    eventCon_.notify_one();
    runner->Run();
    HILOGI("StartEvent end");
}

Status AVReceiverFilter::DoPrepare()
{
    HILOGI("AVReceiverFilter Prepare");
    filterCallback_->OnCallback(shared_from_this(), FilterCallBackCommand::NEXT_FILTER_NEEDED,
        StreamType::STREAMTYPE_ENCODED_VIDEO);
#ifdef DSCH_COLLAB_AV_TRANS_PICTURE_TEST_DEMO
    isRunning_ = true;
    processingThread_ = std::thread(&AVReceiverFilter::Process, this);
#endif
    return Status::OK;
}

Status AVReceiverFilter::DoStart()
{
    HILOGI("AVReceiverFilter Start");
    isRunning_ = true;
    processingThread_ = std::thread(&AVReceiverFilter::Process, this);
    return Status::OK;
}

Status AVReceiverFilter::DoPause()
{
    HILOGI("AVReceiverFilter Pause");
    return Status::OK;
}

Status AVReceiverFilter::DoResume()
{
    HILOGI("AVReceiverFilter Resume");
    return Status::OK;
}

Status AVReceiverFilter::DoStop()
{
    HILOGI("AVReceiverFilter Stop");
    isRunning_ = false;
    cv_.notify_all();
    if (processingThread_.joinable()) {
        processingThread_.join();
    }
    return Status::OK;
}

Status AVReceiverFilter::DoFlush()
{
    HILOGI("AVReceiverFilter Flush");
    return Status::OK;
}

Status AVReceiverFilter::DoRelease()
{
    HILOGI("AVReceiverFilter Release");
    return Status::OK;
}

Status AVReceiverFilter::LinkNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
{
    HILOGI("LinkNext");
    nextFilter_ = nextFilter;
    nextFiltersMap_[outType].push_back(nextFilter_);
    auto filterLinkCallback = std::make_shared<AVReceiverFilterLinkCallback>(shared_from_this());
    nextFilter->OnLinked(outType, meta_, filterLinkCallback);
    return Status::OK;
}

Status AVReceiverFilter::UpdateNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
{
    HILOGI("UpdateNext");
    return Status::OK;
}

Status AVReceiverFilter::UnLinkNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
{
    HILOGI("UnLinkNext");
    return Status::OK;
}

Status AVReceiverFilter::OnLinked(StreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<FilterLinkCallback>& callback)
{
    HILOGI("OnLinked");
    return Status::OK;
}

void AVReceiverFilter::OnLinkedResult(const sptr<Media::AVBufferQueueProducer>& outputBufferQueue,
    std::shared_ptr<Media::Meta>& meta)
{
    HILOGI("OnLinkedResult");
    bufferQProxy_ = sptr<BqProducerProxy>::MakeSptr(shared_from_this());
    bufferQProxy_->producer_ = outputBufferQueue;
    sptr<Media::IProducerListener> listener = bufferQProxy_;
    bufferQProxy_->producer_->SetBufferAvailableListener(listener);
}

Status AVReceiverFilter::OnUpdated(StreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<FilterLinkCallback>& callback)
{
    HILOGI("OnUpdated");
    return Status::OK;
}

void AVReceiverFilter::OnUpdatedResult(std::shared_ptr<Meta>& meta)
{
    HILOGI("OnUpdatedResult");
}

Status AVReceiverFilter::OnUnLinked(StreamType inType, const std::shared_ptr<FilterLinkCallback>& callback)
{
    HILOGI("OnUnLinked");
    return Status::OK;
}

void AVReceiverFilter::OnUnlinkedResult(std::shared_ptr<Meta>& meta)
{
    HILOGI("OnUnlinkedResult");
}

void AVReceiverFilter::OnBufferAvailable()
{
    HILOGI("OnBufferAvailable");
    availableBuffers_++;
    cv_.notify_one();
}

void AVReceiverFilter::OnError(const int32_t errorCode)
{
    HILOGE("AVReceiverFilter::OnError errcode: %{public}d", errorCode);
    if (listener_) {
        listener_->OnError(channelId_, errorCode);
    }
}

void AVReceiverFilter::SetChannelListener(int32_t channelId)
{
    HILOGI("AVReceiverFilter::SetChannelListener enter");
    listener_ = std::make_shared<AVReceiverFilterListener>(shared_from_this());
    channelId_ = channelId;
    ChannelManager::GetInstance().RegisterChannelListener(channelId_, listener_);
}

void AVReceiverFilter::SetEngineListener(const std::shared_ptr<IEngineListener>& listener)
{
    HILOGI("AVReceiverFilter::SetEngineListener enter");
    std::lock_guard<std::mutex> lock(listenerMutex_);
    engineListeners_.push_back(listener);
}

#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
std::shared_ptr<IChannelListener> AVReceiverFilter::GetChannelListener()
{
    return listener_;
}
#endif

std::shared_ptr<AVTransStreamData> AVReceiverFilter::GetStreamData()
{
    if (dataQueue_.empty()) {
        return nullptr;
    }
    auto topData = dataQueue_.top();
    uint32_t curIndex = topData->GetStreamDataExt().index_;
    while (lastIndex_ >= curIndex) {
        HILOGE("invalid index=%{public}u, cur=%{public}lld", curIndex, lastIndex_);
        dataQueue_.pop();
        topData = dataQueue_.top();
        curIndex = topData->GetStreamDataExt().index_;
    }
    if (lastIndex_ + 1 == curIndex) {
        lastIndex_ = curIndex;
        dataQueue_.pop();
        return topData;
    }
    return nullptr;
}

void AVReceiverFilter::AddStreamData(const std::shared_ptr<AVTransStreamData>& data)
{
    std::lock_guard<std::mutex> lock(queueMutex_);
    dataQueue_.push(std::move(data));
    cv_.notify_one();
}

void AVReceiverFilter::Process()
{
    HILOGI("AVReceiverFilter::Process enter");
    while (isRunning_) {
        std::unique_lock<std::mutex> lock(queueMutex_);
        cv_.wait(lock, [this] {
            return !isRunning_ || availableBuffers_ >= 0;
        });
        if (!isRunning_ || availableBuffers_ < 0) {
            HILOGI("exit running process thread");
            while (!dataQueue_.empty()) {
                dataQueue_.pop();
            }
            return;
        }
        auto data = GetStreamData();
        if (data == nullptr) {
            continue;
        }
        DispatchProcessData(data);
    }
}

void AVReceiverFilter::DispatchProcessData(const std::shared_ptr<AVTransStreamData>& data)
{
    HILOGD("AVReceiverFilter::DispatchProcessData enter");
    if (eventHandler_ == nullptr) {
        HILOGE("event handler null");
        return;
    }
    switch (data->GetStreamDataExt().flag_) {
        case AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_PIXEL_MAP: {
            ProcessPixelMap(data);
            break;
        }
        case AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_SURFACE_PARAM: {
            ProcessSurfaceParam(data);
            break;
        }
        default: {
            int32_t ret = RequestAndPushData(data);
            HILOGD("process data ret = %{public}d", ret);
            break;
        }
    }
}

void AVReceiverFilter::ProcessPixelMap(const std::shared_ptr<AVTransStreamData>& data)
{
    HILOGI("start to process pixel map");
    auto pixelMap = GetPixelMap(data);
    std::lock_guard<std::mutex> lock(listenerMutex_);
    for (const auto& listener : engineListeners_) {
        if (auto ptr = listener.lock()) {
            auto func = [ptr, pixelMap]() {
                ptr->OnRecvPixelMap(pixelMap);
            };
            eventHandler_->PostTask(func, AppExecFwk::EventHandler::Priority::LOW);
        }
    }
}

std::shared_ptr<Media::PixelMap> AVReceiverFilter::GetPixelMap(const std::shared_ptr<AVTransStreamData>& data)
{
    HILOGI("AVReceiverFilter::GetPixelMap enter");
    uint8_t* header = data->StreamData()->Data();
    uint32_t dataSize = data->StreamData()->Size();
    Media::SourceOptions sourceOption;
    uint32_t err = ERR_OK;
    std::unique_ptr<Media::ImageSource> imageSource = Media::ImageSource::CreateImageSource(header,
        dataSize, sourceOption, err);
    if (err != ERR_OK) {
        HILOGE("create image source failed");
        return nullptr;
    }
    Media::DecodeOptions decodeOptions;
    decodeOptions.desiredSize = {
        .width = decodePixelMapWidth,
        .height = decodePixelMapHeight,
    };
    std::unique_ptr<Media::PixelMap> pixelMap = imageSource->CreatePixelMap(decodeOptions, err);
    if (err != ERR_OK) {
        HILOGE("decode pixelmap failed");
        return nullptr;
    }
    return std::shared_ptr<Media::PixelMap>(std::move(pixelMap));
}

void AVReceiverFilter::ProcessSurfaceParam(const std::shared_ptr<AVTransStreamData>& data)
{
    HILOGI("start to process surface param");
    auto& param = data->GetStreamDataExt().surfaceParam_;
    std::lock_guard<std::mutex> lock(listenerMutex_);
    for (const auto& listener : engineListeners_) {
        if (auto ptr = listener.lock()) {
            auto func = [ptr, param]() {
                ptr->OnRecvSurfaceParam(param);
            };
            eventHandler_->PostTask(func, AppExecFwk::EventHandler::Priority::HIGH);
        }
    }
}

int32_t AVReceiverFilter::RequestAndPushData(const std::shared_ptr<AVTransStreamData>& data)
{
    std::shared_ptr<AVBuffer> outputBuffer = nullptr;
    Media::AVBufferConfig avBufferConfig;
    avBufferConfig.size = data->StreamData()->Size();
    HILOGD("recv raw stream data size = %{public}u", static_cast<uint32_t>(avBufferConfig.size));
    avBufferConfig.memoryType = Media::MemoryType::HARDWARE_MEMORY;
    avBufferConfig.memoryFlag = Media::MemoryFlag::MEMORY_READ_WRITE;
    Status ret = bufferQProxy_->RequestBuffer(outputBuffer, avBufferConfig);
    if (ret != Status::OK || outputBuffer == nullptr || outputBuffer->memory_ == nullptr) {
        HILOGE("request buffer failed, %{public}d", static_cast<int32_t>(ret));
        bufferQProxy_->CancelBuffer(outputBuffer);
        return static_cast<int32_t>(ret);
    }

    HILOGD("write data to buffer, id=%{public}llu, size=%{public}d",
        outputBuffer->GetUniqueId(), outputBuffer->GetConfig().size);
    auto& memory = outputBuffer->memory_;
    memory->SetSize(avBufferConfig.size);
    int32_t writeRet = memcpy_s(memory->GetAddr(), memory->GetSize(),
        data->StreamData()->Data(), data->StreamData()->Size());
    if (writeRet != ERR_OK) {
        HILOGE("write data to buffer failed, %{public}d", writeRet);
        bufferQProxy_->CancelBuffer(outputBuffer);
        return writeRet;
    }
    outputBuffer->pts_ = data->GetStreamDataExt().pts_;
    ret = bufferQProxy_->PushBuffer(outputBuffer);
    if (ret != Status::OK) {
        HILOGE("push buffer failed, err=%{public}d", static_cast<int32_t>(ret));
        bufferQProxy_->CancelBuffer(outputBuffer);
        return static_cast<int32_t>(ret);
    }
    --availableBuffers_;
    return ERR_OK;
}

void AVReceiverFilter::SetParameter(const std::shared_ptr<Media::Meta>& parameter)
{
    meta_ = parameter;
}
void AVReceiverFilter::GetParameter(std::shared_ptr<Media::Meta>& parameter)
{
    parameter = meta_;
}

void AVReceiverFilter::OnStream(const std::shared_ptr<AVTransStreamData>& stream)
{
    HILOGI("start to parse stream by Stream");
    if (isRunning_) {
        AddStreamData(stream);
    }
}

void AVReceiverFilter::OnBytes(const std::shared_ptr<AVTransDataBuffer>& buffer)
{
    HILOGI("start to parse stream by Bytes");
    if (buffer == nullptr || buffer->Size() < sizeof(AVSenderFilter::version) +
        sizeof(AVSenderFilter::transType) + sizeof(uint32_t)) {
        HILOGE("Invalid buffer or buffer size is too small");
        return;
    }
    uint8_t* dataHeader = buffer->Data();
    size_t offset = 0;

    int32_t ret = ERR_OK;
    int32_t version;
    ret = memcpy_s(&version, sizeof(version),
        dataHeader + offset, sizeof(version));
    if (ret != EOK) {
        HILOGE("Failed to read version from buffer. Error code: %{public}d", ret);
        return;
    }
    offset += sizeof(version);

    int32_t type;
    ret = memcpy_s(&type, sizeof(type),
        dataHeader + offset, sizeof(type));
    if (ret != EOK) {
        HILOGE("Failed to read type from buffer. Error code: %{public}d", ret);
        return;
    }
    offset += sizeof(type);

    uint32_t headerLen;
    ret = memcpy_s(&headerLen, sizeof(headerLen),
        dataHeader + offset, sizeof(headerLen));
    if (ret != EOK) {
        HILOGE("Failed to read headerLen from buffer. Error code: %{public}d", ret);
        return;
    }
    offset += sizeof(headerLen);

    if (buffer->Size() < offset + headerLen) {
        HILOGE("Buffer size is smaller than expected header size");
        return;
    }
    std::shared_ptr<AVTransStreamData> stream = ReadStreamDataFromBuffer(dataHeader + offset,
        headerLen, buffer->Size());
    if (stream != nullptr && isRunning_) {
        AddStreamData(stream);
    }
}

std::shared_ptr<AVTransStreamData> AVReceiverFilter::ReadStreamDataFromBuffer(uint8_t* dataHeader,
    uint32_t headerLen, size_t totalLen)
{
    size_t offset = 0;
    char* headerJsonStr = reinterpret_cast<char*>(dataHeader + offset);
    cJSON* headerJson = cJSON_Parse(headerJsonStr);
    if (headerJson == nullptr) {
        HILOGE("Failed to parse header JSON");
        return nullptr;
    }
    HILOGD("parse header = %{public}s", cJSON_PrintUnformatted(headerJson));
    cJSON* dataLenItem = cJSON_GetObjectItem(headerJson, "dataLen");
    if (dataLenItem == nullptr) {
        HILOGE("Missing 'dataLen' in header JSON");
        cJSON_Delete(headerJson);
        return nullptr;
    }
    size_t rawDataLen = dataLenItem->valueint;
    uint8_t* rawData = dataHeader + offset + headerLen;
    if (rawDataLen > totalLen - (offset + headerLen)) {
        HILOGE("Raw data length exceeds available buffer size");
        cJSON_Delete(headerJson);
        return nullptr;
    }

    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(rawDataLen);
    AVTransStreamDataExt ext;
    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(buffer, ext);
    streamData->DeserializeExtFromJson(headerJson);
    int32_t ret = memcpy_s(buffer->Data(), buffer->Size(),
        rawData, rawDataLen);
    cJSON_Delete(headerJson);
    return ret == ERR_OK ? streamData : nullptr;
}

sptr<IRemoteObject> AVReceiverFilter::BqProducerProxy::AsObject()
{
    return nullptr;
}

void AVReceiverFilter::BqProducerProxy::OnBufferAvailable()
{
    if (auto ptr = filter_.lock()) {
        ptr->OnBufferAvailable();
    }
}

Status AVReceiverFilter::BqProducerProxy::RequestBuffer(std::shared_ptr<AVBuffer>& outBuffer,
    const Media::AVBufferConfig& config)
{
    return producer_->RequestBuffer(outBuffer, config, requestBufferTimeout);
}

Status AVReceiverFilter::BqProducerProxy::PushBuffer(const std::shared_ptr<Media::AVBuffer>& inBuffer)
{
    return producer_->PushBuffer(inBuffer, true);
}

Status AVReceiverFilter::BqProducerProxy::CancelBuffer(const std::shared_ptr<Media::AVBuffer>& inBuffer)
{
    return producer_->PushBuffer(inBuffer, false);
}
} // namespace DistributedCollab
} // namespace OHOS
