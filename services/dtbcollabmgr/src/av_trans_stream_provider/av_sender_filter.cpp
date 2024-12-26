#include "av_sender_filter.h"
#include "av_trans_data_buffer.h"
#include "av_trans_stream_data.h"
#include "channel_manager.h"
#include "dtbcollabmgr_log.h"
#include "filter/filter_factory.h"
#include "image_packer.h"
#include "meta/media_types.h"
#include <chrono>
#include <fstream>
#include <iostream>

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
    static const std::string TAG = "AVSenderFilter";
    static const std::string pixelMapFormat = "image/jpeg";
    static constexpr int32_t pixelMapQuality = 50;

#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
    static const std::string encodeWriteFilePath = "/data/tmp/encode_output_h26x";
    // static const std::string encodeWriteFilePath = "/data/storage/el2/base/encode_output_h26x";
#endif

#define FREE_CJSON(jsonStr, jsonJson) \
do {                                  \
    if (jsonStr) {                    \
        cJSON_free(jsonStr);          \
    }                                 \
    if (jsonJson) {                   \
        cJSON_Delete(jsonJson);       \
    }                                 \
} while (0)
}

static Media::Pipeline::AutoRegisterFilter<AVSenderFilter> g_registerAVSenderFilter("builtin.dtbcollab.sender",
    FilterType::FILTERTYPE_SOURCE,
    [](const std::string& name, const FilterType type) {
        return std::make_shared<AVSenderFilter>(name, FilterType::FILTERTYPE_SOURCE);
    });

AVSenderFilter::AVSenderFilter(std::string name, FilterType type)
    : Filter(name, type)
{
    HILOGI("AVSenderFilter create");
}

AVSenderFilter::~AVSenderFilter()
{
    HILOGI("AVSenderFilter destroy");
}

void AVSenderFilter::Init(const std::shared_ptr<EventReceiver>& receiver,
    const std::shared_ptr<FilterCallback>& callback)
{
    HILOGI("AVSenderFilter Init");
    eventReceiver_ = receiver;
    filterCallback_ = callback;
}

Status AVSenderFilter::DoPrepare()
{
    HILOGI("AVSenderFilter Prepare");
#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
    if (std::filesystem::exists(encodeWriteFilePath)) {
        if (!std::filesystem::remove(encodeWriteFilePath)) {
            HILOGE("delete encode output file failed");
            return Status::ERROR_UNKNOWN;
        }
    }
#endif
    return Status::OK;
}

Status AVSenderFilter::DoStart()
{
    HILOGI("AVSenderFilter Start");
    isRunning_ = true;
    processingThread_ = std::thread(&AVSenderFilter::Process, this);
    return Status::OK;
}

Status AVSenderFilter::DoPause()
{
    HILOGI("AVSenderFilter Pause");
    return Status::OK;
}

Status AVSenderFilter::DoResume()
{
    HILOGI("AVSenderFilter Resume");
    return Status::OK;
}

Status AVSenderFilter::DoStop()
{
    HILOGI("AVSenderFilter Stop");
    isRunning_ = false;
    cv_.notify_all();
    if (processingThread_.joinable()) {
        processingThread_.join();
    }
    return Status::OK;
}

Status AVSenderFilter::DoFlush()
{
    HILOGI("AVSenderFilter Flush");
    return Status::OK;
}

Status AVSenderFilter::DoRelease()
{
    HILOGI("AVSenderFilter Release");
    return Status::OK;
}

Status AVSenderFilter::LinkNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
{
    HILOGI("AVSenderFilter LinkNext");
    return Status::OK;
}

Status AVSenderFilter::UpdateNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
{
    HILOGI("AVSenderFilter UpdateNext");
    return Status::OK;
}

Status AVSenderFilter::UnLinkNext(const std::shared_ptr<Filter>& nextFilter, StreamType outType)
{
    HILOGI("AVSenderFilter UnLinkNext");
    return Status::OK;
}

Status AVSenderFilter::OnLinked(StreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<FilterLinkCallback>& callback)
{
    HILOGI("AVSenderFilter OnLinked");
    bufferQProxy_ = sptr<BqConsumerProxy>::MakeSptr(shared_from_this());
    bufferQProxy_->bufferQ_ = AVBufferQueue::Create(MAX_BUFFER_COUNT,
        Media::MemoryType::UNKNOWN_MEMORY, TAG);
    bufferQProxy_->producer_ = bufferQProxy_->bufferQ_->GetProducer();
    bufferQProxy_->consumer_ = bufferQProxy_->bufferQ_->GetConsumer();
    callback->OnLinkedResult(bufferQProxy_->producer_, const_cast<std::shared_ptr<Meta>&>(meta));
    sptr<Media::IConsumerListener> listener = bufferQProxy_;
    Status ret = bufferQProxy_->consumer_->SetBufferAvailableListener(listener);
    return ret;
}

Status AVSenderFilter::OnUpdated(StreamType inType, const std::shared_ptr<Meta>& meta,
    const std::shared_ptr<FilterLinkCallback>& callback)
{
    HILOGI("AVSenderFilter OnUpdated");
    return Status::OK;
}

Status AVSenderFilter::OnUnLinked(StreamType inType, const std::shared_ptr<FilterLinkCallback>& callback)
{
    HILOGI("AVSenderFilter OnUnLinked");
    return Status::OK;
}

void AVSenderFilter::SetTransChannel(int32_t channelId, const ChannelDataType type)
{
    channelId_ = channelId;
    channelType_ = type;
}

#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
void AVSenderFilter::SetChannelListener(const std::shared_ptr<IChannelListener>& listener)
{
    listener_ = listener;
}

inline int64_t AVSenderFilter::GetEncoderTimeStamp()
{
    std::chrono::microseconds nowUs = std::chrono::duration_cast<std::chrono::microseconds>(
        std::chrono::system_clock::now().time_since_epoch());
    return nowUs.count();
}

void AVSenderFilter::WriteFile(const std::shared_ptr<AVTransDataBuffer>& data)
{
    std::ofstream outFile(encodeWriteFilePath, std::ios::app);
    if (!outFile.is_open()) {
        HILOGE("open write file failed");
        return;
    }
    outFile.write(reinterpret_cast<const char*>(data->Data()), data->Size());
    if (!outFile) {
        HILOGE("Error occurred while writing to file.");
    }
    outFile.close();
}
#endif

void AVSenderFilter::Process()
{
    HILOGI("AVSenderFilter::Process enter");
    while (isRunning_) {
        std::unique_lock<std::mutex> lock(queueMutex_);
        cv_.wait(lock, [this] {
            return !isRunning_ || !sendDatas_.empty();
        });
        if (!isRunning_ || sendDatas_.empty()) {
            HILOGI("exit running process thread");
            return;
        }
        auto data = sendDatas_.front();
        if (data == nullptr) {
            continue;
        }
        SendStreamData(data);
        sendDatas_.pop();
    }
}

void AVSenderFilter::OnBufferAvailable(const std::shared_ptr<AVBuffer>& buffer)
{
    HILOGD("AVSenderFilter OnBufferAvailable enter");
    auto& memory = buffer->memory_;
    uint32_t size = static_cast<uint32_t>(memory->GetSize());
    HILOGD("curIdx=%{public}d, curSize=%{public}u", lastIndex_.load(), size);
    std::shared_ptr<AVTransDataBuffer> transData = std::make_shared<AVTransDataBuffer>(size);
    int32_t ret = memcpy_s(transData->Data(), size, memory->GetAddr(),
        memory->GetSize());

    Media::Event event;
    event.srcFilter = "senderFilter";
    event.type = Media::EventType::EVENT_ERROR;
    event.param = "copy or send failed";
    if (ret != ERR_OK) {
        HILOGE("memcpy failed");
        bufferQProxy_->ReleaseBuffer(buffer);
        eventReceiver_->OnEvent(event);
        return;
    }
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        auto ptr = PackStreamDataForAVBuffer(buffer, transData);
        sendDatas_.push(ptr);
    }
    bufferQProxy_->ReleaseBuffer(buffer);

#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
    WriteFile(transData);
#endif
}

std::shared_ptr<AVTransStreamData> AVSenderFilter::PackStreamDataForAVBuffer(const std::shared_ptr<AVBuffer>& buffer,
    const std::shared_ptr<AVTransDataBuffer>& dataBuffer)
{
    AVTransStreamDataExt ext;
    ext.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_CODEC_DATA;
    ext.index_ = lastIndex_.load();
    lastIndex_++;
    ext.pts_ = buffer->pts_;
#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
    ext.pts_ = GetEncoderTimeStamp();
#endif
    ext.startEncodeT_ = std::chrono::system_clock::now().time_since_epoch().count();
    ext.finishEncodeT_ = ext.startEncodeT_;
    ext.sendEncodeT_ = ext.startEncodeT_;
    return std::make_shared<AVTransStreamData>(dataBuffer, ext);
}

int32_t AVSenderFilter::SendStreamData(const std::shared_ptr<AVTransStreamData>& streamData)
{
    switch (channelType_) {
        case ChannelDataType::BYTES:
            return SendStreamDataByBytes(streamData);
        case ChannelDataType::VIDEO_STREAM:
            return SendStreamDataByStream(streamData);
        default:
            return INVALID_CHANNEL_TYPE;
    }
}

int32_t AVSenderFilter::SendStreamDataByStream(const std::shared_ptr<AVTransStreamData>& streamData)
{
    HILOGD("AVSenderFilter SendStreamDataByStream enter");
#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
    if (auto ptr = listener_.lock()) {
        ptr->OnStream(channelId_, streamData);
    }
#endif
    ChannelManager::GetInstance().SendStream(channelId_, streamData);
    return ERR_OK;
}

int32_t AVSenderFilter::SendStreamDataByBytes(const std::shared_ptr<AVTransStreamData>& streamData)
{
    HILOGD("AVSenderFilter SendStreamDataByBytes enter");
    cJSON* headerJson = streamData->SerializeStreamDataExt();
    if (!headerJson) {
        HILOGE("serialize stream data failed");
        return GET_SERIALIZED_DATA_FAILED;
    }
    const uint8_t* rawData = streamData->StreamData()->Data();
    size_t rawDataLen = streamData->StreamData()->Size();
    cJSON_AddNumberToObject(headerJson, "dataLen", rawDataLen);

    char* headerStr = cJSON_PrintUnformatted(headerJson);
    if (!headerStr) {
        FREE_CJSON(headerStr, headerJson);
        return GET_SERIALIZED_DATA_FAILED;
    }
    size_t headerStrLen = strlen(headerStr);
    uint32_t headerLen = static_cast<uint32_t>(headerStrLen);
    size_t totalLen = sizeof(AVSenderFilter::version) + sizeof(AVSenderFilter::transType) +
        sizeof(headerLen) + headerStrLen + rawDataLen;
    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(totalLen);
#ifdef DSCH_COLLAB_AV_TRANS_TEST_DEMO
    if (auto ptr = listener_.lock()) {
        ptr->OnBytes(channelId_, buffer);
    }
#endif
    ChannelManager::GetInstance().SendBytes(channelId_, buffer);
    FREE_CJSON(headerStr, headerJson);
    return ERR_OK;
}

int32_t AVSenderFilter::WriteDataToBuffer(const std::shared_ptr<AVTransDataBuffer>& buffer,
    cJSON* headerJson, char* headerStr)
{
    uint8_t* dataHeader = buffer->Data();
    size_t offset = 0;
    int32_t ret = memcpy_s(dataHeader + offset, buffer->Capacity() - offset,
        &AVSenderFilter::version, sizeof(AVSenderFilter::version));
    if (ret != EOK) {
        FREE_CJSON(headerStr, headerJson);
        return ret;
    }
    offset += sizeof(AVSenderFilter::version);

    ret = memcpy_s(dataHeader + offset, buffer->Capacity() - offset,
        &AVSenderFilter::transType, sizeof(AVSenderFilter::transType));
    if (ret != EOK) {
        FREE_CJSON(headerStr, headerJson);
        return ret;
    }
    offset += sizeof(AVSenderFilter::transType);

    ret = memcpy_s(dataHeader + offset, buffer->Capacity() - offset,
        &headerLen, sizeof(headerLen));
    if (ret != EOK) {
        FREE_CJSON(headerStr, headerJson);
        return ret;
    }
    offset += sizeof(headerLen);

    ret = memcpy_s(dataHeader + offset, buffer->Capacity() - offset,
        headerStr, headerStrLen);
    if (ret != EOK) {
        FREE_CJSON(headerStr, headerJson);
        return ret;
    }
    offset += headerStrLen;

    ret = memcpy_s(dataHeader + offset, buffer->Capacity() - offset,
        rawData, rawDataLen);
    if (ret != EOK) {
        FREE_CJSON(headerStr, headerJson);
        return ret;
    }
}

int32_t AVSenderFilter::SendPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap)
{
    HILOGI("AVSenderFilter::SendPixelMap enter");
    if (pixelMap == nullptr) {
        HILOGI("pixel map empty");
        return NULL_POINTER_ERROR;
    }
    std::shared_ptr<AVTransDataBuffer> buffer = nullptr;
    int32_t ret = PackPixelMap(pixelMap, buffer);
    if (ret != ERR_OK) {
        return ret;
    }
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        auto ptr = PackStreamDataForPixelMap(buffer);
        sendDatas_.push(ptr);
    }
    return ERR_OK;
}

int32_t AVSenderFilter::PackPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap,
    std::shared_ptr<AVTransDataBuffer>& buffer)
{
    Media::PackOption option = {
        .format = pixelMapFormat,
        .quality = pixelMapQuality,
    };
    int32_t dataSize = pixelMap->GetByteCount();
    buffer = std::make_shared<AVTransDataBuffer>(dataSize);
    Media::ImagePacker packer;
    uint32_t ret = packer.StartPacking(buffer->Data(), buffer->Size(), option);
    if (ret != ERR_OK) {
        HILOGE("start packing failed, %{public}d", ret);
        return ret;
    }
    ret = packer.AddImage(*pixelMap.get());
    if (ret != ERR_OK) {
        HILOGE("add image failed, %{public}d", ret);
        return ret;
    }
    int64_t packSize = 0;
    ret = packer.FinalizePacking(packSize);
    if (ret != ERR_OK) {
        HILOGE("pack image failed, %{public}d", ret);
        return ret;
    }
    buffer->SetRange(0, packSize);
    return ERR_OK;
}

std::shared_ptr<AVTransStreamData> AVSenderFilter::PackStreamDataForPixelMap(
        const std::shared_ptr<AVTransDataBuffer>& dataBuffer)
{
    AVTransStreamDataExt ext;
    ext.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_PIXEL_MAP;
    ext.index_ = lastIndex_.load();
    lastIndex_++;
    PixelMapPackOption option;
    option.quality = pixelMapQuality;
    ext.pixelMapOption_ = option;
    return std::make_shared<AVTransStreamData>(dataBuffer, ext);
}

int32_t AVSenderFilter::SetSurfaceParam(const SurfaceParam& param)
{
    HILOGI("AVSenderFilter::SetSurfaceParam enter");
    {
        std::lock_guard<std::mutex> lock(queueMutex_);
        auto ptr = PackStreamDataForSurfaceParam(param);
        sendDatas_.push(ptr);
    }
    return ERR_OK;
}

std::shared_ptr<AVTransStreamData> AVSenderFilter::PackStreamDataForSurfaceParam(const SurfaceParam& param)
{
    AVTransStreamDataExt ext;
    ext.flag_ = AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_SURFACE_PARAM;
    ext.index_ = lastIndex_.load();
    lastIndex_++;
    ext.surfaceParam_ = param;
    std::shared_ptr<AVTransDataBuffer> dataBuffer = std::make_shared<AVTransDataBuffer>(1);
    return std::make_shared<AVTransStreamData>(dataBuffer, ext);
}

void AVSenderFilter::SetParameter(const std::shared_ptr<Media::Meta>& parameter)
{
    HILOGI("AVSenderFilter SetParameter");
}
void AVSenderFilter::GetParameter(std::shared_ptr<Media::Meta>& parameter)
{
    HILOGI("AVSenderFilter GetParameter");
}

void AVSenderFilter::BqConsumerProxy::OnBufferAvailable()
{
    std::shared_ptr<AVBuffer> filledInputBuffer;
    Status ret = consumer_->AcquireBuffer(filledInputBuffer);
    if (ret != Status::OK) {
        HILOGE("AVSenderFilter::BqConsumerProxy AcquireBuffer fail");
        return;
    }
    if (auto ptr = filter_.lock()) {
        return ptr->OnBufferAvailable(filledInputBuffer);
    }
}

void AVSenderFilter::BqConsumerProxy::ReleaseBuffer(const std::shared_ptr<AVBuffer>& buffer)
{
    Status ret = consumer_->ReleaseBuffer(buffer);
    if (ret != Status::OK) {
        HILOGE("AVSenderFilter::BqConsumerProxy ReleaseBuffer fail");
        return;
    }
}
}
}
