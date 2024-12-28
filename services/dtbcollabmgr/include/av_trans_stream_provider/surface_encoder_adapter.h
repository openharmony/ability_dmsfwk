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

#ifndef OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_ENCODER_ADAPTER_H
#define OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_ENCODER_ADAPTER_H

#include "avcodec_common.h"
#include "avcodec_video_encoder.h"
#include "buffer/avallocator.h"
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
#include <deque>
#include <shared_mutex>
#include <utility>

namespace OHOS {
namespace DistributedCollab {
enum class StateCode {
    PAUSE,
    RESUME,
};
class EncoderAdapterCallback {
public:
    virtual ~EncoderAdapterCallback() = default;
    virtual void OnError(MediaAVCodec::AVCodecErrorType type, int32_t errorCode) = 0;
    virtual void OnOutputFormatChanged(const std::shared_ptr<Media::Meta>& format) = 0;
};

class EncoderAdapterKeyFramePtsCallback {
public:
    virtual ~EncoderAdapterKeyFramePtsCallback() = default;
    virtual void OnReportKeyFramePts(std::string KeyFramePts) = 0;
};

class SurfaceEncoderAdapter : public std::enable_shared_from_this<SurfaceEncoderAdapter> {
public:
    explicit SurfaceEncoderAdapter();
    ~SurfaceEncoderAdapter();

public:
    Media::Status Init(const std::string& mime, bool isEncoder);
    Media::Status Configure(const std::shared_ptr<Media::Meta>& meta);
    Media::Status SetOutputBufferQueue(const sptr<Media::AVBufferQueueProducer>& bufferQueueProducer);
    Media::Status SetEncoderAdapterCallback(const std::shared_ptr<EncoderAdapterCallback>& encoderAdapterCallback);
    Media::Status SetInputSurface(sptr<Surface> surface);
    Media::Status SetTransCoderMode();
    sptr<Surface> GetInputSurface();
    Media::Status Start();
    Media::Status Stop();
    Media::Status Pause();
    Media::Status Resume();
    Media::Status Flush();
    Media::Status Reset();
    Media::Status Release();
    Media::Status NotifyEos(int64_t pts);
    Media::Status SetParameter(const std::shared_ptr<Media::Meta>& parameter);
    void OnOutputBufferAvailable(uint32_t index, std::shared_ptr<Media::AVBuffer> buffer);
    void SetCallingInfo(int32_t appUid, int32_t appPid, const std::string& bundleName, uint64_t instanceId);
    void OnInputParameterWithAttrAvailable(uint32_t index, std::shared_ptr<MediaAVCodec::Format>& attribute,
        std::shared_ptr<MediaAVCodec::Format>& parameter);

    std::shared_ptr<EncoderAdapterCallback> encoderAdapterCallback_;
    std::shared_ptr<EncoderAdapterKeyFramePtsCallback> encoderAdapterKeyFramePtsCallback_;

private:
    void ReleaseBuffer();
    void ConfigureGeneralFormat(MediaAVCodec::Format& format, const std::shared_ptr<Media::Meta>& meta);
    void ConfigureAboutRGBA(MediaAVCodec::Format& format, const std::shared_ptr<Media::Meta>& meta);
    void ConfigureAboutEnableTemporalScale(MediaAVCodec::Format& format, const std::shared_ptr<Media::Meta>& meta);
    bool CheckFrames(int64_t currentPts, int64_t& checkFramesPauseTime);
    void GetCurrentTime(int64_t& currentTime);
    void AddStartPts(int64_t currentPts);
    void AddStopPts();
    bool AddPauseResumePts(int64_t currentPts);

    std::shared_ptr<MediaAVCodec::AVCodecVideoEncoder> codecServer_ = nullptr;
    sptr<Media::AVBufferQueueProducer> outputBufferQueueProducer_ = nullptr;

    std::shared_ptr<Media::Task> releaseBufferTask_ { nullptr };
    std::mutex releaseBufferMutex_;
    std::condition_variable releaseBufferCondition_;
    std::vector<uint32_t> indexs_;
    std::deque<std::pair<int64_t, StateCode>> pauseResumeQueue_;
    std::deque<std::pair<int64_t, int64_t>> mappingTimeQueue_;
    std::atomic<bool> isThreadExit_ = true;
    bool isTransCoderMode = false;

    std::mutex mappingPtsMutex_;
    std::mutex checkFramesMutex_;
    std::mutex stopMutex_;
    std::condition_variable stopCondition_;
    int64_t stopTime_ { -1 };
    std::atomic<int64_t> eosPts_ { UINT32_MAX };
    std::atomic<int64_t> currentPts_ { -1 };
    int64_t totalPauseTime_ { 0 };

    int64_t startBufferTime_ { -1 };
    int64_t lastBufferTime_ { -1 };
    bool isStart_ = false;
    bool isResume_ = false;
    std::string codecMimeType_;
    std::string bundleName_;
    uint64_t instanceId_ { 0 };
    int32_t appUid_ { 0 };
    int32_t appPid_ { 0 };

    std::string keyFramePts_;
    bool isStartKeyFramePts_ = false;
    bool isStopKeyFramePts_ = false;
    int64_t currentKeyFramePts_ { -1 };
    int64_t preKeyFramePts_ { -1 };
    std::deque<std::pair<int64_t, StateCode>> pauseResumePts_;
};
} // namespace MediaAVCodec
} // namespace OHOS
#endif // FILTERS_SURFACE_ENCODER_ADAPTER_H
