/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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
#ifndef OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_DECODER_ADAPTER_MOCK_H
#define OHOS_AV_TRANS_STREAM_FILTERS_SURFACE_DECODER_ADAPTER_MOCK_H

#include <gmock/gmock.h>

#include "surface_decoder_adapter.h"

namespace OHOS {
namespace DistributedCollab {
class ISurfaceDecoderApt {
public:
    virtual ~ISurfaceDecoderApt() = default;
    virtual Media::Status Init(const std::string& mime) = 0;
    virtual Media::Status Configure(const MediaAVCodec::Format& format) = 0;
    virtual sptr<Media::AVBufferQueueProducer> GetInputBufferQueue() = 0;
    virtual Media::Status SetOutputSurface(const sptr<Surface>& surface) = 0;
    virtual Media::Status SetDecoderAdapterCallback(const std::shared_ptr<DecoderAdapterCallback>&) = 0;
    virtual Media::Status Start() = 0;
    virtual Media::Status Stop() = 0;
    virtual Media::Status Pause() = 0;
    virtual Media::Status Resume() = 0;
    virtual Media::Status Flush() = 0;
    virtual Media::Status Release() = 0;
    virtual Media::Status SetParameter(const MediaAVCodec::Format& format) = 0;
public:
    static inline std::shared_ptr<ISurfaceDecoderApt> surfaceDecoderAptMock = nullptr;
};

class SurfaceDecoderAptMock : public ISurfaceDecoderApt {
public:
    MOCK_METHOD1(Init, Media::Status(const std::string& mime));
    MOCK_METHOD1(Configure, Media::Status(const MediaAVCodec::Format& format));
    MOCK_METHOD0(GetInputBufferQueue, sptr<Media::AVBufferQueueProducer>());
    MOCK_METHOD1(SetOutputSurface, Media::Status(const sptr<Surface>& surface));
    MOCK_METHOD1(SetDecoderAdapterCallback, Media::Status(const std::shared_ptr<DecoderAdapterCallback>&));
    MOCK_METHOD0(Start, Media::Status());
    MOCK_METHOD0(Stop, Media::Status());
    MOCK_METHOD0(Pause, Media::Status());
    MOCK_METHOD0(Resume, Media::Status());
    MOCK_METHOD0(Flush, Media::Status());
    MOCK_METHOD0(Release, Media::Status());
    MOCK_METHOD1(SetParameter, Media::Status(const MediaAVCodec::Format& format));
};
}
}
#endif