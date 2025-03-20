/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "surface_decoder_adapter_mock.h"

using namespace std;
using namespace OHOS;
using namespace OHOS::DistributedCollab;

Media::Status SurfaceDecoderAdapter::Init(const std::string& mime)
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return Media::Status::ERROR_UNKNOWN;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->Init(mime);
}

Media::Status SurfaceDecoderAdapter::Configure(const MediaAVCodec::Format& format)
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return Media::Status::ERROR_UNKNOWN;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->Configure(format);
}

sptr<Media::AVBufferQueueProducer> SurfaceDecoderAdapter::GetInputBufferQueue()
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return nullptr;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->GetInputBufferQueue();
}

Media::Status SurfaceDecoderAdapter::SetOutputSurface(const sptr<Surface>& surface)
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return Media::Status::ERROR_UNKNOWN;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->SetOutputSurface(surface);
}

Media::Status SurfaceDecoderAdapter::SetDecoderAdapterCallback(
    const std::shared_ptr<DecoderAdapterCallback>& decoderAdapterCallback)
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return Media::Status::ERROR_UNKNOWN;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->SetDecoderAdapterCallback(decoderAdapterCallback);
}

Media::Status SurfaceDecoderAdapter::Start()
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return Media::Status::ERROR_UNKNOWN;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->Start();
}

Media::Status SurfaceDecoderAdapter::Stop()
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return Media::Status::ERROR_UNKNOWN;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->Stop();
}

Media::Status SurfaceDecoderAdapter::Pause()
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return Media::Status::ERROR_UNKNOWN;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->Pause();
}

Media::Status SurfaceDecoderAdapter::Resume()
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return Media::Status::ERROR_UNKNOWN;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->Resume();
}

Media::Status SurfaceDecoderAdapter::Flush()
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return Media::Status::ERROR_UNKNOWN;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->Flush();
}

Media::Status SurfaceDecoderAdapter::Release()
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return Media::Status::ERROR_UNKNOWN;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->Release();
}

Media::Status SurfaceDecoderAdapter::SetParameter(const MediaAVCodec::Format& format)
{
    if (ISurfaceDecoderApt::surfaceDecoderAptMock == nullptr) {
        return Media::Status::ERROR_UNKNOWN;
    }
    return ISurfaceDecoderApt::surfaceDecoderAptMock->SetParameter(format);
}
