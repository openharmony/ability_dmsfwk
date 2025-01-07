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
#include "av_stream_param.h"
#include "media_description.h"

namespace OHOS {
namespace DistributedCollab {
namespace {
    using MDKey = MediaAVCodec::MediaDescriptionKey;
}

void VidEnc::Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const
{
    switch (mode) {
        case ConfigureMode::Encode:
            ConfigureEncode(meta);
            break;
        case ConfigureMode::Decode:
            ConfigureDecode(meta);
            break;
        default:
            break;
        }
}

void VidEnc::ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const
{
    switch (encFmt) {
        case VideoCodecFormat::VIDEO_DEFAULT:
        case VideoCodecFormat::H264: {
            constexpr int32_t h264Level = 32;
            meta->Set<Media::Tag::MIME_TYPE>(Media::Plugins::MimeType::VIDEO_AVC);
            meta->Set<Media::Tag::VIDEO_H264_PROFILE>(Media::Plugins::VideoH264Profile::BASELINE);
            meta->Set<Media::Tag::VIDEO_H264_LEVEL>(h264Level);
            break;
        }
        case VideoCodecFormat::MPEG4: {
            meta->Set<Media::Tag::MIME_TYPE>(Media::Plugins::MimeType::VIDEO_MPEG4);
            break;
        }
        case VideoCodecFormat::H265: {
            meta->Set<Media::Tag::MIME_TYPE>(Media::Plugins::MimeType::VIDEO_HEVC);
            break;
        }
        default:
            break;
    }
}

void VidEnc::ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const
{
    switch (encFmt) {
        case VideoCodecFormat::VIDEO_DEFAULT:
        case VideoCodecFormat::H264: {
            meta->SetData(std::string(MDKey::MD_KEY_CODEC_MIME), Media::Plugins::MimeType::VIDEO_AVC);
            break;
        }
        case VideoCodecFormat::MPEG4: {
            meta->SetData(std::string(MDKey::MD_KEY_CODEC_MIME), Media::Plugins::MimeType::VIDEO_MPEG4);
            break;
        }
        case VideoCodecFormat::H265: {
            meta->SetData(std::string(MDKey::MD_KEY_CODEC_MIME), Media::Plugins::MimeType::VIDEO_HEVC);
            break;
        }
        default:
            break;
    }
}

void VidRectangle::Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const
{
    switch (mode) {
        case ConfigureMode::Encode:
            ConfigureEncode(meta);
            break;
        case ConfigureMode::Decode:
            ConfigureDecode(meta);
            break;
        default:
            break;
    }
}

void VidRectangle::ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const
{
    meta->Set<Media::Tag::VIDEO_WIDTH>(width);
    meta->Set<Media::Tag::VIDEO_HEIGHT>(height);
}

void VidRectangle::ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const
{
    meta->SetData(std::string(MDKey::MD_KEY_WIDTH), width);
    meta->SetData(std::string(MDKey::MD_KEY_HEIGHT), height);
}

void VidBitRate::Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const
{
    switch (mode) {
        case ConfigureMode::Encode:
            ConfigureEncode(meta);
            break;
        case ConfigureMode::Decode:
            ConfigureDecode(meta);
            break;
        default:
            break;
    }
}

void VidBitRate::ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const
{
    meta->Set<Media::Tag::MEDIA_BITRATE>(bitRate);
}

void VidBitRate::ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const
{
    meta->SetData(std::string(MDKey::MD_KEY_BITRATE), bitRate);
}

void VidFrameRate::Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const
{
    switch (mode) {
        case ConfigureMode::Encode:
            ConfigureEncode(meta);
            break;
        case ConfigureMode::Decode:
            ConfigureDecode(meta);
            break;
        default:
            break;
    }
}

void VidFrameRate::ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const
{
    meta->Set<Media::Tag::VIDEO_FRAME_RATE>(frameRate);
}

void VidFrameRate::ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const
{
    meta->SetData(std::string(MDKey::MD_KEY_FRAME_RATE), frameRate);
}

void VidIsHdr::Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const
{
    switch (mode) {
        case ConfigureMode::Encode:
            ConfigureEncode(meta);
            break;
        case ConfigureMode::Decode:
            ConfigureDecode(meta);
            break;
        default:
            break;
    }
}

void VidIsHdr::ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const
{
    if (isHdr) {
        meta->Set<Media::Tag::VIDEO_H265_PROFILE>(Media::Plugins::HEVCProfile::HEVC_PROFILE_MAIN_10);
    }
}

void VidIsHdr::ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const
{
    if (isHdr) {
        meta->SetData(std::string(MDKey::MD_KEY_PROFILE), Media::Plugins::HEVCProfile::HEVC_PROFILE_MAIN_10);
    }
}

void VidEnableTemporalScale::Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const
{
    switch (mode) {
        case ConfigureMode::Encode:
            ConfigureEncode(meta);
            break;
        case ConfigureMode::Decode:
            ConfigureDecode(meta);
            break;
        default:
            break;
    }
}

void VidEnableTemporalScale::ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const
{
    if (enableTemporalScale) {
        meta->Set<Media::Tag::VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY>(
            enableTemporalScale);
    }
}

void VidEnableTemporalScale::ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const
{
    if (enableTemporalScale) {
        meta->SetData(std::string(MDKey::OH_MD_KEY_VIDEO_ENCODER_ENABLE_TEMPORAL_SCALABILITY),
            1);
    }
}

void VidSurfaceParam::Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const
{
    switch (mode) {
        case ConfigureMode::Encode:
            ConfigureEncode(meta);
            break;
        case ConfigureMode::Decode:
            ConfigureDecode(meta);
            break;
        default:
            break;
    }
}

void VidSurfaceParam::ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const
{
}

void VidSurfaceParam::ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const
{
    SetMetaData(*meta.get(), Media::Tag::VIDEO_ORIENTATION_TYPE, static_cast<int32_t>(
        ConvertToVideoOrientation(surfaceParam)));
}

Media::Plugins::VideoOrientationType VidSurfaceParam::ConvertToVideoOrientation(const SurfaceParam& param) const
{
    if (param.filp == SurfaceFilp::FLIP_NONE) {
        switch (param.rotate) {
            case SurfaceRotate::ROTATE_NONE:
                return Media::Plugins::VideoOrientationType::ROTATE_NONE;
            case SurfaceRotate::ROTATE_90:
                return Media::Plugins::VideoOrientationType::ROTATE_90;
            case SurfaceRotate::ROTATE_180:
                return Media::Plugins::VideoOrientationType::ROTATE_180;
            case SurfaceRotate::ROTATE_270:
                return Media::Plugins::VideoOrientationType::ROTATE_270;
            default:
                return Media::Plugins::VideoOrientationType::ROTATE_NONE;
        }
    } else if (param.filp == SurfaceFilp::FLIP_H) {
        switch (param.rotate) {
            case SurfaceRotate::ROTATE_NONE:
                return Media::Plugins::VideoOrientationType::FLIP_H;
            case SurfaceRotate::ROTATE_90:
                return Media::Plugins::VideoOrientationType::FLIP_H_ROT90;
            case SurfaceRotate::ROTATE_180:
                return Media::Plugins::VideoOrientationType::FLIP_H_ROT180;
            case SurfaceRotate::ROTATE_270:
                return Media::Plugins::VideoOrientationType::FLIP_H_ROT270;
            default:
                return Media::Plugins::VideoOrientationType::FLIP_H;
        }
    } else if (param.filp == SurfaceFilp::FLIP_V) {
        switch (param.rotate) {
            case SurfaceRotate::ROTATE_NONE:
                return Media::Plugins::VideoOrientationType::FLIP_V;
            case SurfaceRotate::ROTATE_90:
                return Media::Plugins::VideoOrientationType::FLIP_V_ROT90;
            case SurfaceRotate::ROTATE_180:
                return Media::Plugins::VideoOrientationType::FLIP_V_ROT180;
            case SurfaceRotate::ROTATE_270:
                return Media::Plugins::VideoOrientationType::FLIP_V_ROT270;
            default:
                return Media::Plugins::VideoOrientationType::FLIP_V;
        }
    }
    return Media::Plugins::VideoOrientationType::ROTATE_NONE;
}
}
}