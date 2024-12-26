
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
#ifndef OHOS_AV_TRANS_STREAM_STREAM_PARAM_H
#define OHOS_AV_TRANS_STREAM_STREAM_PARAM_H

#include "av_stream_common.h"
#include "meta/meta.h"
#include <memory>
#include <string>

namespace OHOS {
namespace DistributedCollab {
enum class StreamParamType : uint32_t {
    VID_ENC_FMT = 0,
    VID_RECTANGLE,
    VID_BITRATE,
    VID_FRAMERATE,
    VID_IS_HDR,
    VID_CAPTURERATE,
    VID_ENABLE_TEMPORAL_SCALE,
    VID_PUBLIC_PARAM_END,
    VID_ORIENTATION_HINT,
};

enum class ConfigureMode {
    Encode,
    Decode
};

struct StreamParam {
    explicit StreamParam(StreamParamType type)
        : type_(type)
    {
    }

    virtual ~StreamParam() = default;

    virtual void Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const = 0;

    StreamParamType type_;
};

struct VidEnc : public StreamParam {
    explicit VidEnc(VideoCodecFormat fmt)
        : StreamParam(StreamParamType::VID_ENC_FMT)
        , encFmt(fmt)
    {
    }

    VideoCodecFormat encFmt;

    void Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const override;

private:
    void ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const;
    void ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const;
};

struct VidRectangle : public StreamParam {
    VidRectangle(int32_t w, int32_t h)
        : StreamParam(StreamParamType::VID_RECTANGLE)
        , width(w)
        , height(h)
    {
    }

    int32_t width;
    int32_t height;

    void Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const override;

private:
    void ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const;
    void ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const;
};

struct VidBitRate : public StreamParam {
    explicit VidBitRate(int32_t br)
        : StreamParam(StreamParamType::VID_BITRATE)
        , bitRate(br)
    {
    }

    int32_t bitRate;

    void Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const override;

private:
    void ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const;
    void ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const;
};

struct VidFrameRate : public StreamParam {
    explicit VidFrameRate(int32_t r)
        : StreamParam(StreamParamType::VID_FRAMERATE)
        , frameRate(r)
    {
    }

    int32_t frameRate;

    void Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const override;

private:
    void ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const;
    void ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const;
};

struct VidIsHdr : public StreamParam {
    explicit VidIsHdr(bool r)
        : StreamParam(StreamParamType::VID_IS_HDR)
        , isHdr(r)
    {
    }
    bool isHdr;
    void Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const override;

private:
    void ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const;
    void ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const;
};

struct VidEnableTemporalScale : public StreamParam {
    explicit VidEnableTemporalScale(bool r)
        : StreamParam(StreamParamType::VID_ENABLE_TEMPORAL_SCALE)
        , enableTemporalScale(r)
    {
    }

    bool enableTemporalScale;

    void Configure(std::shared_ptr<Media::Meta> meta, const ConfigureMode mode) const override;

private:
    void ConfigureEncode(std::shared_ptr<Media::Meta>& meta) const;
    void ConfigureDecode(std::shared_ptr<Media::Meta>& meta) const;
};
}
}
#endif
