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
#ifndef OHOS_AV_TRANS_STREAM_COMMON_DEFINITION_H
#define OHOS_AV_TRANS_STREAM_COMMON_DEFINITION_H

#include <cstdint>
#include <string>

namespace OHOS {
namespace DistributedCollab {
enum class VideoSourceType : uint32_t {
    NV12 = 0,
    NV21,
};

enum class EngineState : uint32_t {
    EMPTY = 0,
    INIT,
    SETTING,
    PREPARE,
    START,
    STOP,
    ERROR,
};

enum class OutputFormatType : int32_t {
    /** Default format */
    FORMAT_DEFAULT = 0,
    /** MPEG4 format */
    FORMAT_MPEG_4 = 2,
    /** M4A format */
    FORMAT_M4A = 6,
    /** WAV format */
    FORMAT_WAV = 10,
};

enum class VideoCodecFormat : int32_t {
    /** Default format */
    VIDEO_DEFAULT,
    /** H.264 */
    H264,
    /** MPEG4 */
    MPEG4,
    /** H.265 */
    H265,
};

const std::string VIDEO_CODEC_LIST_KEY = "VideoCodecList";
} // namespace DistributedCollab
} // namespace OHOS
#endif