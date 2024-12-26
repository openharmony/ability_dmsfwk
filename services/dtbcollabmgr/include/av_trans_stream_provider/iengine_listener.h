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

#ifndef OHOS_AV_TRANS_STREAM_AV_ENGINE_ILISTENER_H
#define OHOS_AV_TRANS_STREAM_AV_ENGINE_ILISTENER_H
#include "pixel_map.h"
#include "av_trans_stream_data.h"

namespace OHOS {
namespace DistributedCollab {
class IEngineListener {
public:
    IEngineListener() = default;
    virtual ~IEngineListener() = default;
    virtual void OnRecvPixelMap(const std::shared_ptr<Media::PixelMap>& pixelMap) = 0;
    virtual void OnRecvSurfaceParam(const SurfaceParam& param) = 0;
};
}
}
#endif