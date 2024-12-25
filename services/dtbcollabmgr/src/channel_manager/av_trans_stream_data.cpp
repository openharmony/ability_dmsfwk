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
#include "av_trans_stream_data.h"
#include "dtbcollabmgr_log.h"

namespace OHOS {
namespace DistributedCollab {
    namespace {
        static constexpr int32_t RADIX = 10;
        static const std::string TAG = "DSchedCollabAVTransStreamData";
    }

    std::shared_ptr<AVTransDataBuffer> AVTransStreamData::StreamData()
    {
        return data_;
    }

    const AVTransStreamDataExt& AVTransStreamData::GetStreamDataExt() const
    {
        return const_cast<const AVTransStreamDataExt&>(ext_);
    }

    cJSON* AVTransStreamData::SerializeStreamDataExt() const
    {
        cJSON* root = cJSON_CreateObject();
        WriteExtFlagToJson(root);
        WriteExtIndexToJson(root);
        switch (ext_.flag_) {
            case AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_PIXEL_MAP: {
                WriteExtPixelMapPackOptionToJson(root);
                return root;
            }
            case AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_SURFACE_PARAM: {
                WriteExtSurfaceParamToJson(root);
                return root;
            }
            default: {
                WriteExtPtsToJson(root);
                WriteExtStartEncodeTToJson(root);
                WriteExtFinishEncodeTToJson(root);
                WriteExtSendEncodeTToJson(root);
                return root;
            }
        }
    }

    inline void AVTransStreamData::WriteExtFlagToJson(cJSON* root) const
    {
        cJSON_AddNumberToObject(root, "flag", static_cast<uint32_t>(ext_.flag_));
    }

    inline void AVTransStreamData::WriteExtIndexToJson(cJSON* root) const
    {
        cJSON_AddNumberToObject(root, "index", ext_.index_);
    }

    inline void AVTransStreamData::WriteExtPtsToJson(cJSON* root) const
    {
        std::string ptsStr = std::to_string(ext_.pts_);
        cJSON_AddStringToObject(root, "pts", ptsStr.c_str());
    }

    inline void AVTransStreamData::WriteExtStartEncodeTToJson(cJSON* root) const
    {
        std::string startEncodeTStr = std::to_string(ext_.startEncodeT_);
        cJSON_AddStringToObject(root, "startEncodeT", startEncodeTStr.c_str());
    }

    inline void AVTransStreamData::WriteExtFinishEncodeTToJson(cJSON* root) const
    {
        std::string finishEncodeTStr = std::to_string(ext_.finishEncodeT_);
        cJSON_AddStringToObject(root, "finishEncodeT", finishEncodeTStr.c_str());
    }

    inline void AVTransStreamData::WriteExtSendEncodeTToJson(cJSON* root) const
    {
        std::string sendEncodeTStr = std::to_string(ext_.sendEncodeT_);
        cJSON_AddStringToObject(root, "sendEncodeT", sendEncodeTStr.c_str());
    }

    inline void AVTransStreamData::WriteExtPixelMapPackOptionToJson(cJSON* root) const
    {
        cJSON* pixelMapJson = cJSON_CreateObject();
        cJSON_AddNumberToObject(pixelMapJson, "quality", ext_.pixelMapOption_.quality);
        cJSON_AddItemToObject(root, "pixel_map", pixelMapJson);
    }

    inline void AVTransStreamData::WriteExtSurfaceParamToJson(cJSON* root) const
    {
        cJSON* surfaceParamJson = cJSON_CreateObject();
        cJSON_AddNumberToObject(surfaceParamJson, "rotate", static_cast<uint32_t>(ext_.surfaceParam_.rotate));
        cJSON_AddNumberToObject(surfaceParamJson, "filp", static_cast<uint32_t>(ext_.surfaceParam_.filp));
        cJSON_AddItemToObject(root, "surface_param", surfaceParamJson);
    }

    int32_t AVTransStreamData::DeserializeStreamDataExt(const char* data)
    {
        if (data == nullptr) {
            HILOGE("empty data");
            return NULL_POINTER_ERROR;
        }
        cJSON* root = cJSON_Parse(data);
        if (root == nullptr) {
            HILOGE("parse recv data ext failed");
            return PARSE_AV_TRANS_STREAM_EXT_FAILED;
        }
        DeserializeExtFromJson(root);
        cJSON_Delete(root);
        return ERR_OK;
    }

    void AVTransStreamData::DeserializeExtFromJson(const cJSON* root)
    {
        AVTransStreamDataExt& dataExt = ext_;
        ReadExtFlagFromJson(dataExt, root);
        if (ext_.flag_ == AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_PIXEL_MAP) {
            return ReadExtPixelMapPackOptionToJson(dataExt, root);
        }
        if (ext_.flag_ == AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_SURFACE_PARAM) {
            return ReadExtSurfaceParamToJson(dataExt, root);
        }
        ReadExtIndexFromJson(dataExt, root);
        ReadExtPtsFromJson(dataExt, root);
        ReadExtStartEncodeTFromJson(dataExt, root);
        ReadExtFinishEncodeTFromJson(dataExt, root);
        ReadExtSendEncodeTFromJson(dataExt, root);
    }

    inline void AVTransStreamData::ReadExtFlagFromJson(AVTransStreamDataExt& dataExt, const cJSON* root)
    {
        const cJSON* flagItem = cJSON_GetObjectItemCaseSensitive(root, "flag");
        if (cJSON_IsNumber(flagItem)) {
            dataExt.flag_ = static_cast<AvCodecBufferFlag>(flagItem->valueint);
        }
    }

    inline void AVTransStreamData::ReadExtIndexFromJson(AVTransStreamDataExt& dataExt, const cJSON* root)
    {
        const cJSON* indexItem = cJSON_GetObjectItemCaseSensitive(root, "index");
        if (cJSON_IsNumber(indexItem)) {
            dataExt.index_ = static_cast<uint32_t>(indexItem->valueint);
        }
    }

    inline void AVTransStreamData::ReadExtPtsFromJson(AVTransStreamDataExt& dataExt, const cJSON* root)
    {
        const cJSON* ptsItem = cJSON_GetObjectItemCaseSensitive(root, "pts");
        if (cJSON_IsString(ptsItem) && ptsItem->valuestring != nullptr) {
            dataExt.pts_ = std::strtoull(ptsItem->valuestring, nullptr, RADIX);
        }
    }

    inline void AVTransStreamData::ReadExtStartEncodeTFromJson(AVTransStreamDataExt& dataExt, const cJSON* root)
    {
        const cJSON* startEncodeTItem = cJSON_GetObjectItemCaseSensitive(root, "startEncodeT");
        if (cJSON_IsString(startEncodeTItem) && startEncodeTItem->valuestring != nullptr) {
            dataExt.startEncodeT_ = std::strtoull(startEncodeTItem->valuestring, nullptr, RADIX);
        }
    }

    inline void AVTransStreamData::ReadExtFinishEncodeTFromJson(AVTransStreamDataExt& dataExt, const cJSON* root)
    {
        const cJSON* finishEncodeTItem = cJSON_GetObjectItemCaseSensitive(root, "finishEncodeT");
        if (cJSON_IsString(finishEncodeTItem) && finishEncodeTItem->valuestring != nullptr) {
            dataExt.finishEncodeT_ = std::strtoull(finishEncodeTItem->valuestring, nullptr, RADIX);
        }
    }

    inline void AVTransStreamData::ReadExtSendEncodeTFromJson(AVTransStreamDataExt& dataExt, const cJSON* root)
    {
        const cJSON* sendEncodeTItem = cJSON_GetObjectItemCaseSensitive(root, "sendEncodeT");
        if (cJSON_IsString(sendEncodeTItem) && sendEncodeTItem->valuestring != nullptr) {
            dataExt.sendEncodeT_ = std::strtoull(sendEncodeTItem->valuestring, nullptr, RADIX);
        }
    }

    inline void AVTransStreamData::ReadExtPixelMapPackOptionToJson(AVTransStreamDataExt& dataExt, const cJSON* root)
    {
        const cJSON* pixelMapJson = cJSON_GetObjectItemCaseSensitive(root, "pixel_map");
        if (pixelMapJson) {
            const cJSON* qualityItem = cJSON_GetObjectItemCaseSensitive(pixelMapJson, "quality");
            if (cJSON_IsNumber(qualityItem)) {
                ext_.pixelMapOption_.quality = static_cast<uint8_t>(cJSON_GetNumberValue(qualityItem));
            }
        }
    }

    inline void AVTransStreamData::ReadExtSurfaceParamToJson(AVTransStreamDataExt& dataExt, const cJSON* root)
    {
        const cJSON* surfaceParamItem = cJSON_GetObjectItemCaseSensitive(root, "surface_param");
        if (surfaceParamItem != nullptr && cJSON_IsObject(surfaceParamItem)) {
            const cJSON* rotateItem = cJSON_GetObjectItemCaseSensitive(surfaceParamItem, "rotate");
            if (cJSON_IsNumber(rotateItem)) {
                dataExt.surfaceParam_.rotate = static_cast<SurfaceRotate>(rotateItem->valueint);
            }

            const cJSON* filpItem = cJSON_GetObjectItemCaseSensitive(surfaceParamItem, "filp");
            if (cJSON_IsNumber(filpItem)) {
                dataExt.surfaceParam_.filp = static_cast<SurfaceFilp>(filpItem->valueint);
            }
        }
    }
} // namespace DistributedCollab
} // namespace OHOS
