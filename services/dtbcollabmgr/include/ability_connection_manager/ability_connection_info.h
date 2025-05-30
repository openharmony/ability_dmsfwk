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

#ifndef OHOS_DSCHED_ABILITY_CONNECTION_INFO_H
#define OHOS_DSCHED_ABILITY_CONNECTION_INFO_H

#include <map>
#include <string>

#include "ability_connection_manager_listener.h"
#include "av_trans_data_buffer.h"
#include "distributed_sched_utils.h"
#include "parcel.h"
#include "pixel_map.h"
#include "refbase.h"
#include "want_params.h"

namespace OHOS {
namespace DistributedCollab {
enum class StreamRole : int32_t {
    SOURCE = 0,
    SINK = 1,
};

enum class FlipOptions : int32_t {
    UNKNOWN = -1,
    HORIZONTAL = 0,
    VERTICAL = 1,
};

enum class VideoPixelFormat : int32_t {
    UNKNOWN = -1,
    NV12 = 0,
    NV21 = 1,
};

enum class DisconnectReason : int32_t {
    UNKNOW = -1,
    PEER_APP_CLOSE_COLLABORATION = 0,
    PEER_APP_EXIT = 1,
    NETWORK_DISCONNECTED = 2,
};

enum class StartOptionParams : int32_t {
    START_IN_FOREGROUND = 0,
    START_IN_BACKGROUND = 1,
};

enum class ConnectErrorCode : int32_t {
    INVALID_SESSION_ID = -1,
    CONNECTED_SESSION_EXISTS = 0,
    PEER_APP_REJECTED = 1,
    LOCAL_WIFI_NOT_OPEN = 2,
    PEER_WIFI_NOT_OPEN = 3,
    PEER_ABILITY_NO_ONCOLLABORATE = 4,
    SYSTEM_INTERNAL_ERROR = 5
};

enum class ColorSpace : int32_t {
    UNKNOWN = 0,
    BT709_LIMIT = 16,
};

struct StreamParams {
    std::string name = "";
    StreamRole role = StreamRole::SOURCE;
    int32_t bitrate = 80000;
    ColorSpace colorSpace = ColorSpace::UNKNOWN;
};

struct SurfaceParams {
    int32_t width = 0;
    int32_t height = 0;
    VideoPixelFormat format = VideoPixelFormat::NV21;
    int32_t rotation = 0;
    FlipOptions flip = FlipOptions::UNKNOWN;
};

struct EventCallbackInfo {
    int32_t sessionId = -1;
    std::string eventType = "";
    DisconnectReason reason = DisconnectReason::UNKNOW;
    std::string msg = "";
    std::shared_ptr<AVTransDataBuffer> data = nullptr;
    std::shared_ptr<Media::PixelMap> image = nullptr;
};

enum class CollaborateEventType : int32_t {
    SEND_FAILURE = 0,
    COLOR_SPACE_CONVERSION_FAILURE = 1,
};

struct CollaborateEventInfo {
    int32_t sessionId = -1;
    CollaborateEventType eventType = CollaborateEventType::SEND_FAILURE;
    std::string eventMsg = "";
};

struct PeerInfo : public Parcelable {
    std::string deviceId;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string serverId;
    // keep compatibility, both serviceName
    std::string serviceName;

    PeerInfo() = default;
    PeerInfo(const std::string& deviceId, const std::string& bundleName,
        const std::string& moduleName, const std::string& abilityName, const std::string& serverId)
        : deviceId(deviceId), bundleName(bundleName), moduleName(moduleName),
        abilityName(abilityName), serverId(serverId), serviceName(serverId) {}

    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static PeerInfo *Unmarshalling(Parcel &parcel);

    bool operator == (const PeerInfo &index) const
    {
        std::string compareInfo = this->deviceId + this->bundleName + this->moduleName +
            this->abilityName + this->serverId;
        std::string otherCompareInfo = index.deviceId + index.bundleName + index.moduleName +
            index.abilityName + index.serverId;
        return compareInfo.compare(otherCompareInfo) == 0;
    }

    bool operator < (const PeerInfo &index) const
    {
        std::string compareInfo = this->deviceId + this->bundleName + this->moduleName +
            this->abilityName + this->serverId;
        std::string otherCompareInfo = index.deviceId + index.bundleName + index.moduleName +
            index.abilityName + index.serverId;
        return compareInfo < otherCompareInfo;
    }

    std::string toString() const
    {
        return "deviceId: " + DistributedSchedule::GetAnonymStr(deviceId) + " " +
            "bundleName: " + bundleName + " " +
            "moduleName: "+ moduleName + " " +
            "abilityName: " + abilityName + " " +
            "serverId: " + serverId;
    }
};

struct ConnectOption : public Parcelable {
    bool needSendData = false;
    bool needSendStream = false;
    bool needReceiveStream = false;
    bool needSendFile = false;
    bool needReceiveFile = false;
    AAFwk::WantParams options;
    AAFwk::WantParams parameters;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static ConnectOption *Unmarshalling(Parcel &parcel);

    bool HasFileTransfer() const
    {
        return needSendFile || needReceiveFile;
    }
};

struct ConnectResult {
    bool isConnected = false;
    ConnectErrorCode errorCode = ConnectErrorCode::SYSTEM_INTERNAL_ERROR;
    int32_t sessionId = -1;
    std::string reason = "";

    ConnectResult() = default;
    ConnectResult(const bool isConnected) : isConnected(isConnected) {}
    ConnectResult(bool isConnected, const ConnectErrorCode errorCode, const std::string& reason)
        : isConnected(isConnected), errorCode(errorCode), reason(reason) {}
};
} // namespace DistributedCollab
} // namespace OHOS
#endif //OHOS_DSCHED_ABILITY_CONNECTION_INFO_H