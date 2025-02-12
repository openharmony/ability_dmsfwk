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

enum class FlipOption : int32_t {
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
    PEER_APP_EXIT = 0,
    NETWORK_DISCONNECTED = 1,
};

struct PeerInfo : public Parcelable {
    std::string deviceId;
    std::string bundleName;
    std::string moduleName;
    std::string abilityName;
    std::string serverId;

    PeerInfo() = default;
    PeerInfo(const std::string& deviceId, const std::string& bundleName,
        const std::string& moduleName, const std::string& abilityName, const std::string& serverId)
        : deviceId(deviceId), bundleName(bundleName), moduleName(moduleName),
        abilityName(abilityName), serverId(serverId) {}

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
    bool needSendData;
    bool needSendStream;
    bool needReceiveStream;
    bool needSendFile;
    bool needReceiveFile;
    AAFwk::WantParams options;
    AAFwk::WantParams parameters;
    bool ReadFromParcel(Parcel &parcel);
    bool Marshalling(Parcel &parcel) const override;
    static ConnectOption *Unmarshalling(Parcel &parcel);
};

struct ConnectResult {
    bool isConnected;
    std::string reason;

    ConnectResult() = default;
    ConnectResult(const bool isConnected) : isConnected(isConnected) {}
    
    ConnectResult(const bool isConnected, const std::string& reason)
        : isConnected(isConnected), reason(reason) {}
};

struct StreamParams {
    std::string name;
    StreamRole role;
};

struct SurfaceParams {
    int32_t width;
    int32_t height;
    VideoPixelFormat format;
    int32_t rotation;
    FlipOption flip = FlipOption::UNKNOWN;
};

struct EventCallbackInfo {
    int32_t sessionId;
    DisconnectReason reason = DisconnectReason::UNKNOW;
    std::string msg;
    std::shared_ptr<AVTransDataBuffer> data = nullptr;
    std::shared_ptr<Media::PixelMap> image = nullptr;
};
} // namespace DistributedCollab
} // namespace OHOS
#endif //OHOS_DSCHED_ABILITY_CONNECTION_INFO_H