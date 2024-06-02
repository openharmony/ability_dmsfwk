/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef OHOS_DISTRIBUTED_DMS_DEVICE_INFO_H
#define OHOS_DISTRIBUTED_DMS_DEVICE_INFO_H

#include <iosfwd>
#include <string>

#include "parcel.h"

#include "dms_constant.h"

namespace OHOS {
namespace DistributedSchedule {
enum {
    UNKNOWN_TYPE = 0x00,
};

enum {
    UNKNOWN_STATE = 0,
    ONLINE = 1,
    OFFLINE = 2,
};

class DmsDeviceInfo : public Parcelable {
public:
    DmsDeviceInfo(const std::string& deviceName, int32_t deviceType, const std::string& networkId,
        int32_t deviceState = ONLINE, int32_t osType = Constants::OH_OS_TYPE, std::string osVersion = "")
        : deviceName_(deviceName), deviceType_(deviceType), networkId_(networkId), deviceState_(deviceState),
        osType_(osType), osVersion_(osVersion) {}
    ~DmsDeviceInfo() = default;

    const std::string& GetDeviceName() const;
    const std::string& GetNetworkId() const;
    int32_t GetDeviceType() const;
    int32_t GetDeviceState() const;
    int32_t GetDeviceOSType() const;
    const std::string& GetGetDeviceOSVersion() const;
    bool Marshalling(Parcel& parcel) const override;

private:
    std::string deviceName_;
    int32_t deviceType_ = UNKNOWN_TYPE;
    std::string networkId_;
    int32_t deviceState_ = UNKNOWN_STATE;
    int32_t osType_ = Constants::OH_OS_TYPE;
    std::string osVersion_ = "";
};
} // namespace DistributedSchedule
} // namespace OHOS

#endif /* OHOS_DISTRIBUTED_DMS_DEVICE_INFO_H */
