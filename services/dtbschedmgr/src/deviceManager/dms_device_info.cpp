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

#include "deviceManager/dms_device_info.h"

#include "parcel_helper.h"
#include "string_ex.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DmsDeviceInfo";
}
const std::string& DmsDeviceInfo::GetDeviceName() const
{
    return deviceName_;
}

const std::string& DmsDeviceInfo::GetNetworkId() const
{
    return networkId_;
}

int32_t DmsDeviceInfo::GetDeviceType() const
{
    return deviceType_;
}

int32_t DmsDeviceInfo::GetDeviceState() const
{
    return deviceState_;
}

int32_t DmsDeviceInfo::GetDeviceOSType() const
{
    return osType_;
}

const std::string& DmsDeviceInfo::GetGetDeviceOSVersion() const
{
    return osVersion_;
}

bool DmsDeviceInfo::Marshalling(Parcel& parcel) const
{
    PARCEL_WRITE_HELPER_RET(parcel, String16, Str8ToStr16(networkId_), false);
    PARCEL_WRITE_HELPER_RET(parcel, String16, Str8ToStr16(deviceName_), false);
    PARCEL_WRITE_HELPER_RET(parcel, Int32, deviceType_, false);
    PARCEL_WRITE_HELPER_RET(parcel, Int32, deviceState_, false);
    PARCEL_WRITE_HELPER_RET(parcel, Int32, osType_, false);
    PARCEL_WRITE_HELPER_RET(parcel, String16, Str8ToStr16(osVersion_), false);
    return true;
}
} // namespace DistributedSchedule
} // namespace OHOS