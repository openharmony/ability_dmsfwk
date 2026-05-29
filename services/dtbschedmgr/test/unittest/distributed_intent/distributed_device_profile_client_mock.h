/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DISTRIBUTED_DEVICE_PROFILE_CLIENT_MOCK_H
#define DISTRIBUTED_DEVICE_PROFILE_CLIENT_MOCK_H

#include <gmock/gmock.h>
#include "distributed_device_profile_client.h"

namespace OHOS {
namespace DistributedDeviceProfile {

class IDistributedDeviceProfileClient {
public:
    virtual ~IDistributedDeviceProfileClient() = default;
    virtual int32_t GetCharacteristicProfile(const std::string& deviceId, const std::string& serviceName,
        const std::string& characteristicId, CharacteristicProfile& characteristicProfile) = 0;
public:
    static inline std::shared_ptr<IDistributedDeviceProfileClient> dpClientMock = nullptr;
};

class DistributedDeviceProfileClientMock : public IDistributedDeviceProfileClient {
public:
    MOCK_METHOD4(GetCharacteristicProfile, int32_t(const std::string& deviceId,
        const std::string& serviceName, const std::string& characteristicId,
        CharacteristicProfile& characteristicProfile));
};

} // namespace DistributedDeviceProfile
} // namespace OHOS
#endif // DISTRIBUTED_DEVICE_PROFILE_CLIENT_MOCK_H