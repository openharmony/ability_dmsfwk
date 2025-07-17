/*
 * Copyright (C) 2025 Huawei Device Co., Ltd.
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

#ifndef MOCK_DEVICE_MANAGER_H
#define MOCK_DEVICE_MANAGER_H

#include <gmock/gmock.h>

#include "device_manager_impl.h"

namespace OHOS {
namespace DistributedHardware {
class IDeviceManager {
public:
    virtual ~IDeviceManager() = default;
    virtual int32_t GetTrustedDeviceList(const std::string &pkgName, const std::string &extra,
        std::vector<DmDeviceInfo> &deviceList);
public:
    static inline std::shared_ptr<IDeviceManager> deviceMgrMock = nullptr;
};

class DeviceManagerMock : public IDeviceManager {
public:
    MOCK_METHOD3(GetTrustedDeviceList, int32_t(const std::string &pkgName, const std::string &extra,
        std::vector<DmDeviceInfo> &deviceList));
};
}
}
#endif
