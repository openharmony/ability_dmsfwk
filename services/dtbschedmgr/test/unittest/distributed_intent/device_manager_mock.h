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

#ifndef DEVICE_MANAGER_MOCK_H
#define DEVICE_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include "dm_device_info.h"
#include "device_manager_impl.h"

namespace OHOS {
namespace DistributedHardware {

class IDeviceManager {
public:
    virtual ~IDeviceManager() = default;
    virtual bool CheckSinkIsSameAccount(const DmAccessCaller& caller, const DmAccessCallee& callee) = 0;
    virtual bool CheckSrcIsSameAccount(const DmAccessCaller& caller, const DmAccessCallee& callee) = 0;
public:
    static inline std::shared_ptr<IDeviceManager> deviceManagerMock = nullptr;
};

class DeviceManagerMock : public IDeviceManager {
public:
    MOCK_METHOD2(CheckSinkIsSameAccount, bool(const DmAccessCaller& caller, const DmAccessCallee& callee));
    MOCK_METHOD2(CheckSrcIsSameAccount, bool(const DmAccessCaller& caller, const DmAccessCallee& callee));
};

} // namespace DistributedHardware
} // namespace OHOS
#endif // DEVICE_MANAGER_MOCK_H