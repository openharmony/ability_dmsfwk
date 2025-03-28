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
#ifndef DTBSCHEDMGR_DEVICE_INFO_STORAGE_MOCK_H
#define DTBSCHEDMGR_DEVICE_INFO_STORAGE_MOCK_H

#include <gmock/gmock.h>

#include "dtbschedmgr_device_info_storage.h"

#include "ability_info.h"

namespace OHOS {
namespace DistributedSchedule {
class IDtbschedmgrDeviceInfoStorage {
public:
    virtual ~IDtbschedmgrDeviceInfoStorage() = default;
    virtual std::vector<std::string> GetNetworkIdList() = 0;
public:
    static inline std::shared_ptr<IDtbschedmgrDeviceInfoStorage> storageMock = nullptr;
};

class DtbschedmgrDeviceInfoStorageMock : public IDtbschedmgrDeviceInfoStorage {
public:
    MOCK_METHOD0(GetNetworkIdList, std::vector<std::string>());
};
}
}
#endif
