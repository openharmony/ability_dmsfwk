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

#ifndef DTBSCHEDMGR_DEVICE_INFO_STORAGE_MOCK_H
#define DTBSCHEDMGR_DEVICE_INFO_STORAGE_MOCK_H

#include <gmock/gmock.h>
#include <string>
#include <vector>
#include "dtbschedmgr_device_info_storage.h"

namespace OHOS {
namespace DistributedSchedule {

class IDtbschedmgrDeviceInfoStorage {
public:
    virtual ~IDtbschedmgrDeviceInfoStorage() = default;
    virtual bool GetLocalDeviceId(std::string& networkId) = 0;
    virtual std::vector<std::string> GetNetworkIdList() = 0;
public:
    static inline std::shared_ptr<IDtbschedmgrDeviceInfoStorage> storageMock = nullptr;
};

class DtbschedmgrDeviceInfoStorageMock : public IDtbschedmgrDeviceInfoStorage {
public:
    MOCK_METHOD1(GetLocalDeviceId, bool(std::string& networkId));
    MOCK_METHOD0(GetNetworkIdList, std::vector<std::string>());
};

} // namespace DistributedSchedule
} // namespace OHOS
#endif // DTBSCHEDMGR_DEVICE_INFO_STORAGE_MOCK_H