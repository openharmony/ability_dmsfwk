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

#ifndef MOCK_DTBSCHEDMGR_DEVICE_INFO_H
#define MOCK_DTBSCHEDMGR_DEVICE_INFO_H

#include <gmock/gmock.h>
#include <string>

#include "dtbschedmgr_device_info_storage.h"

namespace OHOS {
namespace DistributedSchedule {
class DmsMgrDeviceInfoStore {
public:
    virtual ~DmsMgrDeviceInfoStore() = default;
public:
    virtual bool GetLocalDeviceId(std::string& networkId) = 0;
public:
    static inline std::shared_ptr<DmsMgrDeviceInfoStore> dmsStore = nullptr;
};

class MockDmsMgrDeviceInfoStore : public DmsMgrDeviceInfoStore {
public:
    MOCK_METHOD(bool, GetLocalDeviceId, (std::string& networkId));
};
}
}
#endif //MOCK_DTBSCHEDMGR_DEVICE_INFO_H
