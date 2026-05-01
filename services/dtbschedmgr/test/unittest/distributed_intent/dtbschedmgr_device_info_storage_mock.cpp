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

#include "dtbschedmgr_device_info_storage_mock.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {

IMPLEMENT_SINGLE_INSTANCE(DtbschedmgrDeviceInfoStorage);

bool DtbschedmgrDeviceInfoStorage::GetLocalDeviceId(std::string& networkId)
{
    if (IDtbschedmgrDeviceInfoStorage::storageMock == nullptr) {
        return false;
    }
    return IDtbschedmgrDeviceInfoStorage::storageMock->GetLocalDeviceId(networkId);
}

std::vector<std::string> DtbschedmgrDeviceInfoStorage::GetNetworkIdList()
{
    if (IDtbschedmgrDeviceInfoStorage::storageMock == nullptr) {
        return {};
    }
    return IDtbschedmgrDeviceInfoStorage::storageMock->GetNetworkIdList();
}

} // namespace DistributedSchedule
} // namespace OHOS