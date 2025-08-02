/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef DISTRIBUTED_SCHED_PERMISSION_TEST_H
#define DISTRIBUTED_SCHED_PERMISSION_TEST_H

#include "device_manager.h"
#include "gtest/gtest.h"
#include "mock/bundle_manager_internal_mock.h"
#include "mock/dtbschedmgr_device_info_storage_mock.h"
#include "mock/distributed_sched_adapter_mock.h"
#include "mock/dnetwork_adapter_mock.h"


namespace OHOS {
namespace DistributedSchedule {
class DistributedSchedPermissionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    std::string deviceId_;
    static inline std::shared_ptr<BundleManagerInternalMock> bundleMgrMock_ = nullptr;
    static inline std::shared_ptr<DtbschedmgrDeviceInfoStorageMock> storageMock_ = nullptr;
    static inline std::shared_ptr<DistributedSchedAdapterMock> adapter_ = nullptr;
    static inline std::shared_ptr<DnetworkAdapterMock> netAdapter_ = nullptr;

protected:
    class DeviceInitCallBack : public OHOS::DistributedHardware::DmInitCallback {
        void OnRemoteDied() override;
    };
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DISTRIBUTED_SCHED_PERMISSION_TEST_H