/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef DMS_COLLAB_MANAGER_TEST_H
#define DMS_COLLAB_MANAGER_TEST_H

#include "gtest/gtest.h"

#include "device_manager.h"
#include "dsched_collab_manager.h"
#include "continue/mock_dtbschedmgr_device_info.h"
#include "mock/multi_user_manager_mock.h"

namespace OHOS {
namespace DistributedSchedule {

class DSchedCollabManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedCollab> CreateObject();
    sptr<IRemoteObject> GetDSchedService() const;
    static inline std::shared_ptr<MockDmsMgrDeviceInfoStore> dmsStoreMock = nullptr;
    static inline std::shared_ptr<MultiUserManagerMock> multiUserMgrNock_ = nullptr;
protected:
    class DeviceInitCallBack : public OHOS::DistributedHardware::DmInitCallback {
        void OnRemoteDied() override;
    };
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DMS_COLLAB_MANAGER_TEST_H
