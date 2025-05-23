/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef DSCHED_COLLAB_TEST
#define DSCHED_COLLAB_TEST
#include "dsched_collab.h"

#include "gtest/gtest.h"

#include "mock/bundle_manager_internal_mock.h"
#include "mock/distributed_sched_permission_mock.h"
#include "mock/distributed_sched_service_mock.h"
#include "mock/dsched_transport_softbus_adapter_mock.h"
#include "mock/message_parcel_mock.h"

namespace OHOS {
namespace DistributedSchedule {

class DSchedCollabTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    static inline std::shared_ptr<MessageParcelMock> messageParcelMock_ = nullptr;
    static inline std::shared_ptr<DSchedTransportSoftbusAdapterMock> adapterMock_ = nullptr;
    static inline std::shared_ptr<BundleManagerInternalMock> bundleMgrMock_ = nullptr;
    static inline std::shared_ptr<DistributedSchedPermMock> dmsPermMock_ = nullptr;
    static inline std::shared_ptr<DistributedSchedServiceMock> dmsSrvMock_ = nullptr;
    static inline std::shared_ptr<DSchedCollab> dSchedCollab_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DSCHED_COLLAB_TEST