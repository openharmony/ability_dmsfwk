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

#ifndef DMS_CONTINUE_SEND_MANAGER_TEST_H
#define DMS_CONTINUE_SEND_MANAGER_TEST_H

#include "gtest/gtest.h"

#include "mock/ability_manager_client_mock.h"
#include "mock/bundle_manager_internal_mock.h"
#include "mock/dms_continue_condition_manager_mock.h"
#include "mock/dsched_sync_e2e_mock.h"

namespace OHOS {
namespace DistributedSchedule {
class DMSContinueSendMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static inline std::shared_ptr<AbilityManagerClientMock> clientMock_ = nullptr;
    static inline std::shared_ptr<BundleManagerInternalMock> bundleMgrMock_ = nullptr;
    static inline std::shared_ptr<DmsContinueConditionMgrMock> mgrMock_ = nullptr;
};

class DMSContinueRecvMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static inline std::shared_ptr<BundleManagerInternalMock> bundleMgrMock_ = nullptr;
    static inline std::shared_ptr<DmsKvSyncE2EMock> dmsKvMock_ = nullptr;
};
}
}
#endif
