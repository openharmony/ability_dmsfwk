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

#ifndef BLUETOOTH_STATE_TEST_H
#define BLUETOOTH_STATE_TEST_H

#include "gtest/gtest.h"

#include "mock/bundle_manager_internal_mock.h"
#include "mock/dms_continue_condition_manager_mock.h"
#include "mock/dtbschedmgr_device_info_storage_mock.h"

namespace OHOS {
namespace DistributedSchedule {
class ContinueRecommendInfoTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

class DMSContinueRecomMgrTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    static inline std::shared_ptr<DtbschedmgrDeviceInfoStorageMock> storageMock_ = nullptr;
    static inline std::shared_ptr<BundleManagerInternalMock> bundleMgrMock_ = nullptr;
    static inline std::shared_ptr<DmsContinueConditionMgrMock> mgrMock_ = nullptr;
};
}
}
#endif /* BLUETOOTH_STATE_TEST_H */
