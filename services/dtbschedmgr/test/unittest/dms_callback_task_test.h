/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef DMS_CALLBACK_TASK_TEST_H
#define DMS_CALLBACK_TASK_TEST_H

#include "gtest/gtest.h"

#define private public
#include "dms_callback_task.h"
#undef private

namespace OHOS {
namespace DistributedSchedule {
class DmsCallbackTaskTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    void PushMockTask(int64_t taskId, std::string& deviceId);
    std::shared_ptr<DmsCallbackTask> dmsCallbackTask_;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DMS_CALLBACK_TASK_TEST_H