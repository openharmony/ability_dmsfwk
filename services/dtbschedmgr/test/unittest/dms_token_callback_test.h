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

#ifndef DMS_TOKEN_CB_TEST_H
#define DMS_TOKEN_CB_TEST_H

#include "gtest/gtest.h"

#include "mock/multi_user_manager_mock.h"

#define private public
#include "dms_token_callback.h"
#undef private

namespace OHOS {
namespace DistributedSchedule {
class DmsTokenCallbackTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();

    sptr<DmsTokenCallback> dmsTokenCallback_;
    static inline std::shared_ptr<MultiUserManagerMock> multiUserMgrMock_ = nullptr;
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // DMS_TOKEN_CB_TEST_H