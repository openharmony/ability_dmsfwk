/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef SOFTBUS_ADAPTER_TEST_H
#define SOFTBUS_ADAPTER_TEST_H

#include "gtest/gtest.h"

#define private public
#include "softbus_adapter/softbus_adapter.h"
#undef private

namespace OHOS {
namespace DistributedSchedule {
class SoftbusAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

class SubSoftbusAdapterListener : public SoftbusAdapterListener {
public:
    void OnDataRecv(std::string& senderNetworkId, uint8_t* payload, uint32_t dataLen) {};
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // SOFTBUS_ADAPTER_TEST_H
