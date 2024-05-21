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

#ifndef SOFTBUS_TRANSPORT_TEST_H
#define SOFTBUS_TRANSPORT_TEST_H

#include "gtest/gtest.h"

#include "softbus_adapter/transport/dsched_data_buffer.h"
#include "softbus_adapter/transport/dsched_softbus_session.h"
#include "softbus_adapter/transport/dsched_transport_softbus_adapter.h"

namespace OHOS {
namespace DistributedSchedule {
class DSchedDataBufferTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedDataBuffer> dataBufferTest_;
};

class DSchedSoftbusSessionTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
    std::shared_ptr<DSchedSoftbusSession> softbusSessionTest_;
};

class DSchedTransportSoftbusAdapterTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
} // namespace DistributedSchedule
} // namespace OHOS
#endif // SOFTBUS_TRANSPORT_TEST_H