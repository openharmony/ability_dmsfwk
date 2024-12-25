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
#ifndef DISTRIBUTED_COLLAB_DATA_SENDER_RECEIVER_TEST_H
#define DISTRIBUTED_COLLAB_DATA_SENDER_RECEIVER_TEST_H

#include "data_sender_receiver.h"
#include "socket.h"
#include "softbus_mock.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace OHOS {
namespace DistributedCollab {
class DataSenderReceiverTest : public testing::Test {
public:
    SoftbusMock mockSoftbus;
    int32_t socketId = 1234;
    std::shared_ptr<AVTransDataBuffer> buffer = std::make_shared<AVTransDataBuffer>(100);
    AVTransStreamDataExt ext { AvCodecBufferFlag::AVCODEC_BUFFER_FLAG_SYNC_FRAME, 1, 12345, 67890, 123456, 7891011 };
    std::shared_ptr<AVTransStreamData> streamData = std::make_shared<AVTransStreamData>(buffer, ext);
    DataSenderReceiver dataSenderReceiver = DataSenderReceiver(socketId);
    
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};
} // namespace DistributedCollab
} // namespace OHOS
#endif