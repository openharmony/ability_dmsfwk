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

#include "ichannel_listener.h"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

namespace OHOS {
namespace DistributedCollab {
class MockChannelListener : public IChannelListener {
public:
    MockChannelListener() = default;
    ~MockChannelListener() override = default;

    MOCK_METHOD(void, OnConnect, (const int32_t channelId), (const, override));
    MOCK_METHOD(void, OnDisConnect, (const int32_t channelId), (const, override));
    MOCK_METHOD(void, OnStream, (const int32_t channelId, const std::shared_ptr<AVTransStreamData>& stream), (const, override));
    MOCK_METHOD(void, OnBytes, (const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& buffer), (const, override));
    MOCK_METHOD(void, OnMessage, (const int32_t channelId, const std::shared_ptr<AVTransDataBuffer>& buffer), (const, override));
    MOCK_METHOD(void, OnError, (const int32_t channelId, const int32_t errorCode), (const, override));
};

} // namespace DistributedCollab
} // namespace OHOS
#endif