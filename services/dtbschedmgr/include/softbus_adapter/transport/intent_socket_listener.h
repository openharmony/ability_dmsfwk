/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef OHOS_INTENT_SOCKET_LISTENER_H
#define OHOS_INTENT_SOCKET_LISTENER_H

#include <string>
#include <cstdint>

namespace OHOS {
namespace DistributedSchedule {

class IIntentSocketEventListener {
public:
    virtual ~IIntentSocketEventListener() = default;
    virtual void OnIntentSocketBind(int32_t socket, const std::string &peerDeviceId) = 0;
    virtual void OnIntentSocketShutdown(int32_t socket) = 0;
    virtual void OnIntentSocketBytes(int32_t socket, const void *data, uint32_t dataLen) = 0;
};

} // namespace DistributedSchedule
} // namespace OHOS

#endif // OHOS_INTENT_SOCKET_LISTENER_H
