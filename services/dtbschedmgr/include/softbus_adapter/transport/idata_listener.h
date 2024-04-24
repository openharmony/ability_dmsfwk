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

#ifndef OHOS_I_DATA_LISTENER_H
#define OHOS_I_DATA_LISTENER_H

#include "socket.h"

namespace OHOS {
namespace DistributedSchedule {
class IDataListener {
public:
    IDataListener() {}
    virtual ~IDataListener() {}

    virtual void OnBind(int32_t socket, PeerSocketInfo info) = 0;
    virtual void OnShutdown(int32_t socket, bool isSelfCalled) = 0;
    virtual void OnDataRecv(int32_t socket, std::shared_ptr<DSchedDataBuffer> dataBuffer) = 0;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_I_DATA_LISTENER_H