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

#ifndef DISTRIBUTED_INTENT_DSOFTBUS_ADAPTER_MOCK_H
#define DISTRIBUTED_INTENT_DSOFTBUS_ADAPTER_MOCK_H

#include <gmock/gmock.h>
#include <string>
#include "distributed_intent_error_code.h"
#include "distributed_intent_dsoftbus_adapter.h"

namespace OHOS {
namespace DistributedSchedule {

class IDistributedIntentDsoftbusAdapter {
public:
    virtual ~IDistributedIntentDsoftbusAdapter() = default;
    virtual int32_t BindIntentSession(const std::string& deviceId, int32_t& socketFd) = 0;
    virtual int32_t SendIntentDataBySession(int32_t socketFd, IntentDataType dataType,
        const std::string& data) = 0;
    virtual void UnbindIntentSession(int32_t socketFd) = 0;
    virtual int32_t GetSocketFdByDeviceId(const std::string& deviceId) = 0;
public:
    static inline std::shared_ptr<IDistributedIntentDsoftbusAdapter> adapterMock = nullptr;
};

class DistributedIntentDsoftbusAdapterMock : public IDistributedIntentDsoftbusAdapter {
public:
    MOCK_METHOD2(BindIntentSession, int32_t(const std::string& deviceId, int32_t& socketFd));
    MOCK_METHOD3(SendIntentDataBySession, int32_t(int32_t socketFd, IntentDataType dataType,
        const std::string& data));
    MOCK_METHOD1(UnbindIntentSession, void(int32_t socketFd));
    MOCK_METHOD1(GetSocketFdByDeviceId, int32_t(const std::string& deviceId));
};

} // namespace DistributedSchedule
} // namespace OHOS
#endif // DISTRIBUTED_INTENT_DSOFTBUS_ADAPTER_MOCK_H