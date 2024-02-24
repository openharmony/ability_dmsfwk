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

#ifndef OHOS_DSCHED_TRANSPORT_SOFTBUS_ADAPTER_H
#define OHOS_DSCHED_TRANSPORT_SOFTBUS_ADAPTER_H

#include <map>
#include <string>

#include "dsched_softbus_session.h"
#include "idata_listener.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
class DSchedTransportSoftbusAdapter {
DECLARE_SINGLE_INSTANCE_BASE(DSchedTransportSoftbusAdapter);
public:
    int32_t InitChannel();
    int32_t ConnectDevice(std::string &peerDeviceId);
    int32_t SendData(int32_t sessionId, std::shared_ptr<DSchedDataBuffer> dataBuffer);
    int32_t DisconnectDevice(std::string &peerDeviceId);
    int32_t ReleaseChannel();
    void RegisterListener(int32_t serviceType, std::shared_ptr<IDataListener> listener);

private:
    DSchedTransportSoftbusAdapter();
    ~DSchedTransportSoftbusAdapter();

private:
    std::map<int32_t, std::shared_ptr<DSchedSoftbusSession>> sessions_;
    std::map<int32_t, std::vector<IDataListener>> listeners_;
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif  // OHOS_DSCHED_TRANSPORT_SOFTBUS_ADAPTER_H