/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#ifndef OHOS_DMS_CLIENT_H
#define OHOS_DMS_CLIENT_H

#include <atomic>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <string>

#include "iremote_broker.h"
#include "system_ability_load_callback_stub.h"

#include "distributed_extension_types.h"
#include "distributed_event_listener.h"
#include "distributed_sched_types.h"

namespace OHOS {
namespace DistributedSchedule {
class DmsLoadCallback : public SystemAbilityLoadCallbackStub {
public:
    DmsLoadCallback() = default;
    ~DmsLoadCallback() = default;

    void OnLoadSystemAbilitySuccess(int32_t systemAbilityId,
        const sptr<IRemoteObject>& remoteObject) override;
    void OnLoadSystemAbilityFail(int32_t systemAbilityId) override;

    bool WaitForLoadSuccess(int32_t timeoutMs);
    sptr<IRemoteObject> GetRemoteObject() const;

private:
    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::atomic<bool> loadSuccess_ {false};
    sptr<IRemoteObject> remoteObject_;
};

class DistributedClient {
public:
    int32_t RegisterDSchedEventListener(const DSchedEventType& type, const sptr<IDSchedEventListener>& obj);
    int32_t UnRegisterDSchedEventListener(const DSchedEventType& type, const sptr<IDSchedEventListener>& obj);
    int32_t GetContinueInfo(ContinueInfo &continueInfo);
    int32_t GetDSchedEventInfo(const DSchedEventType &type, std::vector<EventNotify> &events);
    int32_t ConnectDExtensionFromRemote(const DExtConnectInfo& connectInfo,
        std::function<void(DExtConnectResultInfo)> callback);

private:
    sptr<IRemoteObject> GetDmsProxy();
    sptr<IRemoteObject> LoadDmsServiceWithTimeout();
    int32_t GetDecodeDSchedEventNotify(MessageParcel &reply, EventNotify &event);
};
}  // namespace DistributedSchedule
}  // namespace OHOS
#endif