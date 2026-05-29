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

#include "distributed_intent_plugin.h"
#include "distributed_intent_dsoftbus_adapter.h"
#include "distributed_intent_error_code.h"
#include "distributed_intent_service.h"
#include "distributed_intent_service_stub.h"
#include "distributed_sched_utils.h"
#include "dtbschedmgr_log.h"
#include "intent_all_connect_manager.h"
#include "intent_permission_checker.h"
#include "remote_intent_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedIntentPlugin";

class DistributedIntentPluginImpl : public IIntentPlugin {
public:
    explicit DistributedIntentPluginImpl(IIntentProvider* provider) : provider_(provider)
    {
        DistributedIntentServiceStub::SetProvider(provider_);
        DistributedIntentDsoftbusAdapter::GetInstance().SetProvider(provider_);
        DistributedIntentDsoftbusAdapter::GetInstance().SetStopped(false);
        IntentPermissionChecker::GetInstance().SetProvider(provider_);
#ifdef DMSFWK_ALL_CONNECT_MGR
        IntentAllConnectManager::GetInstance().Init();
#endif
        HILOGI("DistributedIntentPluginImpl created");
    }

    ~DistributedIntentPluginImpl() override
    {
        DistributedIntentDsoftbusAdapter::GetInstance().SetStopped(true);
#ifdef DMSFWK_ALL_CONNECT_MGR
        IntentAllConnectManager::GetInstance().Uninit();
#endif
    }

    int32_t OnRemoteRequest(uint32_t code, MessageParcel& data,
        MessageParcel& reply, MessageOption& option) override
    {
        if (intentService_ == nullptr) {
            intentService_ = std::make_shared<DistributedIntentService>();
        }
        return intentService_->OnRemoteRequest(code, data, reply, option);
    }

    IIntentSocketEventListener* GetSocketListener() override
    {
        return &DistributedIntentDsoftbusAdapter::GetInstance();
    }

    int32_t StartRemoteIntent(const AAFwk::Want& want,
        const IntentCallerInfo& callerInfo, const sptr<IRemoteObject>& resultCallback) override
    {
        if (intentService_ == nullptr) {
            intentService_ = std::make_shared<DistributedIntentService>();
        }
        return intentService_->StartRemoteIntent(want, callerInfo, resultCallback);
    }

    int32_t SendIntentResult(const AAFwk::Want& want,
        const IntentCallerInfo& callerInfo, const std::string& resultMsg) override
    {
        if (intentService_ == nullptr) {
            intentService_ = std::make_shared<DistributedIntentService>();
        }
        return intentService_->SendIntentResult(want, callerInfo, resultMsg);
    }

    void OnDeviceOffline(const std::string& networkId) override
    {
        HILOGI("OnDeviceOffline: networkId=%{public}s", GetAnonymStr(networkId).c_str());
        std::vector<int32_t> closedSockets;
        DistributedIntentDsoftbusAdapter::GetInstance().ForceCleanupDeviceSessions(networkId, closedSockets);
        if (closedSockets.empty()) {
            return;
        }
#ifdef DMSFWK_ALL_CONNECT_MGR
        IntentAllConnectManager::GetInstance().PublishServiceState(networkId, SCM_IDLE);
#endif
        for (int32_t socketFd : closedSockets) {
            RemoteIntentManager::GetInstance().CleanupSocketMapping(networkId, socketFd);
        }
        RemoteIntentManager::GetInstance().NotifyLinkDisconnected(
            networkId, INTENT_LINK_DISCONNECT_REASON_SHUTDOWN);
        HILOGI("OnDeviceOffline done: networkId=%{public}s, closed=%{public}zu",
            GetAnonymStr(networkId).c_str(), closedSockets.size());
    }

private:
    IIntentProvider* provider_ = nullptr;
    std::shared_ptr<DistributedIntentService> intentService_;
}; // class DistributedIntentPluginImpl

} // anonymous namespace

extern "C" __attribute__((visibility("default"))) void* CreateIntentPlugin(IIntentProvider* provider)
{
    HILOGI("CreateIntentPlugin called");
    if (provider == nullptr) {
        return nullptr;
    }
    auto* plugin = new DistributedIntentPluginImpl(provider);
    return plugin;
}

} // namespace DistributedSchedule
} // namespace OHOS
