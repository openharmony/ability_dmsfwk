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

#ifndef OHOS_DISTRIBUTED_REMOTE_INTENT_MANAGER_H
#define OHOS_DISTRIBUTED_REMOTE_INTENT_MANAGER_H

#include <string>
#include <set>
#include <map>
#include <mutex>
#include <chrono>
#include <vector>

#include "single_instance.h"
#include "distributed_want.h"
#include "distributed_intent_dsoftbus_adapter.h"
#include "distributed_intent_error_code.h"
#include "caller_info.h"
#include "distributed_sched_types.h"
#include "distributed_sched_interface.h"
#include "dms_version_manager.h"
#include "dms_constant.h"

namespace OHOS {
namespace DistributedSchedule {

struct CallbackEntry {
    sptr<IRemoteObject> callback;
    std::chrono::steady_clock::time_point timestamp;
    std::string deviceId;
};

struct IntentContext {
    CallerInfo callerInfo;
    uint64_t requestCode = 0;
    IDistributedSched::AccountInfo accountInfo;
};

class RemoteIntentManager {
    DECLARE_SINGLE_INSTANCE_BASE(RemoteIntentManager);
public:
    int32_t StartRemoteIntent(const OHOS::AAFwk::Want& want,
        const IntentCallerInfo& callerInfo, const sptr<IRemoteObject>& resultCallback);

    int32_t SerializeIntentData(const OHOS::AAFwk::Want& want,
        const IntentContext& ctx, std::string& data, const std::string& resultMsg = "");
    int32_t DeserializeIntentData(const std::string& data,
        OHOS::AAFwk::Want& want, IntentContext& ctx, std::string& resultMsg);
    int32_t SerializeResultData(int32_t resultCode, const std::string& resultMsg,
        uint64_t requestCode, std::string& data);

    void OnIntentDataReceived(const std::string& srcDeviceId,
        IntentDataType dataType, const std::string& data, int32_t socketFd);
    int32_t HandleIntentExecute(const std::string& srcDeviceId,
        const std::string& data, int32_t socketFd);
    int32_t HandleIntentResult(const std::string& srcDeviceId,
        const std::string& data, int32_t socketFd);
    int32_t HandleBusinessResult(const std::string& srcDeviceId,
        const std::string& data, int32_t socketFd);

    int32_t NotifyIntentResult(const sptr<IRemoteObject>& callback,
        uint64_t requestCode, int32_t resultCode, std::string& resultMsg);

    int32_t SendInnerResultBack(int32_t socketFd, uint64_t requestCode,
        int32_t resultCode, IntentDataType dataType);
    int32_t HandleSendIntentResult(const OHOS::AAFwk::Want& want,
        const IntentCallerInfo& callerInfo, const std::string& msg);
    void NotifyLinkDisconnected(const std::string& deviceId, int32_t reason);
    void NotifyAllCallbacksDisconnected(const std::string& deviceId, int32_t reason);

    void CleanupSocketMapping(const std::string& deviceId, int32_t socketFd);

private:
    int32_t PrepareCallerContext(const std::string& localDeviceId, const std::string& dstDeviceId,
        const IntentCallerInfo& intentCallerInfo, CallerInfo& callerInfo,
        IDistributedSched::AccountInfo& accountInfo);
    int32_t SendIntentToRemote(const std::string& dstDeviceId, const OHOS::AAFwk::Want& want,
        const IntentContext& ctx, int32_t& socketFd);
    void RegisterResultCallback(uint64_t requestCode, const std::string& deviceId,
        const sptr<IRemoteObject>& callback);

    int32_t DecodeWantFromJson(const nlohmann::json& root, OHOS::AAFwk::Want& want);
    int32_t ParseCallerInfoFromJson(const nlohmann::json& root, CallerInfo& callerInfo);
    int32_t ValidateCallerInfo(const CallerInfo& callerInfo);
    void ParseAccountInfoFromJson(const nlohmann::json& root, IDistributedSched::AccountInfo& accountInfo);

    int32_t ValidateExecuteRequest(const std::string& srcDeviceId, const AAFwk::Want& want,
        const IntentContext& ctx, const std::string& localDeviceId);
    int32_t CheckAndExecuteIntent(AAFwk::Want& want, const std::string& srcDeviceId,
        const IntentContext& ctx, const std::string& localDeviceId, int32_t socketFd);
    int32_t DoExecuteIntent(AAFwk::Want& want, const std::string& srcDeviceId,
        const IntentContext& ctx, uint64_t dAccessToken, int32_t userId);

    int32_t PrepareResultContext(const std::string& srcDeviceId, const std::string& localDeviceId,
        const IntentCallerInfo& intentCallerInfo, IntentContext& ctx);
    int32_t SendResultToRemote(int32_t socketFd, const OHOS::AAFwk::Want& want,
        const IntentContext& ctx, const std::string& msg);

    void CleanupExpiredCallbacks();

private:
    RemoteIntentManager();
    ~RemoteIntentManager();
    std::map<uint64_t, CallbackEntry> requestCodeCallbackMap_;
    std::map<std::pair<std::string, uint64_t>, int32_t> requestSocketMap_;
    std::mutex connectMutex_;
    std::mutex requestSocketMutex_;
};

} // namespace DistributedSchedule
} // namespace OHOS

#endif // OHOS_DISTRIBUTED_REMOTE_INTENT_MANAGER_H
