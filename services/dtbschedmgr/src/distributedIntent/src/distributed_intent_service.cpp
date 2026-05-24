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

#include "distributed_intent_service.h"
#include "distributed_intent_provider.h"
#include "dtbschedmgr_log.h"
#include "remote_intent_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DistributedIntentService";
}

DistributedIntentService::DistributedIntentService() {}

DistributedIntentService::~DistributedIntentService() {}

int32_t DistributedIntentService::StartRemoteIntent(const OHOS::AAFwk::Want& want,
    const IntentCallerInfo& callerInfo,
    const sptr<IRemoteObject>& resultCallback)
{
    HILOGI("DistributedIntentService::StartRemoteIntent");
    if (resultCallback == nullptr) {
        HILOGE("resultCallback is null");
        return ERR_DI_INVALID_PARAMETER;
    }
    auto* provider = DistributedIntentServiceStub::GetProvider();
    if (provider == nullptr) {
        HILOGE("provider is null");
        return ERR_DI_SYSTEM_WORK_ABNORMALLY;
    }
    std::string localDeviceId;
    if (!provider->GetLocalDeviceId(localDeviceId)) {
        HILOGE("Get local device id failed");
        return ERR_DI_INVALID_PARAMETER;
    }
    std::string dstDeviceId = want.GetElement().GetDeviceID();
    if (dstDeviceId.empty()) {
        HILOGE("Dst device id is empty");
        return ERR_DI_INVALID_PARAMETER;
    }
    return RemoteIntentManager::GetInstance().StartRemoteIntent(
        want, callerInfo, resultCallback);
}

int32_t DistributedIntentService::SendIntentResult(const OHOS::AAFwk::Want& want,
    const IntentCallerInfo& callerInfo, const std::string& resultMsg)
{
    HILOGI("DistributedIntentService::SendIntentResult requestCode=%{public}" PRIu64,
        callerInfo.requestCode);
    return RemoteIntentManager::GetInstance().HandleSendIntentResult(want, callerInfo, resultMsg);
}

} // namespace DistributedSchedule
} // namespace OHOS
