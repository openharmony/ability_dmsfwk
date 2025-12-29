/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "distributed_extension_context.h"

#include "ability_connection.h"
#include "ability_manager_client.h"
#include "dtbschedmgr_log.h"


namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DistributedExtensionContextJS";
using namespace AbilityRuntime;

bool DistributedExtensionContext::ConnectAbility(const AAFwk::Want &want,
    const sptr<AbilityConnectCallback> &connectCallback) const
{
    HILOGI("%{public}s start.", __func__);
    ErrCode ret = ConnectionManager::GetInstance().ConnectAbility(token_, want, connectCallback);
    HILOGI("DistributedExtensionContext::ConnectAbility ret: %{public}d", ret);
    return ret == ERR_OK;
}

ErrCode DistributedExtensionContext::DisconnectAbility(const AAFwk::Want &want,
    const sptr<AbilityConnectCallback> &connectCallback) const
{
    HILOGI("%{public}s start.", __func__);
    ErrCode ret = ConnectionManager::GetInstance().DisconnectAbility(token_, want.GetElement(), connectCallback);
    if (ret != ERR_OK) {
        HILOGE("%{public}s end DisconnectAbility error, ret: %{public}d!", __func__, ret);
    }
    HILOGI("%{public}s end DisconnectAbility.", __func__);
    return ret;
}
}
}
