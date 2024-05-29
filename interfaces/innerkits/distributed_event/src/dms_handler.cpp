/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "dms_handler.h"

#include "dtbschedmgr_log.h"
#include "single_instance.h"

namespace OHOS {
namespace DistributedSchedule {
IMPLEMENT_SINGLE_INSTANCE(DmsHandler);

namespace {
const std::string TAG = "DmsHandle";
}

int32_t DmsHandler::RegisterDSchedEventListener(const DSchedEventType& type, sptr<IDSchedEventListener>& listener)
{
    HILOGI("RegisterListener type:%d", type);
    if (listener == nullptr) {
        HILOGE("RegisterListener is null.");
        return GET_REMOTE_DMS_FAIL;
    }
    int32_t ret = DmsSaClient::GetInstance().AddDSchedEventListener(type, listener);
    if (ret != 0) {
        HILOGE("DmsSaClient AddListener fail");
        return GET_REMOTE_DMS_FAIL;
    }
    return 0;
}

int32_t DmsHandler::UnRegisterDSchedEventListener(const DSchedEventType& type, sptr<IDSchedEventListener> &listener)
{
    HILOGI("RegisterListener type:%d", type);
    if (listener == nullptr) {
        HILOGI("UnRegisterListener is null.");
        return GET_REMOTE_DMS_FAIL;
    }
    int32_t ret = DmsSaClient::GetInstance().DelDSchedEventListener(type, listener);
    if (ret != 0) {
        HILOGE("DmsSaClient AddListener fail");
        return GET_REMOTE_DMS_FAIL;
    }
    return 0;
}

int32_t DmsHandler::GetContinueInfo(ContinueInfo &continueInfo)
{
    HILOGI("%{public}s called", __func__);
    int32_t ret = DmsSaClient::GetInstance().GetContinueInfo(continueInfo);
    if (ret != 0) {
        HILOGE("DmsSaClient GetContinueInfo fail");
        return GET_REMOTE_DMS_FAIL;
    }
    return 0;
}

int32_t DmsHandler::GetDSchedEventInfo(const DSchedEventType &type, std::vector<EventNotify> &events)
{
    HILOGI("%{public}s called", __func__);
    int32_t ret = DmsSaClient::GetInstance().GetDSchedEventInfo(type, events);
    if (ret != ERR_OK) {
        HILOGE("DmsSaClient GetDSchedEventInfo fail, ret %{public}d.", ret);
        return GET_REMOTE_DMS_FAIL;
    }
    return ERR_OK;
}
} // namespace DistributedSchedule
} // namespace OHOS