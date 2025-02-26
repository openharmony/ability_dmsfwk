/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "distributed_extension_proxy.h"

#include "dtbschedmgr_log.h"

namespace OHOS {
namespace DistributedSchedule {
const std::string TAG = "DExtensionProxy";

int32_t DExtensionProxy::TriggerOnCreate(AAFwk::Want &want)
{
    HILOGI("TriggerOnCreate");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        HILOGE("DExtensionProxy::TriggerOnCreate Write interface token failed!");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteParcelable(&want)) {
        HILOGE("DExtensionProxy::TriggerOnCreate due to write want fail");
        return ERR_INVALID_VALUE;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret =
        Remote()->SendRequest(static_cast<uint32_t>(IDExtensionInterfaceCode::CMD_ON_CREATE), data, reply, option);
    if (ret != NO_ERROR) {
        HILOGE("DExtensionProxy::TriggerOnCreate Transact ErrCode = %{public}d", ret);
        return ret;
    }
    HILOGI("TriggerOnCreate Success");

    return NO_ERROR;
}

int32_t DExtensionProxy::TriggerOnDestroy(void)
{
    HILOGI("TriggerOnDestroy");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        HILOGE("DExtensionProxy::TriggerOnDestroy Write interface token failed!");
        return ERR_FLATTEN_OBJECT;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret =
        Remote()->SendRequest(static_cast<uint32_t>(IDExtensionInterfaceCode::CMD_ON_DESTORY), data, reply, option);
    if (ret != NO_ERROR) {
        HILOGE("DExtensionProxy::TriggerOnDestroy Transact ErrCode = %{public}d", ret);
        return ret;
    }
    HILOGI("TriggerOnDestroy Success");

    return NO_ERROR;
}

int32_t DExtensionProxy::TriggerOnCollaborate(AAFwk::WantParams &wantParam)
{
    HILOGI("TriggerOnCollaborate");
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        HILOGE("DExtensionProxy::TriggerOnCollaborate Write interface token failed!");
        return ERR_FLATTEN_OBJECT;
    }

    if (!data.WriteParcelable(&wantParam)) {
        HILOGE("DExtensionProxy::TriggerOnCollaborate due to write want fail");
        return ERR_INVALID_VALUE;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t ret = Remote()->SendRequest(static_cast<uint32_t>(IDExtensionInterfaceCode::CMD_ON_COLLAB_REQUEST),
        data, reply, option);
    if (ret != NO_ERROR) {
        HILOGE("DExtensionProxy::TriggerOnCollaborate Transact ErrCode = %{public}d", ret);
        return ret;
    }
    HILOGI("TriggerOnCollaborate Success");

    return NO_ERROR;
}
}
} // namespace OHOS
