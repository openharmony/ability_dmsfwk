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

#include "dsched_collaborate_callback_mgr.h"

#include "distributed_sched_service.h"
#include "dtbschedmgr_log.h"
#include "parcel_helper.h"

using namespace OHOS::AppExecFwk;

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "DSchedCollaborationCallbackMgr";
const std::u16string DSCHED_EVENT_TOKEN = u"ohos.distributedSchedule.dschedeventlistener";
constexpr int32_t DSCHED_EVENT_CALLBACK = 0;
}

void DSchedCollaborationCallbackMgr::Init()
{
    diedListener_ = new DistributedEventDiedListener();
}

bool DSchedCollaborationCallbackMgr::PushCallback(const sptr<IRemoteObject>& callback)
{
    HILOGI("DSchedCollaborationCallbackMgr PushCallback start!");
    if (diedListener_ == nullptr) {
        HILOGE("DSchedCollaborationCallbackMgr is not init!");
        return false;
    }
    if (callback == nullptr) {
        HILOGE("callback null!");
        return false;
    }
    std::lock_guard<std::mutex> autoLock(collaborateCbLock_);
    std::vector<sptr<IRemoteObject>> vecCallback = collaborateCbArr_;
    for (auto ele = collaborateCbArr_.begin(); ele != collaborateCbArr_.end(); ++ele) {
        if ((*ele) == callback) {
            HILOGW("callback already  exists!");
            return false;
        }
    }
    collaborateCbArr_.push_back(callback);
    callback->AddDeathRecipient(diedListener_);

    std::vector<EventNotify> events;
    if (DistributedSchedService::GetInstance().GetDSchedEventInfo(DMS_COLLABORATION, events) != ERR_OK) {
        HILOGE("GetDSchedEventInfo fail, events size %{public}zu", events.size());
    }
    for (const auto &event : events) {
        int32_t dSchedEventresult = NotifyDSchedEventForOneCB(callback, event);
        if (dSchedEventresult != ERR_OK) {
            HILOGE("Push continuation success, notify dms event result: %{public}d", dSchedEventresult);
        }
    }

    return true;
}

std::vector<sptr<IRemoteObject>> DSchedCollaborationCallbackMgr::GetCallback()
{
    std::lock_guard<std::mutex> autoLock(collaborateCbLock_);
    return collaborateCbArr_;
}

bool DSchedCollaborationCallbackMgr::CleanupCallback(const sptr<IRemoteObject>& callback)
{
    std::lock_guard<std::mutex> autoLock(collaborateCbLock_);
    if (collaborateCbArr_.empty()) {
        HILOGE("No need for cleaning!");
        return false;
    }
    for (auto ele = collaborateCbArr_.begin(); ele != collaborateCbArr_.end(); ++ele) {
        if ((*ele) == callback) {
            collaborateCbArr_.erase(ele);
            HILOGI("callback is exists, cleared successfully.");
            return true;
        }
    }
    HILOGI("callback is not exists!");
    return false;
}

int32_t DSchedCollaborationCallbackMgr::NotifyDSchedEventForOneCB(const sptr<IRemoteObject> &cb,
    const EventNotify& event)
{
    if (cb == nullptr) {
        HILOGE("NotifyDSchedEventForOneCB input callback is null.");
        return INVALID_PARAMETERS_ERR;
    }

    MessageParcel data;
    if (!data.WriteInterfaceToken(DSCHED_EVENT_TOKEN)) {
        HILOGE("NotifyDSchedEventForOneCB write token failed");
        return SEND_REQUEST_DEF_FAIL;
    }
    PARCEL_WRITE_HELPER_RET(data, Int32, event.eventResult_, SEND_REQUEST_DEF_FAIL);
    PARCEL_WRITE_HELPER_RET(data, String, event.srcNetworkId_, SEND_REQUEST_DEF_FAIL);
    PARCEL_WRITE_HELPER_RET(data, String, event.dstNetworkId_, SEND_REQUEST_DEF_FAIL);
    PARCEL_WRITE_HELPER_RET(data, String, event.srcBundleName_, SEND_REQUEST_DEF_FAIL);
    PARCEL_WRITE_HELPER_RET(data, String, event.srcModuleName_, SEND_REQUEST_DEF_FAIL);
    PARCEL_WRITE_HELPER_RET(data, String, event.srcAbilityName_, SEND_REQUEST_DEF_FAIL);
    PARCEL_WRITE_HELPER_RET(data, String, event.destBundleName_, SEND_REQUEST_DEF_FAIL);
    PARCEL_WRITE_HELPER_RET(data, String, event.destModuleName_, SEND_REQUEST_DEF_FAIL);
    PARCEL_WRITE_HELPER_RET(data, String, event.destAbilityName_, SEND_REQUEST_DEF_FAIL);
    PARCEL_WRITE_HELPER_RET(data, Int32, event.dSchedEventType_, SEND_REQUEST_DEF_FAIL);
    PARCEL_WRITE_HELPER_RET(data, Int32, event.state_, SEND_REQUEST_DEF_FAIL);

    MessageParcel reply;
    MessageOption option;
    int32_t ret = cb->SendRequest(DSCHED_EVENT_CALLBACK, data, reply, option);
    HILOGI("NotifyDSchedEventListenerResult transact end, ret: %{public}d.", ret);
    return ret;
}

int32_t DSchedCollaborationCallbackMgr::NotifyDSchedEventResult(int32_t resultCode, const EventNotify& event)
{
    HILOGI("GetCallback IDSchedEventListener");
    std::vector<sptr<IRemoteObject>> vecCallback = GetCallback();
    if (vecCallback.empty()) {
        HILOGD("No listening has been registered, no need to report events");
        return INVALID_PARAMETERS_ERR;
    }
    bool isAllSuc = true;
    for (auto callback = vecCallback.begin(); callback != vecCallback.end(); ++callback) {
        int32_t ret = NotifyDSchedEventForOneCB(*callback, event);
        if (ret != ERR_OK) {
            HILOGE("NotifyDSchedEventForOneCB transact fail, ret: %{public}d", ret);
            isAllSuc = isAllSuc && false;
        }
    }
    if (!isAllSuc) {
        HILOGE("NotifyDSchedEventListenerResult transact fail, isAllSuc: %{public}d", isAllSuc);
        return SEND_REQUEST_DEF_FAIL;
    }
    HILOGI("NotifyDSchedEventResult transact ok.");
    return ERR_OK;
}
} // namespace DistributedSchedule
} // namespace OHOS
