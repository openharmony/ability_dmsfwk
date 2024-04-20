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

#include "common_event_listener.h"

#include "dtbschedmgr_log.h"
#include "mission/distributed_bm_storage.h"
#include "mission/dms_continue_recv_manager.h"
#include "mission/dms_continue_send_manager.h"

namespace OHOS {
namespace DistributedSchedule {
namespace {
const std::string TAG = "CommonEventListener";
}
void CommonEventListener::OnReceiveEvent(const EventFwk::CommonEventData &eventData)
{
    auto want = eventData.GetWant();
    std::string action = want.GetAction();
    int32_t userId = 0;
    HILOGD("OnReceiveEvent called, action = %{public}s", action.c_str());
    if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_OFF) {
        DMSContinueSendMgr::GetInstance().OnDeviceScreenOff();
        DMSContinueRecvMgr::GetInstance().OnDeviceScreenOff();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_SCREEN_ON) {
        DMSContinueSendMgr::GetInstance().OnDeviceScreenOn();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_USER_SWITCHED) {
        userId = eventData.GetCode();
        HILOGI("OnReceiveEvent switched userId:%{public}d", userId);
        DmsBmStorage::GetInstance()->UpdateDistributedData();
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_ADDED) {
        std::string bundleName = want.GetElement().GetBundleName();
        DmsBmStorage::GetInstance()->SaveStorageDistributeInfo(bundleName);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_CHANGED) {
        std::string bundleName = want.GetElement().GetBundleName();
        DmsBmStorage::GetInstance()->SaveStorageDistributeInfo(bundleName);
    } else if (action == EventFwk::CommonEventSupport::COMMON_EVENT_PACKAGE_REMOVED) {
        std::string bundleName = want.GetElement().GetBundleName();
        DmsBmStorage::GetInstance()->DeleteStorageDistributeInfo(bundleName);
    } else {
        HILOGW("OnReceiveEvent undefined action");
    }
}
} // namespace DistributedSchedule
} // namespace OHOS